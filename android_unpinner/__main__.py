import asyncio
import logging
import subprocess
from pathlib import Path

import rich_click as click
from rich.logging import RichHandler

from . import jdwplib
from .vendor import build_tools, frida_tools, gadget_config_file, gadget_files, unpin_file


@click.group()
def cli():
    pass


def adb(cmd: str) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(f"adb {cmd}", shell=True, check=True, capture_output=True, text=True)
    logging.debug(f"cmd='adb {cmd}'\n"
                  f"{proc.stdout=}\n"
                  f"{proc.stderr=}")
    return proc


@cli.command()
@click.option("-f", "--force", help="Overwrite existing files, uninstall existing app.", is_flag=True)
@click.option('-v', '--verbose', count=True)
@click.argument("apk-file")
def run(apk_file, force, verbose):
    logging.basicConfig(
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True, show_path=False, show_level=verbose > 0, omit_repeated_times=False)]
    )
    if verbose == 0:
        logging.getLogger().setLevel("INFO")
        logging.getLogger("jdwplib").setLevel("WARNING")
    elif verbose == 1:
        logging.getLogger().setLevel("INFO")
    else:
        logging.getLogger().setLevel("DEBUG")

    apk_source = Path(apk_file).absolute()
    assert apk_source.exists()
    apk_patched = apk_source.with_suffix(".unpinned.apk")
    if apk_patched.exists():
        if force or click.confirm(f"Delete existing file: {apk_patched.name}?", abort=True):
            apk_patched.unlink()

    package_name = build_tools.package_name(apk_source)
    logging.info(f"Patching {package_name}...")

    logging.info(f"Make {apk_source.name} debuggable...")
    frida_tools.apk.make_debuggable(
        str(apk_source),
        str(apk_patched),
    )

    logging.info(f"Zipalign & re-sign APK...")
    build_tools.zipalign(apk_patched)
    build_tools.sign(apk_patched)

    logging.info(f"Created patched APK: {apk_patched}")

    if not force:
        click.confirm(
            f"About to install patched APK. This removes the existing app with all its data. Continue?",
            abort=True
        )
    logging.info("Uninstall existing app...")
    try:
        adb(f"uninstall {package_name}")
    except subprocess.CalledProcessError:
        logging.info("Uninstall failed, looks like it was not installed after all.")
    logging.info(f"Install {apk_patched.name}...")
    adb(f"install --no-incremental {apk_patched}")

    LIBGADGET = "libgadget.so"
    LIBGADGET_CONF = "libgadget.config.so"

    logging.info(f"Detect architecture...")
    abi = adb("shell getprop ro.product.cpu.abi").stdout.strip()
    if abi == "armeabi-v7a":
        abi = "arm"
    gadget_file = gadget_files.get(abi, gadget_files["arm64"])
    logging.info(f"Copying gadget: {gadget_file}...")
    adb(f"push {gadget_file} /data/local/tmp/{LIBGADGET}")
    adb(f"push {gadget_config_file} /data/local/tmp/{LIBGADGET_CONF}")

    logging.info(f"Copying builtin unpin.js to /data/local/tmp/android-unpinner...")
    adb(f"push {unpin_file} /data/local/tmp/android-unpinner/unpin.js")
    active_scripts = adb(f"shell ls /data/local/tmp/android-unpinner").stdout.splitlines(keepends=False)
    logging.info(f"Active unpinning scripts: {active_scripts}")

    logging.info("Start app (suspended)...")
    adb(f"shell am set-debug-app -w {package_name}")
    adb(f"shell monkey -p {package_name} 1")

    async def inject_frida():
        logging.info("Establish Java Debug Wire Protocol Connection over ADB...")
        async with await jdwplib.JDWPClient.connect_adb() as client:
            logging.info("Advance until android.app.Activity.onCreate...")
            thread_id = await client.advance_to_breakpoint("Landroid/app/Activity;", "onCreate")
            logging.info("Copy Frida gadget into app...")
            await client.exec(thread_id, f"cp /data/local/tmp/{LIBGADGET} /data/data/{package_name}/{LIBGADGET}")
            await client.exec(thread_id,
                              f"cp /data/local/tmp/{LIBGADGET_CONF} /data/data/{package_name}/{LIBGADGET_CONF}")
            logging.info("Inject Frida gadget...")
            await client.load(thread_id, f"/data/data/{package_name}/{LIBGADGET}")
            logging.info("Continue app execution...")
            await client.send_command(jdwplib.Commands.RESUME_VM)

    asyncio.run(inject_frida())

    logging.info("All done!")


if __name__ == "__main__":
    cli()
