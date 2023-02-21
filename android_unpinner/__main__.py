from __future__ import annotations
import asyncio
import logging
import re
import subprocess
from pathlib import Path
from time import sleep

import rich.traceback
import rich_click as click
from rich.logging import RichHandler

from . import jdwplib
from .vendor import build_tools, frida_tools, gadget_config_file, gadget_files
from .vendor.platform_tools import adb, adb_binary

here = Path(__file__).absolute().parent
LIBGADGET = "libgadget.so"
LIBGADGET_CONF = "libgadget.config.so"

force = False


def patch_apk_file(infile: Path, outfile: Path) -> None:
    """
    Patch the APK to be debuggable.
    """
    if outfile.exists():
        if force or click.confirm(f"Delete existing file: {outfile.name}?", abort=True):
            outfile.unlink()

    logging.info(f"Make APK debuggable...")
    frida_tools.apk.make_debuggable(
        str(infile),
        str(outfile),
    )

    logging.info(f"Zipalign & re-sign APK...")
    build_tools.zipalign(outfile)
    build_tools.sign(outfile)

    logging.info(f"Created patched APK: {outfile}")


def ensure_device_connected() -> None:
    try:
        adb("get-state")
    except subprocess.CalledProcessError:
        raise RuntimeError("No device connected via ADB.")


def install_apk(apk_file: Path) -> None:
    """
    Install the APK on the device, replacing any existing installation.
    """
    ensure_device_connected()

    if not force:
        click.confirm(
            f"About to install patched APK. This removes the existing app with all its data. Continue?",
            abort=True,
        )

    package_name = build_tools.package_name(apk_file)
    logging.info("Uninstall existing app...")
    try:
        adb(f"uninstall {package_name}")
    except subprocess.CalledProcessError:
        logging.info("Uninstall failed, looks like it was not installed after all.")

    logging.info(f"Install {apk_file.name}...")
    adb(f"install --no-incremental {apk_file}")


def copy_files() -> None:
    """
    Copy the Frida Gadget and unpinning scripts.
    """
    # TODO: We could later provide the option to use a custom script dir.
    ensure_device_connected()
    logging.info(f"Detect architecture...")
    abi = adb("shell getprop ro.product.cpu.abi").stdout.strip()
    if abi == "armeabi-v7a":
        abi = "arm"
    gadget_file = gadget_files.get(abi, gadget_files["arm64"])
    logging.info(f"Copying matching gadget: {gadget_file.name}...")
    adb(f"push {gadget_file} /data/local/tmp/{LIBGADGET}")
    adb(f"push {gadget_config_file} /data/local/tmp/{LIBGADGET_CONF}")

    logging.info(
        f"Copying builtin Frida scripts to /data/local/tmp/android-unpinner..."
    )
    adb(f"push {here / 'scripts'}/. /data/local/tmp/android-unpinner/")
    active_scripts = adb(
        f"shell ls /data/local/tmp/android-unpinner"
    ).stdout.splitlines(keepends=False)
    logging.info(f"Active frida scripts: {active_scripts}")


def start_app_on_device(package_name: str) -> None:
    ensure_device_connected()
    logging.info("Start app (suspended)...")
    adb(f"shell am set-debug-app -w {package_name}")
    adb(f"shell monkey -p {package_name} 1")

    logging.info("Obtain process id...")
    pid = None
    for i in range(5):
        try:
            pid = adb(f"shell pidof {package_name}").stdout.strip()
            break
        except subprocess.CalledProcessError:
            if i:
                logging.info("Timeout...")
            if i == 4:
                raise
            sleep(1)
    logging.debug(f"{pid=}")
    local_port = int(adb(f"forward tcp:0 jdwp:{pid}").stdout)
    logging.debug(f"{local_port=}")

    async def inject_frida():
        logging.info("Establish Java Debug Wire Protocol Connection over ADB...")
        async with jdwplib.JDWPClient("127.0.0.1", local_port) as client:
            logging.info("Advance until android.app.Activity.onCreate...")
            thread_id = await client.advance_to_breakpoint(
                "Landroid/app/Activity;", "onCreate"
            )
            logging.info("Copy Frida gadget into app...")
            await client.exec(
                thread_id,
                f"cp /data/local/tmp/{LIBGADGET} /data/data/{package_name}/{LIBGADGET}",
            )
            await client.exec(
                thread_id,
                f"cp /data/local/tmp/{LIBGADGET_CONF} /data/data/{package_name}/{LIBGADGET_CONF}",
            )
            logging.info("Inject Frida gadget...")
            await client.load(thread_id, f"/data/data/{package_name}/{LIBGADGET}")
            logging.info("Continue app execution...")
            await client.send_command(jdwplib.Commands.RESUME_VM)

    asyncio.run(inject_frida())


def get_packages() -> list[str]:
    packages = adb("shell pm list packages").stdout.strip().splitlines()
    return [
        p.removeprefix("package:") for p in sorted(packages)
    ]


@click.group()
def cli():
    rich.traceback.install(suppress=[click, click.core])


def _verbosity(ctx, param, verbose):
    logging.basicConfig(
        format="%(message)s",
        datefmt="[%X]",
        handlers=[
            RichHandler(
                show_path=False, show_level=verbose > 0, omit_repeated_times=False
            )
        ],
    )
    if verbose == 0:
        logging.getLogger().setLevel("INFO")
        logging.getLogger("jdwplib").setLevel("WARNING")
    elif verbose == 1:
        logging.getLogger().setLevel("INFO")
    else:
        logging.getLogger().setLevel("DEBUG")


verbosity_option = click.option(
    "-v",
    "--verbose",
    count=True,
    metavar="",
    help="Log verbosity. Can be passed twice.",
    callback=_verbosity,
    expose_value=False,
)


def _force(ctx, param, val):
    global force
    force = val


force_option = click.option(
    "-f",
    "--force",
    help="Affirmatively answer all safety prompts.",
    is_flag=True,
    callback=_force,
    expose_value=False,
)


@cli.command("all")
@verbosity_option
@force_option
@click.argument("apk-file", type=click.Path(path_type=Path, exists=True))
def all_cmd(apk_file):
    """Do everything in a single shot."""
    package_name = build_tools.package_name(apk_file)
    apk_patched = apk_file.with_suffix(".unpinned" + apk_file.suffix)
    logging.info(f"Target: {apk_file.name} ({package_name})")

    patch_apk_file(apk_file, apk_patched)
    install_apk(apk_patched)
    copy_files()
    start_app_on_device(package_name)
    logging.info("All done! 🎉")


@cli.command("install")
@verbosity_option
@force_option
@click.argument("apk-file", type=click.Path(path_type=Path, exists=True))
def install_cmd(apk_file):
    """Install an apk on the device."""
    install_apk(apk_file)
    logging.info("All done! 🎉")


@cli.command()
@verbosity_option
@force_option
@click.argument("infile", type=click.Path(path_type=Path, exists=True))
@click.argument("outfile", type=click.Path(path_type=Path))
def patch_apk(infile, outfile):
    """Patch an APK file to be debuggable."""
    patch_apk_file(infile, outfile)
    logging.info("All done! 🎉")


@cli.command()
@verbosity_option
@force_option
def push_resources():
    """Copy Frida gadget and scripts to device."""
    copy_files()
    logging.info("All done! 🎉")


@cli.command()
@verbosity_option
@force_option
@click.argument("package-name")
def start_app(package_name):
    """Start app on device and inject Frida gadget."""
    start_app_on_device(package_name)
    logging.info("All done! 🎉")


@cli.command()
@verbosity_option
def list_packages():
    """List all packages installed on the device."""
    ensure_device_connected()
    logging.info(f"Enumerating packages...")
    print("\n".join(get_packages()))
    logging.info("All done! 🎉")


@cli.command()
@verbosity_option
@force_option
@click.argument("package", type=str)
@click.argument("outfile", type=click.Path(path_type=Path))
def get_apk(package, outfile):
    """Get an APK file from the device."""
    ensure_device_connected()

    logging.info("Getting package info...")
    if package not in get_packages():
        raise RuntimeError(f"Could not find package: {package}")

    package_info = adb(f"shell pm path {package}").stdout
    if not package_info.startswith("package:"):
        raise RuntimeError(f"Unxepected output from pm path: {package_info!r}")
    package_path = package_info.removeprefix("package:").strip()

    if outfile.exists():
        if force or click.confirm(f"Delete existing file: {outfile.name}?", abort=True):
            outfile.unlink()

    logging.info(f"Pulling package...")
    adb(f"pull {package_path} {outfile}")
    logging.info("All done! 🎉")


if __name__ == "__main__":
    cli()
