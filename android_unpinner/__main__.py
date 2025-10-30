from __future__ import annotations

import os
import zipfile
import asyncio
import logging
import subprocess
from pathlib import Path
from time import sleep

import rich.traceback
import rich_click as click
from rich.logging import RichHandler

from . import jdwplib
from .vendor import build_tools
from .vendor import frida_tools
from .vendor import gadget_config_file_listen, gadget_config_file_script_directory
from .vendor import gadget_files
from .vendor.platform_tools import adb, set_device

here = Path(__file__).absolute().parent
LIBGADGET = "libgadget.so"
LIBGADGET_CONF = "libgadget.config.so"

force = False
gadget_config_file = gadget_config_file_script_directory


def patch_apk_file(infile: Path, outfile: Path) -> None:
    """
    Patch the APK to be debuggable.
    """
    if outfile.exists():
        if force or click.confirm(
            f"Overwrite existing file: {outfile.absolute()}?", abort=True
        ):
            outfile.unlink()

    logging.info("Make APK debuggable...")
    frida_tools.apk.make_debuggable(
        str(infile),
        str(outfile),
    )

    logging.info("Zipalign & re-sign APK...")
    build_tools.zipalign(outfile)
    build_tools.sign(outfile)

    logging.info(f"Created patched APK: {outfile}")


def patch_apk_files(apks: list[Path]) -> list[Path]:
    """
    Patch multiple APK files and return the list of patched filenames.
    """
    patched: list[Path] = []
    for apk in apks:
        if apk.stem.endswith(".unpinned"):
            logging.warning(
                f"Skipping {apk} (filename indicates it is already patched)."
            )
            continue

        outfile = apk.with_suffix(".unpinned" + apk.suffix)
        if outfile.exists():
            logging.warning(f"Reusing existing file: {outfile}")
        else:
            logging.info(f"Patching {apk}...")
            patch_apk_file(apk, outfile)
        patched.append(outfile)
    return patched


def ensure_device_connected() -> None:
    try:
        adb(["get-state"])
    except subprocess.CalledProcessError:
        raise RuntimeError("No device connected via ADB.")


def install_apk(apk_files: list[Path]) -> None:
    """
    Install the APK on the device, replacing any existing installation.
    """
    ensure_device_connected()

    package_name = build_tools.package_name(apk_files[0])

    if package_name in get_packages():
        if not force:
            click.confirm(
                "About to install patched APK. This removes the existing app with all its data. Continue?",
                abort=True,
            )

        logging.info("Uninstall existing app...")
        adb(["uninstall", package_name])

    logging.info(f"Installing {package_name}...")
    if len(apk_files) > 1:
        adb(["install-multiple", "--no-incremental", *[str(x) for x in apk_files]])
    else:
        adb(["install", "--no-incremental", str(apk_files[0])])


def find_apks_in_xapk(xapk_path: Path, output_dir = None) -> list[Path] | None:
    """
    Extracts APK files from an XAPK file to a folder and returns their paths.
    """

    if not xapk_path.name.lower().endswith(".xapk"):
        return None

    if not os.path.exists(xapk_path):
        return None
    
    logging.info(f"Processing XAPK: {os.path.basename(xapk_path)}")
    
    if output_dir is None:
        extraction_dir = xapk_path.parent / f"{xapk_path.stem}_extracted"
    else:
        extraction_dir = Path(output_dir).resolve()

    if os.path.exists(extraction_dir):
        logging.warning(f"Directory '{extraction_dir}' already exists. New files will be merged/overwritten.")
    else:
        os.makedirs(extraction_dir)
        logging.info(f"Created extraction directory: {extraction_dir}")

    apk_files = []

    try:        
        with zipfile.ZipFile(xapk_path, 'r') as zip_ref:
            zip_ref.extractall(extraction_dir)
            logging.info("XAPK extraction complete.")

        logging.info("Searching for APK files...")
        for root, _, files in os.walk(extraction_dir):
            for file_name in files:
                if file_name.lower().endswith(".apk"):
                    full_path = os.path.join(root, file_name)
                    apk_files.append(Path(full_path))
                    logging.info(f"Found APK: {full_path}")
                    
        return apk_files

    except zipfile.BadZipFile:
        logging.error(f"Error: '{xapk_path}' is not a valid ZIP file.")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return None


def process_xapks(apk_files: list[Path]) -> list[Path]:
    """
    Preprocess the list of APK files to handle any XAPK files.
    """
    ret = []
    for apk in apk_files:
        if apks := find_apks_in_xapk(apk):
            ret.extend(apks)
        else:
            ret.append(apk)

    return ret


def copy_files() -> None:
    """
    Copy the Frida Gadget and unpinning scripts.
    """
    # TODO: We could later provide the option to use a custom script dir.
    ensure_device_connected()
    logging.info("Detect architecture...")
    abi = adb(["shell", "getprop", "ro.product.cpu.abi"]).stdout.strip()
    if abi == "armeabi-v7a":
        abi = "arm"
    gadget_file = gadget_files.get(abi, gadget_files["arm64"])
    logging.info(f"Copying matching gadget: {gadget_file.name}...")
    adb(["push", str(gadget_file), f"/data/local/tmp/{LIBGADGET}"])
    adb(["push", str(gadget_config_file), f"/data/local/tmp/{LIBGADGET_CONF}"])

    logging.info("Copying builtin Frida scripts to /data/local/tmp/android-unpinner...")
    adb(["push", f"{here / 'scripts'}/.", "/data/local/tmp/android-unpinner/"])
    active_scripts = adb(["shell", "ls", "/data/local/tmp/android-unpinner"]).stdout.splitlines(
        keepends=False
    )
    logging.info(f"Active frida scripts: {active_scripts}")


def start_app_on_device(package_name: str) -> None:
    ensure_device_connected()
    logging.info("Start app (suspended)...")
    adb(["shell", "am", "set-debug-app", "-w", package_name])
    activity_lines = adb([
        "shell", "cmd", "package", "resolve-activity",
        "--brief", package_name
    ]).stdout.strip().splitlines()
    activity = activity_lines[-1] if activity_lines else ""
    if not activity or activity.lower().startswith("no activity found"):
        raise RuntimeError("Activity not found")
    adb(["shell", "am", "start", "-n", activity])

    logging.info("Obtain process id...")
    pid = None
    for i in range(5):
        try:
            pid = adb(["shell", "pidof", package_name]).stdout.strip()
            break
        except subprocess.CalledProcessError:
            if i:
                logging.info("Timeout...")
            if i == 4:
                raise
            sleep(1)
    logging.debug(f"{pid=}")
    local_port = int(adb(["forward", "tcp:0", f"jdwp:{pid}"]).stdout)
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
    packages = adb(["shell", "pm", "list", "packages"]).stdout.strip().splitlines()
    return [p.removeprefix("package:") for p in sorted(packages)]


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


def _listen(ctx, param, val):
    global gadget_config_file
    if val:
        gadget_config_file = gadget_config_file_listen


listen_option = click.option(
    "-l",
    "--listen",
    help="Configure the Frida gadget to expose a server instead of running unpinning scripts.",
    is_flag=True,
    callback=_listen,
    expose_value=False,
)


def _device(ctx, param, val):
    if val:
        set_device(val)


device_option = click.option(
    "-d",
    "--device",
    help="Device serial number to use when multiple devices are connected.",
    callback=_device,
    expose_value=False,
)


@cli.command("all")
@verbosity_option
@force_option
@listen_option
@device_option
@click.argument(
    "apk-files",
    type=click.Path(path_type=Path, exists=True),
    nargs=-1,
    required=True,
)
def all_cmd(apk_files: list[Path]) -> None:
    """
    Patch a local APK, then install and start it.

    You may pass multiple files for the same package in case of split APKs.
    """
    apk_files = process_xapks(apk_files)
    package_names = {build_tools.package_name(apk) for apk in apk_files}
    if len(package_names) > 1:
        raise RuntimeError(
            "Detected multiple APKs with different package names, aborting."
        )
    package_name = next(iter(package_names))
    logging.info(f"Target: {package_name}")
    apk_patched = patch_apk_files(apk_files)
    install_apk(apk_patched)
    copy_files()
    start_app_on_device(package_name)
    logging.info("All done! 🎉")


@cli.command("install")
@verbosity_option
@force_option
@device_option
@click.argument(
    "apk-files",
    type=click.Path(path_type=Path, exists=True),
    nargs=-1,
    required=True,
)
def install_cmd(apk_files: list[Path]) -> None:
    """
    Install a package on the device.

    You may pass multiple files for the same package in case of split APKs.
    """
    apk_files = process_xapks(apk_files)
    install_apk(apk_files)
    logging.info("All done! 🎉")


@cli.command()
@verbosity_option
@force_option
@click.argument(
    "apks",
    type=click.Path(path_type=Path, exists=True),
    nargs=-1,
    required=True,
)
def patch_apks(apks: list[Path]) -> None:
    """Patch an APK file to be debuggable."""
    apks = process_xapks(apks)
    patch_apk_files(apks)
    logging.info("All done! 🎉")


@cli.command()
@verbosity_option
@force_option
@listen_option
@device_option
def push_resources() -> None:
    """Copy Frida gadget and scripts to device."""
    copy_files()
    logging.info("All done! 🎉")


@cli.command()
@verbosity_option
@force_option
@device_option
@click.argument("package-name")
def start_app(package_name: str) -> None:
    """Start app on device and inject Frida gadget."""
    start_app_on_device(package_name)
    logging.info("All done! 🎉")


@cli.command()
@verbosity_option
@device_option
def list_packages() -> None:
    """List all packages installed on the device."""
    ensure_device_connected()
    logging.info("Enumerating packages...")
    print("\n".join(get_packages()))
    logging.info("All done! 🎉")


@cli.command()
@click.argument("apk-file", type=click.Path(path_type=Path, exists=True))
def package_name(apk_file: Path) -> None:
    """Get the package name for a local APK file."""
    print(build_tools.package_name(apk_file))


@cli.command()
@verbosity_option
@force_option
@device_option
@click.argument("package", type=str)
@click.argument("outdir", type=click.Path(path_type=Path, file_okay=False))
def get_apks(package: str, outdir: Path) -> None:
    """Get all APKs for a specific package from the device."""
    ensure_device_connected()

    logging.info("Getting package info...")
    if package not in get_packages():
        raise RuntimeError(f"Could not find package: {package}")

    package_info = adb(["shell", "pm", "path", package]).stdout
    if not package_info.startswith("package:"):
        raise RuntimeError(f"Unxepected output from pm path: {package_info!r}")
    apks = [p.removeprefix("package:") for p in package_info.splitlines()]
    if not outdir.exists():
        outdir.mkdir()
    for apk in apks:
        logging.info(f"Getting {apk}...")
        outfile = outdir / Path(apk).name
        if outfile.exists():
            if force or click.confirm(
                f"Overwrite existing file: {outfile.absolute()}?", abort=True
            ):
                outfile.unlink()
        adb(["pull", apk, str(outfile.absolute())])

    logging.info("All done! 🎉")


if __name__ == "__main__":
    cli()
