import logging
import subprocess
import sys
from pathlib import Path

here = Path(__file__).absolute().parent

if sys.platform == "win32":
    adb_binary = here / "win32" / "adb.exe"
elif sys.platform == "darwin":
    adb_binary = here / "darwin" / "adb"
else:
    adb_binary = here / "linux" / "adb"


def adb(cmd: str) -> subprocess.CompletedProcess[str]:
    """Helper function to call adb and capture stdout."""
    cmd = f"{adb_binary} {cmd}"
    try:
        proc = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        logging.debug(f"cmd='{cmd}'\n"
                      f"{e.stdout=}\n"
                      f"{e.stderr=}")
        raise
    logging.debug(f"cmd='{cmd}'\n"
                  f"{proc.stdout=}\n"
                  f"{proc.stderr=}")
    return proc
