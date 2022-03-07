from pathlib import Path

here = Path(__file__).absolute().parent

gadget_files = {
    "arm": here / "frida/frida-gadget-15.1.17-android-arm.so",
    "arm64": here / "frida/frida-gadget-15.1.17-android-arm64.so",
    "x86": here / "frida/frida-gadget-15.1.17-android-x86.so",
    "x86_64": here / "frida/frida-gadget-15.1.17-android-x86_64.so",
}
gadget_config_file = here / "frida/gadget-config.json"
