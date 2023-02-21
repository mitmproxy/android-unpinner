from pathlib import Path

here = Path(__file__).absolute().parent

frida_version = "16.0.10"
gadget_files = {
    "arm": here / f"frida/frida-gadget-{frida_version}-android-arm.so",
    "arm64": here / f"frida/frida-gadget-{frida_version}-android-arm64.so",
    "x86": here / f"frida/frida-gadget-{frida_version}-android-x86.so",
    "x86_64": here / f"frida/frida-gadget-{frida_version}-android-x86_64.so",
}
gadget_config_file = here / "frida/gadget-config.json"
