# Android Unpinner

This tool removes certificate pinning from APKs.

 - Does not require root.
 - Uses [`frida-apk`](https://github.com/frida/frida-tools/blob/main/frida_tools/apk.py) to mark app as debuggable.
   This is much less invasive than other approaches, only `AndroidManifest.xml` is touched within the APK.
 - Includes a custom Java Debug Wire Protocol implementation to inject the Frida Gadget via ADB.
 - Uses [HTTPToolkit's excellent unpinning script](https://github.com/httptoolkit/frida-android-unpinning) to defeat certificate pinning.
 - Already includes all native dependencies for Windows/Linux/macOS (`adb`, `apksigner`, `zipalign`, `aapt2`).

The goal was not to build yet another unpinning tool, but to explore some newer avenues for non-rooted devices.
Please shamelessly copy whatever idea you like into other tools. :-)

## Installation

```console
$ git clone https://github.com/mitmproxy/android-unpinner.git
$ cd android-unpinner
$ pip install -e .
```

## Usage

Connect your device via USB and run the following command.

```console
$ android-unpinner all pinning-demo.apk
```

![screenshot](https://uploads.hi.ls/2022-03/2022-03-08_08-18-25.png)

See `android-unpinner --help` for usage details.

You can download APKs from the internet, for example manually from [apkpure.com](https://apkpure.com/) or automatically
using [apkeep](https://github.com/EFForg/apkeep).  
Alternatively, you can [pull APKs from your device using adb](https://stackoverflow.com/a/18003462/934719). A copy of 
`adb` is available in `android_unpinner/vendor/platform_tools`.

## Comparison 

**Compared to using a rooted device, android-unpinner...**

🟥 requires APK patching.  
🟩 does not need to hide from root detection.  

**Compared to [`apk-mitm`](https://github.com/shroudedcode/apk-mitm), android-unpinner...**

🟥 requires active instrumentation from a desktop machine when launching the app.  
🟩 allows more dynamic patching at runtime (thanks to Frida).  
🟩 does less invasive APK patching, e.g. `classes.dex` stays as-is.  

**Compared to [`objection`](https://github.com/sensepost/objection), android-unpinner...**

🟥 supports only one feature (disable pinning) and no interactive analysis shell.  
🟩 is easier to get started with, does not require additional dependencies.  
🟩 does less invasive APK patching, e.g. `classes.dex` stays as-is.  

**Compared to [`frida`](https://frida.re/) + [`LIEF`](https://lief-project.github.io/doc/latest/tutorials/09_frida_lief.html),
android-unpinner...**

🟥 modifies `AndroidManifest.xml`  
🟩 is easier to get started with, does not require additional dependencies.  
🟩 Does not require that the application includes a native library.  

## Licensing

Please note that `android_unpinner/vendor` is a hodgepodge of different licenses.  
Everything new here is licensed under MIT (in particular `jdwplib.py`).
