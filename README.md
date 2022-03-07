# Android Unpinner

This tool removes certificate pinning from APKs.

Work in progress. Hightlights include:

 - Does not require root.
 - Uses [`frida-apk`](https://github.com/frida/frida-tools/blob/main/frida_tools/apk.py) to mark app as debuggable.
   This is much less invasive than other approaches, `classes.dex` and all resources remain unmodified.
 - Includes a new/custom Java Debug Wire Protocol Implementation to inject the Frida Gadget via ADB.
 - Uses HTTPToolkit's unpinning script to defeat certificate pinning 
   (https://github.com/httptoolkit/frida-android-unpinning)
 - Already includes all native dependencies (`apksigner`, `zipalign`, `aapt2`) for Windows/Linux/macOS.

The goal is not to build yet another unpinning tool, but to explore some newer avenues.
Hopefully the good parts are copied by the existing tools. :-)

## Usage

```console
$ android-unpinner run pinning-demo.apk
```

![screenshot](https://uploads.hi.ls/2022-03/2022-03-07_13-41-03.png)

## Comparison

Compared to [`apk-mitm`](https://github.com/shroudedcode/apk-mitm):

🟥 Requires active instrumentation from a desktop machine when launching the app.  
🟩 The apk patching however is much less invasive, `classes.dex` stays as-is.  
🟩 Frida potentially allows more dynamic/better patching at runtime.

Compared to [`objection`](https://github.com/sensepost/objection):

🟥 No interactive analysis.  
🟩 Easier to get started, no additional dependencies.  
🟩 The apk patching is much less invasive, `classes.dex` stays as-is.

Compared to [`frida`](https://frida.re/) + [`LIEF`](https://lief-project.github.io/doc/latest/tutorials/09_frida_lief.html):

🟩 Does not require that the application has a native library.  
🟥 Modifies `AndroidManifest.xml`  

## Licensing

Please note that `android_unpinner/vendor` is a hodgepodge of different licenses.  
Everything new here is licensed under MIT (in particular `jdwplib.py`). 
