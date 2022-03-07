const android_log_write = new NativeFunction(Module.getExportByName(null, '__android_log_write'), 'int', ['int', 'pointer', 'pointer']);
const log = (message) => {
    const tag = Memory.allocUtf8String("frida");
    const str = Memory.allocUtf8String(message);
    android_log_write(3, tag, str);
};

Java.perform(function () {

    var SystemProperties = Java.use('android.os.SystemProperties');
    var get = SystemProperties.get.overload('java.lang.String');

    get.implementation = function (name) {
        if (name === "re.debuggable") {
            log("Fake Debuggable");
            return "0";
        }
        return this.get.call(this, name);
    };

});
