// frida -U -f com.softmedia.receiver.castapp -l hook_url_and_md5.js

var targetDomain = "cast.remotetogo.com";
var targetModule = "libAirReceiver.so";
var targetBase = NULL;

function hookMD5() {
    var md5Address = targetBase.add(0x862ee4);
    console.log("[*] Hooking MD5 at " + md5Address);
    Interceptor.attach(md5Address, {
        onEnter: function (args) {
            var inputStr = args[0].readUtf8String();
            if (inputStr && inputStr.length > 32 && inputStr.indexOf("78b1ad1dcd88176a954c03b38cbb962c") !== -1) {
                console.log("\n=====================================");
                console.log("[+] MD5 Hash Function Called!");
                console.log("    Input: " + inputStr);
                var salt = inputStr.substring(0, 32);
                var timestamp = inputStr.substring(32);
                console.log("    Salt: " + salt);
                console.log("    Timestamp: " + timestamp);
                console.log("=====================================\n");
            }
        }
    });
}

function hookLibc() {
    var snprintfPtr = Module.findExportByName("libc.so", "snprintf");
    if (snprintfPtr) {
        Interceptor.attach(snprintfPtr, {
            onEnter: function (args) {
                this.buf = args[0];
                this.format = args[2].readUtf8String();
            },
            onLeave: function (retval) {
                if (this.format && this.format.indexOf(targetDomain) !== -1) {
                    try {
                        var result = this.buf.readUtf8String();
                        if (result && result.indexOf(targetDomain) !== -1) {
                            console.log("\n=====================================");
                            console.log("[+] URL Constructed (snprintf):");
                            console.log("    " + result);
                            console.log("=====================================\n");
                        }
                    } catch (e) { }
                }
            }
        });
        console.log("[*] Hooked snprintf");
    }
}

function checkModule(moduleName) {
    var m = Process.findModuleByName(moduleName);
    if (!m) return false;

    console.log("[*] Module " + moduleName + " loaded at " + m.base);

    if (moduleName === targetModule) {
        targetBase = m.base;
        hookMD5();
    }

    var curl_easy_setopt = Module.findExportByName(moduleName, "curl_easy_setopt");
    if (curl_easy_setopt) {
        Interceptor.attach(curl_easy_setopt, {
            onEnter: function (args) {
                var option = args[1].toInt32();
                if (option === 10002) { // CURLOPT_URL
                    var url = args[2].readUtf8String();
                    if (url && url.indexOf(targetDomain) !== -1) {
                        console.log("\n=====================================");
                        console.log("[+] URL Requested (curl_easy_setopt):");
                        console.log("    " + url);
                        console.log("=====================================\n");
                    }
                }
            }
        });
    }

    var ssl_write = Module.findExportByName(moduleName, "SSL_write");
    if (ssl_write) {
        Interceptor.attach(ssl_write, {
            onEnter: function (args) {
                var buf = args[1];
                var len = args[2].toInt32();
                if (len > 0) {
                    var data = buf.readUtf8String(Math.min(len, 1024));
                    if (data && data.indexOf(targetDomain) !== -1) {
                        var lines = data.split('\r\n');
                        var requestLine = lines[0];
                        var parts = requestLine.split(' ');
                        var fullUrl = (parts.length >= 2) ? "https://" + targetDomain + parts[1] : requestLine;

                        console.log("\n=====================================");
                        console.log("[+] HTTP Request Sent (SSL_write):");
                        console.log("    Full URL: " + fullUrl);
                        console.log("    --- Headers ---");
                        for (var i = 1; i < lines.length; i++) {
                            if (lines[i] === "") break; // End of headers
                            console.log("    " + lines[i]);
                        }
                        console.log("=====================================\n");
                    }
                }
            }
        });
    }

    return true;
}

function waitForModule(moduleName) {
    if (checkModule(moduleName)) return;

    var dlopenPtr = Module.findExportByName(null, "dlopen");
    if (dlopenPtr) {
        Interceptor.attach(dlopenPtr, {
            onEnter: function (args) {
                this.path = args[0].readUtf8String();
            },
            onLeave: function (retval) {
                if (this.path && this.path.indexOf(moduleName) !== -1) {
                    checkModule(moduleName);
                }
            }
        });
    }

    var android_dlopen_extPtr = Module.findExportByName(null, "android_dlopen_ext");
    if (android_dlopen_extPtr) {
        Interceptor.attach(android_dlopen_extPtr, {
            onEnter: function (args) {
                this.path = args[0].readUtf8String();
            },
            onLeave: function (retval) {
                if (this.path && this.path.indexOf(moduleName) !== -1) {
                    checkModule(moduleName);
                }
            }
        });
    }
}

hookLibc();
waitForModule("libAirReceiver.so");
waitForModule("libcurl.so");
waitForModule("libssl.so");

