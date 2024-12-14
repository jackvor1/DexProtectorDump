const TARGET_LIB = "libdexprotector.so";
const DUMP_DIRECTORY = "/data/data/com.example/dumps/";
var FileLoaded = false;
var libsoBase = null;
var libsoSize = null;

const MAX_SEGMENT_SIZE = 30 * 1024 * 1024;

function ensureDirectory(path) {
    var mkdirPtr = Module.findExportByName("libc.so", "mkdir");
    if (mkdirPtr) {
        var mkdir = new NativeFunction(mkdirPtr, 'int', ['pointer', 'int']);
        var pathPtr = Memory.allocUtf8String(path);
        var mode = 0x1ED;
        var result = mkdir(pathPtr, mode);
        if (result !== 0) {
            console.log("[!] Failed to create directory:", path);
        } else {
            console.log("[*] Dump directory created or already exists:", path);
        }
    } else {
        console.log("[!] Failed to find mkdir function.");
    }
}

function concatenateArrayBuffers(buffers) {
    var totalLength = buffers.reduce((acc, buffer) => acc + buffer.byteLength, 0);
    var temp = new Uint8Array(totalLength);
    var offset = 0;
    buffers.forEach(buffer => {
        temp.set(new Uint8Array(buffer), offset);
        offset += buffer.byteLength;
    });
    return temp.buffer;
}

function dumpLibrary(libso) {
    libsoBase = libso.base;
    libsoSize = libso.size;

    var theDate = new Date();
    var time = theDate.toISOString().replace(/[:.]/g, "_");

    var file_path = DUMP_DIRECTORY + libso.name + "_" + libso.base + "_" + libso.size + "_" + time + ".so";

    console.log("[name]:", libso.name);
    console.log("[base]:", libso.base);
    console.log("[size]:", libso.size);
    console.log("[path]:", libso.path);
    console.log("[dump_path]:", file_path);

    try {
        var ranges = Process.enumerateRangesSync({
            protection: 'r--',
            coalesce: true,
            address: libso.base,
            length: libso.size
        });

        var buffer = [];
        ranges.forEach(range => {
            if (range.size > MAX_SEGMENT_SIZE) {
                console.log("[!] Skipping too large segment:", range.base, "size:", range.size);
                return;
            }

            try {
                var chunk = Memory.readByteArray(range.base, range.size);
                buffer.push(chunk);
                console.log("[*] Reading segment: " + range.base + " size: " + range.size);
            } catch (e) {
                console.log("[!] Error reading memory segment at address " + range.base + ": " + e.message);
            }
        });

        var libso_buffer = concatenateArrayBuffers(buffer);

        if (libso_buffer.byteLength > 0) {
            var file_handle = new File(file_path, "wb");
            if (file_handle) {
                file_handle.write(libso_buffer);
                file_handle.flush();
                file_handle.close();
                console.log("[*] Dump successfully saved to:", file_path);
            } else {
                console.log("[!] Failed to open file for writing:", file_path);
            }
        } else {
            console.log("[!] Failed to assemble library buffer.");
        }
    } catch (e) {
        console.log("[!] Error during library dump:", e.message);
    }
}

function hookDlopenExt() {
    var dlopenExtPtr = Module.findExportByName(null, 'android_dlopen_ext');
    if (!dlopenExtPtr) {
        console.log("[!] Failed to find export 'android_dlopen_ext'.");
        return;
    }

    Interceptor.attach(dlopenExtPtr, {
        onEnter: function(args) {
            var library_path = Memory.readCString(args[0]);
            if (library_path.indexOf(TARGET_LIB) >= 0) {
                console.warn("[*] Target library is being loaded: " + library_path);
                FileLoaded = true;
                var parts = library_path.split('!');
                var lastPart = parts.pop();
                var lib_name = lastPart.substring(lastPart.lastIndexOf('/') + 1);
                this.loadedLibName = lib_name;
            }
        },
        onLeave: function(retVal) {
            if (FileLoaded && this.loadedLibName) {
                var libso = Process.findModuleByName(this.loadedLibName);
                if (!libso) {
                    console.log("[!] Failed to find module after loading:", this.loadedLibName);
                    return;
                }

                dumpLibrary(libso);

                FileLoaded = false;
                this.loadedLibName = null;
            }
        }
    });
}

function bypassProtections() {
    var mprotectPtr = Module.findExportByName("libc.so", "mprotect");
    if (mprotectPtr) {
        var original_mprotect = new NativeFunction(mprotectPtr, 'int', ['pointer', 'size_t', 'int']);
        Interceptor.replace(mprotectPtr, new NativeCallback(function(addr, len, prot) {
            if (libsoBase && libsoSize) {
                var addrPtr = ptr(addr);
                var libEnd = libsoBase.add(libsoSize);
                if (addrPtr.compare(libsoBase) >= 0 && addrPtr.compare(libEnd) < 0) {
                    var newProt = prot | 0x1;
                    console.log("[*] mprotect called for target library. New permissions:", newProt);
                    return original_mprotect(addr, len, newProt);
                }
            }
            return original_mprotect(addr, len, prot);
        }, 'int', ['pointer', 'size_t', 'int']));
        console.log("[*] Hooked mprotect function.");
    } else {
        console.log("[!] Failed to find export 'mprotect'.");
    }

    var prctlPtr = Module.findExportByName("libc.so", "prctl");
    if (prctlPtr) {
        var original_prctl = new NativeFunction(prctlPtr, 'int', ['int', 'long', 'long', 'long', 'long']);
        Interceptor.replace(prctlPtr, new NativeCallback(function(option, arg2, arg3, arg4, arg5) {
            const PROTECTED_OPTIONS = [
                1,
                15,
                22,
                17,
            ];

            if (PROTECTED_OPTIONS.includes(option)) {
                console.log("[*] Hooked prctl call with option:", option, ". Ignoring.");
                return 0;
            }

            return original_prctl(option, arg2, arg3, arg4, arg5);
        }, 'int', ['int', 'long', 'long', 'long', 'long']));
        console.log("[*] Hooked prctl function.");
    } else {
        console.log("[!] Failed to find export 'prctl'.");
    }
}

function hookFileDeletion() {
    var unlinkPtr = Module.findExportByName("libc.so", "unlink");
    if (unlinkPtr) {
        var original_unlink = new NativeFunction(unlinkPtr, 'int', ['pointer']);
        Interceptor.replace(unlinkPtr, new NativeCallback(function(path_ptr) {
            var filename = Memory.readCString(path_ptr);
            if (filename.indexOf(TARGET_LIB) >= 0) {
                console.log("[*] Preventing deletion of file:", filename);
                console.log("[*] Call stack during unlink attempt:");
                console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
                    .map(DebugSymbol.fromAddress).join("\n") || "No stack symbols");
                return -1;
            }
            return original_unlink(path_ptr);
        }, 'int', ['pointer']));
        console.log("[*] Hooked unlink function.");
    }

    var removePtr = Module.findExportByName("libc.so", "remove");
    if (removePtr) {
        var original_remove = new NativeFunction(removePtr, 'int', ['pointer']);
        Interceptor.replace(removePtr, new NativeCallback(function(path_ptr) {
            var filename = Memory.readCString(path_ptr);
            if (filename.indexOf(TARGET_LIB) >= 0) {
                console.log("[*] Preventing deletion of file:", filename);
                console.log("[*] Call stack during remove attempt:");
                console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
                    .map(DebugSymbol.fromAddress).join("\n") || "No stack symbols");
                return -1;
            }
            return original_remove(path_ptr);
        }, 'int', ['pointer']));
        console.log("[*] Hooked remove function.");
    }
}

function handleMemoryAccessViolations() {
    // Additional logging or actions can be added here if needed
}

function init() {
    ensureDirectory(DUMP_DIRECTORY);
    bypassProtections();
    hookFileDeletion();
    hookDlopenExt();
}

if (Process.platform === 'android' && Process.arch.match(/arm|arm64|x86|x64/)) {
    init();
} else {
    console.log("[!] Script is intended to run on Android devices with ARM or x86 architectures.");
}

init();
