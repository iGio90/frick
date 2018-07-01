var libc = Process.platform === "darwin" ? 'libSystem.B.dylib' : 'libc.so';
var base = 0x0;
var sleep = false;
var cContext = null;
var cOff = 0x0;
var targets = {};
var nfs = {};
var nfs_n = {};
var gettid = nf(getnf('gettid', libc, 'int', []));
var linker = Process.findModuleByName('linker');
var main_tid = gettid();
var gn_handler = 0x0;

setup();

function sendContext() {
    var context = {};
    for (var reg in cContext) {
        var what = cContext[reg];
        context[reg] = {
            'value': what
        };
        try {
            var rr = Memory.readPointer(what);
            context[reg]['sub'] = [rr];
            for (var k=0;k<8;k++) {
                rr = Memory.readPointer(rr);
                context[reg]['sub'].push(rr);
            }
        } catch(err) {}
    }
    send('2:::' + cOff + ':::' + JSON.stringify(context));
}

function sendHookInfo() {
    var sbt = Thread.backtrace(cContext, Backtracer.ACCURATE).map(DebugSymbol.fromAddress);
    var tds = [];
    try {
        tds = Memory.readByteArray(cContext.pc.sub(32), 128);
    } catch(err) {}
    send('4:::' + cOff + ':::' + JSON.stringify(sbt) + ':::' + bytesToHex(tds))
}

function setup() {
    gn_handler = Memory.alloc(8);
    Memory.protect(gn_handler, 8, 'rwx');
    Interceptor.replace(gn_handler, new NativeCallback(function (sig) {
        while (sleep) {
            Thread.sleep(1);
        }
        return sig;
    }, 'int', ['int']));

    if (linker !== null) {

        var isLoadingTarget = false;
        var rdI = Interceptor.attach(Module.findExportByName(libc, "open"), {
            onEnter: function() {
                var what = Memory.readUtf8String(this.context.r0);
                if (what.indexOf(module) >= 0) {
                    isLoadingTarget = true;
                }
            },
            onLeave: function(ret) {
                if (!isLoadingTarget) {
                    return;
                }
                rdI.detach();
                isLoadingTarget = false;
                var symb = Module.enumerateSymbolsSync("linker");
                var pp = 0;
                for (var sym in symb) {
                    if (symb[sym].name.indexOf("phdr_table_get_dynamic_section") >= 0) {
                        pp = symb[sym].address
                    }
                }
                var ppI = Interceptor.attach(pp, {
                    onLeave: function (ret) {
                        ppI.detach();

                        base = this.context.r2;
                        send('99:::' + base + ':::' + Process.arch + ':::' + Process.pointerSize);

                        if (Process.findModuleByName('libg.so') !== null) {
                            Interceptor.detachAll();
                            return;
                        }

                        for (var k in dtInitTargets) {
                            att(k, base.add(k));
                        }

                        var dlSym = Interceptor.attach(Module.findExportByName(libc, 'dlsym'), {
                            onLeave: function (ret) {
                                dlSym.detach();

                                // detach dt inits
                                for (var k in targets) {
                                    targets[k + ''].detach();
                                    delete targets[k + ''];
                                }
                                // we attach later to those targets
                                for (var k in pTargets) {
                                    att(k, base.add(k));
                                }
                            }
                        });
                    }
                });
            }
        });
    } else {
        setTimeout(function() {
            base = Process.findModuleByName(module).base;
            send('0:::' + base + ':::' + Process.arch + ':::' + Process.pointerSize);
            for (var k in pTargets) {
                att(k, base.add(k));
            }
            postSetup();
        }, 250);
    }
}

function att(off, pt) {
    if (base === 0) {
        return;
    }
    send('1:::' + pt);
    targets['' + pt] = Interceptor.attach(pt, function() {
        if (sleep) {
            while (sleep) {
                Thread.sleep(1)
            }
            if (targets['' + pt] === null || typeof targets['' + pt] === 'undefined') {
                return;
            }
        }

        sleep = true;
        cContext = this.context;
        cOff = off;
        sendContext();
        sendHookInfo();

        var t_hooks = goodnight();
        while(sleep) {
            Thread.sleep(1);
        }
        for (var k in t_hooks) {
            t_hooks[k].detach();
        }
    });
}

function goodnight() {
    var signal = nf(getnf('signal', libc, 'int', ['int', 'pointer']));
    var tkill = nf(getnf('tkill', libc, 'int', ['int', 'int']));

    signal(12, gn_handler);

    var t_hooks = {};

    var ts = readThreads();
    for (var to in ts) {
        var t = ts[to];
        if (t[0].indexOf('gum') >= 0 ||
            t[0].indexOf('gdbus') >= 0) {
            continue;
        }
        if (t[2] === 'R') {
            if (parseInt(t[0]) !== main_tid) {
                try {
                    tkill(parseInt(t[0]), 12);
                } catch (e) {}
            }
        } else {
            var tpc = ptr(t[29]);
            if (t_hooks[t[29]] !== null && typeof t_hooks[t[29]] !== 'undefined') {
                continue;
            }
            t_hooks[t[29]] = Interceptor.attach(tpc, function () {
                while (sleep) {
                    Thread.sleep(1);
                }
            });
        }
    }

    return t_hooks;
}

function postSetup() {
    var pthread_create_ptr = Module.findExportByName(null, 'pthread_create');
    if (pthread_create_ptr !== null) {
        var pthread_create = nf(getnf('pthread_create', libc, 'int', ['pointer', 'pointer', 'pointer', 'pointer']));

        Interceptor.replace(pthread_create_ptr, new NativeCallback(function (a, b, c, d) {
            var ret = pthread_create(a, b, c, d);
            var dbgs = DebugSymbol.fromAddress(c);
            if (dbgs !== null && dbgs.moduleName === module) {
                var t_tid = Memory.readU16(Memory.readPointer(a).add(8));
                send('3:::' + t_tid + ':::' + c + ':::' + dbgs.name);
            }
            return ret;
        }, 'int', ['pointer', 'pointer', 'pointer', 'pointer']));
    }
}

function readThreads() {
    var m_alloc = Memory.alloc(1024);
    Memory.protect(m_alloc, 1024, 'rwx');

    var opendir = nf(getnf('opendir', libc, 'pointer', ['pointer']));
    var readdir = nf(getnf('readdir', libc, 'pointer', ['pointer']));
    var fopen = nf(getnf('fopen', libc, 'pointer', ['pointer', 'pointer']));
    var fgets = nf(getnf('fgets', libc, 'pointer', ['pointer', 'int', 'pointer']));

    Memory.writeUtf8String(m_alloc, '/proc/self/task');

    var proc_dir = opendir(m_alloc);
    var entry;
    var res = [];

    while ((entry = readdir(proc_dir)) > 0) {
        var line = Memory.readUtf8String(entry.add(19));
        if (line.indexOf('.') >= 0) {
            continue;
        }
        Memory.writeUtf8String(m_alloc, '/proc/' + pid + '/task/' + line + '/stat');
        Memory.writeUtf8String(m_alloc.add(64), 'r');
        try {
            var fp = fopen(m_alloc, m_alloc.add(64));
            line = Memory.readUtf8String(fgets(m_alloc, 1024, fp));
            var name = line.substring(line.indexOf('('), 1 + line.indexOf(')'));
            line = line.replace(' ' + name, '');
            var proc = line.split(' ');
            proc.splice(1, 0, name.replace('(', '').replace(')', ''));
            res.push(proc);
        } catch (e) {
        }
    }
    return res;
}

function nf(n) {
    return n['nf'];
}

function getnf(n, m, r, a) {
    var p = Module.findExportByName(m, n);
    return getnfp(p, r, a);
}

function getnfp(p, r, a) {
    var nf = new NativeFunction(p, r, a);
    var dbgs = DebugSymbol.fromAddress(p);
    var nf_o = {'a': a, 'nf': nf, 'dbgs': dbgs, 'r': r};
    nfs[nf + ''] = nf_o;
    if (dbgs.name !== null && dbgs.name !== '') {
        nfs_n[dbgs.name] = p;
    }
    return nf_o;
}

rpc.exports = {
    add: function (what) {
        att(what, base.add(what));
    },
    addv: function (what) {
        att(what, ptr(what));
    },
    bt: function () {
        return Thread.backtrace(cContext, Backtracer.ACCURATE).map(DebugSymbol.fromAddress);
    },
    c: function () {
        sleep = false;
    },
    ems: function () {
        var m = Process.enumerateModulesSync();
        if (m != null) {
            m = JSON.stringify(m);
        }
        return m;
    },
    ers: function () {
        var m = Process.enumerateRangesSync('---');
        if (m != null) {
            m = JSON.stringify(m);
        }
        return m;
    },
    ets: function () {
        var m = Process.enumerateThreadsSync();
        if (m != null) {
            m = JSON.stringify(m);
        }
        return m;
    },
    fexbn: function (a, b) {
        return Module.findExportByName(a, b);
    },
    fmba: function (w) {
        var m = Process.findModuleByAddress(ptr(w));
        if (m != null) {
            m = JSON.stringify(m);
        }
        return m;
    },
    fmbn: function (w) {
        var m = Process.findModuleByName(w);
        if (m != null) {
            m = JSON.stringify(m);
        }
        return m;
    },
    frba: function (w) {
        var m = Process.findRangeByAddress(ptr(w));
        if (m != null) {
            m = JSON.stringify(m);
        }
        return m;
    },
    gnf: function (p, r, a) {
        try {
            p = ptr(p);
            return JSON.stringify(getnfp(p, r, a));
        } catch (err) {
            return err.toString();
        }
    },
    inject: function(b, name) {
        b = hexToBytes(b);
        var syscall = nf(getnf('syscall', libc, 'int', ['int', 'pointer', 'int']));
        var write = nf(getnf('write', libc, 'int', ['int', 'pointer', 'int']));
        var dlopen = nf(getnf('dlopen', libc, 'int', ['pointer', 'int']));
        var m = Memory.alloc(128);
        Memory.protect(m, 128, 'rw-');
        Memory.writeUtf8String(m, name);
        var fd = syscall(385, m, 0);
        var blob = Memory.alloc(b.length);
        Memory.protect(blob, b.length, 'rwx');
        Memory.writeByteArray(blob, b);
        write(fd, blob, b.length);
        Memory.writeUtf8String(m, '/proc/' + pid + '/fd/' + fd);
        return dlopen(m, 1);
    },
    ivp: function (p) {
        try {
            Memory.readPointer(ptr(p));
            return true;
        } catch (err) {
            return false;
        }
    },
    mal: function (l) {
        return Memory.alloc(l);
    },
    mprot: function (p, l, f) {
        try {
            p = ptr(p);
            Memory.protect(p, l, f);
            return p;
        } catch (err) {
            return null;
        }
    },
    mr: function (p, l) {
        try {
            return Memory.readByteArray(ptr(p), l);
        } catch (err) {
            return null;
        }
    },
    mru8s: function (p, l) {
        try {
            return Memory.readUtf8String(ptr(p), l);
        } catch (err) {
            return null;
        }
    },
    mru16s: function (p, l) {
        try {
            return Memory.readUtf16String(ptr(p), l);
        } catch (err) {
            return null;
        }
    },
    mrans: function (p, l) {
        try {
            return Memory.readAnsiString(ptr(p), l);
        } catch (err) {
            return null;
        }
    },
    mracs: function (p, l) {
        try {
            return Memory.readCString(ptr(p), l);
        } catch (err) {
            return null;
        }
    },
    mw: function (p, w) {
        try {
            p = ptr(p);
            Memory.writeByteArray(p, hexToBytes(w));
            return p;
        } catch (err) {
            return null;
        }
    },
    nfl: function() {
        return JSON.stringify(nfs);
    },
    rp: function(p) {
        try {
            return Memory.readPointer(ptr(p));
        } catch(err) {
            return null;
        }
    },
    rnf: function(p, a) {
        try {
            p = ptr(p) + '';
        } catch(err) {}

        if (typeof p === 'string') {
            p = nfs_n[p];
        }

        var nf = nfs[p];
        if (nf !== null && typeof nf !== 'undefined') {
            if (a.length !== nf['a'].length) {
                return null;
            }

            for (var k=0;k<nf['a'].length;k++) {
                if (nf['a'][k] === 'pointer') {
                    a[k] = ptr(a[k]);
                }
            }

            nf = nf['nf'];

            // if someone come up with a better solution please....
            switch(a.length) {
                case 0:
                    return nf();
                case 1:
                    return nf(a[0]);
                case 2:
                    return nf(a[0], a[1]);
                case 3:
                    return nf(a[0], a[1], a[2]);
                case 4:
                    return nf(a[0], a[1], a[2], a[3]);
                case 5:
                    return nf(a[0], a[1], a[2], a[3], a[4]);
                case 6:
                    return nf(a[0], a[1], a[2], a[3], a[4], a[5]);
            }
        }
        return null;
    },
    rmt: function(p) {
        p = base.add(p);
        if ('' + p in targets) {
            targets['' + p].detach();
            delete targets['' + p];
        }
    },
    rmvt: function(p) {
        p = ptr(p);
        if ('' + p in targets) {
            targets['' + p].detach();
            delete targets['' + p];
        }
    },
    rw: function(r, v) {
        try {
            cContext[r] = v;
            return v;
        } catch(err) {
            return null;
        }
    },
    sc: function() {
        sendContext();
    }
};

function hexToBytes(hex) {
    for (var bytes = [], c = 0; c < hex.length; c += 2)
        bytes.push(parseInt(hex.substr(c, 2), 16));
    return bytes;
}

function bytesToHex(b) {
    var uint8arr = new Uint8Array(b);
    if (!uint8arr) {
        return '';
    }
    var hexStr = '';
    for (var i = 0; i < uint8arr.length; i++) {
        var hex = (uint8arr[i] & 0xff).toString(16);
        hex = (hex.length === 1) ? '0' + hex : hex;
        hexStr += hex;
    }
    return hexStr;
}