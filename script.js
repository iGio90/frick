var base = 0x0;
var targets = {};
var linker = Process.findModuleByName('linker');

function setup() {
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
                            att(base.add(k));
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
                                    att(base.add(k));
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
                att(base.add(k));
            }
            postSetup();
        }, 250);
    }
}

function att(pt) {
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

        cli(this.context);
    });
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

rpc.exports = {
    add: function (what) {
        att(base.add(what));
    },
    addv: function (what) {
        att(ptr(what));
    },
    bt: function () {
        return Thread.backtrace(cContext, Backtracer.ACCURATE).map(DebugSymbol.fromAddress);
    },
    dbgsfa: function(x) {
        try {
            Memory.readPointer(ptr(x));
        } catch (e) {
            return null;
        }
        return DebugSymbol.fromAddress(ptr(x));
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
        return JSON.stringify(readThreads());
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
    ftbp: function (tid) {
        var proc = readTask(tid);
        if (proc !== null) {
            proc = JSON.stringify(proc);
        }
        return proc;
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
        if (fd === -1) {
            return null;
        }
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
    }
};