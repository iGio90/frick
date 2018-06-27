def get_script(module, offsets, dtinitOffsets):
    js = 'var module = "' + module + '";'
    js += 'var pTargets = {};'
    js += 'var dtInitTargets = {};'
    for k, v in offsets.items():
        js += 'pTargets[' + str(k) + '] = ' + str(k) + ';'
    for k, v in dtinitOffsets.items():
        js += 'dtInitTargets[' + str(k) + '] = ' + str(k) + ';'
    js += '''
        var base = 0x0;
        var sleep = false;
        var cContext = null;
        var cOff = 0x0;
        var targets = {};
        
        var linker = Process.findModuleByName('linker');
        if (linker !== null) {
            var isLoadingTarget = false;
            var rdI = Interceptor.attach(Module.findExportByName("libc.so", "open"), {
                onEnter: function() {
                    var what = Memory.readUtf8String(this.context.r0);
                    if (what.indexOf(module) >= 0) {
                        isLoadingTarget = true;
                    }
                }, 
                onLeave: function(ret) {
                    if (isLoadingTarget) {
                        rdI.detach();
                        isLoadingTarget = false;
                        var symb = Module.enumerateSymbolsSync("linker");
                        var pp = 0;
                        for (var sym in symb) {
                            if (symb[sym].name.indexOf("prelink") >= 0) {
                                pp = symb[sym].address
                            }
                        }
                        var ppI = Interceptor.attach(pp, function() {
                            ppI.detach();
                            base = this.context.r1.sub(0x34);
                            send('99:::' + base + ':::' + Process.arch + ':::' + Process.pointerSize);

                            for (var k in dtInitTargets) {
                                att(k, base.add(k));
                            }

                            var dlSym = Interceptor.attach(Module.findExportByName('libc.so', 'dlsym'), {
                                onLeave: function(ret) {
                                    dlSym.detach();

                                    // detach dt inits
                                    for (var k in targets) {
                                        targets[k+''].detach();
                                        delete targets[k+''];
                                    }
                                    // we attach later to those targets
                                    for (var k in pTargets) {
                                        att(k, base.add(k));
                                    }
                                    
                                    postSetup();
                                }                        
                            });
                        });
                    }            
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

        function sendContext() {
            var context = {};
            for (var reg in cContext) {
                var what = cContext[reg];
                context[reg] = {
                    'value': what
                };
                try {
                    var rr = Memory.readPointer(what);
                    context[reg]['sub'] = [rr]
                    while(true) {
                        rr = Memory.readPointer(rr);
                        context[reg]['sub'].push(rr);
                    }
                } catch(err) {
                    continue;
                }
            }
            var sbt = Thread.backtrace(cContext, Backtracer.ACCURATE).map(DebugSymbol.fromAddress);
            var tds = []
            try {
                tds = Memory.readByteArray(cContext.pc.sub(32), 64);
            } catch(err) {}
            send('2:::' + cOff + ':::' + JSON.stringify(context) + ':::' + JSON.stringify(sbt) + ':::' + bytesToHex(tds));
        }
        
        function att(off, pt) {
            if (base == 0) {
                return;
            }
            send('1:::' + pt);
            targets['' + pt] = Interceptor.attach(pt, function() {
                cContext = this.context;
                cOff = off;
                sendContext();
                sleep = true;
                while(sleep) {
                    Thread.sleep(1);
                }
            });
        }
        
        function postSetup() {
            var pthread_create_ptr = Module.findExportByName(null, 'pthread_create');
            if (pthread_create_ptr !== null) {
                var pthread_create = new NativeFunction(pthread_create_ptr, 'int', ['pointer', 'pointer', 'pointer', 'pointer']);
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
            add: function(what) {
                att(what, base.add(what));
            },
            addv: function(what) {
                att(what, ptr(what));
            },
            bt: function() {
                return Thread.backtrace(cContext, Backtracer.ACCURATE).map(DebugSymbol.fromAddress);
            },
            c: function() {
                sleep = false;
            },
            ems: function() {
                var m = Process.enumerateModulesSync();
                if (m != null) {
                    m = JSON.stringify(m);
                }
                return m;
            },
            ers: function() {
                var m = Process.enumerateRangesSync('---');
                if (m != null) {
                    m = JSON.stringify(m);
                }
                return m;
            },
            ets: function() {
                var m = Process.enumerateThreadsSync();
                if (m != null) {
                    m = JSON.stringify(m);
                }
                return m;
            },
            fexbn: function(a, b) {
                return Module.findExportByName(a, b);
            },
            fmba: function(w) {
                var m = Process.findModuleByAddress(ptr(w));
                if (m != null) {
                    m = JSON.stringify(m);
                }
                return m;
            },
            fmbn: function(w) {
                var m = Process.findModuleByName(w);
                if (m != null) {
                    m = JSON.stringify(m);
                }
                return m;
            },
            frba: function(w) {
                var m = Process.findRangeByAddress(ptr(w));
                if (m != null) {
                    m = JSON.stringify(m);
                }
                return m;            
            },
            ivp: function(p) {
                try {
                    Memory.readPointer(ptr(p));
                    return true;
                } catch(err) {
                    return false;
                }
            },
            mal: function(l) {
                return Memory.alloc(l);
            },
            mprot: function(p, l, f) {
                try {
                    p = ptr(p);
                    Memory.protect(p, l, f);
                    return p;
                } catch(err) {
                    return null;
                }
            },
            mr: function(p, l) {
                try {
                    return Memory.readByteArray(ptr(p), l);
                } catch(err) {
                    return null;
                }
            },
            mru8s: function(p, l) {
                try {
                    return Memory.readUtf8String(ptr(p), l);
                } catch(err) {
                    return null;
                }
            },
            mru16s: function(p, l) {
                try {
                    return Memory.readUtf16String(ptr(p), l);
                } catch(err) {
                    return null;
                }
            },
            mrans: function(p, l) {
                try {
                    return Memory.readAnsiString(ptr(p), l);
                } catch(err) {
                    return null;
                }
            },
            mracs: function(p, l) {
                try {
                    return Memory.readCString(ptr(p), l);
                } catch(err) {
                    return null;
                }
            },
            mw: function(p, w) {
                try {
                    p = ptr(p);
                    Memory.writeByteArray(p, hexToBytes(w));
                    return p;
                } catch(err) {
                    console.log(err)
                    return null;
                }
            },
            rp: function(p) {
                try {
                    return Memory.readPointer(ptr(p));
                } catch(err) {
                    return null;
                }
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
    '''
    return js
