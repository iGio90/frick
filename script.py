def get_script(module, offsets):
    js = 'var module = "' + module + '"'
    js += '''
        var base = 0x0;
        var sleep = false;
        var cContext = null;
        var cOff = 0x0;
        
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
            send('2:::' + cOff + ':::' + JSON.stringify(context));
        }
        
        function att(off) {
            if (base == 0) {
                return;
            }
            var pt = base.add(off);
            send('1:::' + pt);
            Interceptor.attach(pt, function() {
                cContext = this.context;
                cOff = off;
                sendContext();
                sleep = true;
                while(sleep) {
                    Thread.sleep(1);
                }
            });
        }
        
        rpc.exports = {
            add: function(what) {
                att(what);
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
            mr: function(p, l) {
                try {
                    p = ptr(p);
                    return Memory.readByteArray(p, l);
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
            rw: function(r, v) {
                try {
                    console.log(JSON.stringify(cContext));
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
        
        setTimeout(function() {
            base = Process.findModuleByName(module).base;
            send('0:::' + base + ':::' + Process.arch + ':::' + Process.pointerSize);            
    '''
    for k, v in offsets.items():
        js += 'att(' + str(k) + ');'
    js += '}, 250);'
    return js