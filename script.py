def get_script(module, offsets):
    js = 'var module = "' + module + '"'
    js += '''
        var base = 0x0;
        var sleep = false;
        
        function att(off) {
            if (base == 0) {
                return;
            }
            var pt = base.add(off);
            send('1:::' + pt);
            Interceptor.attach(pt, function() {
                var context = {}
                for (var reg in this.context) {
                    var what = this.context[reg];
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
                send('2:::' + off + ':::' + JSON.stringify(context));
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
            c: function() {
                sleep = false;
            },
            ivp: function(p) {
                try {
                    var ppt = ptr(p);
                    Memory.readPointer(ppt);
                    return true;
                } catch(err) {
                    return false;
                }
            },
            mr: function(p, l) {
                try {
                    p = ptr(p);
                    send('3:::' + p, Memory.readByteArray(p, l));
                } catch(err) {}
            },
            rp: function(p) {
                try {
                    return Memory.readPointer(ptr(p));
                } catch(err) {
                    return null;
                }
            }
        };
        
        setTimeout(function() {
            base = Process.findModuleByName(module).base;
            send('0:::' + base + ':::' + Process.arch);            
    '''
    for k, v in offsets.items():
        js += 'att(' + str(k) + ');'
    js += '}, 250);'
    return js