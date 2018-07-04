var libc = Process.platform === "darwin" ? 'libSystem.B.dylib' : 'libc.so';
var nfs = {};
var nfs_n = {};

var sleep = false;
var cContext = {};
var cOff = 0x0;
var gn_handler = 0x0;

var gettid = nf(getnf('gettid', libc, 'int', []));
var main_tid = gettid();

setupBase();

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

function readThreads() {
    var path = '/proc/self/task';
    var m_alloc = Memory.alloc(path.length);
    Memory.protect(m_alloc, path.length, 'rw-');

    var opendir = nf(getnf('opendir', libc, 'pointer', ['pointer']));
    var readdir = nf(getnf('readdir', libc, 'pointer', ['pointer']));

    Memory.writeUtf8String(m_alloc, path);

    var proc_dir = opendir(m_alloc);
    var entry;
    var res = [];

    while ((entry = readdir(proc_dir)) > 0) {
        var line = Memory.readUtf8String(entry.add(19));
        if (line.indexOf('.') >= 0) {
            continue;
        }

        var proc;
        if ((proc = readTask(line)) !== null) {
            res.push(proc);
        }
    }
    return res;
}

function readTask(id) {
    var m_alloc = Memory.alloc(1024);
    Memory.protect(m_alloc, 1024, 'rw-');
    var fopen = nf(getnf('fopen', libc, 'pointer', ['pointer', 'pointer']));
    var fgets = nf(getnf('fgets', libc, 'pointer', ['pointer', 'int', 'pointer']));
    Memory.writeUtf8String(m_alloc, '/proc/self/task/' + id + '/stat');
    Memory.writeUtf8String(m_alloc.add(64), 'r');
    try {
        var fp = fopen(m_alloc, m_alloc.add(64));
        var line = Memory.readUtf8String(fgets(m_alloc, 1024, fp));
        var name = line.substring(line.indexOf('('), 1 + line.indexOf(')'));
        line = line.replace(' ' + name, '');
        var proc = line.split(' ');
        proc.splice(1, 0, name.replace('(', '').replace(')', ''));
        return proc;
    } catch (e) {
        return null;
    }
}

function nf(n) {
    return n['nf'];
}

function getnf(n, m, r, a) {
    if (nfs_n[n] !== null && typeof nfs_n[n] !== 'undefined') {
        return nfs['' + nfs_n[n]];
    }
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

function cli(pt, context) {
    sleep = true;
    cContext = context;
    cOff = parseInt(pt);
    sendContext();
    sendHookInfo();

    var t_hooks = goodnight();
    while(sleep) {
        Thread.sleep(1);
    }
    for (var k in t_hooks) {
        t_hooks[k].detach();
    }
}

function setupBase() {
    gn_handler = Memory.alloc(8);
    Memory.protect(gn_handler, 8, 'rwx');
    Interceptor.replace(gn_handler, new NativeCallback(function (sig) {
        while (sleep) {
            Thread.sleep(1);
        }
        return sig;
    }, 'int', ['int']));
}

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

var c_exp = {
    c: function () {
        cContext = {};
        sleep = false;
    },
    sc: function() {
        if (typeof cContext['pc'] === 'undefined') {
            return;
        }
        sendContext();
    }
};

if (rpc.exports === null || typeof rpc.exports === 'undefined') {
    rpc.exports = c_exp;
} else {
    rpc.exports = Object.assign({}, rpc.exports, c_exp);
}
