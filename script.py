def get_script(pid, module, offsets, dtinitOffsets):
    js = 'var pid = ' + str(pid) + ';'
    js += 'var module = "' + module + '";'
    js += 'var pTargets = {};'
    js += 'var dtInitTargets = {};'
    for k, v in offsets.items():
        js += 'pTargets[' + str(k) + '] = ' + str(k) + ';'
    for k, v in dtinitOffsets.items():
        js += 'dtInitTargets[' + str(k) + '] = ' + str(k) + ';'
    with open('script.js', 'r') as f:
        js += f.read()
    return js
