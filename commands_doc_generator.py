import pytablewriter
import sys

from main import Command

writer = pytablewriter.MarkdownTableWriter()
writer.table_name = "Commands list"
writer.header_list = ["command", "short", "info"]
writer.value_matrix = []
writer.margin = 2

current_module = sys.modules['main']
cmds = {}
for key in dir(current_module):
    attr = getattr(current_module, key)
    if isinstance(attr, type):
        try:
            if issubclass(attr, Command):
                cmd = attr(None)
                info = cmd.get_command_info()
                if info is not None:
                    cmds[info['name']] = info
        except:
            continue

subs = {}
for cmd in sorted(cmds):
    cmd_info = cmds[cmd]
    st = ''
    info = ''
    if 'shortcuts' in cmd_info:
        st = ','.join(sorted(cmd_info['shortcuts']))
    if 'info' in cmd_info:
        info = cmd_info['info']
    if 'sub' in cmd_info:
        subs[cmd] = cmd_info['sub']
    writer.value_matrix.append([cmd, st, info])

writer.write_table()


def iter_subs(subs):
    print('---')

    next_subs = {}

    for cmd in sorted(subs):
        writer.table_name = "%s sub commands" % cmd
        writer.value_matrix = []
        cmd_info_arr = subs[cmd]
        for cmd_info in sorted(cmd_info_arr, key=lambda x: x['name']):
            st = ''
            info = ''
            if 'shortcuts' in cmd_info:
                st = ','.join(sorted(cmd_info['shortcuts']))
            if 'info' in cmd_info:
                info = cmd_info['info']
            if 'sub' in cmd_info:
                next_subs[cmd + ' ' + cmd_info['name']] = cmd_info['sub']
            writer.value_matrix.append([cmd_info['name'], st, info])
        writer.write_table()

        if len(next_subs) > 0:
            iter_subs(next_subs)
            next_subs = {}


iter_subs(subs)
