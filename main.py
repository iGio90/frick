#######################################################################################
#
# frick is distributed under the MIT License (MIT)
# Copyright (c) 2018 Giovanni - iGio90 - Rocca
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NON INFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
#

import atexit
import binascii
import capstone
import fcntl
import frida
import json
import os
import script
import six
import struct
import sys
import termios

import readline as readline

from pprint import pprint


def log(what):
    apix = Color.colorify('>', 'red highlight')
    if type(what) is str:
        try:
            what = int(what)
        except:
            try:
                what = int(what, 16)
            except:
                pass
        try:
            what.index('\n')
            ml = True
        except:
            ml = False
        if not ml:
            print('-%s %s' % (apix, what))
        else:
            print(what)
        return

    t = type(what)
    if t is int:
        c = 'green highlight'
        if cli.frida_script is not None and cli.frida_script.exports.ivp(what):
            c = 'red highlight'
        if what < 0:
            v = hex((what + (1 << 32)) % (1 << 32))
        else:
            v = hex(what)
        print('-%s %s (%s)' % (apix, Color.colorify(v, c), Color.colorify(str(what), 'bold')))
    elif t is six.text_type:
        print('-%s %s' % (apix, what.encode('ascii', 'ignore')))
    else:
        pprint(what)


class Arch(object):
    def __init__(self):
        self.capstone_arch = None
        self.capstone_mode = None

    def get_registers(self):
        return []

    def get_capstone_arch(self):
        return self.capstone_arch

    def get_capstone_mode(self):
        return self.capstone_mode

    def set_capstone_arch(self, arch):
        self.capstone_arch = arch

    def set_capstone_mode(self, mode):
        self.capstone_mode = mode


class Arm(Arch):
    def __init__(self):
        super(Arm, self).__init__()
        self.capstone_arch = capstone.CS_ARCH_ARM
        self.capstone_mode = capstone.CS_MODE_ARM

    def get_registers(self):
        r = []
        for i in range(0, 13):
            r.append('r' + str(i))
        r += ['sp', 'pc', 'lr']
        return r


class CommandManager(object):
    def __init__(self, cli):
        self.cli = cli
        self._map = {}

    def init(self):
        current_module = sys.modules[__name__]
        for key in dir(current_module):
            attr = getattr(current_module, key)
            if isinstance(attr, type):
                try:
                    if issubclass(attr, Command):
                        cmd = attr(self.cli)
                        info = cmd.get_command_info()
                        if info is not None:
                            self._map[info['name']] = cmd
                            if 'shortcuts' in info:
                                for sh in info['shortcuts']:
                                    self._map[sh] = cmd
                except:
                    continue

    def handle_command(self, p):
        p = p.split(' ')
        base = p[0]
        args = p[1:]

        if len(args) > 0 and args[0] == '=':
            if base in self._map:
                log('can\'t assign value %s' % base)
                return None
            fm = args[1:]
            if len(fm) > 0:
                tst_method = fm[0]
                if tst_method in self._map:
                    val = self.__internal_handle_command(tst_method, fm[1:], True)
                    if val is None:
                        val = 0
                    self.cli.context_manager.add_value(base, val)
                else:
                    formatted_args = self._format_args(fm)
                    if len(formatted_args) > 1:
                        ev = ''
                        for a in formatted_args:
                            ev += '%s ' % str(a)
                        try:
                            self.cli.context_manager.add_value(base, eval(ev))
                        except:
                            log('failed to evaluate value')
                    else:
                        self.cli.context_manager.add_value(base, formatted_args[0])
            return None
        return self.__internal_handle_command(base, args)

    def parse_sub(self, info, args):
        if 'sub' in info and len(args) > 0:
            for sub in info['sub']:
                found = False
                if args[0] == sub['name']:
                    found = True
                elif 'shortcuts' in sub and args[0] in sub['shortcuts']:
                    found = True
                if found:
                    return sub
        return None

    def _format_args(self, args):
        ret = []
        for i in range(0, len(args)):
            ev = self.try_eval(args[i])
            if str(ev).startswith('0x'):
                try:
                    ev = int(args[i], 16)
                except:
                    pass
            while True:
                try:
                    i = str(ev).index('$')
                    tst = ev[i + 1:i + 3].lower()
                    if tst in self.cli.context_manager.get_context():
                        ev = ev.replace('$%s' % tst, self.cli.context_manager.get_context()[tst]['value'])
                        continue
                    tst = ev[i + 1:i + 4].lower()
                    if tst in self.cli.context_manager.get_context():
                        ev = ev.replace('$%s' % tst, self.cli.context_manager.get_context()[tst]['value'])
                except:
                    break
            ev = self.try_eval(ev)

            c_val = self.cli.context_manager.get_value(str(ev))
            if c_val is not None:
                ev = c_val
            try:
                ev = int(args[i])
            except:
                pass

            ret.append(ev)
        return ret

    def try_eval(self, what):
        try:
            return eval(what)
        except:
            return what

    def __internal_handle_command(self, base, args, store=False):
        try:
            command = self._map[base]
        except:
            command = None

        if command is None:
            log('command not found')
            return None

        info = command.get_command_info()
        s_info = info
        f_exec = None
        s_args = args

        while True:
            s_info = self.parse_sub(s_info, s_args)
            if s_info is not None:
                info = s_info
                try:
                    f_exec = getattr(command, '__%s__' % s_info['name'])
                except:
                    pass
                s_args = s_args[1:]
            else:
                break
        args = s_args

        if 'args' in info:
            min_args = info['args']
            if min_args > len(args):
                log('not enough arguments')
                # todo print help
                return

        if f_exec is None:
            try:
                f_exec = getattr(command, '__%s__' % info['name'])
            except:
                pass
        if f_exec is None:
            log('no functions found for %s' % info['name'])
            return None
        else:
            formatted_args = self._format_args(args)
            try:
                data = f_exec(formatted_args)
                if data is not None:
                    if not store:
                        try:
                            f_exec = getattr(command, '__%s_result__' % info['name'])
                            f_exec(data)
                        except:
                            pass
                    else:
                        try:
                            f_exec = getattr(command, '__%s_store__' % info['name'])
                            data = f_exec(data)
                        except:
                            pass
                return data
            except Exception as e:
                log('error while running command %s: %s' % (info['name'], e))
                return None


class ContextManager(object):
    def __init__(self, cli):
        self._cli = cli
        self.base = 0x0
        self.arch = None
        self.pointer_size = 0x0
        self.context_offset = 0x0
        self.context = None
        self.target_package = ''
        self.target_module = ''
        self.target_offsets = {}
        self.values = {}

    def add_target_offset(self, offset, name=''):
        self.target_offsets[offset] = name

    def add_value(self, key, value):
        self.values[key] = value

    def apply_arch(self, arch):
        if arch == 'arm':
            self.arch = Arm()
        self.add_value('arch', arch)
        return self.arch

    def apply_pointer_size(self, pointer_size):
        self.pointer_size = pointer_size

    def clean(self):
        self.target_offsets = {}
        self.context = None
        self.context_offset = 0x0

    def set_base(self, base):
        self.base = base
        self.add_value('base', base)

    def set_context(self, offset, context):
        self.context_offset = offset
        self.context = context

    def set_target(self, package, module):
        self.target_package = package
        self.target_module = module

    def get_arch(self):
        return self.arch

    def get_base(self):
        return self.base

    def get_context(self):
        return self.context

    def get_context_offset(self):
        return self.context_offset

    def get_pointer_size(self):
        return self.pointer_size

    def get_target_module(self):
        return self.target_module

    def get_target_offsets(self):
        return self.target_offsets

    def get_value(self, key):
        if key in self.values:
            return self.values[key]
        return None

    def print_context(self):
        if self.arch is not None:
            all_registers = self.arch.get_registers()
        else:
            all_registers = self.context.keys()
        for r in all_registers:
            have_sub = False
            if 'sub' in self.context[r]:
                have_sub = True
                value = Color.colorify(self.context[r]['value'], 'red highlight')
            else:
                value = Color.colorify(self.context[r]['value'], 'green highlight')
            reg_name = r.upper()
            while len(reg_name) < 4:
                reg_name += ' '
            p = '%s: %s' % (Color.colorify(reg_name, 'bold'), value)
            if have_sub:
                subs = self.context[r]['sub']
                for i in range(0, len(subs)):
                    if i != len(subs) - 1:
                        p += ' -> %s' % Color.colorify(subs[i], 'red highligh')
                    else:
                        p += ' -> %s' % Color.colorify(subs[i], 'green highligh')
            print(p)

    def save(self):
        if os.path.exists('.session'):
            os.remove('.session')
        ext = ''
        if len(self.target_offsets) > 0:
            ext += 'add '
            for t in self.target_offsets:
                ext += '%s ' % str(t)
        if self.target_package is not '':
            ext += '\nattach %s %s' % (self.target_package, self.target_module)
        if ext is not '':
            with open('.session', 'w') as f:
                f.write(ext)
            log('session saved')
        else:
            log('add offsets or target package before using \'save\'')

    def load(self):
        if not os.path.exists('.session'):
            log('session file not found. use \'save\' to save offsets and target for the next cycle')
            return
        self.clean()
        with open('.session', 'r') as f:
            f = f.read()
            for l in f.split('\n'):
                self._cli.cmd_manager.handle_command(l)


class Color:
    """
    Colorify class.
    by @hugsy
    https://github.com/hugsy/gef/blob/master/gef.py#L325
    """
    colors = {
        "normal": "\033[0m",
        "gray": "\033[1;38;5;240m",
        "red": "\033[31m",
        "green": "\033[32m",
        "yellow": "\033[33m",
        "blue": "\033[34m",
        "pink": "\033[35m",
        "bold": "\033[1m",
        "underline": "\033[4m",
        "underline_off": "\033[24m",
        "highlight": "\033[3m",
        "highlight_off": "\033[23m",
        "blink": "\033[5m",
        "blink_off": "\033[25m",
    }

    @staticmethod
    def redify(msg):
        return Color.colorify(msg, attrs="red")

    @staticmethod
    def greenify(msg):
        return Color.colorify(msg, attrs="green")

    @staticmethod
    def blueify(msg):
        return Color.colorify(msg, attrs="blue")

    @staticmethod
    def yellowify(msg):
        return Color.colorify(msg, attrs="yellow")

    @staticmethod
    def grayify(msg):
        return Color.colorify(msg, attrs="gray")

    @staticmethod
    def pinkify(msg):
        return Color.colorify(msg, attrs="pink")

    @staticmethod
    def boldify(msg):
        return Color.colorify(msg, attrs="bold")

    @staticmethod
    def underlinify(msg):
        return Color.colorify(msg, attrs="underline")

    @staticmethod
    def highlightify(msg):
        return Color.colorify(msg, attrs="highlight")

    @staticmethod
    def blinkify(msg):
        return Color.colorify(msg, attrs="blink")

    @staticmethod
    def colorify(text, attrs):
        """Color a text following the given attributes."""
        colors = Color.colors
        msg = [colors[attr] for attr in attrs.split() if attr in colors]
        msg.append(text)
        if colors["highlight"] in msg:   msg.append(colors["highlight_off"])
        if colors["underline"] in msg:   msg.append(colors["underline_off"])
        if colors["blink"] in msg:       msg.append(colors["blink_off"])
        msg.append(colors["normal"])
        return "".join(msg)


class Command(object):
    def __init__(self, cli):
        self.cli = cli

    def get_command_info(self):
        return None


class Add(Command):
    def get_command_info(self):
        return {
            'name': 'add',
            'info': 'add offset from base 0x0 in arg0 with optional name for this target in other args',
            'args': 1,
            'sub': [
                {
                    'name': 'pointer',
                    'info': 'add a virtual address in arg0 with optional name in other args',
                    'args': 1,
                    'shortcuts': [
                        'ptr', 'p'
                    ]
                }
            ]
        }

    def __add__(self, args):
        ptr = args[0]
        name = ''
        if len(args) > 1:
            for a in args[1:]:
                name += str(a) + ' '
        self.cli.context_manager.add_target_offset(ptr, name)
        if self.cli.frida_script is not None:
            self.cli.frida_script.exports.add(ptr)
        return ptr

    def __add_result__(self, result):
        log('%s added to target offsets' % Color.colorify('0x%x' % result, 'red highlight'))

    def __pointer__(self, args):
        if self.cli.frida_script is not None and type(args[0]) is int:
            self.cli.frida_script.exports.addv(args[0])
            return args[0]

    def __pointer_result__(self, result):
        log('%s added to target offsets' % Color.colorify('0x%x' % result, 'red highlight'))

class Attach(Command):
    def get_command_info(self):
        return {
            'name': 'attach',
            'args': 1,
            'info': 'attach to target package name in arg0 with target module name in arg1',
            'shortcuts': [
                'att'
            ]
        }

    def __attach__(self, args):
        package = args[0]
        module = args[1]
        if not module.endswith('.so'):
            module += '.so'
        pid = self.cli.frida_device.spawn([package])
        process = self.cli.frida_device.attach(pid)
        log("frida %s" % Color.colorify('attached', 'bold'))
        self.cli.frida_script = process.create_script(script.get_script(
            module, self.cli.context_manager.get_target_offsets()))
        log("script %s" % Color.colorify('injected', 'bold'))
        self.cli.frida_device.resume(package)
        self.cli.frida_script.on('message', self.cli.on_frida_message)
        self.cli.frida_script.on('destroyed', self.cli.on_frida_script_destroyed)
        self.cli.frida_script.load()
        self.cli.context_manager.set_target(package, module)
        return None


class Backtrace(Command):
    def get_command_info(self):
        return {
            'name': 'backtrace',
            'info': '',
            'shortcuts': [
                'bt'
            ]
        }

    def __backtrace__(self, args):
        if self.cli.context_manager.get_context() is not None:
            return self.cli.frida_script.exports.bt()

    def __backtrace_result__(self, result):
        if len(result) > 0:
            self.cli.context_title('backtrace')
            for b in result:
                name = ''
                if 'name' in b:
                    name = b['name']
                    if 'moduleName' in b:
                        name += ' ' + b['moduleName']
                print('%s\t%s' % (Color.colorify(b['address'], 'red highlight'), name))

    def __backtrace_store__(self, data):
        return None


class DeStruct(Command):
    def get_command_info(self):
        return {
            'name': 'destruct',
            'info': 'read at address arg0 for len arg1 and optional depth arg2',
            'args': 2,
            'shortcuts': [
                'ds', 'des'
            ]
        }

    def __destruct__(self, args):
        depth = self.cli.context_manager.get_pointer_size() * 4
        if len(args) > 2:
            depth = args[2]
        if depth % 8 != 0:
            return 'depth must be multiple of 8'
        try:
            data = self.cli.frida_script.exports.mr(args[0], args[1])
            result = self._recursive(data, depth)
            lines = self._get_lines(result, 0)
            return '\n'.join(lines)
        except:
            return None

    def __destruct_store__(self, data):
        return None

    def __destruct_result__(self, result):
        log(result)

    def _get_lines(self, arr, depth):
        result = []
        while len(arr) > 0:
            line = '    ' * depth
            obj = arr.pop(0)
            if 'value' in obj:
                dec = obj['decimal']
                if dec != 0x0 and dec != 0xfffffff:
                    line += '%s' % Color.colorify(obj['value'], 'green highlight')
                else:
                    line += obj['value']
                result.append(line)
            elif 'ptr' in obj:
                line += Color.colorify(obj['ptr'], 'red highlight')
                result.append(line)
                if 'tree' in obj and obj['tree'] is not None:
                    result += self._get_lines(obj['tree'], depth + 1)
        return result

    def _recursive(self, data, depth):
        _struct = []
        while len(data) > 0:
            chunk_size = self.cli.context_manager.get_pointer_size()
            if len(data) < chunk_size:
                break
            chunk = data[0:chunk_size]
            i_val = struct.unpack('>L', chunk)[0]
            if i_val < 255:
                _struct.append({'value': '0x%s' % (binascii.hexlify(chunk)), 'decimal': i_val})
            else:
                val = struct.unpack('<L', data[0:chunk_size])[0]
                try:
                    read = depth
                    if depth < self.cli.context_manager.get_pointer_size() * 2:
                        read = self.cli.context_manager.get_pointer_size()
                    sd = self.cli.frida_script.exports.mr(val, read)
                    if sd is not None:
                        obj = {'ptr': '0x%x' % val}
                        if depth >= self.cli.context_manager.get_pointer_size() * 2:
                            obj['tree'] = self._recursive(sd, depth / 2)
                        _struct.append(obj)
                        data = data[chunk_size:]
                        continue
                except:
                    pass
                _struct.append({'value': '0x%s' % (binascii.hexlify(chunk)), 'decimal': i_val})
            data = data[chunk_size:]
        return _struct


class DisAssembler(Command):
    def get_command_info(self):
        return {
            'name': 'disasm',
            'args': 1,
            'info': 'disassemble the given hex payload in arg0 or a pointer in arg0 with len in arg1',
            'shortcuts': [
                'd', 'dis'
            ]
        }

    def __disasm__(self, args):
        if self.cli.context_manager.get_base() == 0:
            log('a target attached is needed before using disasm')
            return None

        if self.cli.context_manager.get_arch() is None:
            log('this arch is not yet supported :(')
        else:
            cs = capstone.Cs(self.cli.context_manager.get_arch().get_capstone_arch(),
                             self.cli.context_manager.get_arch().get_capstone_mode())
            if type(args[0]) is str:
                b = binascii.unhexlify(args[0])
                off = 0
                if len(args) > 1:
                    off = args[1]
            else:
                l = 32
                if len(args) > 1:
                    l = args[1]
                b = Memory(self.cli)._internal_read_data_(args[0], l)[1]
                off = args[0]
            ret = []
            for i in cs.disasm(b, off):
                faddr = '0x%x' % i.address
                if self.cli.context_manager.get_context() is not None:
                    pc = int(self.cli.context_manager.get_context()['pc']['value'], 16)
                    if pc == i.address or pc + 1 == i.address:
                        faddr = ' ' + Color.colorify(faddr, 'red highlight')
                ret.append("%s:\t%s\t%s" % (faddr, Color.colorify(i.mnemonic.upper(), 'bold'), i.op_str))
            return ret

    def __disasm_result__(self, result):
        self.cli.context_title('disasm')
        print('\n'.join(result))

    def __disasm_store__(self, data):
        return None


class Find(Command):
    def get_command_info(self):
        return {
            'name': 'find',
            'args': 1,
            'info': 'utilities to find stuffs',
            'shortcuts': [
                'f', 'fi'
            ],
            'sub': [
                {
                    'name': 'export',
                    'args': 1,
                    'info': 'find export name arg0 in target module or in optional module arg1',
                    'shortcuts': ['e', 'ex', 'exp']
                }
            ]
        }

    def __export__(self, args):
        module = self.cli.context_manager.get_target_module()
        if len(args) > 1:
            module = args[1]
        return [args[0], self.cli.frida_script.exports.fexbn(module, args[0])]

    def __export_result__(self, result):
        if len(result) > 1 and result[1] is not None:
            self.cli.context_title(result[0])
            log(Color.colorify(result[1], 'red highlight'))

    def __export_store__(self, data):
        return int(data[1], 16)


class Help(Command):
    def get_command_info(self):
        return {
            'name': 'help',
            'shortcuts': [
                'h'
            ]
        }

    def __help__(self, args):
        self.print_commands_list()
        return None

    def print_commands_list(self):
        c_map = {}
        for cmd in self.cli.cmd_manager._map.values():
            cmd_info = cmd.get_command_info()
            c_map[cmd_info['name']] = cmd
        result = self.recursive_help(c_map, 0)
        log('\n'.join(result))

    def recursive_help(self, cmd_map, depth):
        result = []
        for what in sorted(cmd_map):
            if depth == 0:
                cmd_info = cmd_map[what].get_command_info()
            else:
                cmd_info = cmd_map[what]

            st = self.get_command_help_line(cmd_info, depth)
            result.append(st)
            if 'sub' in cmd_info:
                sub_map = {}
                for s in cmd_info['sub']:
                    sub_map[s['name']] = s
                result += self.recursive_help(sub_map, depth + 1)
            if depth == 0:
                result.append('')
        return result

    def get_command_help_line(self, cmd_info, depth):
        cmd_name = cmd_info['name']
        st = '    ' * depth
        st += Color.colorify(cmd_name, 'pink highlight')
        if 'shortcuts' in cmd_info:
            shortcuts = cmd_info['shortcuts']
            st += ' (%s)' % Color.colorify((','.join(sorted(shortcuts))), 'green highlight')
        if 'info' in cmd_info:
            st += '\n'
            st += '    ' * depth
            st += '%s' % cmd_info['info']

        return st


class Hexdump(Command):
    def get_command_info(self):
        return {
            'name': 'hexdump',
            'args': 2,
            'shortcuts': [
                'hd', 'hdump'
            ],
            'info': 'a shortcut to memory read command'
        }

    def __hexdump__(self, args):
        return Memory(self.cli).__read__(args)

    def __hexdump_result__(self, result):
        self.cli.hexdump(result[1], result[0])

    def __hexdump_store__(self, data):
        return None


class Info(Command):
    def get_command_info(self):
        return {
            'name': 'info',
            'args': 1,
            'info': 'get information about your target',
            'shortcuts': [
                'i', 'in'
            ],
            'sub': [
                {
                    'name': 'modules',
                    'info': 'list all modules or single module in optional arg0',
                    'shortcuts': ['module', 'mod', 'mo', 'md', 'm']
                },
                {
                    'name': 'ranges',
                    'info': 'list all ranges or single range in optional arg0',
                    'shortcuts': ['range', 'r', 'rg']
                }
            ]
        }

    def __modules__(self, args):
        if len(args) > 0:
            what = args[0]
            try:
                if isinstance(what, str):
                    return self.cli.frida_script.exports.fmbn(what)
                else:
                    return self.cli.frida_script.exports.fmba(what)
            except:
                return None
        else:
            try:
                return self.cli.frida_script.exports.ems()
            except:
                return None

    def __modules_result__(self, result):
        what = json.loads(result)
        if type(what) is dict:
            self._print_module(what)
        else:
            for m in what:
                self._print_module(m)

    def __modules_store(self, data):
        data = json.loads(data)
        if type(data) is dict:
            return data['base']
        return None

    def _print_module(self, module):
        self.cli.context_title(module['name'])
        print('name: %s\nbase: %s\nsize: %s (%s)' % (Color.colorify(module['name'], 'bold'),
                                                     Color.colorify(module['base'], 'red highlight'),
                                                     Color.colorify('0x%x' % module['size'], 'green highlight'),
                                                     Color.colorify(str(module['size']), 'bold')))
        if 'path' in module:
            print('path: %s' % Color.colorify(module['path'], 'highlight'))

    def __ranges__(self, args):
        if len(args) > 0:
            try:
                return self.cli.frida_script.exports.frba(args[0])
            except:
                return None
        else:
            try:
                return self.cli.frida_script.exports.ers()
            except:
                return None

    def __ranges_result__(self, result):
        what = json.loads(result)
        if type(what) is dict:
            self._print_range(what)
        else:
            for m in what:
                self._print_range(m)

    def __ranges_store__(self, data):
        data = json.loads(data)
        if type(data) is dict:
            return data['base']
        return None

    def _print_range(self, range):
        self.cli.context_title(range['base'])
        print('base: %s\nsize: %s (%s)\nprot: %s' % (Color.colorify(range['base'], 'red highlight'),
                                                     Color.colorify('0x%x' % range['size'], 'green highlight'),
                                                     Color.colorify(str(range['size']), 'bold'),
                                                     Color.colorify(range['protection'], 'ping highlight')))
        if 'file' in range:
            print('\npath: %s' % Color.colorify(range['file']['path'], 'highlight'))


class Memory(Command):
    def get_command_info(self):
        return {
            'name': 'memory',
            'args': 1,
            'info': 'memory operations',
            'shortcuts': [
                'mem', 'm'
            ],
            'sub': [
                {
                    'name': 'alloc',
                    'args': 1,
                    'info': 'allocate arg0 size in the heap and return the pointer',
                    'shortcuts': [
                        'a', 'al'
                    ]
                },
                {
                    'name': 'dump',
                    'args': 3,
                    'info': 'read bytes in arg0 for len in arg1 and store into filename arg2',
                    'shortcuts': [
                        'd'
                    ]
                },
                {
                    'name': 'read',
                    'args': 2,
                    'info': 'read bytes from address in arg0 for len in arg1',
                    'shortcuts': ['rd', 'r'],
                    'sub': [
                        {
                            'name': 'pointer',
                            'info': 'read a pointer from address in arg0',
                            'args': 1,
                            'shortcuts': [
                                'p', 'ptr'
                            ]
                        },
                        {
                            'name': 'byte',
                            'info': 'read a signed byte from address in arg0 with optional endianness in arg1 (le/be)',
                            'args': 1,
                            'shortcuts': [
                                'b'
                            ]
                        },
                        {
                            'name': 'ubyte',
                            'info': 'read an unsigned byte from address in arg0 with '
                                    'optional endianness in arg1 (le/be)',
                            'args': 1,
                            'shortcuts': [
                                'ub'
                            ]
                        },
                        {
                            'name': 'short',
                            'info': 'read a signed short from address in arg0 with optional endianness in arg1 (le/be)',
                            'args': 1,
                            'shortcuts': [
                                's'
                            ]
                        },
                        {
                            'name': 'ushort',
                            'info': 'read an unsigned short from address in arg0 with '
                                    'optional endianness in arg1 (le/be)',
                            'args': 1,
                            'shortcuts': [
                                'us'
                            ]
                        },
                        {
                            'name': 'int',
                            'info': 'read a signed int from address in arg0 with optional endianness in arg1 (le/be)',
                            'args': 1,
                            'shortcuts': [
                                'i'
                            ]
                        },
                        {
                            'name': 'uint',
                            'info': 'read an unsigned int from address in arg0 with '
                                    'optional endianness in arg1 (le/be)',
                            'args': 1,
                            'shortcuts': [
                                'ui'
                            ]
                        },
                        {
                            'name': 'long',
                            'info': 'read a signed long from address in arg0 with optional endianness in arg1 (le/be)',
                            'args': 1,
                            'shortcuts': [
                                'l'
                            ]
                        },
                        {
                            'name': 'ulong',
                            'info': 'read an unsigned long from address in arg0 with '
                                    'optional endianness in arg1 (le/be)',
                            'args': 1,
                            'shortcuts': [
                                'ul'
                            ]
                        },
                        {
                            'name': 'utf8string',
                            'info': 'read utf8 string from address in arg0 and optional len in arg1',
                            'args': 1,
                            'shortcuts': [
                                'utf8str', 'utf8s', 'utf8', 'u8s'
                            ]
                        },
                        {
                            'name': 'utf16string',
                            'info': 'read utf16 string from address in arg0 and optional len in arg1',
                            'args': 1,
                            'shortcuts': [
                                'utf16str', 'utf16s', 'utf16', 'u16s'
                            ]
                        },
                        {
                            'name': 'ansistring',
                            'info': 'read ansi string from address in arg0 and optional len in arg1',
                            'args': 1,
                            'shortcuts': [
                                'ansistr', 'ansi', 'ans'
                            ]
                        },
                        {
                            'name': 'asciistring',
                            'info': 'read ascii string from address in arg0 and optional len in arg1',
                            'args': 1,
                            'shortcuts': [
                                'asciistr', 'ascii', 'acs'
                            ]
                        }
                    ]
                },
                {
                    'name': 'protect',
                    'args': 3,
                    'info': 'protect address in arg0 for the len arg1 and the prot format in arg2 (rwx)',
                    'shortcuts': ['prot', 'pro', 'pr', 'p'],
                },
                {
                    'name': 'write',
                    'args': 2,
                    'info': 'write into address arg0 the bytes in args... (de ad be ef)',
                    'shortcuts': ['wr', 'w'],
                }
            ]
        }

    def _get_string_length(self, args):
        l = -1
        if len(args) > 1:
            l = args[1]
        return l

    def _internal_read_data_(self, ptr, len):
        try:
            return [ptr, self.cli.frida_script.exports.mr(ptr, len)]
        except Exception as e:
            log('failed to read data from device: %s' % e)
            return None

    def _parse_endianness_(self, args):
        if len(args) > 1 and args[1] == 'le':
            return '<'
        return '>'

    def _read_data_by_type(self, args, data_len, data_mark):
        b = self._internal_read_data_(args[0], data_len)
        if b is not None:
            c = b.pop(1)
            val = struct.unpack('%s%s' % (self._parse_endianness_(args), data_mark), c)[0]
            b.append(val)
        return b

    def __alloc__(self, args):
        if self.cli.frida_script is not None:
            return int(self.cli.frida_script.exports.mal(args[0]), 16)
        return None

    def __alloc_result(self, result):
        log(result)

    def __ansistring__(self, args):
        try:
            l = self._get_string_length(args)
            return [args[0], self.cli.frida_script.exports.mrans(args[0], l)]
        except Exception as e:
            log('failed to read data from device: %s' % e)
            return None

    def __ansistring_result__(self, result):
        self.cli.context_title('0x%x' % result[0])
        log(result[1])

    def __ansistring_store__(self, data):
        return data[1]

    def __asciistring__(self, args):
        try:
            l = self._get_string_length(args)
            return [args[0], self.cli.frida_script.exports.mracs(args[0], l)]
        except Exception as e:
            log('failed to read data from device: %s' % e)
            return None

    def __asciistring_result__(self, result):
        self.cli.context_title('0x%x' % result[0])
        log(result[1])

    def __asciistring_store__(self, data):
        return data[1]

    def __byte__(self, args):
        return self._read_data_by_type(args, 1, 'b')

    def __byte_result__(self, result):
        self.cli.context_title('0x%x' % result[0])
        log(result[1])

    def __byte_store__(self, data):
        return data[1]

    def __dump__(self, args):
        data = self._internal_read_data_(args[0], args[1])
        if data is not None:
            data = data[1]
            try:
                with open(args[2], 'wb') as f:
                    f.write(data)
                return [str(args[1]), args[2]]
            except Exception as e:
                log('failed to write data: %s' % e)
                return None

    def __dump_result__(self, result):
        log('written %s bytes into %s' % (result[0], result[1]))

    def __int__(self, args):
        return self._read_data_by_type(args, 4, 'i')

    def __int_result__(self, result):
        self.cli.context_title('0x%x' % result[0])
        log(result[1])

    def __int_store__(self, data):
        return data[1]

    def __long__(self, args):
        return self._read_data_by_type(args, 8, 'q')

    def __long_result__(self, result):
        self.cli.context_title('0x%x' % result[0])
        log(result[1])

    def __long_store__(self, data):
        return data[1]

    def __pointer__(self, args):
        try:
            return int(self.cli.frida_script.exports.rp(args[0]), 16)
        except Exception as e:
            log('failed to read data from device: %s' % e)
            return None

    def __pointer_result__(self, result):
        log(result)

    def __protect__(self, args):
        try:
            return int(self.cli.frida_script.exports.mprot(args[0], args[1], args[2]), 16)
        except Exception as e:
            log('failed to read data from device: %s' % e)
            return None

    def __protect_result__(self, result):
        log(result)

    def __read__(self, args):
        return self._internal_read_data_(args[0], args[1])

    def __read_result__(self, result):
        self.cli.hexdump(result[1], result[0])

    def __read_store__(self, data):
        return data[1]

    def __short__(self, args):
        return self._read_data_by_type(args, 2, 'h')

    def __short_result__(self, result):
        self.cli.context_title('0x%x' % result[0])
        log(result[1])

    def __short_store__(self, data):
        return data[1]

    def __ubyte__(self, args):
        return self._read_data_by_type(args, 1, 'B')

    def __ubyte_result__(self, result):
        self.cli.context_title('0x%x' % result[0])
        log(result[1])

    def __ubyte_store__(self, data):
        return data[1]

    def __uint__(self, args):
        return self._read_data_by_type(args, 4, 'I')

    def __uint_result__(self, result):
        self.cli.context_title('0x%x' % result[0])
        log(result[1])

    def __uint_store__(self, data):
        return data[1]

    def __ulong__(self, args):
        return self._read_data_by_type(args, 8, 'Q')

    def __ulong_result__(self, result):
        self.cli.context_title('0x%x' % result[0])
        log(result[1])

    def __ulong_store__(self, data):
        return data[1]

    def __ushort__(self, args):
        return self._read_data_by_type(args, 2, 'H')

    def __ushort_result__(self, result):
        self.cli.context_title('0x%x' % result[0])
        log(result[1])

    def __ushort_store__(self, data):
        return data[1]

    def __utf8string__(self, args):
        try:
            l = self._get_string_length(args)
            return [args[0], self.cli.frida_script.exports.mru8s(args[0], l)]
        except Exception as e:
            log('failed to read data from device: %s' % e)
            return None

    def __utf8string_result__(self, result):
        self.cli.context_title('0x%x' % result[0])
        log(result[1])

    def __utf8string_store__(self, data):
        return data[1]

    def __utf16string__(self, args):
        try:
            l = self._get_string_length(args)
            return [args[0], self.cli.frida_script.exports.mru16s(args[0], l)]
        except Exception as e:
            log('failed to read data from device: %s' % e)
            return None

    def __utf16string_result__(self, result):
        self.cli.context_title('0x%x' % result[0])
        log(result[1])

    def __utf16string_store__(self, data):
        return data[1]

    def __write__(self, args):
        try:
            return int(self.cli.frida_script.exports.mw(args[0], ''.join(args[1:])), 16)
        except Exception as e:
            log('failed to write data to device: %s' % e)
            return None


class Pack(Command):
    def get_command_info(self):
        return {
            'name': 'pack',
            'args': 1,
            'info': 'pack value in arg0 to return a string usable with memory write',
            'shortcuts': [
                'pa'
            ]
        }

    def __pack__(self, args):
        l = ''
        for a in args:
            if type(a) is int:
                c = ''
                if len(str(a)) % 2 is not 0:
                    c = '0'
                l += '%s%x' % (c, a)
            elif type(a) is str:
                l += binascii.hexlify(a)
        r = [l[i:i + 2] for i in range(0, len(l), 2)]
        return ' '.join(r)

    def __pack_result__(self, result):
        log(result)


class Print(Command):
    def get_command_info(self):
        return {
            'name': 'print',
            'args': 1,
            'shortcuts': [
                'p', 'pr'
            ]
        }

    def __print__(self, args):
        if len(args) > 1:
            ev = ''
            for a in args:
                ev += '%s ' % str(a)
            try:
                return eval(ev)
            except:
                log('failed to evaluate value')
                return None
        else:
            return args[0]

    def __print_result__(self, result):
        log(result)


class Registers(Command):
    def get_command_info(self):
        return {
            'name': 'registers',
            'shortcuts': [
                'r', 'reg', 'regs'
            ],
            'info': 'interact with registers',
            'sub': [
                {
                    'name': 'write',
                    'shortcuts': ['wr', 'w'],
                    'args': 2,
                    'info': 'write in register arg0 the value arg1'
                }
            ]
        }

    def __registers__(self, args):
        try:
            self.cli.frida_script.exports.sc()
        except:
            pass

    def __write__(self, args):
        reg = args[0].lower()
        if reg in self.cli.context_manager.get_context():
            try:
                what = args[1]
                if isinstance(what, str):
                    what = int('0x%s' % what, 16)
                v = self.cli.frida_script.exports.rw(reg, what)
                if v is not None:
                    return args[1]
                else:
                    print('failed to write into register %s' % reg)
                    return None
            except Exception as e:
                print('failed to write into register %s - %s' % (reg, e))
                return None
        print('%s - register not found' % (Color.colorify(reg, 'bold')))
        return None

    def __write_result__(self, result):
        print('%s (%u)' % (Color.colorify('0x%x' % result, 'green highlight'), result))


class Quit(Command):
    def get_command_info(self):
        return {
            'name': 'quit',
            'args': 0,
            'shortcuts': [
                'q'
            ]
        }

    def __quit__(self, args):
        sys.exit(0)


class Run(Command):
    def get_command_info(self):
        return {
            'name': 'run',
            'info': 'continue the execution of the process to the next target offset',
            'shortcuts': [
                'continue', 'cont', 'start', 'go', 'next', 'c'
            ]
        }

    def __run__(self, args):
        self.cli.frida_script.exports.c()
        return None


class Session(Command):
    def get_command_info(self):
        return {
            'name': 'session',
            'args': 1,
            'shortcuts': [
                's', 'ss'
            ],
            'sub': [
                {
                    'name': 'save',
                    'info': 'saves current target offsets, package and module to be immediatly executed with \'load\'',
                    'shortcuts': [
                        's', 'sv'
                    ]
                },
                {
                    'name': 'load',
                    'info': 'load session from previously saved information',
                    'shortcuts': [
                        'l', 'ld'
                    ]
                }
            ]
        }

    def __load__(self, args):
        self.cli.context_manager.load()
        return None

    def __save__(self, args):
        self.cli.context_manager.save()
        return None


class Set(Command):
    def get_command_info(self):
        return {
            'name': 'set',
            'args': 1,
            'sub': [
                {
                    'name': 'capstone',
                    'info': 'capstone configurations',
                    'args': 1,
                    'shortcuts': [
                        'cs'
                    ],
                    'sub': [
                        {
                            'name': 'arch',
                            'args': 1,
                            'info': 'set the capstone arch in arg0',
                            'shortcuts': [
                                'a', 'ar'
                            ]
                        },
                        {
                            'name': 'mode',
                            'args': 1,
                            'info': 'set the capstone mode in arg0',
                            'shortcuts': [
                                'm', 'md', 'mod'
                            ]
                        }
                    ]
                }
            ]
        }

    def __arch__(self, args):
        arch_list = [k for k, v in capstone.__dict__.items() if not k.startswith("__") and k.startswith("CS_ARCH")]
        if type(args[0]) is str:
            __arch_test = 'CS_ARCH_%s' % args[0].upper()
            if __arch_test in arch_list:
                if self.cli.context_manager.get_arch() is not None:
                    __arch = getattr(capstone, __arch_test)
                    self.cli.context_manager.get_arch().get_capstone_arch(__arch)
                    return __arch
                else:
                    print('need a target attached before doing this')
        log('arch not found. use one of:')
        log(' '.join(sorted(arch_list)).replace('CS_ARCH_', '').lower())

    def __mode__(self, args):
        mode_list = [k for k, v in capstone.__dict__.items() if not k.startswith("__") and k.startswith("CS_MODE")]
        if type(args[0]) is str:
            __mode_test = 'CS_MODE_%s' % args[0].upper()
            if __mode_test in mode_list:
                if self.cli.context_manager.get_arch() is not None:
                    __mode = getattr(capstone, __mode_test)
                    self.cli.context_manager.get_arch().get_capstone_arch(__mode)
                    return __mode
                else:
                    print('need a target attached before doing this')
        log('mode not found. use one of:')
        log(' '.join(sorted(mode_list)).replace('CS_MODE_', '').lower())
        return None


class FridaCli(object):
    def __init__(self):
        try:
            self.frida_device = frida.get_usb_device(5)
            self.frida_device.on('lost', FridaCli.on_device_detached)
        except:
            log('remote frida device not found')
            sys.exit(0)

        self.frida_script = None

        self.cmd_manager = CommandManager(self)
        self.context_manager = ContextManager(self)

    def start(self):
        self.cmd_manager.init()
        log('%s started - GL HF!' % Color.colorify('frick', 'green highligh'))

        readline.parse_and_bind('tab: complete')
        hist = os.path.join(os.environ['HOME'], '.frick_history')

        try:
            readline.read_history_file(hist)
        except IOError:
            pass
        atexit.register(readline.write_history_file, hist)

        while True:
            inp = six.moves.input().strip()
            if len(inp) > 0:
                self.cmd_manager.handle_command(inp)

    def hexdump(self, data, offset=0):
        b_to_h = lambda b: ' '.join('%02x' % i for i in six.iterbytes(b))
        result = []
        while len(data) > 0:
            chunk_size = 16
            if len(data) < chunk_size:
                chunk_size = len(data)
            hexline = ''
            n = data[0:chunk_size]
            y = 0
            while len(n) > 0:
                ptr_size = cli.context_manager.get_pointer_size()
                if len(n) >= ptr_size:
                    try:
                        i_val = struct.unpack('>L', n[0:ptr_size])[0]
                        if i_val > 255:
                            ptr = struct.unpack('<L', n[0:ptr_size])[0]
                            if self.frida_script.exports.ivp(ptr):
                                hexline += '%s' % Color.colorify(b_to_h(n[0:ptr_size]).upper(), 'red highlight')
                                n = n[ptr_size:]
                                y += ptr_size
                                if y % 8 == 0:
                                    hexline += '  '
                                else:
                                    hexline += ' '
                                continue
                    except:
                        pass
                else:
                    ptr_size = len(n)
                var_hex = b_to_h(n[0:ptr_size])
                var_i = int('0x%s' % ''.join(var_hex.split(' ')), 16)
                if var_i > 0:
                    hexline += '%s' % Color.colorify(var_hex.upper(), 'green highlight')
                else:
                    hexline += '%s' % var_hex.upper()
                n = n[ptr_size:]
                y += ptr_size
                if y % 8 == 0:
                    hexline += '  '
                else:
                    hexline += ' '
            diff = 16 - y
            while diff > 0:
                hexline += ' '
                diff -= 1

            address = Color.colorify(('%08x' % (offset + (16 * len(result)))).upper(), 'yellow highlight')

            tail = ''
            for i in range(0, chunk_size):
                char = data[i:i + 1]
                if ord(char) < 32 or ord(char) > 126:
                    tail += '.'
                    continue
                t = ''
                try:
                    t = data[i:i + 1].decode('ascii')
                except:
                    pass
                if len(t) < 1:
                    t = '.'
                tail += t
            tail = Color.colorify(tail.replace('\n', '.').replace('\t', '.').replace(' ', '.'),
                                  'yellow highlight')
            result.append('%s: %s%s' % (address, hexline, tail))
            data = data[chunk_size:]
        if len(result) > 0:
            self.context_title('0x%x' % offset)
            print('\n'.join(result))

    @staticmethod
    def get_terminal_size():
        """Return the current terminal size."""
        try:
            cmd = struct.unpack("hh", fcntl.ioctl(1, termios.TIOCGWINSZ, "1234"))
            tty_rows, tty_columns = int(cmd[0]), int(cmd[1])
            return tty_rows, tty_columns
        except OSError:
            return 600, 100

    @staticmethod
    def context_title(m):
        row, cols = FridaCli.get_terminal_size()
        if not m:
            print(Color.colorify('-' * cols, 'blue bold'))
        else:
            trail_len = len(m) + 8
            title = ""
            title += Color.colorify("{:{padd}<{width}}[ ".format("", width=cols - trail_len, padd='-'),
                                    attrs='blue highlight')
            title += Color.colorify(m, 'highlight')
            title += Color.colorify(" ]{:{padd}<4}".format("", padd='-'),
                                    attrs='blue highlight')
            print(title)

    @staticmethod
    def on_frida_message(message, data):
        if 'payload' in message:
            parts = message['payload'].split(':::')
            try:
                id = int(parts[0])
            except:
                id = -1

            if id < 0:
                log(message)
                return

            if id == 0:
                cli.context_manager.set_base(int(parts[1], 16))
                if cli.context_manager.apply_arch(parts[2]) is not None:
                    log('target arch: %s' % Color.colorify(parts[2], 'green bold'))
                cli.context_manager.apply_pointer_size(int(parts[3]))
                log('pointer size: %s' % Color.colorify(parts[3], 'green bold'))
                log('target base at %s' % Color.colorify('0x%x' % cli.context_manager.get_base(), 'red highlight'))
            elif id == 1:
                log('attached to %s' % Color.colorify(parts[1], 'red highlight'))
            elif id == 2:
                cli.context_manager.set_context(int(parts[1]), json.loads(parts[2]))
                name = cli.context_manager.get_target_offsets()[int(parts[1])]
                if name is not '':
                    cli.context_title('%s - 0x%x' % (name, cli.context_manager.get_context_offset()))
                else:
                    cli.context_title('0x%x' % (cli.context_manager.get_context_offset()))
                cli.context_manager.print_context()
                dis = DisAssembler(cli)
                dis.__disasm_result__(dis.__disasm__(
                    [parts[4].encode('ascii', 'ignore'),
                     int(cli.context_manager.get_context()['pc']['value'], 16) - 32]))
                Backtrace(cli).__backtrace_result__(json.loads(parts[3]))
        else:
            log(message)

    @staticmethod
    def on_frida_script_destroyed():
        cli.frida_script = None

    @staticmethod
    def on_device_detached():
        log('device detached!')
        cli.frida_script = None


if __name__ == '__main__':
    global cli
    cli = FridaCli()
    cli.start()
