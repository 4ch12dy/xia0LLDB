# MIT License
# 
# Copyright (c) 2017 Derek Selander

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import lldb
import os
import shlex
import optparse

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
    'command script add -f xbt.handle_command xbt -h "Resymbolicate stripped ObjC backtrace"')
    print('"xbt" command installed --> just run xbt')

def handle_command(debugger, command, exe_ctx, result, internal_dict):
    '''
    Symbolicate backtrace. Will symbolicate a stripped backtrace
    from an executable if the backtrace is using Objective-C 
    code. Currently doesn't work on aarch64 stripped executables
    but works great on x64 :]
    '''
    command_args = shlex.split(command, posix=False)


    target = exe_ctx.target
    thread = exe_ctx.thread
    if thread is None:
        result.SetError('LLDB must be paused to execute this command')
        return

    frameString = xia0_StackTraceFrame(target,thread)
    result.AppendMessage(frameString)


def xia0_StackTraceFrame(target, thread):
  frame_string = ''
  idx = 0
  for f in thread.frames:
      function = f.GetFunction()
      load_addr = f.addr.GetLoadAddress(target)
      if not function:
          file_addr = f.addr.GetFileAddress()
          start_addr = f.GetSymbol().GetStartAddress().GetFileAddress()
          symbol_offset = file_addr - start_addr
          frame_string += '  frame #{num}: [file:{f_addr} mem:{m_addr}] {mod}`{symbol} + {offset} \n'.format(num=idx, f_addr=attrStr(str(hex(file_addr)), 'cyan'), m_addr=attrStr(hex(load_addr),'grey'),mod=attrStr(str(f.addr.module.file.basename), 'yellow'), symbol=f.addr.symbol.name, offset=symbol_offset)
     
      else:
          frame_string += '  frame #{num}: {addr} {mod}`{func} at {file} {args} \n'.format(
              num=idx, addr=hex(load_addr), mod=attrStr(str(f.addr.module.file.basename), 'yellow'),
              func='%s [inlined]' % function if f.IsInlined() else function,
              file=f.addr.symbol.name,
              args=get_args_as_string(f, showFuncName=False) if not f.IsInlined() else '()')
      idx = idx + 1
  return frame_string

def attrStr(msg, color='black'):      
    clr = {
    'cyan' : '\033[36m',
    'grey' : '\033[2m',
    'blink' : '\033[5m',
    'redd' : '\033[41m',
    'greend' : '\033[42m',
    'yellowd' : '\033[43m',
    'pinkd' : '\033[45m',
    'cyand' : '\033[46m',
    'greyd' : '\033[100m',
    'blued' : '\033[44m',
    'whiteb' : '\033[7m',
    'pink' : '\033[95m',
    'blue' : '\033[94m',
    'green' : '\033[92m',
    'yellow' : '\x1b\x5b33m',
    'red' : '\033[91m',
    'bold' : '\033[1m',
    'underline' : '\033[4m'
    }[color]
    return clr + msg + ('\x1b\x5b39m' if clr == 'yellow' else '\033[0m')

