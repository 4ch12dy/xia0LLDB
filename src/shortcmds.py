#! /usr/bin/env python3

 #  ______ ______ ______ ______ ______ ______ ______ ______ ______ ______ ______ ______ ______ ______ ______ ______ ______ 
 # |______|______|______|______|______|______|______|______|______|______|______|______|______|______|______|______|______| 
 #        _        ___  _      _      _____  ____   
 #       (_)      / _ \| |    | |    |  __ \|  _ \  
 #  __  ___  __ _| | | | |    | |    | |  | | |_) | 
 #  \ \/ / |/ _` | | | | |    | |    | |  | |  _ <  
 #   >  <| | (_| | |_| | |____| |____| |__| | |_) | 
 #  /_/\_\_|\__,_|\___/|______|______|_____/|____/                                                                                                                   
 #  ______ ______ ______ ______ ______ ______ ______ ______ ______ ______ ______ ______ ______ ______ ______ ______ ______ 
 # |______|______|______|______|______|______|______|______|______|______|______|______|______|______|______|______|______|

import lldb
import os
import shlex
import optparse
import json
import re
import utils


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f shortcmds.croc croc -h "croc: go to can run oc env point"')
    debugger.HandleCommand('command script add -f shortcmds.log_malloc_stack log_malloc_stack -h "open to log malloc stack info"')
    debugger.HandleCommand('command script add -f shortcmds.impt_heap impt_heap -h "import lldb.macosx.heap script"')
                    
def croc(debugger, command, exe_ctx, result, internal_dict):
    command_args = shlex.split(command, posix=False)

    _ = exe_ctx.target
    _ = exe_ctx.thread
    
    utils.ILOG("going to env that can run oc script")
    utils.exe_cmd(debugger, "b CFBundleGetMainBundle")
    utils.exe_cmd(debugger, "c")
    utils.exe_cmd(debugger, "br del -f")
    utils.SLOG("now you can exe oc")
    # result.AppendMessage(str('usage: croc [-m moduleName, -a address, -u UserDefaults]'))
    return

def log_malloc_stack(debugger, command, exe_ctx, result, internal_dict):
    command_args = shlex.split(command, posix=False)

    _ = exe_ctx.target
    _ = exe_ctx.thread
    
    utils.exe_cmd(debugger, "po turn_on_stack_logging(1)")

    # result.AppendMessage(str('usage: croc [-m moduleName, -a address, -u UserDefaults]'))
    return

    
def impt_heap(debugger, command, exe_ctx, result, internal_dict):
    command_args = shlex.split(command, posix=False)

    _ = exe_ctx.target
    _ = exe_ctx.thread
    
    utils.exe_cmd(debugger, "command script import lldb.macosx.heap")

    # result.AppendMessage(str('usage: croc [-m moduleName, -a address, -u UserDefaults]'))
    return