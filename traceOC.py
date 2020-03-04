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

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
    'command script add -f traceOC.handle_command traceOC -h "trace ObjectC function call"')
    # print('========')
    # print('[traceOC]: trace ObjectC function call')
    # print('\ttraceOC ')
    # print('\tmore usage, try "traceOC -h"')
                    
def handle_command(debugger, command, exe_ctx, result, internal_dict):
    command_args = shlex.split(command, posix=False)
    parser = generate_option_parser()
    try:
        (_, _) = parser.parse_args(command_args)
    except:
        result.SetError(parser.usage)
        return
        
    _ = exe_ctx.target
    _ = exe_ctx.thread
    
    # ret = traceOC(debugger)
    result.AppendMessage("traceOC command is still developing. please wait...\n")
    
    return

def generate_option_parser():
    usage = "traceOC"
    parser = optparse.OptionParser(usage=usage, prog="lookup")

    parser.add_option("-a", "--address",
                    action="store_true",
                    default=None,
                    dest='patchAddress',
                    help="kill anti-debug in lldb")
                        
    return parser
