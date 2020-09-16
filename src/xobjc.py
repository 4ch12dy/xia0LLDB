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
    debugger.HandleCommand('command script add -f xobjc.ivars ivars -h "ivars made by xia0"')
    debugger.HandleCommand('command script add -f xobjc.methods methods -h "methods made by xia0"')
    debugger.HandleCommand('command script add -f xobjc.xivars xivars -h "ivars made by xia0 for macOS or ivars not work"')
    debugger.HandleCommand('command script add -f xobjc.xmethods xmethods -h "methods made by xia0 for macOS or methods not work"')


def ivars(debugger, command, exe_ctx, result, internal_dict):

    def generate_option_parser():
        usage = "usage: xmethods"
        parser = optparse.OptionParser(usage=usage, prog="lookup")

        parser.add_option("-n", "--name",
                            action="store",
                            default=None,
                            dest="name",
                            help="set the class name for methods")

        return parser

    command_args = shlex.split(command, posix=False)
    parser = generate_option_parser()
    try:
        (options, args) = parser.parse_args(command_args)
    except:
        result.SetError(parser.usage)
        return
        
    _ = exe_ctx.target
    _ = exe_ctx.thread

    if options.name:
        clzname = options.name
        clzname = re.search("^\"(.*)\"$", clzname).group(1)
        utils.ILOG("will get methods for class:\"{}\"".format(clzname))
        code = '''  
            Class clz =  objc_getClass(\"{}\");
            id ret = [clz _ivarDescription];

            ret
        '''.format(clzname)
        ret = utils.exe_script(debugger, code)
        
        result.AppendMessage(ret)
        return result
    
    clz = args[0]
    code = '''
        id ret = [{} _ivarDescription];
        ret
    '''.format(clz)
    ret = utils.exe_script(debugger, code)
    
    result.AppendMessage(ret)         
    return result

def methods(debugger, command, exe_ctx, result, internal_dict):
    def generate_option_parser():
        usage = "usage: xmethods"
        parser = optparse.OptionParser(usage=usage, prog="lookup")

        parser.add_option("-n", "--name",
                            action="store",
                            default=None,
                            dest="name",
                            help="set the class name for methods")

        return parser
    

    command_args = shlex.split(command, posix=False)
    parser = generate_option_parser()
    try:
        (options, args) = parser.parse_args(command_args)
    except:
        result.SetError(parser.usage)
        return
    
    _ = exe_ctx.target
    _ = exe_ctx.thread

    if options.name:
        clzname = options.name
        try:
            clzname = re.search("^\"(.*)\"$", clzname).group(1)
        except:
            utils.ELOG("input format error! need \"class name\"")
            return
        utils.ILOG("will get methods for class:\"{}\"".format(clzname))
        code = '''  
            Class clz =  objc_getClass(\"{}\");
            id ret = [clz _shortMethodDescription];

            ret
        '''.format(clzname)
        ret = utils.exe_script(debugger, code)
        
        result.AppendMessage(ret)
        return result
    
    clz = args[0]
    code = '''
        id ret = [{} _shortMethodDescription];
        ret
    '''.format(clz)
    ret = utils.exe_script(debugger, code)
    
    result.AppendMessage(ret)         
    return result
    
def xivars(debugger, command, exe_ctx, result, internal_dict):

    def generate_option_parser():
        usage = "usage: xivars"
        parser = optparse.OptionParser(usage=usage, prog="lookup")

        parser.add_option("-a", "--address",
                            action="store",
                            default=None,
                            dest="address",
                            help="set a breakpoint at absolute address")

        return parser

    command_args = shlex.split(command, posix=False)
    parser = generate_option_parser()
    try:
        (options, args) = parser.parse_args(command_args)
    except:
        result.SetError(parser.usage)
        return
        
    _ = exe_ctx.target
    _ = exe_ctx.thread

    result.AppendMessage("command is still developing. please wait...\n")
                        
    return parser

def xmethods(debugger, command, exe_ctx, result, internal_dict):
    def generate_option_parser():
        usage = "usage: xmethods"
        parser = optparse.OptionParser(usage=usage, prog="lookup")

        parser.add_option("-a", "--address",
                            action="store",
                            default=None,
                            dest="address",
                            help="set a breakpoint at absolute address")

        return parser
    

    command_args = shlex.split(command, posix=False)
    parser = generate_option_parser()
    try:
        (options, args) = parser.parse_args(command_args)
    except:
        result.SetError(parser.usage)
        return
    
    _ = exe_ctx.target
    _ = exe_ctx.thread

    result.AppendMessage("command is still developing. please wait...\n")
                        
    return parser