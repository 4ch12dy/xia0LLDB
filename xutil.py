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
import ds
import optparse
import json


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
    'command script add -f xutil.handle_command xutil -h "Resymbolicate stripped ObjC backtrace"')
    print('"xutil" command installed -> xutil')
    
def handle_command(debugger, command, exe_ctx, result, internal_dict):
    '''
    Symbolicate backtrace. Will symbolicate a stripped backtrace
    from an executable if the backtrace is using Objective-C 
    code. Currently doesn't work on aarch64 stripped executables
    but works great on x64 :]
    '''
    command_args = shlex.split(command, posix=False)
    parser = generate_option_parser()
    try:
        (options, args) = parser.parse_args(command_args)
    except:
        result.SetError(parser.usage)
        return

    target = exe_ctx.target
    thread = exe_ctx.thread

    if options.address:
        address = [int(options.address, 16)]
        firstFrameAddr = address[0]
    else:
        frameAddresses = [f.addr.GetLoadAddress(target) for f in thread.frames]
        firstFrameAddr = frameAddresses[0]

    # run xia0 script
    command_script = generateXia0zScript(firstFrameAddr)
    response = exeScript(debugger,command_script)

    # return 2 screen
    result.AppendMessage(response)
    return 

def exeScript(debugger,command_script):
    res = lldb.SBCommandReturnObject()
    interpreter = debugger.GetCommandInterpreter()
    interpreter.HandleCommand('exp -lobjc -O -- ' + command_script, res)

    if not res.HasResult():
        result.SetError('There\'s no result ' + res.GetError())
        return
    response = res.GetOutput()
    return response

def generateXia0zScript(frame_addr):

    command_script = 'uintptr_t frame_addr =' + str(frame_addr) + ';'

    command_script += r'''
    
    NSMutableDictionary *retdict = [NSMutableDictionary dictionary];
    NSMutableArray *retArr = [NSMutableArray array];

    unsigned int c_size = 0;
    const char *path = (char *)[[[NSBundle mainBundle] executablePath] UTF8String];
    const char **allClasses = (const char **)objc_copyClassNamesForImage(path, &c_size);
    
    NSString *c_size_str = [@(c_size) stringValue];

    uintptr_t tmpDis = 0;
    uintptr_t theDistance = 0xffffffffffffffff;
    NSString* theMethodName = nil;
    NSString* theClassName = nil;

    // go all class
    for (int i = 0; i < c_size; i++) {
        Class cls = objc_getClass(allClasses[i]);
        tmpDis = 0;

        // for methold of a class
        unsigned int m_size = 0;
        struct objc_method ** metholds = (struct objc_method **)class_copyMethodList(cls, &m_size);
        NSMutableDictionary *tmpdict = [NSMutableDictionary dictionary];

        for (int j = 0; j < m_size; j++) {
            struct objc_method * meth = metholds[j];
            id implementation = (id)method_getImplementation(meth);
            NSString* m_name = NSStringFromSelector((SEL)method_getName(meth));
            [tmpdict setObject:m_name forKey:(id)[@((uintptr_t)implementation) stringValue]];

            if(frame_addr <= (uintptr_t)implementation){
                if(((uintptr_t)implementation - frame_addr) <= theDistance){
                    theDistance = (uintptr_t)implementation - frame_addr;
                    theMethodName = m_name;
                    theClassName = (NSString*)NSStringFromClass(cls);
                }
            }
        }

        // for class methold of a class
        unsigned int cm_size = 0;
        struct objc_method **classMethods = (struct objc_method **)class_copyMethodList((Class)objc_getMetaClass((const char *)class_getName(cls)), &cm_size);
        for (int k = 0; k < cm_size; k++) {
            struct objc_method * meth = classMethods[k];
            id implementation = (id)method_getImplementation(meth);
            NSString* cm_name = NSStringFromSelector((SEL)method_getName(meth));
            [tmpdict setObject:cm_name forKey:(id)[@((uintptr_t)implementation) stringValue]];

            if(frame_addr <= (uintptr_t)implementation){
                if(((uintptr_t)implementation - frame_addr) <= theDistance){
                    theDistance = (uintptr_t)implementation - frame_addr;
                    theMethodName = cm_name;
                    theClassName = (NSString*)NSStringFromClass(cls);
                }
            }
        }
        free(metholds);
        free(classMethods);
        [retdict setObject:tmpdict forKey:(NSString*)NSStringFromClass(cls)];
    }
    free(allClasses);
    NSMutableString* retStr = [NSMutableString string];
    [retStr appendString:@"["];

    [retStr appendString:theClassName];
    [retStr appendString:@" "];
    [retStr appendString:theMethodName];
    [retStr appendString:@"]"];

    retStr
    '''
    return command_script

def generateOptions():
    expr_options = lldb.SBExpressionOptions()
    expr_options.SetUnwindOnError(True)
    expr_options.SetLanguage (lldb.eLanguageTypeObjC_plus_plus)
    expr_options.SetCoerceResultToId(False)
    return expr_options

def generate_option_parser():
    usage = "usage: %prog [options] path/to/item"
    parser = optparse.OptionParser(usage=usage, prog="lookup")

    parser.add_option("-a", "--address",
                      action="store",
                      default=None,
                      dest="address",
                      help="Only try to resymbolicate this address")

    
    return parser
