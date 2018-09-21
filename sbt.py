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
    'command script add -f sbt.handle_command sbt -h "Resymbolicate stripped ObjC backtrace"')
    print('"sbt" command installed -> sbt')
    
def handle_command(debugger, command, exe_ctx, result, internal_dict):
    '''
    Symbolicate backtrace. Will symbolicate a stripped backtrace
    from an executable if the backtrace is using Objective-C 
    code. Currently doesn't support block symbolicating :)
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


    frameString = SymbolishStackTraceFrame(debugger,target,thread)
    # return 2 screen
    result.AppendMessage(str(frameString))
    return 

def SymbolishStackTraceFrame(debugger,target, thread):
    frame_string = ''
    idx = 0

    for f in thread.frames:
        function = f.GetFunction()
        # mem address
        load_addr = f.addr.GetLoadAddress(target)

        if not function:
            # file address
            file_addr = f.addr.GetFileAddress()
            # offset
            start_addr = f.GetSymbol().GetStartAddress().GetFileAddress()
            symbol_offset = file_addr - start_addr
            # isMainModuleFromAddress? findname : symbol name
            if isMainModuleFromAddress(target,debugger,load_addr):
                if idx + 2 == len(thread.frames):
                     metholdName = 'main + ' + str(symbol_offset)
                else:
                    command_script = findSymbolFromAddressScript(load_addr)
                    response = exeScript(debugger,command_script)
                    metholdName = str(response).replace("\n","")
                frame_string += '  frame #{num}: [file:{f_addr} mem:{m_addr}] {mod}`{symbol}\n'.format(num=idx, f_addr=attrStr(str(hex(file_addr)), 'cyan'), m_addr=attrStr(hex(load_addr),'grey'),mod=attrStr(str(f.addr.module.file.basename), 'yellow'), symbol=attrStr(metholdName, 'green'))
            else:
                metholdName = f.addr.symbol.name
                frame_string += '  frame #{num}: [file:{f_addr} mem:{m_addr}] {mod}`{symbol} + {offset} \n'.format(num=idx, f_addr=attrStr(str(hex(file_addr)), 'cyan'), m_addr=attrStr(hex(load_addr),'grey'),mod=attrStr(str(f.addr.module.file.basename), 'yellow'), symbol=metholdName, offset=symbol_offset)
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

def isMainModuleFromAddress(target,debugger,address):
    #  get moduleName of address
    addr = target.ResolveLoadAddress(address)
    moduleName = addr.module.file.basename
    #  get executable path
    getExecutablePathScript = r''' 
    const char *path = (char *)[[[NSBundle mainBundle] executablePath] UTF8String];
    path
    '''
    # is in executable path?
    path = exeScript(debugger, getExecutablePathScript)

    if not moduleName or not str(path):
        return False

    if moduleName in str(path):
        return True
    else:
        return False

def exeScript(debugger,command_script):
    res = lldb.SBCommandReturnObject()
    interpreter = debugger.GetCommandInterpreter()
    interpreter.HandleCommand('exp -lobjc -O -- ' + command_script, res)

    if not res.HasResult():
        result.SetError('There\'s no result ' + res.GetError())
        return
    response = res.GetOutput()
    return response

def findSymbolFromAddressScript(frame_addr):

    command_script = 'uintptr_t frame_addr =' + str(frame_addr) + ';'

    command_script += r'''
    
    // NSMutableDictionary *retdict = [NSMutableDictionary dictionary];
    // NSMutableArray *retArr = [NSMutableArray array];

    unsigned int c_size = 0;
    const char *path = (char *)[[[NSBundle mainBundle] executablePath] UTF8String];
    const char **allClasses = (const char **)objc_copyClassNamesForImage(path, &c_size);
    
    NSString *c_size_str = [@(c_size) stringValue];

    uintptr_t tmpDis = 0;
    uintptr_t theDistance = 0xffffffffffffffff;
    NSString* theMethodName = nil;
    NSString* theClassName = nil;
    NSString* theMetholdType = nil;

    // go all class
    for (int i = 0; i < c_size; i++) {
        Class cls = objc_getClass(allClasses[i]);
        tmpDis = 0;

        // for methold of a class
        unsigned int m_size = 0;
        struct objc_method ** metholds = (struct objc_method **)class_copyMethodList(cls, &m_size);
        // NSMutableDictionary *tmpdict = [NSMutableDictionary dictionary];

        for (int j = 0; j < m_size; j++) {
            struct objc_method * meth = metholds[j];
            id implementation = (id)method_getImplementation(meth);
            NSString* m_name = NSStringFromSelector((SEL)method_getName(meth));
            // [tmpdict setObject:m_name forKey:(id)[@((uintptr_t)implementation) stringValue]];

            if(frame_addr <= (uintptr_t)implementation){
                if(((uintptr_t)implementation - frame_addr) <= theDistance){
                    theDistance = (uintptr_t)implementation - frame_addr;
                    theMethodName = m_name;
                    theClassName = (NSString*)NSStringFromClass(cls);
                    theMetholdType = @"-";
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
            // [tmpdict setObject:cm_name forKey:(id)[@((uintptr_t)implementation) stringValue]];

            if(frame_addr <= (uintptr_t)implementation){
                if(((uintptr_t)implementation - frame_addr) <= theDistance){
                    theDistance = (uintptr_t)implementation - frame_addr;
                    theMethodName = cm_name;
                    theClassName = (NSString*)NSStringFromClass(cls);
                    theMetholdType = @"+";
                }
            }
        }
        free(metholds);
        free(classMethods);
        // [retdict setObject:tmpdict forKey:(NSString*)NSStringFromClass(cls)];
    }
    free(allClasses);

    NSMutableString* retStr = [NSMutableString string];
    [retStr appendString:theMetholdType];
    [retStr appendString:@"["];
    [retStr appendString:theClassName];
    [retStr appendString:@" "];
    [retStr appendString:theMethodName];
    [retStr appendString:@"]"];
    [retStr appendString:@" + "];
    [retStr appendString:(id)[@((uintptr_t)theDistance) stringValue]];

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
