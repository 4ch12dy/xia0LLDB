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
import colorme
import utils

BLOCK_JSON_FILE = None

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
    'command script add -f sbt.handle_command sbt -h "Resymbolicate stripped ObjC backtrace"')
    # print('========')
    # print('[sbt]: Resymbolicate stripped ObjC backtrace')
    # print('\txbr [-f BlockSymbolFile]')
    # print('\tmore usage, try "sbt -h"')

                    
def handle_command(debugger, command, exe_ctx, result, internal_dict):
    global BLOCK_JSON_FILE
    
    '''
    Symbolicate backtrace. Will symbolicate a stripped backtrace
    from an executable if the backtrace is using Objective-C 
    code. Currently doesn't support block symbolicating :)
    '''
    command_args = shlex.split(command, posix=False)
    parser = generate_option_parser()
    
    try:
        (options, _) = parser.parse_args(command_args)
    except:
        result.SetError(parser.usage)
        return

    if options.verbose:
        BLOCK_JSON_FILE = None

        
    result.AppendMessage('  ==========================================xia0LLDB===========================================')
    if options.file:
        BLOCK_JSON_FILE = str(options.file)
        result.AppendMessage('  BlockSymbolFile    {}'.format(colorme.attr_str(BLOCK_JSON_FILE, 'redd')))
    else:
        if BLOCK_JSON_FILE:
            result.AppendMessage('  BlockSymbolFile    {}'.format(colorme.attr_str(BLOCK_JSON_FILE, 'redd')))
            pass
        else:
            result.AppendMessage('  BlockSymbolFile    {}'.format(colorme.attr_str('Not Set The Block Symbol Json File, Try \'sbt -f\'', 'redd')))
            pass
    result.AppendMessage('  =============================================================================================')

    target = exe_ctx.target
    thread = exe_ctx.thread

    # if options.address:
    #     address = [int(options.address, 16)]
    #     firstFrameAddr = address[0]
    # else:
    #     frameAddresses = [f.addr.GetLoadAddress(target) for f in thread.frames]
    #     firstFrameAddr = frameAddresses[0]

    frameString = symbolish_stack_trace_frame(debugger,target,thread)
    # return 2 screen
    result.AppendMessage(str(frameString))
    return 


def symbolish_stack_trace_frame(debugger,target, thread):
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
            modulePath = str(f.addr.module.file)

            # is_main_module_from_address? findname : symbol name
            if is_main_module_from_address(target,debugger,load_addr):
                if idx + 2 == len(thread.frames):
                    metholdName = 'main + ' + str(symbol_offset)
                else:
                    command_script = find_symbol_from_address_script(load_addr, modulePath)
                    one = utils.exe_script(debugger,command_script)
                    # is set the block file path
                    if BLOCK_JSON_FILE and len(BLOCK_JSON_FILE) > 0:
                        two = find_block_symbol_from_adress(file_addr)
                        response = choose_best(one, two)
                    else:
                        response = one
                    response = check_if_analysis_error(response)
                    metholdName = str(response).replace("\n","")
                frame_string += '  frame #{num}: [file:{f_addr} mem:{m_addr}] {mod}`{symbol}\n'.format(num=idx, f_addr=colorme.attr_str(str(hex(file_addr)), 'cyan'), m_addr=colorme.attr_str(hex(load_addr),'grey'),mod=colorme.attr_str(str(f.addr.module.file.basename), 'yellow'), symbol=colorme.attr_str(metholdName, 'green'))
            else:
                metholdName = f.addr.symbol.name
                frame_string += '  frame #{num}: [file:{f_addr} mem:{m_addr}] {mod}`{symbol} + {offset} \n'.format(num=idx, f_addr=colorme.attr_str(str(hex(file_addr)), 'cyan'), m_addr=colorme.attr_str(hex(load_addr),'grey'),mod=colorme.attr_str(str(f.addr.module.file.basename), 'yellow'), symbol=metholdName, offset=symbol_offset)
        else:
            frame_string += '  frame #{num}: {addr} {mod}`{func} at {file}\n'.format(
                    num=idx, addr=hex(load_addr), mod=colorme.attr_str(str(f.addr.module.file.basename), 'yellow'),
                    func='%s [inlined]' % function if f.IsInlined() else function,
                    file=f.addr.symbol.name)
        
        idx = idx + 1
    return frame_string

def choose_best(scriptRet, jsonFileRet):
    one = scriptRet.replace(" ", "")
    two = jsonFileRet.replace(" ", "")

    try:
        # skip first methold type char "-/+" and turn distance to int
        oneDis = int(one[1:].split('+')[1], 10)
        twoDis = int(two[1:].split('+')[1], 10)

    except Exception:
        return '===[E]===:' + scriptRet

    if oneDis < twoDis:
        return scriptRet
    else:
        return jsonFileRet

    return jsonFileRet

def check_if_analysis_error(frameString):
    maxDis = 2500
    frameString_strip = frameString.replace(" ", "")
    try:
        # skip first methold type char "-/+" and turn distance to int
        dis = int(frameString_strip[1:].split('+')[1], 10)
    except Exception:
        return '===[E]===:' + frameString
    
    if 'cxx_destruct' in frameString:
        return "Maybe c function? Found [OC .cxx_destruct]  # Symbol:{}".format(frameString)
        
    if 'cxx_construct' in frameString:
        return "Maybe c function? Found [OC .cxx_construct] # Symbol:{}".format(frameString)
        
    if dis >= maxDis:
        return 'Maybe c function? Distance:{} >= {} # Symbol:{}'.format(dis, maxDis, frameString)
    else:
        return frameString
    
def find_block_symbol_from_adress(address):
    try:
        f = open(BLOCK_JSON_FILE, 'r')
        symbolJsonArr = json.loads(f.read())
        f.close()
    except Exception:
        return "ERROR in handle json file, check file path and content is correct:{}. + 0".format(BLOCK_JSON_FILE)

    if type(address) is int:
        pass
    else:
        address = int(address, 16)

    theDis = 0xffffffffffffffff
    theSymbol = ''
    for block in symbolJsonArr:
        blockAddr = int(block['address'], 16)
        # curDis = address - blockAddr
        if blockAddr <= address and (address - blockAddr) <= theDis:
            theDis = address - blockAddr
            theSymbol = block['name']
    
    result = theSymbol + ' + ' + str(theDis)
    return result

def is_main_module_from_address(target,debugger,address):
    #  get moduleName of address
    addr = target.ResolveLoadAddress(address)
    moduleName = addr.module.file.basename
    modulePath = str(addr.module.file)
    #  get executable path
    getExecutablePathScript = r''' 
    const char *path = (char *)[[[NSBundle mainBundle] executablePath] UTF8String];
    path
    '''
    # is in executable path?
    path = utils.exe_script(debugger, getExecutablePathScript)
    appDir = os.path.dirname(path.strip()[1:-1])


    if not moduleName or not str(path):
        return False

    if appDir in modulePath:
        return True

    else:
        return False

    if moduleName in str(path):
        return True
    else:
        return False

def find_symbol_from_address_script(frame_addr, module_path):
    command_script = 'uintptr_t frame_addr =' + str(frame_addr) + ';'
    command_script += 'const char *path =\"' + str(module_path) + '\";'
    command_script += r'''
    
    // NSMutableDictionary *retdict = [NSMutableDictionary dictionary];
    // NSMutableArray *retArr = [NSMutableArray array];

    unsigned int c_size = 0;
    //const char *path = (char *)[[[NSBundle mainBundle] executablePath] UTF8String];
    const char **allClasses = (const char **)objc_copyClassNamesForImage(path, &c_size);
    
    // NSString *c_size_str = [@(c_size) stringValue];

    uintptr_t tmpDis = 0;
    uintptr_t theDistance = 0xffffffffffffffff;
    uintptr_t theIMP = 0;
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

            if(frame_addr >= (uintptr_t)implementation){
                if((frame_addr - (uintptr_t)implementation) <= theDistance){
                    theDistance = frame_addr - (uintptr_t)implementation);
                    theIMP = (uintptr_t)implementation;
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

            if(frame_addr >= (uintptr_t)implementation){
                if((frame_addr - (uintptr_t)implementation) <= theDistance){
                    theDistance = frame_addr - (uintptr_t)implementation);
                    theIMP = (uintptr_t)implementation;
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
    // [retStr appendString:@" -> "];
    // [retStr appendString:(id)[@((uintptr_t)theIMP) stringValue]];
    [retStr appendString:@" + "];
    NSNumber* theDistanceNum =  [NSNumber numberWithInt:theDistance];
    [retStr appendString:(id)[theDistanceNum stringValue]];

    retStr
    '''
    return command_script

def generate_option_parser():
    usage = "usage: sbt -f block-json-file-path"
    parser = optparse.OptionParser(usage=usage, prog="lookup")

    # parser.add_option("-a", "--address",
    #                   action="store",
    #                   default=None,
    #                   dest="address",
    #                   help="Only try to resymbolicate this address")

    parser.add_option("-f", "--file",
                    action="store",
                    default=None,
                    dest="file",
                    help="special the block json file")

    parser.add_option("-r", "--reset",
                    action="store_true",
                    default=None,
                    dest='verbose',
                    help="reset block file to None")

    return parser
