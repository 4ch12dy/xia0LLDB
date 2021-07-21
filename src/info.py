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
    debugger.HandleCommand(
    'command script add -f info.handle_command info -h "[usage] info [-a,-m]"')
    # print('========')
    # print('[info]: get basic info of process/function/module/address/...')
    # print('\tinfo [-m moduleName, -a address, -f funtionName, -u UserDefaults]')
    # print('\tmore usage, try "info -h"')
                    
def handle_command(debugger, command, exe_ctx, result, internal_dict):
    command_args = shlex.split(command, posix=False)
    parser = generate_option_parser()
    try:
        (options, _) = parser.parse_args(command_args)
    except:
        result.SetError(parser.usage)
        return
        
    _ = exe_ctx.target
    _ = exe_ctx.thread
    
    if options.moduleName:
        ret = get_module_info_by_name(debugger, str(options.moduleName))
        result.AppendMessage(str(ret))
        return
        
    if options.address:
        ret = get_address_info_by_address(debugger, str(options.address))
        result.AppendMessage(str(ret))
        return

    if options.function:
        ret = get_func_info_by_name(debugger, str(options.function))
        result.AppendMessage(str(ret))
        return

    if options.UserDefaults:
        ret = get_userdefaults_info_by_key(debugger, str(options.UserDefaults))
        result.AppendMessage(str(ret))
        return
            
    result.AppendMessage(str('usage: info [-m moduleName, -a address, -u UserDefaults]'))
    return 

#   get module info by module name 
def get_module_info_by_name(debugger, moduleName):

    command_script = '@import Foundation;NSString* moduleName = @"' + moduleName + '";' 
    command_script += r'''
    NSMutableString* retStr = [NSMutableString string];
    
    uint32_t count = (uint32_t)_dyld_image_count();
    for(uint32_t i = 0; i < count; i++){
        char* curModuleName_cstr = (char*)_dyld_get_image_name(i);
        long slide = (long)_dyld_get_image_vmaddr_slide(i);
        uintptr_t baseAddr = (uintptr_t)_dyld_get_image_header(i);
        NSString* curModuleName = @(curModuleName_cstr);
        if([curModuleName containsString:moduleName]) {
            [retStr appendString:@"\n=======\nModule Path : "];
            [retStr appendString:@(curModuleName_cstr)];
            [retStr appendString:@"\nModule Silde: "];
            [retStr appendString:(id)[@(slide) stringValue]];
            [retStr appendString:@"\nModule base : "];
            [retStr appendString:(id)[@(baseAddr) stringValue]];
        }
    }
    retStr
    '''
    retStr = utils.exe_script(debugger, command_script)
    if "error" in retStr:
        utils.ELOG("something error in OC script # " + retStr.strip())
        utils.ILOG("so use command to get info")
        ret = utils.exe_cmd(debugger, "im li -o -f")
        pattern = ".*" + moduleName.replace("\"", "")
        match = re.search(pattern, ret) # TODO: more strict
        if match:
            found = match.group(0)
        else:
            utils.ELOG("not found image:"+moduleName)
            return

        return found

    return utils.hex_int_in_str(retStr)

#   get address info by address
def get_address_info_by_address(debugger, address):
    command_script = "@import Foundation;"
    command_script += 'void * targetAddr = (void*)' + address + ';' 
    command_script += r'''
    NSMutableString* retStr = [NSMutableString string];

    typedef struct dl_info {
        const char      *dli_fname;     /* Pathname of shared object */
        void            *dli_fbase;     /* Base address of shared object */
        const char      *dli_sname;     /* Name of nearest symbol */
        void            *dli_saddr;     /* Address of nearest symbol */
    } Dl_info;

    Dl_info dl_info;

    dladdr(targetAddr, &dl_info);

    char* module_path = (char*)dl_info.dli_fname;
    uintptr_t module_base = (uintptr_t)dl_info.dli_fbase;
    char* symbol_name = (char*)dl_info.dli_sname;
    if (!symbol_name) {
        symbol_name = "";
    }
    uintptr_t symbol_addr = (uintptr_t)dl_info.dli_saddr;


    [retStr appendString:@"Module  path: "];
    [retStr appendString:@(module_path)];
    [retStr appendString:@"\nModule  base: "];
    NSNumber* module_baseNum =  [NSNumber numberWithUnsignedLongLong:(unsigned long)module_base];
    [retStr appendString:(id)[module_baseNum stringValue]];

    long slide = 0;
    NSString* targetModulePath = @(module_path);
    uint32_t count = (uint32_t)_dyld_image_count();
    for(uint32_t i = 0; i < count; i++){
        char* curModuleName_cstr = (char*)_dyld_get_image_name(i);
        slide = (long)_dyld_get_image_vmaddr_slide(i);
        uintptr_t baseAddr = (uintptr_t)_dyld_get_image_header(i);
        NSString* curModuleName = @(curModuleName_cstr);
        if((BOOL)[curModuleName isEqualToString:targetModulePath]) {
            [retStr appendString:@"\nModule slide: "];
            NSNumber* slideNum =  [NSNumber numberWithInt:slide];
            [retStr appendString:(id)[slideNum stringValue]];
            break;
        }
    }

    [retStr appendString:@"\ntarget  addr: "];
    NSNumber* targetAddrNum =  [NSNumber numberWithUnsignedLongLong:(long)targetAddr];
    [retStr appendString:(id)[targetAddrNum stringValue]];

    uintptr_t target_file_addr = (uintptr_t)((uint64_t)targetAddr - slide);
    [retStr appendString:@"\nFile    addr: "];
    NSNumber* target_file_addrNum = [NSNumber numberWithUnsignedLongLong:target_file_addr];
    [retStr appendString:(id)[target_file_addrNum stringValue]];

    [retStr appendString:@"\nSymbol  name: "];
    [retStr appendString:@(symbol_name)];
    [retStr appendString:@"\nSymbol  addr: "];
    NSNumber* symbol_addrNum =  [NSNumber numberWithUnsignedLongLong:symbol_addr];
    [retStr appendString:(id)[symbol_addrNum stringValue]];

    retStr
    '''
    retStr = utils.exe_script(debugger, command_script)
    return utils.hex_int_in_str(retStr)

def get_func_info_by_name(debugger, funcName):
    command_script = 'const char * func_name = "' + funcName + '";'
    command_script += r'''
    NSMutableString* retStr = [NSMutableString string];

    #define RTLD_LAZY   0x1
    #define RTLD_NOW    0x2
    #define RTLD_LOCAL  0x4
    #define RTLD_GLOBAL 0x8

    typedef struct dl_info {
        const char      *dli_fname;     /* Pathname of shared object */
        void            *dli_fbase;     /* Base address of shared object */
        const char      *dli_sname;     /* Name of nearest symbol */
        void            *dli_saddr;     /* Address of nearest symbol */
    } Dl_info;

    Dl_info dl_info;

    void* handle = (void*)dlopen(0, RTLD_GLOBAL | RTLD_NOW);
    void* target_ptr = (void*)dlsym(handle, func_name);

    if(target_ptr){
        uintptr_t target_addr = (uintptr_t)target_ptr;
        
        dladdr(target_ptr, &dl_info);
        
        char* module_path = (char*)dl_info.dli_fname;
        uintptr_t module_base = (uintptr_t)dl_info.dli_fbase;
        char* symbol_name = (char*)dl_info.dli_sname;
        uintptr_t symbol_addr = (uintptr_t)dl_info.dli_saddr;
        

        [retStr appendString:@"Func   name: "];
        [retStr appendString:@((char*)func_name)];
        [retStr appendString:@"\nFunc   addr: "];
        [retStr appendString:(id)[@(target_addr) stringValue]];
        
        [retStr appendString:@"\nModule Path: "];
        [retStr appendString:@(module_path)];
        [retStr appendString:@"\nModule base: "];
        [retStr appendString:(id)[@(module_base) stringValue]];
        [retStr appendString:@"\nSymbol name: "];
        [retStr appendString:@(symbol_name)];
        [retStr appendString:@"\nSymbol addr: "];
        [retStr appendString:(id)[@(symbol_addr) stringValue]];
    
    }else{
        [retStr appendString:@"[-] dlsym not found symbol:"];
        [retStr appendString:@((char*)func_name)];
    }
    retStr
    '''
    retStr = utils.exe_script(debugger, command_script)
    return utils.hex_int_in_str(retStr)

    
def get_userdefaults_info_by_key(debugger, key):
    command_script = r'''
    NSArray *keys = [[[NSUserDefaults standardUserDefaults] dictionaryRepresentation] allKeys];
    NSArray *values = [[[NSUserDefaults standardUserDefaults] dictionaryRepresentation] allValues];
    
    
    NSMutableDictionary *retDic = [NSMutableDictionary dictionaryWithObjects:values forKeys:keys]

    retDic
    '''
    return utils.exe_script(debugger, command_script)

def generate_option_parser():
    usage = "usage: info info [-m moduleName, -a address, -f funtionName, -u UserDefaults]'"
    parser = optparse.OptionParser(usage=usage, prog="lookup")

    parser.add_option("-m", "--moduleName",
                        action="store",
                        default=None,
                        dest="moduleName",
                        help="get module info by name")
                        
    parser.add_option("-a", "--address",
                        action="store",
                        default=None,
                        dest="address",
                        help="get address info by address")

    parser.add_option("-f", "--function",
                    action="store",
                    default=None,
                    dest="function",
                    help="get function info by name")

    parser.add_option("-u", "--UserDefaults",
                    action="store_true",
                    default=None,
                    dest="UserDefaults",
                    help="show UserDefaults info")
       

    return parser
