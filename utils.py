import re
import lldb
import os


def ILOG(log):
    print("[*] " + log)

def ELOG(log):
    print("[-] " + log)

def SLOG(log):
    print("[+] " + log)

def exe_cmd(debugger, command):
    res = lldb.SBCommandReturnObject()
    interpreter = debugger.GetCommandInterpreter()
    interpreter.HandleCommand(command, res)

    if not res.HasResult():
        # something error
        return res.GetError()
            
    response = res.GetOutput()
    return response

def get_app_path(debugger):
    ret = exe_cmd(debugger, "target list")
    pattern = '/.*\('
    match = re.search(pattern, ret)
    if match:
        found = match.group(0)
        found = found.split("(")[0]
        found = found.strip()
    else:
        ELOG("failed to auto get main module, use -m option")
        return

    mainImagePath = found
    SLOG("use \"target list\" to get main module:" + mainImagePath)
    return mainImagePath

def getAllImageOfApp(debugger, appDir):
    command_script = '@import Foundation;NSString* appDir = @"' + appDir + '";' 
    command_script += r'''
    NSMutableString* retStr = [NSMutableString string];
    
    uint32_t count = (uint32_t)_dyld_image_count();
    for(uint32_t i = 0; i < count; i++){
        char* curModuleName_cstr = (char*)_dyld_get_image_name(i);
        long slide = (long)_dyld_get_image_vmaddr_slide(i);
        uintptr_t baseAddr = (uintptr_t)_dyld_get_image_header(i);
        NSString* curModuleName = @(curModuleName_cstr);
        if([curModuleName containsString:appDir]) {
            [retStr appendString:(id)[@(i) stringValue]];
            [retStr appendString:@","];
            [retStr appendString:@(curModuleName_cstr)];
            [retStr appendString:@"#"];
        }
    }
    retStr
    '''
    ret = exeScript(debugger, command_script)
    return ret