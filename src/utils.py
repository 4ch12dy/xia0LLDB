#! /usr/bin/env python3

import re
import lldb
import os

def ILOG(log):
    print("[*] " + log)

def ELOG(log):
    print("[-] " + log)

def SLOG(log):
    print("[+] " + log)

def hex_int_in_str(needHexStr):

    def handler(reobj):
        intvalueStr = reobj.group(0)

        r = hex(int(intvalueStr))
        return r

    # pylint: disable=anomalous-backslash-in-string
    pattern = '(?<=\s)[0-9]{1,}(?=\s)'

    return re.sub(pattern, handler, needHexStr, flags = 0)

def convertToInt(hex_num_or_num):
    ret = None
    if re.match('^0x[0-9a-fA-F]+$', hex_num_or_num):
        ret = int(hex_num_or_num, 16)
    elif re.match('^[0-9]+$', hex_num_or_num):
        ret = int(hex_num_or_num, 10)
    else:
        ret = False

    return ret

def exe_script(debugger,command_script):
    res = lldb.SBCommandReturnObject()
    interpreter = debugger.GetCommandInterpreter()
    interpreter.HandleCommand('exp -lobjc -O -- ' + command_script, res)

    if not res.HasResult():
        # something error
        return res.GetError()

    response = res.GetOutput()
    return response


def exe_cmd(debugger, command):
    res = lldb.SBCommandReturnObject()
    interpreter = debugger.GetCommandInterpreter()
    interpreter.HandleCommand(command, res)

    if not res.HasResult():
        # something error
        return res.GetError()

    response = res.GetOutput()
    return response

def get_app_exe_path(debugger=lldb.debugger):
    ret = exe_cmd(debugger, "target list")

    # pylint: disable=anomalous-backslash-in-string
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

def get_main_image_path(debugger):
    command_script = '@import Foundation;' 
    command_script += r'''

    // const char *path = (char *)[[[NSBundle mainBundle] executablePath] UTF8String];
    id bundle = objc_msgSend((Class)objc_getClass("NSBundle"), @selector(mainBundle));
    id exePath = objc_msgSend((id)bundle, @selector(executablePath));
    const char *path  = (char *)objc_msgSend((id)exePath, @selector(UTF8String));
    
    path
    '''
    retStr = exe_script(debugger, command_script)
    
    return retStr.strip()[1:-1]

# slide = (long)_dyld_get_image_vmaddr_slide(i);

def get_image_slide(debugger, idx=0):
    command_script = '@import Foundation;' 

    command_script += "uint32_t i = {};".format(idx)
    command_script += r'''
    NSString* ret = @"wqkejkwqlej";
    long slide = (long)_dyld_get_image_vmaddr_slide(i);
    //ret = @(slide);
    
    slide
    '''
    retStr = exe_script(debugger, command_script)
    retStr = retStr.strip()

    return convertToInt(retStr)


def get_all_image_of_app(debugger=lldb.debugger, appDir=None):
    if not appDir:
        app_path = get_app_exe_path()
        if app_path.startswith("/private"):
            app_path = app_path[8:]
        appDir = os.path.dirname(app_path)
    ILOG("app dir:{}".format(appDir))
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
            NSNumber* iNum =  [NSNumber numberWithInt:i];
            [retStr appendString:(id)[iNum stringValue]];
            [retStr appendString:@","];
            [retStr appendString:@(curModuleName_cstr)];
            [retStr appendString:@"#"];
        }
    }
    retStr
    '''
    ret = exe_script(debugger, command_script)
    images = []
    try:
        image_arr = ret.strip().split("#")
        for image_str in image_arr:
            if image_str and image_str != "":
                image_idx = image_str.split(",")[0]
                image_name = image_str.split(",")[1]
                image_info = {}
                image_info["idx"] = image_idx
                image_info["name"] = image_name
                images.append(image_info)
    except Exception as e:
        ELOG("failed to get app images from:{}".format(ret))
    return images

def is_process_running():
    status = exe_cmd(lldb.debugger, "process status")
    if "running" in status:
        return True
    if "stopped" in status:
        return False

    return False