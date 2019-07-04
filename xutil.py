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


BLOCK_JSON_FILE = None

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
    'command script add -f xutil.handle_command xutil -h "xia0 tool"')
    print('"xutil" command installed -> xutil')
                    
def handle_command(debugger, command, exe_ctx, result, internal_dict):
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
        setBreakpointAtMainImage(debugger, str(options.address))
        return

    if options.ivars:
        ret = printIvarsOfObject(debugger, str(options.ivars))
        result.AppendMessage(str(ret))
        return

    if options.module:
        ret = mload(debugger, str(options.module))
        result.AppendMessage(str(ret))
        return
    
    result.AppendMessage(str('nothing.'))
    return 


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

def setBreakpointAtMainImage(debugger, address):
#    imageName = 'QQ'
#    command_script = r''' NSString * name = @"''' + imageName + '";'
    
    command_script = r'''
    uint32_t count = (uint32_t)_dyld_image_count();
    NSMutableString* retStr = [NSMutableString string];
    int idx = 0;
    NSString* image_name = @"";
    const char *path = (char *)[[[NSBundle mainBundle] executablePath] UTF8String];
    NSString* imagePath = [[NSString alloc] initWithUTF8String:path];
    
    for(int i = 0; i < count; i++){
        const char* imageName = (const char*)_dyld_get_image_name(i);
        NSString* imageNameStr = [[NSString alloc] initWithUTF8String:imageName];
        if([imageNameStr isEqualToString:imagePath]){
            idx = i;
            image_name = imageNameStr;
            break;
        }
    }
    uintptr_t slide =  (uintptr_t)_dyld_get_image_vmaddr_slide(idx);
    NSString *slideStr = [@(slide) stringValue];
    [retStr appendString:image_name];
    [retStr appendString:@"#"];
    [retStr appendString:slideStr];

    slideStr
    '''
    slide = exeScript(debugger, command_script)
    debugger.HandleCommand('br set -a "%s+%s"' % (slide, str(address)))

def printIvarsOfObject(debugger, address):
    command_script = 'id xobject = (id)' + address + ';' 
    command_script += r'''
    NSMutableString* retStr = [NSMutableString string];
    const char* name;
    unsigned int count;
    struct objc_property **properties = (struct objc_property**)class_copyPropertyList((Class)object_getClass(xobject), &count);
    for(int i=0;i<count;i++){
        [retStr appendString:@"one"];
        name = (const char*)property_getName(properties[i]);
    }
    // retStr = [(NSObject*)xobject performSelector:(SEL)NSSelectorFromString(@"_ivarDescription")];
    //retStr = objc_msgsend(xobject, (SEL)NSSelectorFromString(@"_ivarDescription"));
    name
    '''
    retStr = exeScript(debugger, command_script)
    return retStr

def mload(debugger, modulePath):
    command_script = 'const char* module = "' + modulePath + '";' 
    command_script += r'''
    void *handle = (void *)dlopen(module, 2); 
    id retVal = handle ? @"Success" : @"fail"; 
    retVal
    '''
    retStr = exeScript(debugger, command_script)
    return retStr

def showAllUserDefaults(debugger):
    command_script = r'''
    NSArray *keys = [[[NSUserDefaults standardUserDefaults] dictionaryRepresentation] allKeys];
    NSArray *values = [[[NSUserDefaults standardUserDefaults] dictionaryRepresentation] allValues];
    NSMutableString* retStr = [NSMutableString string];
    
    for(int i = 0; i < 1; i++){
       [retStr appendString:keys[i]];
       [retStr appendString:@"------->"];
       [retStr appendString:values[i]];
       [retStr appendString:@"\n"];
    }
    retStr
    '''
    return exeScript(debugger, command_script)
    

def exeScript(debugger,command_script):
    res = lldb.SBCommandReturnObject()
    interpreter = debugger.GetCommandInterpreter()
    interpreter.HandleCommand('exp -lobjc -O -- ' + command_script, res)

    if not res.HasResult():
        # something error
        return res.GetError()
            
    response = res.GetOutput()
    return response

def generateOptions():
    expr_options = lldb.SBExpressionOptions()
    expr_options.SetUnwindOnError(True)
    expr_options.SetLanguage (lldb.eLanguageTypeObjC_plus_plus)
    expr_options.SetCoerceResultToId(False)
    return expr_options

def generate_option_parser():
    usage = "usage: sbt -f block-json-file-path"
    parser = optparse.OptionParser(usage=usage, prog="lookup")

    parser.add_option("-a", "--address",
                        action="store",
                        default=None,
                        dest="address",
                        help="break at address")

    parser.add_option("-m", "--module",
                    action="store",
                    default=None,
                    dest="module",
                    help="special the block json file")

    parser.add_option("-i", "--ivars",
                    action="store",
                    default=None,
                    dest="ivars",
                    help="po address object ivars")

    return parser
