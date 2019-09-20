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

'''

specail thanks to xia0z & Proteas

'''

import lldb
import commands
import shlex
import optparse
import re
from xia0 import *

def __lldb_init_module (debugger, dict):
    debugger.HandleCommand('command script add -f xbr.xbr xbr -h "set breakpoint on ObjC Method"')
    print('========')
    print('[xbr]: set breakpoint on OC function even striped')
    print('\txbr "-[UIView initWithFrame:]" or "className" for all the class metholds')
    print('\tmore usage, try "xbr -h"')

def create_command_arguments(command):
    return shlex.split(command)
    
def is_command_valid(args):
    if len(args) == 0:
        return False

    arg = args[0]
    if len(arg) == 0:
        return False

    ret = re.match('^[+-]\[.+ .+\]$', arg) # TODO: more strict
    if not ret:
        return False

    return True

def is_br_all_cmd(args):
    if len(args) == 0:
        return False

    arg = args[0]
    if len(arg) == 0:
        return False

    ret = re.match('^[a-zA-z]*$', arg)

    if not ret:
        return False
    return True

def is_just_address_cmd(args):
    if len(args) == 0:
        return False

    arg = args[0]
    if len(arg) == 0:
        return False

    ret = re.match('^0x[0-9a-fA-F]+$', arg)

    if not ret:
        return False
    return True

def get_class_name(arg):
    match = re.search('(?<=\[)[^\[].*[^ ](?= +)', arg) # TODO: more strict
    if match:
        return match.group(0)
    else:
        return None

def get_method_name(arg):
    match = re.search('(?<= )[^ ].*[^\]](?=\]+)', arg) # TODO: more strict
    if match:
        return match.group(0)
    else:
        return None

def is_class_method(arg):
    if len(arg) == 0:
        return False

    if arg[0] == '+':
        return True
    else:
        return False
    
def get_selected_frame():
    debugger = lldb.debugger
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    thread = process.GetSelectedThread()
    frame = thread.GetSelectedFrame()

    return frame

def get_class_method_address(class_name, method_name):
    frame = get_selected_frame();
    class_addr = frame.EvaluateExpression("(Class)object_getClass((Class)NSClassFromString(@\"%s\"))" % class_name).GetValueAsUnsigned()
    if class_addr == 0:
        return 0

    sel_addr = frame.EvaluateExpression("(SEL)NSSelectorFromString(@\"%s\")" % method_name).GetValueAsUnsigned()
    has_method = frame.EvaluateExpression("(BOOL)class_respondsToSelector(%d, %d)" % (class_addr, sel_addr)).GetValueAsUnsigned()
    if not has_method:
        return 0

    method_addr = frame.EvaluateExpression('(void *)class_getMethodImplementation(%d, %d)' % (class_addr, sel_addr))

    return method_addr.GetValueAsUnsigned()

def get_instance_method_address(class_name, method_name):
    frame = get_selected_frame();
    class_addr = frame.EvaluateExpression("(Class)NSClassFromString(@\"%s\")" % class_name).GetValueAsUnsigned()
    print 'classAddr:%x' % class_addr
    if class_addr == 0:
        return 0

    sel_addr = frame.EvaluateExpression("(SEL)NSSelectorFromString(@\"%s\")" % method_name).GetValueAsUnsigned()
    print 'selAddr:%x' % sel_addr
    has_method = frame.EvaluateExpression("(BOOL)class_respondsToSelector(%d, %d)" % (class_addr, sel_addr)).GetValueAsUnsigned()
    if not has_method:
        return 0

    method_addr = frame.EvaluateExpression('(void *)class_getMethodImplementation(%d, %d)' % (class_addr, sel_addr))
    
    return method_addr.GetValueAsUnsigned()

def exeScript(debugger,command_script):
    res = lldb.SBCommandReturnObject()
    interpreter = debugger.GetCommandInterpreter()
    interpreter.HandleCommand('exp -lobjc -O -- ' + command_script, res)

    if not res.HasResult():
        # something error
        return res.GetError()
            
    response = res.GetOutput()
    return response

def getAllMethodAddressOfClass(debugger, classname):

    command_script = 'const char* className = "' + classname + '";' 

    command_script += r'''
    //NSMutableArray *mAddrArr = [NSMutableArray array];
    NSMutableString* retStr = [NSMutableString string];

    unsigned int m_size = 0;
    Class cls = objc_getClass(className);
    struct objc_method ** metholds = (struct objc_method **)class_copyMethodList(cls, &m_size);
    

    for (int j = 0; j < m_size; j++) {
        struct objc_method * meth = metholds[j];
        id implementation = (id)method_getImplementation(meth);
        NSString* m_name = NSStringFromSelector((SEL)method_getName(meth));
        
        //[mAddrArr addObject:(id)[@((uintptr_t)implementation) stringValue]];
        [retStr appendString:(id)[@((uintptr_t)implementation) stringValue]];
        [retStr appendString:@"-"];
    }

    unsigned int cm_size = 0;
    struct objc_method **classMethods = (struct objc_method **)class_copyMethodList((Class)objc_getMetaClass((const char *)class_getName(cls)), &cm_size);
    for (int k = 0; k < cm_size; k++) {
        struct objc_method * meth = classMethods[k];
        id implementation = (id)method_getImplementation(meth);
        NSString* cm_name = NSStringFromSelector((SEL)method_getName(meth));
        //[mAddrArr addObject:(id)[@((uintptr_t)implementation) stringValue]];
        [retStr appendString:(id)[@((uintptr_t)implementation) stringValue]];
        [retStr appendString:@"-"];
    }
    retStr
    '''
    retStr = exeScript(debugger, command_script)
    return retStr

def getProcessModuleSlide(debugger, modulePath):
    command_script = r'''
    uint32_t count = (uint32_t)_dyld_image_count();
    NSMutableString* retStr = [NSMutableString string];
    uint32_t idx = 0;
    NSString* image_name = @"";
    const char *path = (char *)[[[NSBundle mainBundle] executablePath] UTF8String];
    '''
   
    if modulePath:
        command_script += 'NSString* modulePath = @"{}"\n'.format(modulePath)
    else:
        command_script += 'NSString* modulePath = [[NSString alloc] initWithUTF8String:path];'

    command_script += r'''
    NSString* imagePath = modulePath;
    for(uint32_t i = 0; i < count; i++){
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
    return slide

def xbr(debugger, command, result, dict):
    args = create_command_arguments(command)

    command_args = shlex.split(command, posix=False)
    parser = generate_option_parser()
    try:
        (options, args) = parser.parse_args(command_args)
    except:
        result.SetError(parser.usage)
        return

    # check is options?
    if options.address:
        targetAddr = options.address

        if targetAddr.startswith("0x"):
            targetAddr_int = int(targetAddr, 16)
        else:
            targetAddr_int = int(targetAddr, 10)
          
        print("[*] breakpoint at address:{}".format(ILOG(hex(targetAddr_int))))
        lldb.debugger.HandleCommand ('breakpoint set --address %d' % targetAddr_int)
        return

    # check is arg is address ? mean auto add slide
    if is_just_address_cmd(args):

        if options.modulePath:
            modulePath = options.modulePath
            print("[*] you specail the module:" + ILOG(modulePath))
        else:
            print("[*] you not specail the module, default is main module")
            modulePath = None

        targetAddr = args[0]

        if targetAddr.startswith("0x"):
            targetAddr_int = int(targetAddr, 16)
        else:
            targetAddr_int = int(targetAddr, 10)
        
        moduleSlide = getProcessModuleSlide(debugger, modulePath)
        moduleSlide = int(moduleSlide, 10)
        brAddr = moduleSlide + targetAddr_int

        print("[*] ida's address:{} main module slide:{} target breakpoint address:{}".format(ILOG(hex(targetAddr_int)), ILOG(hex(moduleSlide)), ILOG(hex(brAddr))))
        
        lldb.debugger.HandleCommand ('breakpoint set --address %d' % brAddr)
        return

    # check is breakpoint at all methods address(IMP) for given classname
    if is_br_all_cmd(args):
        classname = args[0]
        ret = getAllMethodAddressOfClass(debugger, classname)

        addrArr = ret.split('-')[:-1]

        for addr in addrArr:
            address = int(addr)
            if address:
                lldb.debugger.HandleCommand ('breakpoint set --address %x' % address)
        
        result.AppendMessage("Set %ld breakpoints of %s" % (len(addrArr),classname))
        return
    


    if not is_command_valid(args):
        print 'please specify the param, for example: "-[UIView initWithFrame:]"'
        return

    arg = args[0]
    class_name = get_class_name(arg)
    method_name = get_method_name(arg)
#    xlog = 'className:'+ str(class_name) + '\tmethodName:' + str(method_name)
    print class_name, method_name
    address = 0
    if is_class_method(arg):
        address = get_class_method_address(class_name, method_name)
    else:
        address = get_instance_method_address(class_name, method_name)

    print 'methodAddr:%x' % address
    if address:
        lldb.debugger.HandleCommand ('breakpoint set --address %x' % address)
    else:
        print "fail, please check the arguments"

def generate_option_parser():
    usage = "usage: xbr [options] args"
    parser = optparse.OptionParser(usage=usage, prog="lookup")

    parser.add_option("-a", "--address",
                        action="store",
                        default=None,
                        dest="address",
                        help="set a breakpoint at absolute address")

    parser.add_option("-m", "--modulePath",
                action="store",
                default=None,
                dest="modulePath",
                help="set a breakpoint at address auto add given module")

    return parser
