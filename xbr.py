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


def xbr(debugger, command, result, dict):
    args = create_command_arguments(command)

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
