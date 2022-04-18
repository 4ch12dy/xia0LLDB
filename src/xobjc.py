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
    debugger.HandleCommand('command script add -f xobjc.xprotocol xprotocol -h "print protocol info"')


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

def objc_parse_typesign(sign_str):
    sign_str = ''.join([i for i in sign_str if not i.isdigit()])
    chunks = []

    simpleTypeEncodeing = {"c": "char", "i": "int", "s": "short", "l": "long", "q": "longlong",
                           "C": "unsigned char", "I": "unsigned int", "S": "unsigned short", "L": "unsiged long",
                           "Q": "unsigned long long", "f": "float", "d": "double", "B": "bool",
                           "v": "void", "*": "char*", "#": "class", ":": "selector", "?": "unknown"}

    i = 0
    pointerCount = 0
    pointerStart = False

    while i < len(sign_str):

        stuff = ""

        t = sign_str[i]

        if t in simpleTypeEncodeing.keys():
            stuff = simpleTypeEncodeing[t]

            if pointerStart:
                stuff = stuff + pointerCount * "*"
                pointerStart = False
            chunks.append(stuff)

            i = i + 1
            continue

        elif t == "@":
            stuff = "id"
            if i + 1 == len(sign_str):
                if pointerStart:
                    stuff = stuff + pointerCount * "*"
                    pointerStart = False
                chunks.append(stuff)
                i = i + 1
                continue

            if sign_str[i + 1] == "\"":

                j = i + 2
                while sign_str[j] != "\"":
                    j = j+1

                stuff = sign_str[i+2:j]
                i = j
            elif sign_str[i + 1] == "?":
                stuff = "block"
                i = i + 1
            if pointerStart:
                stuff = stuff + pointerCount * "*"
                pointerStart = False
            chunks.append(stuff)
            i = i + 1
            continue

        elif t == "^":
            pointerCount = pointerCount + 1
            pointerStart = True

            i = i + 1
            continue

        elif t == "{":
            if i+1 == len(sign_str):
                if pointerStart:
                    stuff = stuff + pointerCount * "*"
                    pointerStart = False
                chunks.append(stuff)
                i = i+1
                continue

            j = i+1
            while sign_str[j] != "=":
                j = j+1
            stuff = sign_str[i+1:j]

            k = j
            openCount = 1

            while k+1 < len(sign_str) and openCount:

                if sign_str[k] == "{":
                    openCount = openCount+1

                if sign_str[k] == "}":
                    openCount = openCount-1
                k = k + 1

            i = k

            if pointerStart:
                stuff = stuff + pointerCount * "*"
                pointerStart = False
            chunks.append(stuff)
            i = i + 1
            continue
        else:
            return []

        i = i + 1
    return chunks


def objc_obj_name(debugger, obj_addr):
    command_script = '@import Foundation;NSObject* obj = (NSObject*)' + obj_addr + ';' 
    command_script += r'''    
    Class clz = [obj class];
    const char * clz_name = (const char *)class_getName(clz);
    NSString* clzName = [NSString stringWithUTF8String:clz_name];
    clzName
    '''
    retStr = utils.exe_script(debugger, command_script)

    return str(retStr.strip())

def objc_dump_ivars(debugger, obj_addr):
    command_script = '@import Foundation;NSObject* obj = (NSObject*)' + obj_addr + ';' 
    command_script += r'''
    NSMutableString* retStr = [NSMutableString string];

    typedef struct objc_ivar *Ivar;

    Class clz = [obj class];
    unsigned int count = 0;
    Ivar *vars = (Ivar *)class_copyIvarList(clz, &count);

    for (int i=0; i<count; i++) {
        Ivar var = vars[i];
        long offset = (long)ivar_getOffset(var);
        NSString* varName = [NSString stringWithUTF8String:(const char *)ivar_getName(var)];
        NSString* varTypeStr = [NSString stringWithUTF8String:(const char *)ivar_getTypeEncoding(var)];

        //NSString* dumpStr = [NSString stringWithFormat:@"-> %@ %@; // %p -> %p", ParseTypeString(varTypeStr)[0], varName, varAddr, *varAddr];
        void** varAddr = (void**)((unsigned char *)(__bridge void *)obj + offset);
        
        [retStr appendString:varName];
        [retStr appendString:@","];
        [retStr appendString:varTypeStr];
        [retStr appendString:@","];
        [retStr appendString:(id)[@((long)varAddr) stringValue]];
        [retStr appendString:@"||"];
    }
    retStr
    '''
    retStr = utils.exe_script(debugger, command_script)
    arr = retStr.strip().split("||")

    retArr = []

    for item in arr:
        if len(item) <= 0:
            continue
        info = item.split(",")

        if len(info) != 3:
            continue
            
        retArr.append([info[0], info[1], hex(utils.convertToInt(info[2])) ])

    return retArr

def objc_dump_methods(debugger, classname):
    command_script = '@import Foundation;char* classname = (char*)\"' + classname + '\";' 
    command_script += r'''
    NSMutableString* retStr = [NSMutableString string];

    typedef struct objc_method *Method;
   
    unsigned int m_size = 0;
    Class cls = objc_getClass(classname);
    struct objc_method ** metholds = (struct objc_method **)class_copyMethodList(cls, &m_size);
    
    for (int j = 0; j < m_size; j++) {
        struct objc_method * meth = metholds[j];
        id implementation = (id)method_getImplementation(meth);
        NSString* m_name = NSStringFromSelector((SEL)method_getName(meth));
        

        char buffer[100];
        buffer[0] = '\0';
        method_getReturnType (meth, buffer, sizeof(buffer));

        NSString* retTypeStr =[NSString stringWithUTF8String:buffer];


        //[mAddrArr addObject:(id)[@((uintptr_t)implementation) stringValue]];
        NSNumber* implementationNum =  [NSNumber numberWithUnsignedLongLong:(uintptr_t)implementation];
        [retStr appendString:@"-"];
        [retStr appendString:@","];
        [retStr appendString:m_name];
        [retStr appendString:@","];
        [retStr appendString:(id)[implementationNum stringValue]];
        [retStr appendString:@","];
        [retStr appendString:retTypeStr];
        [retStr appendString:@","];

        unsigned int argumentCount = (unsigned int)method_getNumberOfArguments (meth);
        for (int i = 2; i < argumentCount; i++) {
            method_getArgumentType (meth, i, buffer, sizeof(buffer));
            NSString* argTypeStr =[NSString stringWithUTF8String:buffer];
            [retStr appendString:argTypeStr];
            [retStr appendString:@","];
        }
        [retStr appendString:@"||"];
    }

    unsigned int cm_size = 0;
    struct objc_method **classMethods = (struct objc_method **)class_copyMethodList((Class)objc_getMetaClass((const char *)class_getName(cls)), &cm_size);
    for (int k = 0; k < cm_size; k++) {
        struct objc_method * meth = classMethods[k];
        id implementation = (id)method_getImplementation(meth);
        NSString* cm_name = NSStringFromSelector((SEL)method_getName(meth));

        char buffer[100];
        buffer[0] = '\0';
        method_getReturnType (meth, buffer, sizeof(buffer));

        NSString* retTypeStr =[NSString stringWithUTF8String:buffer];


        //[mAddrArr addObject:(id)[@((uintptr_t)implementation) stringValue]];
        NSNumber* implementationNum =  [NSNumber numberWithUnsignedLongLong:(uintptr_t)implementation];
        [retStr appendString:@"+"];
        [retStr appendString:@","];
        [retStr appendString:cm_name];
        [retStr appendString:@","];
        [retStr appendString:(id)[implementationNum stringValue]];
        [retStr appendString:@","];
        [retStr appendString:retTypeStr];
        [retStr appendString:@","];
        unsigned int argumentCount = (unsigned int)method_getNumberOfArguments (meth);
        for (int i = 2; i < argumentCount; i++) {
            method_getArgumentType (meth, i, buffer, sizeof(buffer));
            NSString* argTypeStr =[NSString stringWithUTF8String:buffer];
            [retStr appendString:argTypeStr];
            [retStr appendString:@","];
        }
        [retStr appendString:@"||"];
    }

    retStr
    '''
    retStr = utils.exe_script(debugger, command_script)
    
    arr = retStr.strip().split("||")
    retArr = []

    for item in arr:
        if len(item) <= 0:
            continue

        methodInfo = item.split(",")


        methodArr = []
        for val in methodInfo:
            if len(val) <= 0:
                continue
            methodArr.append(val)
            
        retArr.append(methodArr)

    return retArr


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

    obj = args[0]

    clz = objc_obj_name(debugger, obj)
    ret = objc_dump_ivars(debugger, obj)
   
    utils.ILOG("Dump ivars for {}({})".format(obj, clz))


    for item in ret:

        typeStr = item[1]
        typeStrList = objc_parse_typesign(item[1])
        if typeStrList and len(typeStrList) > 0:
            typeStr = typeStrList[0]

        line = "\t{} {}; // {}".format(typeStr, item[0], item[2])

        print(line)

    # result.AppendMessage("command is still developing. please wait...\n")
    #result.AppendMessage(ret)
                        
    return parser


methodArgIdx = 0
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

    def is_address(args):
        if len(args) == 0:
            return False

        arg = args[0]
        if len(arg) == 0:
            return False

        ret = re.match('^0x[0-9a-fA-F]+$', arg)

        if not ret:
            return False
        return True

    clz = args[0]
    obj = clz
    if is_address(args):
        clz = objc_obj_name(debugger, args[0])

    ret = objc_dump_methods(debugger, clz)

    
    utils.ILOG("Dump methods for {}({})".format(obj, clz))
    # print(ret)

    for method in ret:
        if len(method) < 4:
            utils.ELOG("Error method!")
            break

        addr = hex(utils.convertToInt(method[2])) 


        retType = method[3]
        retTypeList = objc_parse_typesign(method[3])

        if retTypeList and len(retTypeList) > 0:
            retType = retTypeList[0]

        selname = method[1]
        argCount = len(method) - 4

        if argCount > 0:
            global methodArgIdx

            arr = method[4:]
            methodArgIdx = 0
            def handler(reobj):
                global methodArgIdx
                r = reobj.group(0)

                argType = arr[methodArgIdx]
                argTypeList = objc_parse_typesign(argType)

                if argTypeList and len(argTypeList) > 0:
                    argType = argTypeList[0]

                        
                r = r +"(" + argType + ")" + "a" + str(methodArgIdx) + " "
                methodArgIdx = methodArgIdx + 1
                return r

            selname = re.sub(":", handler ,selname, flags=0)

        line = "\t{} ({}){};// {}".format(method[0], retType, selname, addr)

        print(line)

        
    # result.AppendMessage("command is still developing. please wait...\n")
                        
    return parser



def objc_dump_protocol(debugger, protocol_name):
    command_script = '@import Foundation;const char * name = (const char *)\"' + protocol_name + '\";' 
    command_script += r'''
    NSMutableString* retStr = [NSMutableString string];
    
    struct objc_method_description {
        SEL _Nullable name;               /**< The name of the method */
        char * _Nullable types;           /**< The types of the method arguments */
    };
    unsigned int protocolCount;
    Protocol * * __protocols = (Protocol **)objc_copyProtocolList (&protocolCount);

    for (int i = 0; i < protocolCount; i++) {
        const char *protocolName = (const char * )protocol_getName (__protocols[i]);
        
        
        if (strcmp(name, protocolName) == 0) {
            unsigned int adopteeCount;
            Protocol ** adoptees = (Protocol **)protocol_copyProtocolList (__protocols[i], &adopteeCount);
            free (adoptees);

            struct objc_method_description *methods;
            unsigned int count;
            unsigned int requiredCount = 0;
            unsigned int optionalCount = 0;

            methods = (struct objc_method_description *)protocol_copyMethodDescriptionList (__protocols[i], YES, YES, &count);
            for (int i = 0; i < count; i++) {
                [retStr appendString:@"-"];
                [retStr appendString:@","];
                [retStr appendString:NSStringFromSelector(methods[i].name)];
                [retStr appendString:@","];
                [retStr appendString:[NSString stringWithUTF8String:methods[i].types]];
                [retStr appendString:@"||"];
            }
            requiredCount += count;
            free (methods);
            
            
            
            methods = (struct objc_method_description *)protocol_copyMethodDescriptionList (__protocols[i], YES, NO, &count);
            for (int i = 0; i < count; i++) {
                [retStr appendString:@"+"];
                [retStr appendString:@","];
                [retStr appendString:NSStringFromSelector(methods[i].name)];
                [retStr appendString:@","];
                [retStr appendString:[NSString stringWithUTF8String:methods[i].types]];
                [retStr appendString:@"||"];
            }
            requiredCount += count;
            free (methods);

            methods = (struct objc_method_description *)protocol_copyMethodDescriptionList (__protocols[i], NO, YES, &count);
            for (int i = 0; i < count; i++) {
                [retStr appendString:@"-"];
                [retStr appendString:@","];
                [retStr appendString:NSStringFromSelector(methods[i].name)];
                [retStr appendString:@","];
                [retStr appendString:[NSString stringWithUTF8String:methods[i].types]];
                [retStr appendString:@"||"];
            }
            optionalCount += count;
            free (methods);
            
            
            methods = (struct objc_method_description *)protocol_copyMethodDescriptionList (__protocols[i], NO, NO, &count);
            for (int i = 0; i < count; i++) {
                [retStr appendString:@"+"];
                [retStr appendString:@","];
                [retStr appendString:NSStringFromSelector(methods[i].name)];
                [retStr appendString:@","];
                [retStr appendString:[NSString stringWithUTF8String:methods[i].types]];
                [retStr appendString:@"||"];
            }
            optionalCount += count;
            free (methods);

            break;
        }
    }

    free (__protocols);

    retStr
    '''
    retStr = utils.exe_script(debugger, command_script)

    arr = retStr.strip().split("||")
    retArr = []

    for item in arr:
        if len(item) <= 0:
            continue

        
        protocolInfo = item.split(",")

        if len(protocolInfo) != 3:
            utils.ELOG("Error for protocolInfo")
            break
        
        retArr.append([protocolInfo[0], protocolInfo[1], protocolInfo[2]])

    return retArr


protocolArgIdx = 0
def xprotocol(debugger, command, exe_ctx, result, internal_dict):

    def generate_option_parser():
        usage = "usage: xprotocol"
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

    protocol_name = args[0]
    utils.ILOG("Dump protocol for {}".format(protocol_name))
    ret = objc_dump_protocol(debugger, protocol_name)

    for protocol in ret:

        typeArr = objc_parse_typesign(protocol[2])
        retType = typeArr[0]

        selname = protocol[1]
        argCount = len(typeArr) - 1

        if argCount > 0:
            global protocolArgIdx

            protocolArgIdx = 3
            def handler(reobj):
                global protocolArgIdx
                r = reobj.group(0)

                argType = typeArr[protocolArgIdx]
                        
                r = r +"(" + argType + ")" + "a" + str(protocolArgIdx) + " "
                protocolArgIdx = protocolArgIdx + 1
                return r

            selname = re.sub(":", handler ,selname, flags=0)

        line = "\t{} ({}){};".format(protocol[0], retType, selname)

        print(line)

    # result.AppendMessage("command is still developing. please wait...\n")

                        
    return parser