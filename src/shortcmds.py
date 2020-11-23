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
    debugger.HandleCommand('command script add -f shortcmds.croc croc -h "croc: go to can run oc env point"')
    debugger.HandleCommand('command script add -f shortcmds.log_malloc_stack log_malloc_stack -h "open to log malloc stack info"')
    debugger.HandleCommand('command script add -f shortcmds.heap heap -h "import lldb.macosx.heap script"')
    debugger.HandleCommand('command script add -f shortcmds.pblock pblock -h "print objc block"')
    debugger.HandleCommand('command script add -f shortcmds.mem_dump mem_dump -h "[mem_dump outFile addr size]:dump process memory to file"')
    debugger.HandleCommand('command script add -f shortcmds.mr mr -h "[mr addr count]: dump mem of bytes"')
    debugger.HandleCommand('command script add -f shortcmds.save_image save_image -h "[save_image UIImageObj]: save image to file"')



def croc(debugger, command, exe_ctx, result, internal_dict):
    command_args = shlex.split(command, posix=False)

    _ = exe_ctx.target
    _ = exe_ctx.thread
    
    utils.ILOG("going to env that can run oc script")
    utils.exe_cmd(debugger, "b CFBundleGetMainBundle")
    utils.exe_cmd(debugger, "c")
    utils.exe_cmd(debugger, "br del -f")
    utils.SLOG("now you can exe oc")
    # result.AppendMessage(str('usage: croc [-m moduleName, -a address, -u UserDefaults]'))
    return

def log_malloc_stack(debugger, command, exe_ctx, result, internal_dict):
    command_args = shlex.split(command, posix=False)

    _ = exe_ctx.target
    _ = exe_ctx.thread
    
    utils.exe_cmd(debugger, "po turn_on_stack_logging(1)")

    # result.AppendMessage(str('usage: croc [-m moduleName, -a address, -u UserDefaults]'))
    return

    
def heap(debugger, command, exe_ctx, result, internal_dict):
    command_args = shlex.split(command, posix=False)

    _ = exe_ctx.target
    _ = exe_ctx.thread
    
    utils.exe_cmd(debugger, "command script import lldb.macosx.heap")

    # result.AppendMessage(str('usage: croc [-m moduleName, -a address, -u UserDefaults]'))
    return


# memory read --binary --outfile /Users/xia0/byte/workrecord/shape/data.bin --count 0x0000cc80 0x138b80

def mem_dump(debugger, command, exe_ctx, result, internal_dict):
    command_args = shlex.split(command, posix=False)

    _ = exe_ctx.target
    _ = exe_ctx.thread

    if len(command_args) != 3:
        utils.ELOG("[usage] mem_dump outFile addr size")
        return

    outfile = command_args[0]
    start_addr = utils.convertToInt(command_args[1])
    size = eval(command_args[2])

    if not start_addr:
        utils.ELOG("params format error")
        return

    utils.ILOG("default address will plus main image slide")
    slide = utils.get_image_slide(debugger, 0)
    start_addr = start_addr + slide

    cmd = "memory read --binary --outfile {} --count {} {}".format(outfile, size, start_addr)
    utils.ILOG("mem dump:{}".format(cmd))
    ret = utils.exe_cmd(debugger, cmd)

    result.AppendMessage(str(ret))
    return

def mr(debugger, command, exe_ctx, result, internal_dict):
    command_args = shlex.split(command, posix=False)

    _ = exe_ctx.target
    _ = exe_ctx.thread

    if len(command_args) != 2:
        utils.ELOG("[usage] mr addr count")
        return

    start_addr = utils.convertToInt(command_args[0])
    size = eval(command_args[1])
    
    if not start_addr:
        utils.ELOG("params format error")
        return

    # utils.ILOG("default address will plus main image slide")
    # slide = utils.get_image_slide(debugger, 0)
    # start_addr = start_addr + slide

    cmd = "memory read  {} --count {}".format(start_addr, size)
    utils.ILOG("mem read:{}".format(cmd))
    ret = utils.exe_cmd(debugger, cmd)

    result.AppendMessage(str(ret))
    return

def save_image(debugger, command, exe_ctx, result, internal_dict):
    command_args = shlex.split(command, posix=False)

    _ = exe_ctx.target
    _ = exe_ctx.thread

    if len(command_args) < 1 :
        utils.ELOG("[usage] save_image UIImageObj")
        return

    image_obj_addr = command_args[0]
    script = '@import Foundation;'
    script += "UIImage* image = (UIImage*){}".format(image_obj_addr)
    script += '''
    NSString* ret = @"DONE";
    if (image != nil){
        NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,
                                                            NSUserDomainMask, YES);
        NSString *documentsDirectory = [paths objectAtIndex:0];
        NSString* path = [documentsDirectory stringByAppendingPathComponent:
                        @"xia0.gif" ];
        NSData* data = UIImagePNGRepresentation(image);
        [data writeToFile:path atomically:YES];
    }

    ret
    '''
    ret = utils.exe_script(debugger, script)

    result.AppendMessage(str(ret))
    return


def pblock(debugger, command, exe_ctx, result, internal_dict):
    command_args = shlex.split(command, posix=False)

    _ = exe_ctx.target
    _ = exe_ctx.thread

    block_addr_raw = command_args[0]
    block_addr = utils.convertToInt(block_addr_raw)
    if block_addr:
        utils.ILOG("block addr:{}".format(hex(block_addr)))
    else:
        utils.ELOG("block addr format err:{}".format(block_addr_raw))
        return
        

    header = '''
    enum {
        BLOCK_HAS_COPY_DISPOSE =  (1 << 25),
        BLOCK_HAS_CTOR =          (1 << 26), // helpers have C++ code
        BLOCK_IS_GLOBAL =         (1 << 28),
        BLOCK_HAS_STRET =         (1 << 29), // IFF BLOCK_HAS_SIGNATURE
        BLOCK_HAS_SIGNATURE =     (1 << 30),
    };

    struct Block_literal_1 {
        void *isa; // initialized to &_NSConcreteStackBlock or &_NSConcreteGlobalBlock
        int flags;
        int reserved;
        void (*invoke)(void *, ...);
        struct Block_descriptor_1 {
            unsigned long int reserved; // NULL
            unsigned long int size;         // sizeof(struct Block_literal_1)
            // optional helper functions
            void (*copy_helper)(void *dst, void *src);     // IFF (1<<25)
            void (*dispose_helper)(void *src);             // IFF (1<<25)
            // required ABI.2010.3.16
            const char *signature;                         // IFF (1<<30)
        } *descriptor;
        // imported variables
    };
    '''

    code = header
    code += 'struct Block_literal_1 real = *((struct Block_literal_1 *)(void*){});'.format(block_addr)
    code += '''
    NSString* ret = @"";
    NSMutableDictionary *dict = [NSMutableDictionary dictionary];
    [dict setObject:[NSNumber numberWithLong:(long)real.invoke] forKey:@"invoke"];

#if 0
    if (real.flags & BLOCK_HAS_SIGNATURE) {
        char *signature;
        if (real.flags & BLOCK_HAS_COPY_DISPOSE) {
            signature = (char *)(real.descriptor)->signature;
        } else {
            signature = (char *)(real.descriptor)->copy_helper;
        }
        
        NSMethodSignature *sig = [NSMethodSignature signatureWithObjCTypes:signature];
        NSMutableArray *types = [NSMutableArray array];
        
        [types addObject:[NSString stringWithUTF8String:(char *)[sig methodReturnType]]];
        
        for (NSUInteger i = 0; i < sig.numberOfArguments; i++) {
            char *type = (char *)[sig getArgumentTypeAtIndex:i];
            [types addObject:[NSString stringWithUTF8String:type]];
        }
        
        [dict setObject:types forKey:@"signature"];
    }
    
    NSMutableArray* sigArr = dict[@"signature"];
    
    if(!sigArr){
        ret = [NSString stringWithFormat:@"Imp: 0x%lx", [dict[@"invoke"] longValue]];
    }else{
        NSMutableString* sig = [NSMutableString stringWithFormat:@"%@ ^(", decode(sigArr[0])];
        for (int i = 2; i < sigArr.count; i++) {
            if(i == sigArr.count - 1){
                [sig appendFormat:@"%@", decode(sigArr[i])];
            }else{
                [sig appendFormat:@"%@ ,", decode(sigArr[i])];
            }
        }
        [sig appendString:@");"];
        ret = [NSString stringWithFormat:@"Imp: 0x%lx    Signature: %s", [dict[@"invoke"] longValue], [sig UTF8String]];
    }
    ret
#else
    dict
#endif
    '''
    ret = utils.exe_script(debugger, code)

    print(ret)

