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
import colorme
import utils

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
    'command script add -f choose.handle_command choose -h "cycript choose on lldb"')
    # print('========')
    # print('[choose]: cycript choose on lldb')
    # print('\tchoose "className"')
    # print('\tmore usage, try "choose -h"')
            
def handle_command(debugger, command, exe_ctx, result, internal_dict):
    command_args = shlex.split(command, posix=False)
    parser = generate_option_parser()
    try:
        (_, args) = parser.parse_args(command_args)
    except:
        result.SetError(parser.usage)
        return
        
    _ = exe_ctx.target
    _ = exe_ctx.thread
    
    if not args:
        ret = "[usage] choose className"
    else:
        ret = choose(debugger, str(args[0]))
        
    result.AppendMessage(str(ret))
    
    return 

def choose(debugger, classname):
    command_script = '@import Foundation;NSString * className = @"' + classname + '";' 
    command_script += r'''
    
    // define
    #define KERN_SUCCESS 0
    
    // typedef
    typedef unsigned long       uintptr_t;

    
    #define MALLOC_PTR_IN_USE_RANGE_TYPE    1
    typedef int kern_return_t;
    typedef unsigned int mach_port_t;
    typedef mach_port_t     task_t;
    
    typedef uintptr_t       vm_offset_t;
    typedef vm_offset_t         vm_address_t;
    typedef uintptr_t       vm_size_t;
    typedef struct {
        vm_address_t    address;
        vm_size_t       size;
    } vm_range_t;
    
    typedef kern_return_t (*memory_reader_t)(task_t task, vm_address_t remote_address, vm_size_t size, void **local_memory);
    typedef void (*vm_range_recorder_t)(task_t task, void *baton, unsigned type, vm_range_t *range, unsigned size);
    typedef struct malloc_introspection_t {
        kern_return_t (*enumerator)(task_t task, void *, unsigned type_mask, vm_address_t zone_address, memory_reader_t reader, vm_range_recorder_t recorder); /* enumerates all the malloc pointers in use */
    } malloc_introspection_t;
    
    typedef struct _malloc_zone_t {
        void  *reserved1; 
        void  *reserved2; 
        size_t  (*size)(struct _malloc_zone_t *zone, const void *ptr); 
        void  *(*malloc)(struct _malloc_zone_t *zone, size_t size);
        void  *(*calloc)(struct _malloc_zone_t *zone, size_t num_items, size_t size); 
        void  *(*valloc)(struct _malloc_zone_t *zone, size_t size); 
        void  (*free)(struct _malloc_zone_t *zone, void *ptr);
        void  *(*realloc)(struct _malloc_zone_t *zone, void *ptr, size_t size);
        void  (*destroy)(struct _malloc_zone_t *zone); 
        const char  *zone_name;
        unsigned  (*batch_malloc)(struct _malloc_zone_t *zone, size_t size, void **results, unsigned num_requested); 
        void  (*batch_free)(struct _malloc_zone_t *zone, void **to_be_freed, unsigned num_to_be_freed); 
        struct malloc_introspection_t *introspect;
        unsigned  version;
        void *(*memalign)(struct _malloc_zone_t *zone, size_t alignment, size_t size);
        void (*free_definite_size)(struct _malloc_zone_t *zone, void *ptr, size_t size);
        size_t  (*pressure_relief)(struct _malloc_zone_t *zone, size_t goal);
    } malloc_zone_t;
    

    struct XZChoice {
        NSMutableArray * query_; // std::set<Class> query_;
        NSMutableArray * result_; // std::set<id> result_;
    };

    struct XZObjectStruct {
        Class isa_;
    };
    
    // function memory_reader_t
    
    memory_reader_t task_peek = [](task_t task, vm_address_t remote_address, vm_size_t size, void **local_memory) -> kern_return_t {
        *local_memory = (void*) remote_address;
        return KERN_SUCCESS;
    };
    
    // function copy_class_list: get the class list
    typedef Class * (*copy_class_list_t)(size_t &size);
    copy_class_list_t copy_class_list = [](size_t &size) -> Class *{
        size = (size_t)objc_getClassList(NULL, 0);
        Class * data = (Class *)(malloc(sizeof(Class) * size));
        for (;;) {
            size_t writ = (size_t)objc_getClassList(data, (int)size);
            if (writ <= size) {
                size = writ;
                return data;
            }
            
            Class * copy = (Class *)(realloc(data, sizeof(Class) * writ));
            if (copy == NULL) {
                free(data);
                return NULL;
            }
            data = copy;
            size = writ;
        }
    }
    // function void choose_(task_t task, void *baton, unsigned type, vm_range_t *ranges, unsigned count)
    typedef void (*choose__t)(task_t task, void *baton, unsigned type, vm_range_t *ranges, unsigned count);
    choose__t choose_ = [](task_t task, void *baton, unsigned type, vm_range_t *ranges, unsigned count) -> void {
        XZChoice * choiz = (struct XZChoice *)(baton);
        for (unsigned i = 0; i < count; ++i) {
            vm_range_t &range = ranges[i];
            void * data = (void *)(range.address);
            size_t size = range.size;
            if (size < sizeof(XZObjectStruct))
                continue;
            
            uintptr_t * pointers = (uintptr_t *)(data);
    #ifdef __arm64__
            void * isa = (void *)(pointers[0] & 0x1fffffff8);
    #else
            struct objc_class * isa = (struct objc_class *)(pointers[0]);
    #endif
            //uint64_t p = (uint64_t)isa;
            //[choiz->result_ addObject:[@(p) stringValue]];

            size_t needed;
            for(unsigned i=0; i < [choiz->query_ count]; i++){
                void * result = (void *)[choiz->query_ objectAtIndex:i];
                uint64_t result_intv = (uint64_t)result;
                uint64_t isa_intv = (uint64_t)isa;
                uint64_t data_intv = (uint64_t)data;
                
                if(result_intv == isa_intv){
                    /*
                    NSMutableString* tmpStr = [NSMutableString string];
                    [tmpStr appendString:@"isa:"];
                    [tmpStr appendString:[@(isa_intv) stringValue]];
                    [tmpStr appendString:@"query:"];
                    [tmpStr appendString:[@(result_intv) stringValue]];
                    [tmpStr appendString:@"object:"];
                    [tmpStr appendString:[@(data_intv) stringValue]];
                    [choiz->result_ addObject:tmpStr];
                    continue;
                    */
                    
                    size_t boundary = 496;
                    
                    #ifdef __LP64__
                            boundary *= 2;
                    #endif
                    
                    needed = (size_t)class_getInstanceSize((Class)result));
                    if ((needed <= boundary && (needed + 15) / 16 * 16 != size) || (needed > boundary && (needed + 511) / 512 * 512 != size)){
                        continue;
                    }
                    [choiz->result_ addObject:(id)data];
                }
            }
        }
    }
    
    XZChoice choice;
    choice.query_ = (NSMutableArray*)[NSMutableArray array];
    choice.result_ = (NSMutableArray*)[NSMutableArray array];
    
    Class _class = NSClassFromString(className);
    size_t number;
    Class * classes = copy_class_list(number);
    
    for (size_t i = 0; i != number; ++i) {
        for (Class current = classes[i]; current != Nil; current = (Class)class_getSuperclass(current)) {
            if (current == _class) {
                [choice.query_ addObject:classes[i]];
                break;
            }
        }
    }
    free(classes);
    
    vm_address_t *zones = 0;
    unsigned int num_zones = 0;
    task_t task = 0;
    kern_return_t err = (kern_return_t)malloc_get_all_zones (task, task_peek, &zones, &num_zones);
    
    for (unsigned i = 0; i != num_zones; ++i) {
        const malloc_zone_t * zone = (const malloc_zone_t *)(zones[i]);
        if (zone == NULL || zone->introspect == NULL)
            continue;
        zone->introspect->enumerator((task_t)mach_task_self(), &choice, MALLOC_PTR_IN_USE_RANGE_TYPE, zones[i], task_peek, choose_);
    }

    NSArray* choosed = choice.result_;
    NSMutableString* retStr = [NSMutableString string];
    unsigned choosedSize = [choosed count];
    if(choosedSize == 0){

        [retStr appendString:@"Not found any object of class: "];
        [retStr appendString:className];

    }else{
        uint64_t objAdrr = (uint64_t)choosed;
        [retStr appendString:@"====>xia0LLDB NSArray Address: "];
        [retStr appendString:[@(objAdrr) stringValue]];
        [retStr appendString:@"\tsize: "];
        [retStr appendString:[@(choosedSize) stringValue]];
        [retStr appendString:@"\n"];
        [retStr appendString:@"|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | \n"];
        [retStr appendString:@"V  V  V  V  V  V  V  V  V  V  V  V  V  V  V  V  V  V  V  V \n"];

        for (unsigned i = 0; i != [choosed count]; ++i) {

            if([(NSObject*)([choosed objectAtIndex:i]) isKindOfClass:[NSString class]]){
                [retStr appendString: @"Now not support print the NSString, You can po it by yourself like below:"];
                [retStr appendString:@"\n1. p/x "];
                [retStr appendString:[@(objAdrr) stringValue]];
                [retStr appendString:@"\n2. po (NSArray*)above_hex_address_vaule : print the NSArray contain NSString"];
                [retStr appendString:@"\n3. po [(NSArray*)above_hex_address_vaule objectAtIndex:0] : print first NSString"];
                break;
            
            }else{

                uint64_t objAdrr = (uint64_t)[choosed objectAtIndex:i];
                [retStr appendString:@"======>xia0LLDB Object Address: "];
                [retStr appendString:[@(objAdrr) stringValue]];
                [retStr appendString:@"\n"];
                [retStr appendString:[(NSObject*)([choosed objectAtIndex:i]) description]];
            }
            
            [retStr appendString:@"\n"];
        }

    }

    retStr
    '''
    retStr = utils.exe_script(debugger, command_script)
    return colorme.attr_str(utils.hex_int_in_str(retStr), 'green')
    
def generate_option_parser():
    usage = "usage: choose className"
    parser = optparse.OptionParser(usage=usage, prog="lookup")

    parser.add_option("-c", "--childClass",
                    action="store_true",
                    default=None,
                    dest='print childClass',
                    help="print childClass")
                        
    return parser
