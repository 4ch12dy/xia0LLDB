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
    if options.classname:
        ret = choose(debugger, str(options.classname))
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
    
def choose(debugger, classname):
    command_script = 'NSString * className = @"' + classname + '";' 
    command_script += r'''
    
    // define
    #define KERN_SUCCESS 0
    
    // typedef
    typedef unsigned long		uintptr_t;

    
    #define MALLOC_PTR_IN_USE_RANGE_TYPE	1
    typedef int kern_return_t;
    typedef unsigned int mach_port_t;
    typedef mach_port_t		task_t;
    
    typedef uintptr_t		vm_offset_t;
    typedef vm_offset_t     	vm_address_t;
    typedef uintptr_t		vm_size_t;
    typedef struct {
        vm_address_t	address;
        vm_size_t		size;
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
            struct objc_class * isa = (struct objc_class *)(pointers[0] & 0x1fffffff8);
    #else
            struct objc_class * isa = (struct objc_class *)(pointers[0]);
    #endif
            //uint64_t p = (uint64_t)isa;
            //[choiz->result_ addObject:[@(p) stringValue]];

            size_t needed;
            for(int i=0; i < [choiz->query_ count]; i++){
                struct objc_class * result = (struct objc_class *)[choiz->query_ objectAtIndex:i];
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
                    if (!(needed <= boundary && (needed + 15) / 16 * 16 != size) || (needed > boundary && (needed + 511) / 512 * 512 != size)){
                        [choiz->result_ addObject:(id)data];
                    }
                }
            }
        }
    }
    
    
    XZChoice choice;
    choice.query_ = [NSMutableArray array];
    choice.result_ = [NSMutableArray array];
    
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
    
    choice.result_
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
                        
    parser.add_option("-c", "--choose",
                        action="store",
                        default=None,
                        dest="classname",
                        help="get OC object from class name")

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
