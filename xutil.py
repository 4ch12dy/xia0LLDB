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
    'command script add -f xutil.handle_command xutil -h "[usage] xutil [options] args"')
    print('"xutil" installed -> xutil [-b addr, -s module, -l dylib]')
                    
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
    
#    if options.help:
#        result.AppendMessage("[usage] xutil [options] args")
#        return
    if not args:
        ret = "[usage] xutil test"
    elif str(args[0]) in "test":
        ret = hook(debugger)
        result.AppendMessage(str(ret))
        return

    if options.kAntiDebug:
        ret = killAntiDebug(debugger)
        result.AppendMessage(str('kill antiDebug:')+str(ret))
        # lldb.debugger.HandleCommand ('re write %lx 0' % (int(ret), ))
        return
    
    if options.mainModuleAddress:
        setBreakpointAtMainImage(debugger, str(options.mainModuleAddress))
        return
        
    if options.sildeModule:
        ret = getBaseAddressFromModule(debugger, options.sildeModule)
        result.AppendMessage(str(ret))
        return
        
    if options.loadModule:
        ret = mload(debugger, str(options.loadModule))
        result.AppendMessage(str(ret))
        return

    if options.testarg:
        ret = test(debugger, options.testarg)
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
    
    
def getBaseAddressFromModule(debugger, moduleName):
    command_script = 'NSString* moduleName = @"' + moduleName + '";' 
    command_script += r'''
    NSMutableString* retStr = [NSMutableString string];
    
    uint32_t count = (uint32_t)_dyld_image_count();
    for(uint32_t i = 0; i < count; i++){
        char* curModuleName_cstr = (char*)_dyld_get_image_name(i);
        long slide = (long)_dyld_get_image_vmaddr_slide(i);
        NSString* curModuleName = @(curModuleName_cstr);
        if([curModuleName containsString:moduleName]) {
            char hex[20];
            sprintf(hex, "%p", slide);
            [retStr appendString:@"Module:"];
            [retStr appendString:@(curModuleName_cstr)];
            [retStr appendString:@"\nSilde:"];
            [retStr appendString:@(hex)];
        }
    }
    retStr
    '''
    retStr = exeScript(debugger, command_script)
    return retStr

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

def test(debugger, testarg):
    command_script = 'void * targetAddr = (void*)' + testarg + ';' 
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

    [retStr appendString:@(module_path)];

    retStr
    '''
    retStr = exeScript(debugger, command_script)
    return retStr

def killAntiDebug(debugger):
    command_script = '' 
    command_script += r'''
    NSMutableString* retStr = [NSMutableString string];
    
    #define RTLD_LAZY   0x1
    #define RTLD_NOW    0x2
    #define RTLD_LOCAL  0x4
    #define RTLD_GLOBAL 0x8

    #define VM_PROT_READ    ((vm_prot_t) 0x01) 
    #define VM_PROT_WRITE   ((vm_prot_t) 0x02)  
    #define VM_PROT_EXECUTE ((vm_prot_t) 0x04)

    #define PROT_NONE   0x00    /* [MC2] no permissions */
    #define PROT_READ   0x01    /* [MC2] pages can be read */
    #define PROT_WRITE  0x02    /* [MC2] pages can be written */
    #define PROT_EXEC   0x04    /* [MC2] pages can be executed */

    #define MAP_SHARED  0x0001
    #define MAP_ANON    0x1000

    #define KERN_SUCCESS            0

    typedef unsigned int mach_port_t;
    typedef int     kern_return_t;
    typedef unsigned int        vm_inherit_t;
    typedef mach_port_t     task_t;
    typedef int     vm_prot_t;

    typedef unsigned long       uintptr_t;
    typedef uintptr_t       vm_offset_t;
    typedef vm_offset_t         vm_address_t;
    typedef uint64_t        mach_vm_address_t;
    typedef int     boolean_t;
    typedef int     vm_behavior_t;
    typedef uint32_t vm32_object_id_t;
    typedef uintptr_t       vm_size_t;
    typedef int *vm_region_recurse_info_t;

    typedef unsigned long long  memory_object_offset_t;
    struct vm_region_submap_short_info_64 {
        vm_prot_t       protection;     /* present access protection */
        vm_prot_t       max_protection; /* max avail through vm_prot */
        vm_inherit_t        inheritance;/* behavior of map/obj on fork */
        memory_object_offset_t  offset;     /* offset into object/map */
            unsigned int            user_tag;   /* user tag on map entry */
            unsigned int            ref_count;   /* obj/map mappers, etc */
            unsigned short          shadow_depth;   /* only for obj */
            unsigned char           external_pager;  /* only for obj */
            unsigned char           share_mode; /* see enumeration */
        boolean_t       is_submap;  /* submap vs obj */
        vm_behavior_t       behavior;   /* access behavior hint */
        vm32_object_id_t    object_id;  /* obj/map name, not a handle */
        unsigned short      user_wired_count; 
    };

    typedef unsigned int        __darwin_natural_t;
    typedef __darwin_natural_t  natural_t;
    typedef natural_t mach_msg_type_number_t;

    typedef struct vm_region_submap_short_info_64    vm_region_submap_short_info_data_64_t;

    #define VM_REGION_SUBMAP_SHORT_INFO_COUNT_64                \
    ((mach_msg_type_number_t)                   \
     (sizeof (vm_region_submap_short_info_data_64_t) / sizeof (natural_t)))

    #define VM_FLAGS_OVERWRITE 0x4000  /* delete any existing mappings first */

    // init value
    kern_return_t kret;
    task_t self_task = (task_t)mach_task_self();

    // get target address and page
    void *handle = (void*)dlopen(0, RTLD_GLOBAL | RTLD_NOW);
    uintptr_t target_ptr = (uintptr_t)dlsym(handle, "ptrace");
    unsigned long page_start = (unsigned long) (target_ptr) & ~(0x1000-0x1);
    unsigned long patch_offset = (unsigned long)target_ptr - page_start;
    [retStr appendString:@"\n[*] target address: "];
    [retStr appendString:(id)[@((uintptr_t)target_ptr) stringValue]]
    [retStr appendString:@" and offset: "];
    [retStr appendString:(id)[@((uintptr_t)patch_offset) stringValue]]
    [retStr appendString:@"\n"];
    

    // map new page for patch
    
    void *new_page = (void *)mmap(NULL, 0x1000, 0x1 | 0x2, 0x1000 | 0x0001, -1, 0);
    if (!new_page ){
        [retStr appendString:@"[-] mmap failed!\n"];
        return;
    }


    [retStr appendString:@"[*] mmap new page: "];
    [retStr appendString:(id)[@((uintptr_t)new_page) stringValue]]
    [retStr appendString:@" success! \n"];

    kret = (kern_return_t)vm_copy(self_task, (unsigned long)page_start, 0x1000, (vm_address_t) new_page);
    if (kret != KERN_SUCCESS){
        [retStr appendString:@"[-] vm_copy faild!\n"];
        return;
    }
    [retStr appendString:@"[+] vm_copy success!\n"];

    // start patch
    uint8_t patch_ret_ins_data[4] = {0xc0, 0x03, 0x5f, 0xd6}; // ret
    /*
    kret = (kern_return_t)mach_vm_write(self_task, (vm_address_t)((unsigned long)new_page+patch_offset), (vm_offset_t)patch_ret_ins_data, 4);
    if (kret != KERN_SUCCESS){
        [retStr appendString:@"[-] patch data mach_vm_write faild!\n"];
        return;
    }
    */
    // use memcpy to replace mach_vm_write
    memcpy((void *)((unsigned long)new_page+patch_offset), patch_ret_ins_data, 4);
    [retStr appendString:@"[+] mach_vm_write success!\n"];
    
    // set back to r-x
    (int)mprotect(new_page, 0x1000, PROT_READ | PROT_EXEC);
    [retStr appendString:@"[*] set new page back to r-x success!\n"];

    // remap
    vm_prot_t prot;
    vm_inherit_t inherit;
    
    // get page info
    vm_address_t region = (vm_address_t) page_start;
    vm_size_t region_len = 0;
    struct vm_region_submap_short_info_64 vm_info;
    mach_msg_type_number_t info_count = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
    natural_t max_depth = 99999;
    kret = (kern_return_t)vm_region_recurse_64(self_task, &region, &region_len,
                                            &max_depth,
                                            (vm_region_recurse_info_t) &vm_info,
                                            &info_count);
    if (kret != KERN_SUCCESS){
        [retStr appendString:@"[-] vm_region_recurse_64 faild!\n"];
        return;
    }

    [retStr appendString:@"[*] vm_region_recurse_64 success!\n"];

    prot = vm_info.protection & (PROT_READ | PROT_WRITE | PROT_EXEC);
    inherit = vm_info.inheritance;
    [retStr appendString:@"[*] get page info success!\n"];
    
    vm_prot_t c;
    vm_prot_t m;
    mach_vm_address_t target = (mach_vm_address_t)page_start;
    
    kret = (kern_return_t)mach_vm_remap(self_task, &target, 0x1000, 0,
                       VM_FLAGS_OVERWRITE, self_task,
                       (mach_vm_address_t) new_page, true,
                       &c, &m, inherit);
    if (kret != KERN_SUCCESS){
        [retStr appendString:@"[-] remap mach_vm_remap faild!\n"];
        return;
    }
    [retStr appendString:@"[+] remap success!\n"];

    // clear cache
    void* clear_start_ = (void*)(page_start + patch_offset);
    sys_icache_invalidate (clear_start_, 4);
    sys_dcache_flush (clear_start_, 4);

    [retStr appendString:@"[*] clear cache success!\n"];
    
    retStr
    '''

    retStr = exeScript(debugger, command_script)
    return retStr
    # lldb.debugger.HandleCommand ('re write $x0 0')
    
def hook(debugger):
    command_script = ''
    command_script += r'''
    @import Foundation;
    @import ObjectiveC;
    
    NSString* hookLog = @"";
        
    
    Class clz = (Class)objc_getClass("ViewController");
    SEL originalSelector = NSSelectorFromString(@"onClick:");
    SEL hookSelector = NSSelectorFromString(@"imageFromColor:");
    SEL swizzledSelector = NSSelectorFromString([NSString stringWithFormat:@"_xia0_swizzle_%x_%@", arc4random(), NSStringFromSelector(originalSelector)]);
        
    Method originalMethod = class_getInstanceMethod(clz, originalSelector);
    Method hookMethod = class_getInstanceMethod(clz, hookSelector);
    if (!originalMethod) {
        hookLog = @"NULL originalMethod";
    }
    
   method_setImplementation(originalMethod, method_getImplementation(hookMethod));
    //class_addMethod(class, swizzledSelector, xblock, method_getTypeEncoding(originalMethod));
    //Method newMethod = class_getInstanceMethod(clz, swizzledSelector);
    //method_exchangeImplementations(originalMethod, newMethod);
    hookLog = @"Success";
    
    hookLog
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
    usage = "usage: xutil [options] args"
    parser = optparse.OptionParser(usage=usage, prog="lookup")

    parser.add_option("-b", "--breakpointAtMainModule",
                        action="store",
                        default=None,
                        dest="mainModuleAddress",
                        help="set a breakpoint at main module of given address")
                        
    parser.add_option("-s", "--slide",
                        action="store",
                        default=None,
                        dest="sildeModule",
                        help="get slide of given module")

    parser.add_option("-l", "--load",
                    action="store",
                    default=None,
                    dest="loadModule",
                    help="load a macho file")

    parser.add_option("-k", "--killAntiDebug",
                action="store_true",
                default=None,
                dest='kAntiDebug',
                help="bypass anti debug")

    parser.add_option("-t", "--test",
                action="store",
                default=None,
                dest="testarg",
                help="do some testing")
                
#    parser.add_option("-h", "--help",
#                    action="store_true",
#                    default=None,
#                    dest='help',
#                    help="print this help info")


    return parser
