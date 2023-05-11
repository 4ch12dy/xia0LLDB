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

'''

special thanks to xia0z & Proteas

'''

import lldb
import subprocess
import shlex
import optparse
import re
import utils

def __lldb_init_module (debugger, dict):
    debugger.HandleCommand('command script add -f xbr.xbr xbr -h "set breakpoint on ObjC Method"')
    # print('========')
    # print('[xbr]: set breakpoint on OC function even striped')
    # print('\txbr "-[UIView initWithFrame:]" or "className" for all the class metholds')
    # print('\tmore usage, try "xbr -h"')

def create_command_arguments(command):
    return shlex.split(command)
    
def is_command_valid(args):
    if len(args) == 0:
        return False

    arg = args[0]
    if len(arg) == 0:
        return False

    # pylint: disable=anomalous-backslash-in-string
    parm = '^[+-]\[.+ .+\]$'
    ret = re.match(parm, arg) # TODO: more strict
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

def is_br_all_cmd_x(args):
    if len(args) == 0:
        return False

    arg = args[0]
    if len(arg) == 0:
        return False

    if "$" in arg:
        return True

    return False

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
    # pylint: disable=anomalous-backslash-in-string
    parm = '(?<=\[)[^\[].*[^ ](?= +)'
    match = re.search(parm, arg) # TODO: more strict
    if match:
        return match.group(0)
    else:
        return None

def get_method_name(arg):
    # pylint: disable=anomalous-backslash-in-string
    parm = '(?<= )[^ ].*[^\]](?=\]+)'
    match = re.search(parm, arg) # TODO: more strict
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
    frame = get_selected_frame()
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
    frame = get_selected_frame()
    class_addr = frame.EvaluateExpression("(Class)NSClassFromString(@\"%s\")" % class_name).GetValueAsUnsigned()
    utils.SLOG('found class address:0x%x' % class_addr)
    if class_addr == 0:
        return 0

    sel_addr = frame.EvaluateExpression("(SEL)NSSelectorFromString(@\"%s\")" % method_name).GetValueAsUnsigned()
    utils.SLOG('found selector address:0x%x' % sel_addr)
    has_method = frame.EvaluateExpression("(BOOL)class_respondsToSelector(%d, %d)" % (class_addr, sel_addr)).GetValueAsUnsigned()
    if not has_method:
        return 0

    method_addr = frame.EvaluateExpression('(void *)class_getMethodImplementation(%d, %d)' % (class_addr, sel_addr))
    
    return method_addr.GetValueAsUnsigned()

def get_all_method_address_of_class(debugger, classname):

    command_script = '@import Foundation;const char* className = "' + classname + '";' 

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
        NSNumber* implementationNum =  [NSNumber numberWithUnsignedLongLong:(uintptr_t)implementation];
        [retStr appendString:(id)[implementationNum stringValue]];
        [retStr appendString:@"-"];
    }

    unsigned int cm_size = 0;
    struct objc_method **classMethods = (struct objc_method **)class_copyMethodList((Class)objc_getMetaClass((const char *)class_getName(cls)), &cm_size);
    for (int k = 0; k < cm_size; k++) {
        struct objc_method * meth = classMethods[k];
        id implementation = (id)method_getImplementation(meth);
        NSString* cm_name = NSStringFromSelector((SEL)method_getName(meth));
        //[mAddrArr addObject:(id)[@((uintptr_t)implementation) stringValue]];
        NSNumber* implementationNum =  [NSNumber numberWithUnsignedLongLong:(uintptr_t)implementation];
        [retStr appendString:(id)[implementationNum stringValue]];
        [retStr appendString:@"-"];
    }
    retStr
    '''
    retStr = utils.exe_script(debugger, command_script)
    return retStr

def get_main_image_index(debugger):
    command_script = '@import Foundation;' 
    command_script += r'''
    #define	MH_EXECUTE	0x2		/* demand paged executable file */
    #ifdef __LP64__
    typedef struct mach_header_64 mach_header_t;
    #else
    typedef struct mach_header mach_header_t;
    #endif
    
    uint32_t idx = 0;
    for (int i = 0; i < (uint32_t)_dyld_image_count(); i++) {
        mach_header_t* mh = (mach_header_t*)_dyld_get_image_header(i);
        if (mh && mh->filetype == MH_EXECUTE) {
            idx = i;
            break;        
        }
    }
    
    char ret[50] = {0};

    sprintf(ret, "$%d$", idx);
    
    (char*)ret
    '''
    
    retStr = utils.exe_script(debugger, command_script)
    retStr = retStr.split("$")[1]
    return int(retStr)

def get_macho_mod_init_first_func(debugger):
    idx = get_main_image_index(debugger)
    utils.ILOG(f"main image idx:{idx}")
    command_script = '@import Foundation;'
    command_script += f"uint32_t idx = {idx};"
    command_script += r'''
    //NSMutableString* retStr = [NSMutableString string];

    #define MH_MAGIC_64 0xfeedfacf 
    #define LC_SEGMENT_64   0x19
    typedef int                     integer_t;
    typedef integer_t       cpu_type_t;
    typedef integer_t       cpu_subtype_t;
    typedef integer_t       cpu_threadtype_t;

    struct mach_header_64 {
        uint32_t    magic;      /* mach magic number identifier */
        cpu_type_t  cputype;    /* cpu specifier */
        cpu_subtype_t   cpusubtype; /* machine specifier */
        uint32_t    filetype;   /* type of file */
        uint32_t    ncmds;      /* number of load commands */
        uint32_t    sizeofcmds; /* the size of all the load commands */
        uint32_t    flags;      /* flags */
        uint32_t    reserved;   /* reserved */
    };

    struct load_command {
        uint32_t cmd;       /* type of load command */
        uint32_t cmdsize;   /* total size of command in bytes */
    };

    typedef int             vm_prot_t;
    struct segment_command_64 { /* for 64-bit architectures */
        uint32_t    cmd;        /* LC_SEGMENT_64 */
        uint32_t    cmdsize;    /* includes sizeof section_64 structs */
        char        segname[16];    /* segment name */
        uint64_t    vmaddr;     /* memory address of this segment */
        uint64_t    vmsize;     /* memory size of this segment */
        uint64_t    fileoff;    /* file offset of this segment */
        uint64_t    filesize;   /* amount to map from the file */
        vm_prot_t   maxprot;    /* maximum VM protection */
        vm_prot_t   initprot;   /* initial VM protection */
        uint32_t    nsects;     /* number of sections in segment */
        uint32_t    flags;      /* flags */
    };

    struct section_64 { /* for 64-bit architectures */
        char        sectname[16];   /* name of this section */
        char        segname[16];    /* segment this section goes in */
        uint64_t    addr;       /* memory address of this section */
        uint64_t    size;       /* size in bytes of this section */
        uint32_t    offset;     /* file offset of this section */
        uint32_t    align;      /* section alignment (power of 2) */
        uint32_t    reloff;     /* file offset of relocation entries */
        uint32_t    nreloc;     /* number of relocation entries */
        uint32_t    flags;      /* flags (section type and attributes)*/
        uint32_t    reserved1;  /* reserved (for offset or index) */
        uint32_t    reserved2;  /* reserved (for count or sizeof) */
        uint32_t    reserved3;  /* reserved */
    };

    int x_offset = 0;
    struct mach_header_64* header = (struct mach_header_64*)_dyld_get_image_header(idx);

    if(header->magic != MH_MAGIC_64) {
        return ;
    }

    x_offset = sizeof(struct mach_header_64);
    int ncmds = header->ncmds;
    uint64_t modInitFirstAddr = 0;
    char* secName;

    while(ncmds--) {
        /* go through all load command to find __TEXT segment*/
        struct load_command * lcp = (struct load_command *)((uint8_t*)header + x_offset);
        x_offset += lcp->cmdsize;
        
        if(lcp->cmd == LC_SEGMENT_64) {
            struct segment_command_64 * curSegment = (struct segment_command_64 *)lcp;
            struct section_64* curSection = (struct section_64*)((uint8_t*)curSegment + sizeof(struct segment_command_64));
            
            if(!strcmp(curSection->segname, "__DATA")){

                for (int i = 0; i < curSegment->nsects; i++) {

                    if (!strcmp(curSection->sectname, "__mod_init_func")) {
                        uint64_t memAddr = curSection->addr;
                        uint64_t modInitAddrArr = memAddr + (uint64_t)_dyld_get_image_vmaddr_slide(idx);
                        modInitFirstAddr = *((uint64_t*)modInitAddrArr)
                        break;
                    }
                    curSection = (struct section_64*)((uint8_t*)curSection + sizeof(struct section_64));
                }
                break;
            }
        }
    }
    char ret[50] = {0};

    sprintf(ret, "0x%016lx", modInitFirstAddr);

    (char*)ret
    '''
    retStr = utils.exe_script(debugger, command_script)
    return utils.hex_int_in_str(retStr)

def get_macho_entry_offset(debugger):
    idx = get_main_image_index(debugger)
    utils.ILOG(f"main image idx:{idx}")
    command_script = '@import Foundation;' 
    command_script += f"uint32_t idx = {idx};"
    command_script += r'''
    //NSMutableString* retStr = [NSMutableString string];

    #define MH_MAGIC_64 0xfeedfacf 
    #define LC_SEGMENT_64   0x19
    #define LC_REQ_DYLD     0x80000000
    #define LC_MAIN         (0x28|LC_REQ_DYLD)

    typedef int             integer_t;
    typedef integer_t       cpu_type_t;
    typedef integer_t       cpu_subtype_t;
    typedef integer_t       cpu_threadtype_t;

    struct mach_header_64 {
        uint32_t    magic;      /* mach magic number identifier */
        cpu_type_t  cputype;    /* cpu specifier */
        cpu_subtype_t   cpusubtype; /* machine specifier */
        uint32_t    filetype;   /* type of file */
        uint32_t    ncmds;      /* number of load commands */
        uint32_t    sizeofcmds; /* the size of all the load commands */
        uint32_t    flags;      /* flags */
        uint32_t    reserved;   /* reserved */
    };

    struct load_command {
        uint32_t cmd;       /* type of load command */
        uint32_t cmdsize;   /* total size of command in bytes */
    };

    typedef int             vm_prot_t;
    struct segment_command_64 { /* for 64-bit architectures */
        uint32_t    cmd;        /* LC_SEGMENT_64 */
        uint32_t    cmdsize;    /* includes sizeof section_64 structs */
        char        segname[16];    /* segment name */
        uint64_t    vmaddr;     /* memory address of this segment */
        uint64_t    vmsize;     /* memory size of this segment */
        uint64_t    fileoff;    /* file offset of this segment */
        uint64_t    filesize;   /* amount to map from the file */
        vm_prot_t   maxprot;    /* maximum VM protection */
        vm_prot_t   initprot;   /* initial VM protection */
        uint32_t    nsects;     /* number of sections in segment */
        uint32_t    flags;      /* flags */
    };

    struct section_64 { /* for 64-bit architectures */
        char        sectname[16];   /* name of this section */
        char        segname[16];    /* segment this section goes in */
        uint64_t    addr;       /* memory address of this section */
        uint64_t    size;       /* size in bytes of this section */
        uint32_t    offset;     /* file offset of this section */
        uint32_t    align;      /* section alignment (power of 2) */
        uint32_t    reloff;     /* file offset of relocation entries */
        uint32_t    nreloc;     /* number of relocation entries */
        uint32_t    flags;      /* flags (section type and attributes)*/
        uint32_t    reserved1;  /* reserved (for offset or index) */
        uint32_t    reserved2;  /* reserved (for count or sizeof) */
        uint32_t    reserved3;  /* reserved */
    };

    struct entry_point_command {
        uint32_t  cmd;  /* LC_MAIN only used in MH_EXECUTE filetypes */
        uint32_t  cmdsize;  /* 24 */
        uint64_t  entryoff; /* file (__TEXT) offset of main() */
        uint64_t  stacksize;/* if not zero, initial stack size */
    };

    int x_offset = 0;
    struct mach_header_64* header = (struct mach_header_64*)_dyld_get_image_header(idx);

    if(header->magic != MH_MAGIC_64) {
        return ;
    }

    x_offset = sizeof(struct mach_header_64);
    int ncmds = header->ncmds;
    //uint64_t textStart = 0;
    //uint64_t textEnd = 0;
    uint64_t main_addr = 0;
    while(ncmds--) {
        /* go through all load command to find __TEXT segment*/
        struct load_command * lcp = (struct load_command *)((uint8_t*)header + x_offset);
        x_offset += lcp->cmdsize;
        if(lcp->cmd == LC_MAIN) {
            uintptr_t slide =  (uintptr_t)_dyld_get_image_vmaddr_slide(idx);          
            struct entry_point_command* main_cmd = (struct entry_point_command*)lcp;
            main_addr = (uint64_t)slide + main_cmd->entryoff + 0x100000000;

            break;
        }
    }
    char ret[50] = {0};

    /*
    char textStartAddrStr[20];
    sprintf(textStartAddrStr, "0x%016lx", textStart);

    char textEndAddrStr[20];
    sprintf(textEndAddrStr, "0x%016lx", textEnd);


    char* splitStr = ",";
    strcpy(ret,textStartAddrStr);
    strcat(ret,splitStr);
    strcat(ret,textEndAddrStr);
    */

    sprintf(ret, "0x%016lx", main_addr);
    
    (char*)ret
    '''
    retStr = utils.exe_script(debugger, command_script)
    return retStr

def get_main_image_path(debugger):
    command_script = '@import Foundation;' 
    command_script += r'''

    // const char *path = (char *)[[[NSBundle mainBundle] executablePath] UTF8String];
    id bundle = objc_msgSend((Class)objc_getClass("NSBundle"), @selector(mainBundle));
    id exePath = objc_msgSend((id)bundle, @selector(executablePath));
    const char *path  = (char *)objc_msgSend((id)exePath, @selector(UTF8String));
    
    path
    '''
    retStr = utils.exe_script(debugger, command_script)
    return retStr

def get_process_module_slide(debugger, modulePath):
    command_script = '@import Foundation;' 
    command_script += r'''
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
    slide = utils.exe_script(debugger, command_script)
    return slide

def get_all_class_plus_load_methods(debugger):
    command_script = '@import Foundation;' 
    command_script += r'''
    NSMutableString* retStr = [NSMutableString string];

    unsigned int c_size = 0;
    const char *path = (char *)[[[NSBundle mainBundle] executablePath] UTF8String];
    const char **allClasses = (const char **)objc_copyClassNamesForImage(path, &c_size);

    for (int i = 0; i < c_size; i++) {
        Class cls = objc_getClass(allClasses[i]);
        unsigned int cm_size = 0;
        struct objc_method **classMethods = (struct objc_method **)class_copyMethodList((Class)objc_getMetaClass((const char *)class_getName(cls)), &cm_size);

        for (int k = 0; k < cm_size; k++) {
            struct objc_method * meth = classMethods[k];
            id implementation = (id)method_getImplementation(meth);
            NSString* cm_name = NSStringFromSelector((SEL)method_getName(meth));
            if([cm_name isEqualToString:@"load"]){
                [retStr appendString:(id)[@((uintptr_t)implementation) stringValue]];
                [retStr appendString:@","];
            }
        }
        free(classMethods);
    }
    free(allClasses);
    retStr
    '''
    return utils.exe_script(debugger, command_script)

def xbr(debugger, command, result, dict):
    raw_args = create_command_arguments(command)

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
          
        utils.ILOG("breakpoint at address:{}".format(hex(targetAddr_int)))
        lldb.debugger.HandleCommand ('breakpoint set --address %d' % targetAddr_int)
        return

    if options.entryAddress:
        if options.entryAddress == "main":
            entryAddrStr = get_macho_entry_offset(debugger)
            entryAddr_int = int(entryAddrStr.strip()[1:-1], 16)
            utils.ILOG("breakpoint at main function:{}".format(hex(entryAddr_int)))
            lldb.debugger.HandleCommand ('breakpoint set --address %d' % entryAddr_int)
        elif options.entryAddress == "init":
            initFunAddrStr = get_macho_mod_init_first_func(debugger)
            initFunAddr_int = int(initFunAddrStr.strip()[1:-1], 16)
            utils.ILOG("breakpoint at mod int first function:{}".format(hex(initFunAddr_int)))
            lldb.debugger.HandleCommand ('breakpoint set --address %d' % initFunAddr_int)
        elif options.entryAddress == "load":
            
            ret = get_all_class_plus_load_methods(debugger)
            if "<object returned empty description>" in ret:
                utils.ILOG("not found +[* load] method")
                return
            all_load_addrs_str_arr = ret.strip().split(",")
            all_load_addrs = []
            for addr in all_load_addrs_str_arr:
                if addr != "":
                    all_load_addrs.append(int(addr, 10))
            utils.ILOG("will set breakpoint at all +[* load] methold, count:{}".format(len(all_load_addrs)))
            for addr in all_load_addrs:
                lldb.debugger.HandleCommand ('breakpoint set --address %d' % addr)
                utils.SLOG("set br at:{}".format(hex(addr)))
            # utils.ILOG("load:\n{}\n".format([hex(addr) for addr in all_load_addrs]))
        else:
            utils.ELOG("you should special the -E options:[main/init/load]")

        return
        

    # check is arg is address ? mean auto add slide
    if is_just_address_cmd(args):

        if options.modulePath:
            modulePath = options.modulePath
            utils.ILOG("you special the module:" + modulePath)
        else:
            utils.ILOG("you not special the module, default is main module")
            modulePath = None

        targetAddr = args[0]

        if targetAddr.startswith("0x"):
            targetAddr_int = int(targetAddr, 16)
        else:
            targetAddr_int = int(targetAddr, 10)

        moduleSlide = get_process_module_slide(debugger, modulePath)
        if "error" in moduleSlide:
            utils.ELOG("error in oc script # " + moduleSlide.strip())
            if modulePath:
                targetImagePath = modulePath
            else:               
                mainImagePath = get_main_image_path(debugger)
                if "no value available" in  mainImagePath or "error" in mainImagePath:
                    ret = utils.exe_cmd(debugger, "target list")
                    # pylint: disable=anomalous-backslash-in-string
                    pattern = '/.*\('
                    match = re.search(pattern, ret) # TODO: more strict
                    if match:
                        found = match.group(0)
                        found = found.split("(")[0]
                        found = found.strip()
                    else:
                        utils.ELOG("failed to auto get main module, use -m option")
                        return
 
                    mainImagePath = found
                    print("[+] use \"target list\" to get main module:" + mainImagePath)
                else:
                    mainImagePath = mainImagePath.strip()[1:-1]

                targetImagePath = mainImagePath

            ret = utils.exe_cmd(debugger, "image list -o -f")
            pattern = '0x.*?' + targetImagePath.replace("\"", "")
            match = re.search(pattern, ret) # TODO: more strict
            if match:
                found = match.group(0)
            else:
                utils.ELOG("not found image:"+targetImagePath)
                return
            moduleSlide = found.split()[0]
            utils.ILOG("use \"image list -o -f\" cmd to get image slide:"+moduleSlide)
            moduleSlide = int(moduleSlide, 16)

        else:
            moduleSlide = int(moduleSlide, 10)
            
        brAddr = moduleSlide + targetAddr_int

        utils.ILOG("ida's address:{} module slide:{} target breakpoint address:{}".format(hex(targetAddr_int), hex(moduleSlide), hex(brAddr)))
        
        lldb.debugger.HandleCommand ('breakpoint set --address %d' % brAddr)
        return

    # check is breakpoint at all methods address(IMP) for given classname
    if is_br_all_cmd_x(args):
        classname = args[0]
        begin = classname.find('$')
        end = classname.rfind('$')
        classname = classname[begin+1 : end]
        utils.ILOG("classname:{}".format(classname))

        ret = get_all_method_address_of_class(debugger, classname)

        addrArr = ret.split('-')[:-1]

        for addr in addrArr:
            address = int(addr)
            if address:
                lldb.debugger.HandleCommand ('breakpoint set --address %x' % address)
        
        result.AppendMessage("Set %ld breakpoints of %s" % (len(addrArr),classname))
        return

    if is_br_all_cmd(args):
        classname = args[0]
        ret = get_all_method_address_of_class(debugger, classname)

        addrArr = ret.split('-')[:-1]

        for addr in addrArr:
            address = int(addr)
            if address:
                lldb.debugger.HandleCommand ('breakpoint set --address %x' % address)
        
        result.AppendMessage("Set %ld breakpoints of %s" % (len(addrArr),classname))
        return
    


    if not is_command_valid(raw_args):
        print('please specify the param, for example: "-[UIView initWithFrame:]"')
        return

    arg_ = raw_args[0]
    class_name = get_class_name(arg_)
    method_name = get_method_name(arg_)
#    xlog = 'className:'+ str(class_name) + '\tmethodName:' + str(method_name)
    utils.ILOG("className:{} methodName:{}".format(class_name, method_name))
    # print class_name, method_name
    address = 0
    if is_class_method(arg_):
        address = get_class_method_address(class_name, method_name)
    else:
        address = get_instance_method_address(class_name, method_name)

    utils.SLOG('found method address:0x%x' % address)
    if address:
        lldb.debugger.HandleCommand ('breakpoint set --address %x' % address)
    else:
        utils.ELOG("fail, please check the arguments")

def generate_option_parser():
    usage = "usage: xbr [-a/-m/-E] args"
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

    parser.add_option("-E", "--entryAddress",
            action="store",
            default=None,
            dest="entryAddress",
            help="set a breakpoint at entry address/main/load")

    return parser
