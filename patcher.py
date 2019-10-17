
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

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
    'command script add -f patcher.handle_command patcher -h "patch code in lldb"')
    print('========')
    print('[patcher]: patch code in lldb')
    print('\tpatcher -a patch_addr -i instrument -s instrument_count')
    print('\tmore usage, try "patcher -h"')
                    
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


    if options.patchAddress and options.patchInstrument:
        patch_addr = int(options.patchAddress, 16)
        patch_ins = options.patchInstrument
        # default instrument size is 1
        patch_size = 0x1

        if options.patchSize:
            patch_size = int(options.patchSize)

        ret = patcher(debugger, patch_ins, patch_addr, patch_size)

        result.AppendMessage(str(ret))
    else:
        result.AppendMessage("check it !")

    return


def getTextSegmentAddr(debugger):
    command_script = '@import Foundation;' 
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
    struct mach_header_64* header = (struct mach_header_64*)_dyld_get_image_header(0);

    if(header->magic != MH_MAGIC_64) {
        return ;
    }

    x_offset = sizeof(struct mach_header_64);
    int ncmds = header->ncmds;
    uint64_t textStart = 0;
    uint64_t textEnd = 0;

    while(ncmds--) {
        /* go through all load command to find __TEXT segment*/
        struct load_command * lcp = (struct load_command *)((uint8_t*)header + x_offset);
        x_offset += lcp->cmdsize;
        
        if(lcp->cmd == LC_SEGMENT_64) {
            struct segment_command_64 * curSegment = (struct segment_command_64 *)lcp;
            struct section_64* curSection = (struct section_64*)((uint8_t*)curSegment + sizeof(struct segment_command_64));
            
            // check current section of segment is __TEXT?
            if(!strcmp(curSection->segname, "__TEXT") && !strcmp(curSection->sectname, "__text")){
                uint64_t memAddr = curSection->addr;
               
                textStart = memAddr + (uint64_t)_dyld_get_image_vmaddr_slide(0);
                textEnd = textStart + curSection->size;
                /*
                [retStr appendString:@" "];
                [retStr appendString:(id)[@(textStart) stringValue]];
                [retStr appendString:@" , "];
                [retStr appendString:(id)[@(textEnd) stringValue]];
                */
                break;
            }
        }
    }
    char ret[50];

    char textStartAddrStr[20];
    sprintf(textStartAddrStr, "0x%016lx", textStart);

    char textEndAddrStr[20];
    sprintf(textEndAddrStr, "0x%016lx", textEnd);


    char* splitStr = ",";
    strcpy(ret,textStartAddrStr);
    strcat(ret,splitStr);
    strcat(ret,textEndAddrStr);

    ret
    '''
    retStr = exeScript(debugger, command_script)
    return hexIntInStr(retStr)

def patch_code(debugger, addr, ins, count):
    command_script = '@import Foundation;\n'
    command_script += 'uint64_t x_addr = {};\n'.format(addr)
    command_script += 'uint8_t patch_data[] = {};\n'.format(ins)
    command_script += 'int insCount = {};\n'.format(count)
    command_script += r'''
    NSMutableString* retStr = [NSMutableString string];

    void * patch_addr = (void*)x_addr;
    //uint8_t patch_data[] = {0xc0, 0x03, 0x5f, 0xd6};
    int patch_data_size = 4*insCount;

    // =====================================================patch code=============================================
    typedef bool (*patch_code_t)(void* patch_addr, uint8_t* patch_data, int patch_data_size);
        patch_code_t patch_code = [](void* patch_addr, uint8_t* patch_data, int patch_data_size) -> bool {
        #define PAGE_SIZE        0x0000000000004000

        #define PAGE_MASK        0x0000000000003fff
        
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

        typedef int                     __int32_t;

        typedef __int32_t       __darwin_pid_t;   

        typedef __darwin_pid_t        pid_t; 

        // init value
        kern_return_t kret;
        task_t self_task = (task_t)mach_task_self();

        /* Set platform binary flag */
        #define FLAG_PLATFORMIZE (1 << 1)

        // platformize_me 
        // https://github.com/pwn20wndstuff/Undecimus/issues/112
        /*

        void* handle = (void*)dlopen("/usr/lib/libjailbreak.dylib", RTLD_LAZY);
        if (!handle){
            //[retStr appendString:@"[-] /usr/lib/libjailbreak.dylib dlopen failed!\n"];
            return false;
        }
        
        // Reset errors
        (const char *)dlerror();
        typedef void (*fix_entitle_prt_t)(pid_t pid, uint32_t what);
        fix_entitle_prt_t ptr = (fix_entitle_prt_t)dlsym(handle, "jb_oneshot_entitle_now");
        
        const char *dlsym_error = (const char *)dlerror();
        if (dlsym_error) return;
        
        ptr((pid_t)getpid(), FLAG_PLATFORMIZE);
        //[retStr appendString:@"\n[+] platformize me success!"];

        */

        void* target_addr = patch_addr;

        // 1. get target address page and patch offset
        unsigned long page_start = (unsigned long) (target_addr) & ~PAGE_MASK;
        unsigned long patch_offset = (unsigned long)target_addr - page_start;

        // map new page for patch
        void *new_page = (void *)mmap(NULL, PAGE_SIZE, 0x1 | 0x2, 0x1000 | 0x0001, -1, 0);
        if (!new_page ){
            //[retStr appendString:@"[-] mmap failed!\n"];
            return false;
        }

        kret = (kern_return_t)vm_copy(self_task, (unsigned long)page_start, PAGE_SIZE, (vm_address_t) new_page);
        if (kret != KERN_SUCCESS){
            //[retStr appendString:@"[-] vm_copy faild!\n"];
            return false;
        }


        // 4. start patch
        /*
         nop -> {0x1f, 0x20, 0x03, 0xd5}
         ret -> {0xc0, 0x03, 0x5f, 0xd6}
        */
        // char patch_ins_data[4] = {0x1f, 0x20, 0x03, 0xd5};
        //    mach_vm_write(task_self, (vm_address_t)(new+patch_offset), patch_ret_ins_data, 4);
        memcpy((void *)((uint64_t)new_page+patch_offset), patch_data, patch_data_size);
        //[retStr appendString:@"[+] patch ret[0xc0 0x03 0x5f 0xd6] with memcpy\n"];
        
        // set back to r-x
        (int)mprotect(new_page, PAGE_SIZE, PROT_READ | PROT_EXEC);
        //[retStr appendString:@"[*] set new page back to r-x success!\n"];

        
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
            //[retStr appendString:@"[-] vm_region_recurse_64 faild!\n"];
            return false;
        }

        prot = vm_info.protection & (PROT_READ | PROT_WRITE | PROT_EXEC);
        inherit = vm_info.inheritance;
        //[retStr appendString:@"[*] get page info done.\n"];
        
        vm_prot_t c;
        vm_prot_t m;
        mach_vm_address_t target = (mach_vm_address_t)page_start;
        
        kret = (kern_return_t)mach_vm_remap(self_task, &target, PAGE_SIZE, 0,
                           VM_FLAGS_OVERWRITE, self_task,
                           (mach_vm_address_t) new_page, true,
                           &c, &m, inherit);
        if (kret != KERN_SUCCESS){
            //[retStr appendString:@"[-] remap mach_vm_remap faild!\n"];
            return false;
        }
        //[retStr appendString:@"[+] remap to target success!\n"];

        // clear cache
        void* clear_start_ = (void*)(page_start + patch_offset);
        sys_icache_invalidate (clear_start_, 4);
        sys_dcache_flush (clear_start_, 4);

        return true;
    };
    // =====================================================patch code=============================================
    
    patch_code(patch_addr, patch_data, patch_data_size);

    [retStr appendString:@"patch done."];
    retStr
    '''
    retStr = exeScript(debugger, command_script)
    return hexIntInStr(retStr)

def patcher(debugger, ins, addr, size):
    supportInsList = {'nop':'0x1f, 0x20, 0x03, 0xd5 ', 'ret':'0xc0, 0x03, 0x5f, 0xd6'}

    print("[*] start patch text at address:{} size:{} to ins:\"{}\" and data:{}".format(hex(addr), size, ins, supportInsList[ins]))
    
    # for i in range(size):
    #     patch_code(debugger, hex(curPatchAddr), supportInsList[ins])
    #     print("[+] current patch address:{} patch done".format(hex(curPatchAddr)))
    #     curPatchAddr += 4
    ins_data = ""
    for i in range(size):
        ins_data += supportInsList[ins]
        if i != size - 1:
            ins_data += ","

    build_ins_data = "{" + ins_data + "}"

    print("[*] make ins data:\n{}".format(build_ins_data))

    patch_code(debugger, hex(addr), build_ins_data, size)
    print("[+] patch done")
    return "[x] power by xia0@2019"

def hexIntInStr(needHexStr):

    def handler(reobj):
        intvalueStr = reobj.group(0)
        
        r = hex(int(intvalueStr))
        return r

    pattern = '(?<=\s)[0-9]{1,}(?=\s)'

    return re.sub(pattern, handler, needHexStr, flags = 0)

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
    usage = "patcher"
    parser = optparse.OptionParser(usage=usage, prog="lookup")

    parser.add_option("-a", "--address",
                    action="store",
                    default=None,
                    dest='patchAddress',
                    help="need patch code address")

    parser.add_option("-i", "--instrument",
                action="store",
                default=None,
                dest='patchInstrument',
                help="patch instrument type")

    parser.add_option("-s", "--size",
            action="store",
            default=None,
            dest='patchSize',
            help="patch instrument count")
                        
    return parser
