
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
    debugger.HandleCommand(
    'command script add -f patcher.handle_command patcher -h "patch code in lldb"')
    # print('========')
    # print('[patcher]: patch code in lldb')
    # print('\tpatcher -a patch_addr -i instrument -s instrument_count')
    # print('\tmore usage, try "patcher -h"')
                    
def handle_command(debugger, command, exe_ctx, result, internal_dict):
    command_args = shlex.split(command, posix=False)
    parser = generate_option_parser()
    try:
        (options, _) = parser.parse_args(command_args)
    except:
        result.SetError(parser.usage)
        return
        
    _ = exe_ctx.target
    _ = exe_ctx.thread


    if options.patchInstrument:
        if options.patchAddress:
            patch_addr = int(options.patchAddress, 16)
        else:
            ret = utils.exe_cmd(debugger, "p/x $pc")
            ret = ret.strip()
            pattern = '0x[0-9a-f]+'
            match = re.search(pattern, ret)
            if match:
                found = match.group(0)
            else:
                utils.ELOG("not get address:"+ret)
                return

            utils.ILOG("you not set patch address, default is current pc address:{}".format(found))
            patch_addr = int(found, 16)
        
        patch_ins = options.patchInstrument
        # default instrument size is 1
        patch_size = 0x1
        patch_ins = patch_ins.replace("\"", "")
        patch_ins = patch_ins.replace("'", "")

        if options.patchSize:
            patch_size = int(options.patchSize)

        ret = patcher(debugger, patch_ins, patch_addr, patch_size)

        result.AppendMessage(str(ret))
    else:
        result.AppendMessage("[-] args error, check it !")

    return

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
    retStr = utils.exe_script(debugger, command_script)
    return utils.hex_int_in_str(retStr)

def is_raw_data(data):

    # pylint: disable=anomalous-backslash-in-string
    pattern = "\{\s*0x[0-9a-fA-F]{2}\s*,\s*0x[0-9a-fA-F]{2}\s*,\s*0x[0-9a-fA-F]{2}\s*,\s*0x[0-9a-fA-F]{2}\s*\}"
    ret = re.match(pattern, data)

    if not ret:
        return False
    return True

def patcher(debugger, ins, addr, size):
    if is_raw_data(ins):
        utils.ILOG("detect you manual set ins data:{}".format(ins))
        utils.ILOG("start patch text at address:{} size:{} to ins data:{}".format(hex(addr), size, ins))
        patch_code(debugger, hex(addr), ins, size)
        return "[x] power by xia0@2019"

    supportInsList = {'nop':'0x1f, 0x20, 0x03, 0xd5 ', 'ret':'0xc0, 0x03, 0x5f, 0xd6', 'mov0':'0x00, 0x00, 0x80, 0xd2', 'mov1':'0x20, 0x00, 0x80, 0xd2'}
    if ins not in supportInsList.keys():
        utils.ELOG("patcher not support this ins type:{}".format(ins))
        return "[x] power by xia0@2019"

    utils.ILOG("start patch text at address:{} size:{} to ins:\"{}\" and data:{}".format(hex(addr), size, ins, supportInsList[ins]))
    
    # for i in range(size):
    #     patch_code(debugger, hex(curPatchAddr), supportInsList[ins])
    #     utils.SLOG("current patch address:{} patch done".format(hex(curPatchAddr)))
    #     curPatchAddr += 4
    ins_data = ""
    for i in range(size):
        ins_data += supportInsList[ins]
        if i != size - 1:
            ins_data += ","

    build_ins_data = "{" + ins_data + "}"

    utils.ILOG("make ins data:\n{}".format(build_ins_data))

    patch_code(debugger, hex(addr), build_ins_data, size)
    utils.SLOG("patch done")
    return "[x] power by xia0@2019"

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
