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
	'command script add -f traceOC.handle_command traceOC -h "trace ObjectC function call"')
	print('========')
	print('[traceOC]: trace ObjectC function call')
	print('\ttraceOC ')
	print('\tmore usage, try "traceOC -h"')
					
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
	
	result.AppendMessage(str('[x] happy debugging~ kill antiDebug by xia0@2019'))

	ret = traceOC(debugger)
	
	return

def patchPtrace(debugger):
	command_script = '' 
	command_script += r'''
	NSMutableString* retStr = [NSMutableString string];
   
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
		[retStr appendString:@"[-] /usr/lib/libjailbreak.dylib dlopen failed!\n"];
		return;
	}
	
	// Reset errors
	(const char *)dlerror();
	typedef void (*fix_entitle_prt_t)(pid_t pid, uint32_t what);
	fix_entitle_prt_t ptr = (fix_entitle_prt_t)dlsym(handle, "jb_oneshot_entitle_now");
	
	const char *dlsym_error = (const char *)dlerror();
	if (dlsym_error) return;
	
	ptr((pid_t)getpid(), FLAG_PLATFORMIZE);
	[retStr appendString:@"\n[+] platformize me success!"];

	*/

	// get target address and page
	void* handle = (void*)dlopen(0, RTLD_GLOBAL | RTLD_NOW);
	uintptr_t target_ptr = (uintptr_t)dlsym(handle, "ptrace");
	unsigned long page_start = (unsigned long) (target_ptr) & ~PAGE_MASK;
	unsigned long patch_offset = (unsigned long)target_ptr - page_start;
	[retStr appendString:@"\n[*] ptrace target address: "];
	[retStr appendString:(id)[@((uintptr_t)target_ptr) stringValue]]
	[retStr appendString:@" and offset: "];
	[retStr appendString:(id)[@((uintptr_t)patch_offset) stringValue]]
	[retStr appendString:@"\n"];
	

	// map new page for patch
	
	void *new_page = (void *)mmap(NULL, PAGE_SIZE, 0x1 | 0x2, 0x1000 | 0x0001, -1, 0);
	if (!new_page ){
		[retStr appendString:@"[-] mmap failed!\n"];
		return;
	}


	[retStr appendString:@"[*] mmap new page: "];
	[retStr appendString:(id)[@((uintptr_t)new_page) stringValue]]
	[retStr appendString:@" success. \n"];

	kret = (kern_return_t)vm_copy(self_task, (unsigned long)page_start, PAGE_SIZE, (vm_address_t) new_page);
	if (kret != KERN_SUCCESS){
		[retStr appendString:@"[-] vm_copy faild!\n"];
		return;
	}
	[retStr appendString:@"[+] vm_copy target to new page.\n"];

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
	[retStr appendString:@"[+] patch ret[0xc0 0x03 0x5f 0xd6] with memcpy\n"];
	
	// set back to r-x
	(int)mprotect(new_page, PAGE_SIZE, PROT_READ | PROT_EXEC);
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

	prot = vm_info.protection & (PROT_READ | PROT_WRITE | PROT_EXEC);
	inherit = vm_info.inheritance;
	[retStr appendString:@"[*] get page info done.\n"];
	
	vm_prot_t c;
	vm_prot_t m;
	mach_vm_address_t target = (mach_vm_address_t)page_start;
	
	kret = (kern_return_t)mach_vm_remap(self_task, &target, PAGE_SIZE, 0,
					   VM_FLAGS_OVERWRITE, self_task,
					   (mach_vm_address_t) new_page, true,
					   &c, &m, inherit);
	if (kret != KERN_SUCCESS){
		[retStr appendString:@"[-] remap mach_vm_remap faild!\n"];
		return;
	}
	[retStr appendString:@"[+] remap to target success!\n"];

	// clear cache
	void* clear_start_ = (void*)(page_start + patch_offset);
	sys_icache_invalidate (clear_start_, 4);
	sys_dcache_flush (clear_start_, 4);

	[retStr appendString:@"[*] clear cache success!\n"];
	
	[retStr appendString:@"[+] all done! happy debug~"];

	retStr
	'''

	retStr = exeScript(debugger, command_script)
	return hexIntInStr(retStr)

def getTextSegmentAddr(debugger):
	command_script = '@import Foundation;' 
	command_script += r'''
	NSMutableString* retStr = [NSMutableString string];

	#define MH_MAGIC_64 0xfeedfacf 
	#define	LC_SEGMENT_64	0x19
	typedef int                     integer_t;
	typedef integer_t       cpu_type_t;
	typedef integer_t       cpu_subtype_t;
	typedef integer_t       cpu_threadtype_t;

	struct mach_header_64 {
		uint32_t	magic;		/* mach magic number identifier */
		cpu_type_t	cputype;	/* cpu specifier */
		cpu_subtype_t	cpusubtype;	/* machine specifier */
		uint32_t	filetype;	/* type of file */
		uint32_t	ncmds;		/* number of load commands */
		uint32_t	sizeofcmds;	/* the size of all the load commands */
		uint32_t	flags;		/* flags */
		uint32_t	reserved;	/* reserved */
	};

	struct load_command {
		uint32_t cmd;		/* type of load command */
		uint32_t cmdsize;	/* total size of command in bytes */
	};

	typedef int             vm_prot_t;
	struct segment_command_64 { /* for 64-bit architectures */
		uint32_t	cmd;		/* LC_SEGMENT_64 */
		uint32_t	cmdsize;	/* includes sizeof section_64 structs */
		char		segname[16];	/* segment name */
		uint64_t	vmaddr;		/* memory address of this segment */
		uint64_t	vmsize;		/* memory size of this segment */
		uint64_t	fileoff;	/* file offset of this segment */
		uint64_t	filesize;	/* amount to map from the file */
		vm_prot_t	maxprot;	/* maximum VM protection */
		vm_prot_t	initprot;	/* initial VM protection */
		uint32_t	nsects;		/* number of sections in segment */
		uint32_t	flags;		/* flags */
	};

	struct section_64 { /* for 64-bit architectures */
		char		sectname[16];	/* name of this section */
		char		segname[16];	/* segment this section goes in */
		uint64_t	addr;		/* memory address of this section */
		uint64_t	size;		/* size in bytes of this section */
		uint32_t	offset;		/* file offset of this section */
		uint32_t	align;		/* section alignment (power of 2) */
		uint32_t	reloff;		/* file offset of relocation entries */
		uint32_t	nreloc;		/* number of relocation entries */
		uint32_t	flags;		/* flags (section type and attributes)*/
		uint32_t	reserved1;	/* reserved (for offset or index) */
		uint32_t	reserved2;	/* reserved (for count or sizeof) */
		uint32_t	reserved3;	/* reserved */
	};

	int offset = 0;
	struct mach_header_64* header = (struct mach_header_64*)_dyld_get_image_header(0);

	if(header->magic != MH_MAGIC_64) {
	    return ;
	}

	offset = sizeof(struct mach_header_64);
	int ncmds = header->ncmds;

	while(ncmds--) {
	    /* go through all load command to find __TEXT segment*/
	    struct load_command * lcp = (struct load_command *)((uint8_t*)header + offset);
	    offset += lcp->cmdsize;
	    
	    if(lcp->cmd == LC_SEGMENT_64) {
	        struct segment_command_64 * curSegment = (struct segment_command_64 *)lcp;
	        struct section_64* curSection = (struct section_64*)((uint8_t*)curSegment + sizeof(struct segment_command_64));
	        
	        // check current section of segment is __TEXT?
	        if(!strcmp(curSection->segname, "__TEXT") && !strcmp(curSection->sectname, "__text")){
	            uint64_t memAddr = curSection->addr;
	           
	            uint64_t textStart = memAddr + (uint64_t)_dyld_get_image_vmaddr_slide(0);
	            uint64_t textEnd = textStart + curSection->size;
	            [retStr appendString:@" "];
	            [retStr appendString:(id)[@(textStart) stringValue]];
	            [retStr appendString:@" , "];
	            [retStr appendString:(id)[@(textEnd) stringValue]];
	            break;
	        }
	        
	    }
	}

	retStr
	'''
	retStr = exeScript(debugger, command_script)
	return hexIntInStr(retStr)

def lookupObjectC(debugger, startAddr, endAddr):
	command_script = '@import Foundation;\n'
	command_script += 'uint64_t text_start = {};uint64_t text_end = {};\n'.format(startAddr, endAddr)
	command_script += r'''
	NSMutableString* retStr = [NSMutableString string];
	uint8_t * p = (uint8_t*)text_start;
    int size = text_end - text_start;

    for(int i = 0; i < size ;i++ ){
        /*
         mov       x16, #0x1a -> 0xd2800350
         svc        #0x80 -> 0xd4001001
         */
        if (*((uint32_t*)p) == 0xd4001001) {
        	[retStr appendString:@" "];
            [retStr appendString:(id)[@((uint64_t)p) stringValue]];
        }
        p++;
    }
	retStr
	'''
	retStr = exeScript(debugger, command_script)
	return hexIntInStr(retStr)

def xia0Hook(debugger, svcAddr):
	command_script = '@import Foundation;\n'
	command_script += 'uint64_t target_addr = {};\n'.format(svcAddr)
	command_script += r'''
	NSMutableString* retStr = [NSMutableString string];

	#define PAGE_SIZE        0x0000000000004000

	#define PAGE_MASK        0x0000000000003fff

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

	int len = (int)sysconf(_SC_PAGESIZE);

	[retStr appendString:@"len= "];
	[retStr appendString:(id)[@(len) stringValue]];
	[retStr appendString:@"\n"];
    
    // 1. get target address page and patch offset
    unsigned long page_start = (unsigned long) (target_addr) & ~PAGE_MASK;
    unsigned long patch_offset = (unsigned long)target_addr - page_start;

    
    // 2. map new page for patch
    void *new_page = (void *)mmap(NULL, PAGE_SIZE, 0x1 | 0x2, 0x1000 | 0x0001, -1, 0);

    [retStr appendString:@"new_page= "];
	[retStr appendString:(id)[@((uint64_t)new_page) stringValue]];
	[retStr appendString:@"\n"];

	// 3.copy target 4 ins to new page
    int copy_size = 4*4;
    void* copy_from_addr = ( void*)(target_addr - copy_size);
    memcpy((void *)(new_page), copy_from_addr, copy_size);

    /*
     cmp x16, #0x1a
     b.ne loc_not_ptrace_svc_jmp
     ldr x17, #0x8
     br x17
     orig_svc_next_addr_1
     orig_svc_next_addr_2
     ldr x17, #0x8
     br x17
     orig_svc_addr_1
     orig_svc_addr_2
     */

    uint64_t orig_svc_addr = (uint64_t)target_addr;
    uint64_t orig_svc_next_addr = (uint64_t)(target_addr+1*4);
    uint8_t check_jmp_data[] = {0x1f, 0x6a, 0x00, 0xf1, 0x51, 0x00, 0x00, 0x58, 0x20, 0x02, 0x1f, 0xd6, (uint8_t)((orig_svc_next_addr&0xff)), (uint8_t)((orig_svc_next_addr>>8*1)&0xff),  (uint8_t)((orig_svc_next_addr>>8*2)&0xff),  (uint8_t)((orig_svc_next_addr>>8*3)&0xff),  (uint8_t)((orig_svc_next_addr>>8*4)&0xff),  (uint8_t)((orig_svc_next_addr>>8*5)&0xff),  (uint8_t)((orig_svc_next_addr>>8*6)&0xff),  (uint8_t)((orig_svc_next_addr>>8*7)&0xff), 0x51, 0x00, 0x00, 0x58, 0x20, 0x02, 0x1f, 0xd6, (uint8_t)((orig_svc_addr&0xff)), (uint8_t)((orig_svc_addr>>8*1)&0xff),  (uint8_t)((orig_svc_addr>>8*2)&0xff),  (uint8_t)((orig_svc_addr>>8*3)&0xff),  (uint8_t)((orig_svc_addr>>8*4)&0xff),  (uint8_t)((orig_svc_addr>>8*5)&0xff),  (uint8_t)((orig_svc_addr>>8*6)&0xff), (uint8_t)((orig_svc_addr>>8*7)&0xff)};
    int check_jmp_data_size = 10*4;
    memcpy((void *)((uint64_t)new_page+4*4), (void*)check_jmp_data, check_jmp_data_size);

    // 4.patch target address to jmp hook code
    void* patch_addr = copy_from_addr;
    uint64_t new_p = (uint64_t)new_page;
    
    /*
     ldr x16, #0x8
     br x16
     hook_code_addr_1
     hook_code_addr_2
     */
	uint8_t patch_data[] = {0x50, 0x00, 0x00, 0x58, 0x00, 0x02, 0x1f, 0xd6, (uint8_t)(new_p&0xff), (uint8_t)((new_p>>8*1)&0xff),  (uint8_t)((new_p>>8*2)&0xff),  (uint8_t)((new_p>>8*3)&0xff),  (uint8_t)((new_p>>8*4)&0xff),  (uint8_t)((new_p>>8*5)&0xff),  (uint8_t)((new_p>>8*6)&0xff),  (uint8_t)((new_p>>8*7)&0xff)};
	int patch_data_size = 4*4;

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

	// 5. set new page to r-x
    mprotect(new_page, len, PROT_READ | PROT_EXEC);

	retStr
	'''
	retStr = exeScript(debugger, command_script)
	return hexIntInStr(retStr)

def traceOC(debugger):
	print("[*] start patch ptrace funtion to bypass antiDebug")
	patchPtrace(debugger)
	print("[+] success ptrace funtion to bypass antiDebug")

	print("[*] start patch svc ins to bypass antiDebug")
	# get text segment start/end address 
	
	ret = getTextSegmentAddr(debugger)
	textAddrs = ret.split(',')

	if len(textAddrs) < 2:
		print("[-] failed to get text segment:" + str(textAddrs))
		return

	textStart = ret.split(',')[0]
	textEnd = ret.split(',')[1]
	textStart = textStart.strip()
	textEnd = textEnd.strip()

	print("[+] get text segment start address:{} and end address:{}".format(textStart, textEnd))
	
	# lookup svc ins go through all text code
	ret = lookupObjectC(debugger, textStart, textEnd)
	svcAddrs = ret.strip()
	svcAddrs = svcAddrs.split()

	if len(svcAddrs) < 1:
		print("[-] not found svc ins, so don't need patch")
		return

	for svcAddr in svcAddrs:
		print("[+] found svc address:{}".format(svcAddr))
		print("[*] start hook svc at address:{}".format(svcAddr))
		ret = xia0Hook(debugger, svcAddr)
		if ret:
			print("[+] success hook svc at address:{}".format(svcAddr))


	print("[*] all patch done")

	return

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
	usage = "traceOC"
	parser = optparse.OptionParser(usage=usage, prog="lookup")

	parser.add_option("-a", "--address",
					action="store_true",
					default=None,
					dest='patchAddress',
					help="kill anti-debug in lldb")
						
	return parser
