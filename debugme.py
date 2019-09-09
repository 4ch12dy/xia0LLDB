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
	'command script add -f debugme.handle_command debugme -h "kill anti-debug in lldb"')
	print('========')
	print('[debugme]: kill anti-debug in lldb')
	print('\tdebugme ')
	print('\tmore usage, try "debugme -h"')
					
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
	
	ret = debugme(debugger)
	result.AppendMessage(str('Kill antiDebug by xia0:')+str(ret))
	
	return 

def debugme(debugger):
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
	usage = "debugme"
	parser = optparse.OptionParser(usage=usage, prog="lookup")

	parser.add_option("-a", "--address",
					action="store_true",
					default=None,
					dest='patchAddress',
					help="kill anti-debug in lldb")
						
	return parser
