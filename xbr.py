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

specail thanks to xia0z & Proteas

'''

import lldb
import commands
import shlex
import optparse
import re

def __lldb_init_module (debugger, dict):
	debugger.HandleCommand('command script add -f xbr.xbr xbr -h "set breakpoint on ObjC Method"')
	print('"xbr" installed --> xbr "-[UIView initWithFrame:]"')

def create_command_arguments(command):
	return shlex.split(command)
	
def is_command_valid(args):
	""
	if len(args) == 0:
		return False

	arg = args[0]
	if len(arg) == 0:
		return False

	ret = re.match('^[+-]\[.+ .+\]$', arg) # TODO: more strict
	if not ret:
		return False

	return True

def get_class_name(arg):
	match = re.search('(?<=\[)[^\[].*[^ ](?= +)', arg) # TODO: more strict
	if match:
		return match.group(0)
	else:
		return None

def get_method_name(arg):
	match = re.search('(?<= )[^ ].*[^\]](?=\]+)', arg) # TODO: more strict
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
	frame = get_selected_frame();
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
	frame = get_selected_frame();
	class_addr = frame.EvaluateExpression("(Class)NSClassFromString(@\"%s\")" % class_name).GetValueAsUnsigned()
	print 'classAddr:%x' % class_addr
	if class_addr == 0:
		return 0

	sel_addr = frame.EvaluateExpression("(SEL)NSSelectorFromString(@\"%s\")" % method_name).GetValueAsUnsigned()
	print 'selAddr:%x' % sel_addr
	has_method = frame.EvaluateExpression("(BOOL)class_respondsToSelector(%d, %d)" % (class_addr, sel_addr)).GetValueAsUnsigned()
	if not has_method:
		return 0

	method_addr = frame.EvaluateExpression('(void *)class_getMethodImplementation(%d, %d)' % (class_addr, sel_addr))
	
	return method_addr.GetValueAsUnsigned()

def xbr(debugger, command, result, dict):
	args = create_command_arguments(command)

	if not is_command_valid(args):
		print 'please specify the param, for example: "-[UIView initWithFrame:]"'
		return

	arg = args[0]
	class_name = get_class_name(arg)
	method_name = get_method_name(arg)
#    xlog = 'className:'+ str(class_name) + '\tmethodName:' + str(method_name)
	print class_name, method_name
	address = 0
	if is_class_method(arg):
		address = get_class_method_address(class_name, method_name)
	else:
		address = get_instance_method_address(class_name, method_name)

	print 'methodAddr:%x' % address
	if address:
		lldb.debugger.HandleCommand ('breakpoint set --address %x' % address)
	else:
		print "fail, please check the arguments"
