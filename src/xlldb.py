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
import utils
import colorme


XLLDB_VERSION = "3.1"

def banner():
    # pylint: disable
    xia0LLDB = r'''
           https://github.com/4ch12dy/xia0LLDB
          Welcome to xia0LLDB - Python3 Edition
          ,--.          ,--.  ,--.   ,--.   ,------.  ,-----.   
,--.  ,--.`--' ,--,--. /    \ |  |   |  |   |  .-.  \ |  |) /_  
 \  `'  / ,--.' ,-.  ||  ()  ||  |   |  |   |  |  \  :|  .-.  \ 
 /  /.  \ |  |\ '-'  | \    / |  '--.|  '--.|  '--'  /|  '--' /  
'--'  '--'`--' `--`--'  `--'  `-----'`-----'`-------' `------'   
'''
    return xia0LLDB

def __lldb_init_module(debugger, internal_dict):
    print(banner())
    print("[xia0LLDB] * Version: {} ".format(XLLDB_VERSION))
    colorme.bootstrap_notice()
    file_path = os.path.realpath(__file__)
    dir_name = os.path.dirname(file_path)
    print("[xia0LLDB] + Loading all scripts from " + dir_name)
    load_python_scripts_dir(dir_name,debugger)
    print("[xia0LLDB] * Finished ")

def load_python_scripts_dir(dir_name, debugger):
    this_files_basename = os.path.basename(__file__)
    cmd = ''
    for file in os.listdir(dir_name):
        if file.endswith('.py'):
            cmd = 'command script import ' 
        elif file.endswith('.txt'):
            cmd = 'command source -e0 -s1 '
        else: 
            continue

        if file != this_files_basename:
            fullpath = dir_name + '/' + file
            utils.exe_cmd(debugger, cmd + fullpath)
