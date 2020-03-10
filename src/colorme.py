#! /usr/bin/env python3
#
# colorme.py
# xia0LLDB
#
# Created by Lakr Aream on 3/4/20.
# Copyright 2020 Lakr Aream. All rights reserved.
#

import os

# Used to test if we are in Xcode
def envtest_inXcode():
    lookup = os.environ["PATH"]
    if "/Xcode.app/Contents/Developer/usr/bin" in lookup:
        return True
    else:
        return False
    
# A summary to tell if we need to disable color output
def should_enable_color_output():
    sig1 = envtest_inXcode()
    if sig1:
        return False
    return True

# By xia0, used to append color attr to terminal
def _attr_str(msg, color='black'):      
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

# Get attr if needed
def attr_str(msg, color='black'):
    if should_enable_color_output():
        return _attr_str(msg, color)
    return msg

# Letting our user to know about it
def bootstrap_notice():
    if not should_enable_color_output():
        print("[xia0LLDB] * Disabling color in output due to Xcode detected")