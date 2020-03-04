#! /usr/bin/env python3

import re


IS_NO_COLOR_OUTPUT = False

import colorme

def ILOG(msg):
    return colorme.attrStr(msg, 'green')

def ELOG(msg):
    return colorme.attrStr(msg, 'red')

def hexIntInStr(needHexStr):

    def handler(reobj):
        intvalueStr = reobj.group(0)
        
        r = hex(int(intvalueStr))
        return r

    # pylint: disable=anomalous-backslash-in-string
    pattern = '(?<=\s)[0-9]{1,}(?=\s)'

    return re.sub(pattern, handler, needHexStr, flags = 0)
