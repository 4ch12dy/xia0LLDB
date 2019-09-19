#!/bin/bash
shell_root_dir=$(pwd)
xlldb_file="xlldb.py"
xlldb_file_path=$shell_root_dir"/"$xlldb_file
lldbinit=$HOME"/.lldbinit"

sed -i "" '/.*xlldb\.py/d' $lldbinit

if [[ -f $lldbinit ]]; then
    echo "lldbinit file exist, add xlldb.py to $lldbinit"
    echo -e "\ncommand script import $xlldb_file_path" >> $lldbinit
else
    echo "lldbinit file not exist, add xlldb.py to $lldbinit"
    echo -e "\ncommand script import $xlldb_file_path" > $lldbinit  
fi

echo "done."