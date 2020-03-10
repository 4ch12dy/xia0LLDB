#!/bin/bash
shell_root_dir=$(pwd)
xlldb_file="xlldb.py"
xlldb_file_path="$shell_root_dir/src/$xlldb_file"
lldbinit="$HOME/.lldbinit"

sed -i "" '/.*xlldb\.py/d' $lldbinit 2>/dev/null

echo "[*] delete origin xia0LLDB in $lldbinit"

if [[ -f $lldbinit ]]; then
    echo "[*] lldbinit file exist, add $xlldb_file_path to $lldbinit"
    echo -e "\ncommand script import $xlldb_file_path" >> $lldbinit
    echo -e "\ncommand alias freshxlldb command script import $xlldb_file_path" >> $lldbinit
else
    echo "[+] lldbinit file not exist, add $xlldb_file_path to $lldbinit"
    echo -e "\ncommand script import $xlldb_file_path" > $lldbinit
    echo -e "\ncommand alias freshxlldb command script import $xlldb_file_path" >> $lldbinit
fi

echo "[+] xia0LLDB has installed! Happy debugging~"