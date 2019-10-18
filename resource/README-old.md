## xia0's lldb python script (Progressing)

[中文版README](./README-zh.md)

### Warning(注意)

There is a problem that lldb import xia0LLDB  in last macOS Catalina, because the last macOS's lldb default use python3. Here is a way to change it to python2

```
defaults write com.apple.dt.lldb DefaultPythonVersion 2
```

thanks to xqwang@wxq491216 provide this solution.  I will update xia0LLDB with python3 soon.



由于mac新系统Catalina中的lldb默认为python3解释器，所以xia0LLDB导入的时候会报错，可以通过以下修改lldb的Python解释器版本

```bash
defaults write com.apple.dt.lldb DefaultPythonVersion 2
```

感谢xqwang@wxq491216提供的解决方案，有时间的话我会尽快将项目移植到Python3版本

### Install 

`git clone xia0LLDB_git_project `

`command script import git-xia0LLDB-path/xlldb.py` in lldb or `.lldbinit`

you can run `install.sh` auto add command script import git-xia0LLDB-path/xlldb.py to your `.lldbinit`

Happy debugging~~

### Commands

- `pcc`  is alias of  `process connect connect://127.0.0.1:1234 `
- `xbr   `  set breakpoint at OC class method although strip symbol like:`xbr "-[yourClass yourMethod]"`
- `sbt` the replacement of `bt` , it can restore frame OC symbol on stackframe. if you want to restore block symbol, you can use the ida python script provided to get block symbol json file. then input `sbt -f  block_json_file_path`  in lldb. Beside it can show more infomation: mem address, file address
- `xutil` this command has some useful tools(maybe fixable)
- `info` very useful command to get info of address/function/module and so on
- `ivars`  print all ivars of OC object (iOS Only)
- `methods`print all methods of OC object (iOS Only)
- `choose` get instance object of given class name, a lldb version of cycript's choose command
- `debugme` hook ptrace and inlinehook svc ins done.
- `dumpdecrypted` dump macho file in lldb
- `patcher` runtime patch instrument in lldb

### TODO

- Anti-anti-debug：bypass anti debug in lldb （done at 2019/09/11）
- OCHOOK：hook ObjectC function in lldb
- NetworkLog：minitor network info
- UI Debug：some useful command for UI debug
- xbr: set breakpoint at address of methods of class（done at 2019/08/11）
- traceOC: trace ObjectC call by inlinehook msg_send stub code
- ...

### Update

- [2019/07/04] Update for **sbt -x / xutil**  :  xutil cmd and sbt -x to disable color output in Xcode
- [2019/07/21] Update for  **choose**  : lldb's choose command version of cycript's choose command
- [2019/08/07] Fix critical bugs in **choose**  : Fix critical bugs
- [2019/08/11] Update for **xbr** : `xbr className` can set breakpoint at adresses of all methods of class
- [2019/08/13] New **debugme**: kill anti debug in lldb
- [2019/08/20] New **info**:  get info of address/function/module and so on
- [2019/09/11] **debugme** update: hook ptrace and inlinehook svc ins done.
- [2019/09/22] new **dumpdecrypted**: dump macho image in lldb
- [2019/09/27] **dumpdecrypted** update: can dump all image in app dir 
- [2019/10/17] new  **patcher** :runtime patch instrument in lldb



#### Update for sbt -x 2019/07/04

disable color output for Xcode terminal not support color output.

**sbt**

```
Usage: sbt -f block-json-file-path

Options:
  -h, --help            show this help message and exit
  -f FILE, --file=FILE  special the block json file
  -x, --XcodeNoColor    disable color output for Xcode
  -r, --reset           reset block file to None
```

**xutil**

```
(lldb) xutil -h
Usage: xutil [options] args

Options:
  -h, --help            show this help message and exit
  -b MAINMODULEADDRESS, --breakpointAtMainModule=MAINMODULEADDRESS
                        set a breakpoint at main module of given address
  -s SILDEMODULE, --slide=SILDEMODULE
                        get slide of given module
  -l LOADMODULE, --load=LOADMODULE
                        load a macho file
```

- `xutil -b mainModuleAddress`: auto set breakpoint of address on main image (auto add the main image slide)

  ```
  (lldb) xutil -b 0x0000000100009b60
  Breakpoint 2: where = choose`-[ViewController onClick:] at ViewController.m:53, address = 0x000000010001db60
  ```

- `xutil -s moduleName`: get silde of given module name

  ```
  (lldb) xutil -s choose
  Module:/var/containers/Bundle/Application/2E718F3A-CCBF-4251-9BB6-BBF57267CABB/choose.app/choose
  Silde:0x14000
  ```

- `xutil -l machoFilePath`: load the macho file like dylib in the process

  ```
  (lldb) xutil -l /Library/MobileSubstrate/DynamicLibraries/test.dylib
  Success
  ```

  

#### Update for choose 2019/07/21

##### choose

lldb's choose command version of cycript's choose command, test on iPhone6P in iOS10. **enjoy~**

```
(lldb) choose
[usage] choose className

(lldb) choose AppDelegate
<__NSArrayM 0x170054370>(
<AppDelegate: 0x17403e840>
)

(lldb) choose ViewController
<__NSArrayM 0x174054a90>(
<ViewController: 0x109e10550>
)
```

一些解释：

关于那两个计算公式的解释：iOS的malloc分配内存的时候会有tiny和small两种region。其中tiny以16B为quantum，small以512B为quantum。并且tiny在32位、64位机器上size分别为496B和1008B。所以，needed <= boundary是在检查分配内存是否小于tiny的size。(needed + 15) / 16 * 16 != size)主要是检查分配大小needed是否为16的倍数。更多关于苹果堆设计可以看我分析的一遍文章：

[http://4ch12dy.site/2019/04/01/%E6%B7%B1%E5%85%A5%E7%90%86%E8%A7%A3macos-heap/%E6%B7%B1%E5%85%A5%E7%90%86%E8%A7%A3macos-heap/](http://4ch12dy.site/2019/04/01/深入理解macos-heap/深入理解macos-heap/)



~~Tips: It seemdifferent of heap layout by malloc in iOS12, So choose cmd maybe has some bugs~~

~~说明:iOS12可能是malloc的布局发生了一些变化，导致choose的时候可能出现bug，后面有时间在适配一下。~~

是我自己代码写得有问题导致得….其他设备或者系统如果有问题的话，欢迎issue 或pr



#### Fix critical bugs in choose 2019/08/07

fix need check and something error when choose NSString



#### Update for xbr 2019/08/11

`xbr className` can set breakpoint at adresses of all methods of given class name.

```
(lldb) xbr UPLivePlayerVC
Breakpoint 1: where = TestPaly`-[UPLivePlayerVC progressSliderSeekTime:] at UPLivePlayerVC.m:205, address = 0x0000000102dc134c
Breakpoint 2: where = TestPaly`-[UPLivePlayerVC progressSliderTouchDown:] at UPLivePlayerVC.m:197, address = 0x0000000102dc1184
Breakpoint 3: where = TestPaly`-[UPLivePlayerVC progressSliderValueChanged:] at UPLivePlayerVC.m:201, address = 0x0000000102dc11ec
...
Breakpoint 45: where = TestPaly`-[UPLivePlayerVC setUrl:] at UPLivePlayerVC.h:13, address = 0x0000000102dc2990
Breakpoint 46: where = TestPaly`-[UPLivePlayerVC play] at UPLivePlayerVC.m:124, address = 0x0000000102dbfd84
Breakpoint 47: where = TestPaly`-[UPLivePlayerVC pause] at UPLivePlayerVC.m:132, address = 0x0000000102dbfe1c
Set 47 breakpoints of UPLivePlayerVC
```

usage is above. Enjoy~

#### New debugme 2019/08/13

Base single instruction patch to anti-anti-debug in lldb 

```
(lldb) debugme
Kill antiDebug by xia0:
[*] target address: 6501024128 and offset: 384
[*] mmap new page: 4572217344 success! 
[+] vm_copy success!
[+] mach_vm_write success!
[*] set new page back to r-x success!
[*] vm_region_recurse_64 success!
[*] get page info success!
[+] remap success!
[*] clear cache success!
[+] all done! happy debug~
```

paper see：http://4ch12dy.site/2019/08/12/xia0lldb-anti-anti-debug/xia0lldb-anti-anti-debug/

##### fix iOS11/12 vm_remap bug 2019/09/04

This bug is about wrong memory page size. I use the 4K on 32bit device instead of 16K on 64bit device.

Fxxk it!!! confuse me long time!

##### inline hook svc done 2019/09/11

now debugme can hook ptrace and inlinehook svc to kill anti debug. it is so strong ever!!!

```
[*] start patch ptrace funtion to bypass antiDebug
[+] success ptrace funtion to bypass antiDebug
[*] start patch svc ins to bypass antiDebug
[+] get text segment start address:0x100017430 and end address:0x10001a398
[+] found svc address:0x100017528
[*] start hook svc at address:0x100017528
[+] success hook svc at address:0x100017528
[+] found svc address:0x100017540
[*] start hook svc at address:0x100017540
[+] success hook svc at address:0x100017540
[*] all patch done
[x] happy debugging~ kill antiDebug by xia0@2019
```

#### New info 2019/08/20

get info of address/function/module and so on

```
usage: info  [-m moduleName, -a address, -f funtionName, -u UserDefaults]
```



#### Update xbr 2019/09/22

add new options :  set breakpoint at main/init function and more set br utils

##### set br at main/init func

parse macho image in memory and found `LC_MAIN` and `__DATA,__mod_init_func`

```
(lldb) xbr -E init
[*] breakpoint at mod int first function:0x1034c7db8
Breakpoint 2: where = WeChat ___lldb_unnamed_symbol143521$$WeChat, address = 0x00000001034c7db8

(lldb) xbr -E main
[*] breakpoint at main function:0x10001ba94
Breakpoint 3: where = com_kwai_gif`___lldb_unnamed_symbol36$$com_kwai_gif, address = 0x000000010001ba94
```



#### New dumpdecrypted 2019/09/22

dump macho image in lldb

```
(lldb) dumpdecrypted
[+] Dumping WeChat
[+] detected 64bit ARM binary in memory.
[+] offset to cryptid found: @0x100018d48(from 0x100018000) = d48
[+] Found encrypted data at address 00004000 of length 101662720 bytes - type 1.
[+] Opening /private/var/containers/Bundle/Application/86E712C8-84CA-49AF-B2EA-01C37395A746/WeChat.app/WeChat for reading.
[+] Reading header
[+] Detecting header type
[+] Executable is a plain MACH-O image
[+] Opening /var/mobile/Containers/Data/Application/9649276C-C413-4916-B5AB-AE13C8D7B652/Documents/WeChat.decrypted for writing.
[+] Copying the not encrypted start of the file
[+] Dumping the decrypted data into the file
[+] Copying the not encrypted remainder of the file
[+] Setting the LC_ENCRYPTION_INFO->cryptid to 0 at offset d48
[+] Closing original file
[+] Closing dump file
[*] This mach-o file decrypted done.

Developed By xia0@2019
```

##### update dumpdecrypted 2019/09/27

can dump all images in app dir

```
(lldb) dumpdecrypted
[*] start dump image:/var/containers/Bundle/Application/701B4574-1606-41F3-B0DB-92D34F92E886/com_kwai_gif.app/com_kwai_gif

[+] Dumping com_kwai_gif
[+] detected 64bit ARM binary in memory.
[+] offset to cryptid found: @0x100014980(from 0x100014000) = 980
[+] Found encrypted data at address 00004000 of length 16384 bytes - type 1.
[+] Opening /private/var/containers/Bundle/Application/701B4574-1606-41F3-B0DB-92D34F92E886/com_kwai_gif.app/com_kwai_gif for reading.
[+] Reading header
[+] Detecting header type
[+] Executable is a plain MACH-O image
[+] Opening /var/mobile/Containers/Data/Application/23C75F90-C42D-4F43-83D9-5DCCA36FE2D5/Documents/com_kwai_gif.decrypted for writing.
[+] Copying the not encrypted start of the file
[+] Dumping the decrypted data into the file
[+] Copying the not encrypted remainder of the file
[+] Setting the LC_ENCRYPTION_INFO->cryptid to 0 at offset 980
[+] Closing original file
[+] Closing dump file
[*] This mach-o file decrypted done.
[+] dump macho file at:/var/mobile/Containers/Data/Application/23C75F90-C42D-4F43-83D9-5DCCA36FE2D5/Documents/com_kwai_gif.decrypted


[*] start dump image:/private/var/containers/Bundle/Application/701B4574-1606-41F3-B0DB-92D34F92E886/com_kwai_gif.app/Frameworks/gifIMFramework.framework/gifIMFramework

[+] Dumping gifIMFramework
[+] detected 64bit ARM binary in memory.
[+] offset to cryptid found: @0x100064bd0(from 0x100064000) = bd0
[+] Found encrypted data at address 00004000 of length 2752512 bytes - type 1.
[+] Opening /private/var/containers/Bundle/Application/701B4574-1606-41F3-B0DB-92D34F92E886/com_kwai_gif.app/Frameworks/gifIMFramework.framework/gifIMFramework for reading.
[+] Reading header
[+] Detecting header type
[+] Executable is a plain MACH-O image
[+] Opening /var/mobile/Containers/Data/Application/23C75F90-C42D-4F43-83D9-5DCCA36FE2D5/Documents/gifIMFramework.decrypted for writing.
[+] Copying the not encrypted start of the file
[+] Dumping the decrypted data into the file
[+] Copying the not encrypted remainder of the file
[+] Setting the LC_ENCRYPTION_INFO->cryptid to 0 at offset bd0
[+] Closing original file
[+] Closing dump file
[*] This mach-o file decrypted done.
[+] dump macho file at:/var/mobile/Containers/Data/Application/23C75F90-C42D-4F43-83D9-5DCCA36FE2D5/Documents/gifIMFramework.decrypted

...
[*] Developed By xia0@2019
```

#### New patcher 2019/10/17

runtime patch instrument in lldb, now support instrument : nop, ret

```
(lldb) patcher -a 0x0000000100233a18 -i nop -s 8
[*] start patch text at address:0x100233a18 size:8 to ins:"nop" and data:0x1f, 0x20, 0x03, 0xd5 
[*] make ins data:
{0x1f, 0x20, 0x03, 0xd5 ,0x1f, 0x20, 0x03, 0xd5 ,0x1f, 0x20, 0x03, 0xd5 ,0x1f, 0x20, 0x03, 0xd5 ,0x1f, 0x20, 0x03, 0xd5 ,0x1f, 0x20, 0x03, 0xd5 ,0x1f, 0x20, 0x03, 0xd5 ,0x1f, 0x20, 0x03, 0xd5 }
[+] patch done
[x] power by xia0@2019
(lldb) x/12i 0x0000000100233a18
    0x100233a18: 0xd503201f   nop    
    0x100233a1c: 0xd503201f   nop    
    0x100233a20: 0xd503201f   nop    
    0x100233a24: 0xd503201f   nop    
    0x100233a28: 0xd503201f   nop    
    0x100233a2c: 0xd503201f   nop    
    0x100233a30: 0xd503201f   nop    
    0x100233a34: 0xd503201f   nop    
    0x100233a38: 0xf941ac14   ldr    x20, [x0, #0x358]
    0x100233a3c: 0xf9419c15   ldr    x21, [x0, #0x338]
    0x100233a40: 0xf941a400   ldr    x0, [x0, #0x348]
    0x100233a44: 0xf9400008   ldr    x8, [x0]
```



### Screenshot

**bt**

![orig_bt](./resource/orig_bt.png)

**sbt**

![sbt-noblockfile](./resource/sbt-noblockfile.png)

**sbt -f block_json_file**

![sbt-blockfile](./resource/sbt-blockfile.png)

**debugme**

![debugme](./resource/debugme.png)



### Document

- [About_this_project](http://4ch12dy.site/2018/10/03/xia0LLDB/xia0LLDB/)
- [sbt command for frida](http://4ch12dy.site/2019/07/02/xia0CallStackSymbols/xia0CallStackSymbols/)

### Credits

- [http://blog.imjun.net/posts/restore-symbol-of-iOS-app/](http://blog.imjun.net/posts/restore-symbol-of-iOS-app/) thanks to the ida_block_json.py script

- https://github.com/DerekSelander/LLDB Special thanks to DerekSelander's LLDB provide the code framework

- [https://lldb.llvm.org/tutorial.html](https://lldb.llvm.org/tutorial.html) 

- https://github.com/hankbao/Cycript/blob/bb99d698a27487af679f8c04c334d4ea840aea7a/ObjectiveC/Library.mm choose command in cycript

- https://opensource.apple.com/source/lldb/lldb-179.1/examples/darwin/heap_find/heap.py.auto.html

  Apple lldb opensource about heap

- [https://blog.0xbbc.com/2015/07/%e6%8a%bd%e7%a6%bbcycript%e7%9a%84choose%e5%8a%9f%e8%83%bd/](https://blog.0xbbc.com/2015/07/抽离cycript的choose功能/) 

