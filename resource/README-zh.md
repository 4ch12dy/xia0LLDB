## xia0's lldb python script (开发中)

[English README](../README.md)

> 不推荐看中文的文档，除了安装以外，关于命令详情建议看英文版。中文版会比英文版更新慢很多

### 安装

`git clone xia0LLDB_git_project `

在lldb命令行之中直接输入`command script import git-xia0LLDB-path/xlldb.py` 就能导入使用

如果你想以后打开lldb就能自动导入可以运行项目目录下的自动安装脚本

运行 `install.sh` 自动添加 command script import git-xia0LLDB-path/xlldb.py 到 `.lldbinit`文件

Happy debugging~~

### 支持的命令

- `pcc`  仅仅是  `process connect connect://127.0.0.1:1234 `的简写
- `xbr   `  能够针对符号表strip以后的可执行文件对OC方法下断点，例如`xbr "-[yourClass yourMethod]"`
- `sbt`  该命令和bt命令类似，但是能够提供很多的信息。包括栈帧的内存地址，文件地址。最重要的是还能恢复strip以后的OC函数符号。如果你还想回复block的符号，可以用提供了ida脚本提取block符号以后。手动指定即可。例如 `sbt -f  block_json_file_path` 
- `xutil`  一些实用的命令集合，这个命令会不定更改，功能不是很稳定。
- `info` 非常实用的命令，能够获取地址/函数/模块的信息
- `ivars` 获取OC对象的所有成员变量信息(仅支持iOS)
- `methods` 获取对象的所有方法信息(仅支持iOS)
- `choose`  动态获取一个类在内存中的对象，这是cycript中的choose在lldb的移植版本

### 一些正在做或者想做的功能

- Anti-anti-debug：反反调试，即绕过应用的反调试机制 （已完成 2019/09/11）
- OCHOOK：在lldb中能够进行OC方法的HOOK等操作
- NetworkLog：监控lldb中能够监控网络数据
- UI Debug：一些UI相关的实用命令
- xbr增加对类所有方法下断点（已完成！2019/08/11）
- ...

### 重要更新

- [2019/07/04] 更新了 **sbt -x / xutil**  :  增加了xutil命令以及给sbt命令增加了`-x`选项去禁用xcode颜色输出
- [2019/07/21] 增加了**choose** : 增加了cycript中choose的lldb版本
- [2019/08/07] 更新了**choose** : 修复了一个严重的bug
- [2019/08/11]  更新了**xbr** : 能够通过下面的方式`xbr className` 直接对一个类的所有方法下断点
- [2019/08/13] 增加 了**debugme**: 一个在lldb中自包含的绕过反调试的命令
- [2019/08/20] 增加了**info**:  非常实用的命令，能够获取地址/函数/模块的信息
- [2019/09/11] 更新了**debugme** : 解决了通过26号系统调用内联汇编来反调试的类型



#### 更新了 sbt -x 2019/07/04

由于Xcode的终端不支持颜色输出，所以sbt命令增加了-x选项，设置以后会禁用颜色输出。

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

- `xutil -b mainModuleAddress`: 直接对ida中的地址下断点，会自动加上主模块的偏移

  ```
  (lldb) xutil -b 0x0000000100009b60
  Breakpoint 2: where = choose`-[ViewController onClick:] at ViewController.m:53, address = 0x000000010001db60
  ```

- `xutil -s moduleName`:获取给定模块的偏移

  ```
  (lldb) xutil -s choose
  Module:/var/containers/Bundle/Application/2E718F3A-CCBF-4251-9BB6-BBF57267CABB/choose.app/choose
  Silde:0x14000
  ```

- `xutil -l machoFilePath`: 记载一个dylib到目标进程

  ```
  (lldb) xutil -l /Library/MobileSubstrate/DynamicLibraries/test.dylib
  Success
  ```

  

#### 更新了choose 2019/07/21

##### choose

从cycript移植到lldb的choose命令，在iOS10 iPhone6p测试通过。 **enjoy~**

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



#### 修复了choose一个严重bug 2019/08/07

修复了堆内存zone的大小判断以及获取NSString类时候的错误



#### 更新了xbr 2019/08/11

xbr命令增加一个功能，`xbr className`就能够自动对该类的所有方法下断点，获取其方法调用顺序。

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

这里可以看出，已经对`UPLivePlayerVC`类的47个方法下了断点。

#### 增加了debugme 2019/08/13

基于内存patch的单指令patch反反调试

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

相关分析见：http://4ch12dy.site/2019/08/12/xia0lldb-anti-anti-debug/xia0lldb-anti-anti-debug/

##### 修复了在iOS11/12 vm_remap的bug 2019/09/04

这个bug困扰了我好久，修复了有内存页大小错误的bug，我错误的用了32位设备的4K页大小，正确的应该是64位设备的16K页大小

##### 通过hook svc指令绕过反调试完成 2019/09/11

现在debug命令能够hook ptrace库函数，以及svc指令来进行反调试的情况。

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

#### 增加了info 2019/08/20

获取一些关于地址/函数/模块的详细信息

```
usage: info  [-m moduleName, -a address, -f funtionName, -u UserDefaults]
```



### 相关截图

**bt**

![orig_bt](./resource/orig_bt.png)

**sbt**

![sbt-noblockfile](./resource/sbt-noblockfile.png)

**sbt -f block_json_file**

![sbt-blockfile](./resource/sbt-blockfile.png)

**debugme**

![debugme](./resource/debugme.png)



### 分析文档

- [关于项目的分析](http://4ch12dy.site/2018/10/03/xia0LLDB/xia0LLDB/)
- [此项目的Frida移植版本](http://4ch12dy.site/2019/07/02/xia0CallStackSymbols/xia0CallStackSymbols/)

### 致谢

- [http://blog.imjun.net/posts/restore-symbol-of-iOS-app/](http://blog.imjun.net/posts/restore-symbol-of-iOS-app/) thanks to the ida_block_json.py script

- https://github.com/DerekSelander/LLDB Special thanks to DerekSelander's LLDB provide the code framework

- [https://lldb.llvm.org/tutorial.html](https://lldb.llvm.org/tutorial.html) 

- https://github.com/hankbao/Cycript/blob/bb99d698a27487af679f8c04c334d4ea840aea7a/ObjectiveC/Library.mm choose command in cycript

- https://opensource.apple.com/source/lldb/lldb-179.1/examples/darwin/heap_find/heap.py.auto.html

  Apple lldb opensource about heap

- [https://blog.0xbbc.com/2015/07/%e6%8a%bd%e7%a6%bbcycript%e7%9a%84choose%e5%8a%9f%e8%83%bd/](https://blog.0xbbc.com/2015/07/抽离cycript的choose功能/) 抽离Cycript的choose功能

