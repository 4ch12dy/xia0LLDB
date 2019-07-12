## xia0's lldb python script (Progressing)

### Install 

`git clone `项目以后，在`lldb`命令行中输入`command script import git-xia0LLDB-path/xlldb.py `即可导入安装

### Commands

- `pcc` 这个命令仅仅是 `process connect connect://127.0.0.1:1234 `的一个alias，后面输入目标ip和port连接到目标设备。例如：`pcc `

- `xbr`可以直接对OC函数下断点，即使macho符号表被strip。例如：`xbr "-[yourClass yourMethod]"`

- `sbt`代替系统的`bt`命令，专门为了strip后的栈符号恢复。仅仅输入`sbt`即可。`sbt`还可以恢复block函数符号，通过提供的ida python脚本得到的json文件，然后输入`sbt -f block_json_file_path` 即可解析block符号。如下效果：

  #### 原始bt结果

  ![orig_bt](./resource/orig_bt.png)

  #### sbt （不带block符号文件）

  ![sbt-noblockfile](./resource/sbt-noblockfile.png)

  #### sbt （带有block符号文件）

  ![sbt-blockfile](./resource/sbt-blockfile.png)

  

  `sbt`命令可以提供更多的信息，内存地址在文件中的地址，不用手动计算直接在ida中查找即可。更强大的是可以恢复OC函数的符号，很清晰就能看到当前的调用栈情况。

### Update

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



### Document

- [关于项目的分析](http://4ch12dy.site/2018/10/03/xia0LLDB/xia0LLDB/)
- [此项目的Frida移植版本](http://4ch12dy.site/2019/07/02/xia0CallStackSymbols/xia0CallStackSymbols/)

### Credits

- [http://blog.imjun.net/posts/restore-symbol-of-iOS-app/](http://blog.imjun.net/posts/restore-symbol-of-iOS-app/)
- [https://lldb.llvm.org/tutorial.html](https://lldb.llvm.org/tutorial.html)

