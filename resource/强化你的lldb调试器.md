### 强化你的lldb调试器

### Why?

lldb作为苹果iOS和macOS的调试器在正向开发中十分强大，不过对于逆向人员来说却不是很友好。尤其是那些符号表被strip以后的执行文件。去定位追溯一个函数的执行流程时，查看当前的栈帧只有一堆内存地址，如果要定位是哪个函数通常的流程就是找到当前模块的内存偏移，然后栈上的地址逐一减去改偏移然后去ida中查找改地址，最后才能定位到函数名。流程琐碎且都是重复工作，花费大量时间去定位符号信息。因此我想做一个能自动恢复栈帧符号的命令。只要输入改命令就能显示函数的调用情况。

### How?

但是符号表都已经被strip了怎么才能恢复符号呢？我的想法就是macho可执行文件中其实是有很大一部分段储存的OC函数信息，里面肯定是有类名和方法名的，我们要做的就是通过栈中的地址，遍历所有的类以及方法，找到最佳的类方法即可。判断原则就是找到距离栈地址最近且小于等于栈地址的类方法。然后记录类名和方法名即可。

正好lldb提供了python的接口，可以开发自定义的命令。

### And what ?

虽然有python接口，但是lldb里面集成了一个OC的解释器，其语法要求特别严格，按照通常开发的写法会有很多错误，经过不断的调试和修复bug，一个开发版基于lldb python栈符号恢复命令开发完成。git地址在[这里](https://git.xiaojukeji.com/zhangshun/xia0LLDB)

这里面还有的搜索算法以及异常处理还需要优化，以及对于block这类函数还不能恢复，不过对于大多数的场景目前还是可用。具体效果可以如下：

![https://git.xiaojukeji.com/zhangshun/xia0LLDB/blob/master/resource/b_bt.jpg](https://git.xiaojukeji.com/zhangshun/xia0LLDB/blob/master/resource/b_bt.jpg)

![https://git.xiaojukeji.com/zhangshun/xia0LLDB/raw/master/resource/b_sbt.jpg](https://git.xiaojukeji.com/zhangshun/xia0LLDB/raw/master/resource/b_sbt.jpg)

