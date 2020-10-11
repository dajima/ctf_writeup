# CTF中fd(0,1,2)被关闭获取shell回显的分析
## 使用xinetd部署题目
![1](./1.PNG)
这种情况下，fd(0,1,2)都被重定向到同一个socket中了，所以可以考试使用dup2()系统调用复制一个fd，相当于重新打开标准输入输出，这样就可以获取shell回显，如果fd(0,1,2)都被关闭那可以考虑复制socket句柄到fd(0,1,2)？还没试验过，如果fd(0,1,2)都关闭了，可以尝试open /dev/tty或者/dev/pts/?

执行如下命令可以直接重定向fd，https://stackoverflow.com/questions/30968734/reopen-stdout-and-stderr-after-closing-them
$ exec 1>&0
$ exec 2>&0

## 使用pwntools调试
![5](./5.PNG)

可以看到pwntools脚本启动二进制时，标准输入是一个管道，用于连接Python脚本和二进制程序，标准输出和错误输出是tty设备，因此通过dup2的方式只能复制管道fd，如下，依旧无法打开标准输出获取shell回显。

![4](./4.PNG)

### pwntools open /dev/tty
![7](./7.PNG)
使用如下命令，可以确认， /dev/tty指向的是当前进程的终端，因此向 /dev/tty输入会回显到bash中
![6](./6.PNG)
shellcode中打开 /dev/tty后，标准输入变成了 /dev/tty的句柄，因此标准输出可以回显，理论上在实际题目使用socket重定向的场景先open (/dev/tty)这种方式打开的句柄应该无法回显，因为没有重定向到socket，但是别人成功了，不知道为什么？

![8](./8.PNG)

这是本地用socat作的实验，成功打开了/dev/tty，可以看到fd1，但是依旧无法获得回显，因为正常回显要从unix socket到socat发给client，直接发给tty理论上是服务看到回显的

![9](./9.PNG)

回显到了socat启动的地方，说明/dev/tty绑定的是socat启动的bash终端


## 使用socat部署
![2](./2.PNG)

使用socat部署题目标准输入输出被重定向到unix socket，此时通过dup2（0，1）可以打开标准输出获取shell回显

## 直接运行二进制题目


![3](./3.PNG)

直接运行二进制fd(0,1,2)都指向了tty设备，此时dup复制任意fd(0,1,2)都可以，也可以通过open（/dev/tty）的方式打开标准输出