> 近几个月在项目中使用docker和consul做了一些容器服务化的工作，这里主要是对docker用到的一些linux内核技术做总结。基本上是对[https://blog.yadutaf.fr/2014/01/19/introduction-to-linux-namespaces-part-1,2,3,4,5/](https://blog.yadutaf.fr/2013/12/22/introduction-to-linux-namespaces-part-1-uts/)，
[https://lwn.net/Articles/531114/#series_index](https://lwn.net/Articles/531114/#series_index) 这两个系列博客的翻译整合，加入了部分自己的理解。示例代码也全部来自以上两个系列文章，为了学习方便，我在github上面建了个仓库存放示例代码，[代码地址](https://github.com/shishujuan/docker-basis/tree/master)。

# 1 概述
Linux容器技术(LXC)近几年十分流行，而其依托的技术并不是很新的东西，而是Linux内核自带的一套内核级别环境隔离机制。当然，最流行的LXC技术莫过于docker了，现在社区版本更名叫moby了。 Linux容器技术依赖Linux内核的3个主要的隔离机制：chroot，cgroups，namespace。先来看看namespace，在Linux Kernel3.8以后，Linux支持6种namespace。分别是：

|namespace|含义|flag|
|:----:|:----:|:----:|
|UTS| 主机名| CLONE_NEWUTS
|IPC|进程间通信|CLONE_NEWIPC
|PID|chroot进程树|CLONE_NEWPID
|NS(FS)|挂载点(mount points)|CLONE_NEWNS
|NET|网络访问，包括接口|CLONE_NEWNET
|USER|将虚拟的本地UID映射到真实的UID|CLONE_NEWUSER


Linux内核提供了一套API用于操作namespace实现环境隔离，目前namespace操作的API包括clone(), setns()以及unshare(), 此外还有/proc下的部分文件，下面一一来看。

## 1.1 使用clone创建新进程同时创建namespace
代码 [ns.c](https://github.com/shishujuan/docker-basis/blob/master/namespace/ns.c) 从子进程运行 /bin/bash，先从这个例子来看看Linux namespace的作用（为了简单起见，略去了错误检查代码）。

注意到在代码中使用了clone来代替更常见的fork系统调用，clone实际上是Unix系统调用fork的一种更通用的实现方式，它的原型是这样的

```
int clone(int (*child_func)(void *), void *child_stack, int flags, void *arg);
```

`child_func`参数为传递子进程运行的主函数，如上面的`child_main`；`child_stack`参数为子进程使用的栈空间，参数flags可以指定使用的CLONE_*标志，一次可以指定多个flag；而args则是子进程的参数。编译运行上面的代码，结果如下所示，运行正常，但是我们很难区分这是在子进程运行的/bin/bash还是本身的/bin/bash。

```
root@ubuntu:/home/vagrant/nstest# gcc -Wall ns.c -o ns && ./ns
 - Hello ?
 - World !
root@ubuntu:/home/vagrant/nstest#  #inside container
root@ubuntu:/home/vagrant/nstest# exit
root@ubuntu:/home/vagrant/nstest#  #outside container
```

于是，`CLONE_NEWUTS`可以派上用场了。UTS namespace提供了主机名和域名的隔离，这样每个容器就有独立的主机名和域名，从而可以在网络上被当作一个独立的节点而不是宿主机的一个进程。修改clone函数这行代码，加入CLONE_NEWUTS的flag，然后在子进程中调用`sethostname`函数，修改后代码 [ns_uts.c](https://github.com/shishujuan/docker-basis/blob/master/ns_uts.c)

以root身份运行它

```
root@ubuntu:/home/vagrant/nstest# gcc -Wall ns_uts.c -o ns_uts && ./ns_uts
 - Hello ?
 - World !
root@In Namespace:/home/vagrant/nstest#  #inside container
root@In Namespace:/home/vagrant/nstest# exit
root@ubuntu:/home/vagrant/nstest#        #outside container
```

可以看到，在子进程中hostname变成了`In Namespace`，而父进程的hostname为ubuntu不受子进程修改hostname的影响，通过CLONE_NEWUTS实现了主机名的隔离。注意，如果不加`CLONE_NEWUTS`标记运行，会发现退出子进程后hostname也还原了，这是因为bash只在登录的时候读取一次UTS，等你重新登陆就会发现hostname变了。因此，为了hostname隔离，加上`CLONE_NEWUTS`标志。

docker容器的hostname也是通过该机制实现的隔离，每个容器都有自己的hostname（默认是容器ID），并不会对宿主机的hostname产生任何影响。

```
root@ubuntu:/home/ssj# docker exec -it ssjtestnew /bin/bash
root@c9df3369e321:/# hostname
c9df3369e321
```

## 1.2 /proc/PID/ns文件

从/proc/PID/ns目录中，我们可以看到一个进程的namespace。比如我们运行上面的 `./ns`，并查看父子进程的namespace，结果如下，可以看到ns和子进程bash的ns目录中，除了UTS namespace是不一样的，表明这两个进程在不同的UTS名字空间，其他5个namespace是相同的。/proc/PID/ns目录中的为符号链接，指向的是对应namespace的名字，名字命名规则是namespace类型+inode数字，如ipc:[4026531839]。

```
root@ubuntu:/home/vagrant# ps -ef 
root      3086  2741  0 02:46 pts/0    00:00:00 ./ns
root      3087  3086  0 02:46 pts/0    00:00:00 /bin/bash
root@ubuntu:/home/vagrant# ls -ls /proc/3086/ns/
total 0
0 lrwxrwxrwx 1 root root 0 Aug 16 02:47 ipc -> ipc:[4026531839]
0 lrwxrwxrwx 1 root root 0 Aug 16 02:47 mnt -> mnt:[4026531840]
0 lrwxrwxrwx 1 root root 0 Aug 16 02:47 net -> net:[4026531956]
0 lrwxrwxrwx 1 root root 0 Aug 16 02:47 pid -> pid:[4026531836]
0 lrwxrwxrwx 1 root root 0 Aug 16 02:47 user -> user:[4026531837]
0 lrwxrwxrwx 1 root root 0 Aug 16 02:47 uts -> uts:[4026531838]
root@ubuntu:/home/vagrant# ls -ls /proc/3087/ns/ 
total 0
0 lrwxrwxrwx 1 root root 0 Aug 16 02:47 ipc -> ipc:[4026531839]
0 lrwxrwxrwx 1 root root 0 Aug 16 02:47 mnt -> mnt:[4026531840]
0 lrwxrwxrwx 1 root root 0 Aug 16 02:47 net -> net:[4026531956]
0 lrwxrwxrwx 1 root root 0 Aug 16 02:47 pid -> pid:[4026531836]
0 lrwxrwxrwx 1 root root 0 Aug 16 02:47 user -> user:[4026531837]
0 lrwxrwxrwx 1 root root 0 Aug 16 02:47 uts -> uts:[4026532182]
root@ubuntu:/home/vagrant# readlink /proc/3086/ns/uts # show parent UTS namespace
uts:[4026531838]
root@ubuntu:/home/vagrant# readlink /proc/3087/ns/uts # show child UTS namespace
uts:[4026532182]
root@ubuntu:/home/vagrant# touch ~/uts
root@ubuntu:/home/vagrant# mount --bind /proc/3087/ns/uts ~/uts

```
当然namespace还有其他的用处，只要namespace的文件描述符是打开的，即便该namespace所有进程都终止了，该namespace还是依旧存在。我们如果直接退出程序，可以看到进程退出后/proc/PID目录会整个删掉，包括ns目录。于是，为了保存子进程的UTS namespace，我们用mount命令先挂载该namespace，稍后我们会用setns()将进程加入到该UTS namespace。

```
mount --bind /proc/3087/ns/uts ~/uts
```

## 1.3 加入已经存在的namespace：setns()
通过setns和execve可以让一个进程加入一个已经存在的namespace并在那个namespace执行命令。测试代码 [ns_setns.c](https://github.com/shishujuan/docker-basis/blob/master/namespace/ns_setns.c)，这里用到上一节中保留的UTS namespace。

运行结果如下：

```
root@ubuntu:/home/vagrant/nstest# gcc -o ns_setns ns_setns.c 
root@ubuntu:/home/vagrant/nstest# ./ns_setns ~/uts /bin/bash 
root@In Namespace:/home/vagrant/nstest# echo $$  ## show pid
3375
root@In Namespace:/home/vagrant/nstest# hostname
In Namespace
root@In Namespace:/home/vagrant/nstest# readlink /proc/3375/ns/
ipc   mnt   net   pid   user  uts   
root@In Namespace:/home/vagrant/nstest# readlink /proc/3375/ns/uts 
uts:[4026532182]
```
可以看到该进程的UTS namespace为我们指定的之前保留的child process的UTS namespace。

## 1.4 隔离一个namespace：unshare()
unshare函数可以让进程脱离一个namespace，它与clone类似，不同的是，**unshare不需要创建新的进程**，而是在当前进程直接隔离namespace。

测试代码 [ns_unshare.c](https://github.com/shishujuan/docker-basis/blob/master/namespace/ns_unshare.c) ，运行之，在参数中我们传递`-m`用来隔离NS namespace（即挂载点的namespace），结果可以看到在新的NS namespace的shell进程中umount了一个目录`/run/lock`，并不影响老的shell进程的挂载点。

```
root@ubuntu:/home/vagrant/nstest# echo $$         #Show pid of shell
4434
root@ubuntu:/home/vagrant/nstest# readlink /proc/4434/ns/mnt     # Show shell NS namespace id
mnt:[4026532183]
root@ubuntu:/home/vagrant/nstest# cat /proc/4434/mounts|grep '/run/lock'
none /run/lock tmpfs rw,nosuid,nodev,noexec,relatime,size=5120k 0 0
root@ubuntu:/home/vagrant/nstest# ./ns_unshare -m /bin/bash        #Start new shell in separate mount namespace
hello, pid=4927
root@ubuntu:/home/vagrant/nstest# echo $$
4927
root@ubuntu:/home/vagrant/nstest# readlink /proc/4927/ns/mnt   #Show mount namespace ID in new shell
mnt:[4026532184]
root@ubuntu:/home/vagrant/nstest# cat /proc/4927/mounts|grep 'run/lock'
none /run/lock tmpfs rw,nosuid,nodev,noexec,relatime,size=5120k 0 0
root@ubuntu:/home/vagrant/nstest# umount /run/lock    #Umount dir in separate mount namespace
root@ubuntu:/home/vagrant/nstest# cat /proc/4927/mounts|grep 'run/lock'
root@ubuntu:/home/vagrant/nstest# exit
root@ubuntu:/home/vagrant/nstest# cat /proc/4434/mounts|grep '/run/lock'  #Old shell not affected
none /run/lock tmpfs rw,nosuid,nodev,noexec,relatime,size=5120k 0 0
```

至此，namespace操作的相关API函数已经都说完了，接下来分别看看这6个namespace。

# 2 UTS Namespace
UTS是实现主机名和域名的隔离，在第一节中已经说过，这里不再赘述。

# 3 IPC Namespace
IPC指Unix/Linux下进程间通信的方式，可以通过共享内存，信号量，消息队列，管道等方法实现。这里我们要隔离IPC namespace，实现方式也很简单，在clone函数的flags参数中加入CLONE_NEWIPC即可，这样你可以在新的namespace中创建IPC，甚至是命名一个，并不会有与其他应用冲突的风险。

我们在最初的实例代码ns.c中修改一下，加入CLONE_NEWIPC的flag。修改的代码只有一行，如下。当然这里的CLONE_NEWUTS不是必须的，保留这个flag只是为了更加方便的显示效果。

```
/*
ns_ipc.c: used to test ipc
*/
[...]
int child_pid = clone(child_main, child_stack+STACK_SIZE,
      CLONE_NEWUTS | CLONE_NEWIPC| SIGCHLD, NULL);
[...]
```

先通过`ipcmk -Q`创建一个IPC队列，队列ID为65536，然后运行`./ns_ipc`，可以看到在新的namespace中并没有该IPC队列，做到了IPC隔离。

```
root@ubuntu:/home/vagrant/nstest# ipcmk -Q 
Message queue id: 65536
root@ubuntu:/home/vagrant/nstest# ipcs -q

------ Message Queues --------
key        msqid      owner      perms      used-bytes   messages    
0x0a3817cf 65536      root       644        0            0           

root@ubuntu:/home/vagrant/nstest# ./ns_ipc 
 - Hello ?
 - World !
root@In Namespace:/home/vagrant/nstest# ipcs -q

------ Message Queues --------
key        msqid      owner      perms      used-bytes   messages    

root@In Namespace:/home/vagrant/nstest# exit
root@ubuntu:/home/vagrant/nstest# ipcs -q

------ Message Queues --------
key        msqid      owner      perms      used-bytes   messages    
0x0a3817cf 65536      root       644        0            0   
```

接下来可能有人要问了，那这种父子进程在不同的IPC namespace了，它们之间怎么通信呢？前面说过，进程间通信有信号量，共享内存，管道，FIFO，sockets等。由于上下文的改变，使用信号量也许不是最佳方案。而使用共享内存则有效率上的问题，如果不隔离网络栈的话也可以用sockets，但是我们现在要一步步隔离一切，因此sockets也不合适。FIFO则可以用于任意进程间的通信，FIFO是一种特殊的文件类型，在文件系统中是有对应路径的，它的问题也与sockets类似，因为我们要隔离文件系统的话，它也不合适。管道用于有亲属关系的进程之间通信，比如父子进程或者兄弟进程之间通信，很适合不同namespace的进程通信。更多进程间通信内容可以参见[这篇文章](http://www.cnblogs.com/biyeymyhjob/archive/2012/11/03/2751593.html)。

使用管道实现不同namespace之间进程通信的示例代码 [ns_ipc.c](https://github.com/shishujuan/docker-basis/blob/master/namespace/ns_ipc.c)，运行之，可以看到位于不同namespace的父子进程确实通信成功了。

```
root@ubuntu:/home/vagrant/nstest# ./ns_ipc
 - Hello ?
 - World !
root@In Namespace:/home/vagrant/nstest# exit
root@ubuntu:/home/vagrant/nstest# 
```

# 4 PID Namespace
实现PID隔离加上CLONE_NEWPID标识即可。示例代码 [ns_pid.c](https://github.com/shishujuan/docker-basis/blob/master/namespace/ns_pid.c) ，运行之：

```
root@ubuntu:/home/vagrant/nstest# ./ns_pid
 - [ 7627] Hello ?
 - [    1] World !
root@In Namespace:/home/vagrant/nstest# echo $$    ##In new PID namespace
1
root@In Namespace:/home/vagrant/nstest# kill -KILL 7627
bash: kill: (7627) - No such process

###host ps view
root@ubuntu:/home/vagrant/nstest# ps -ef|grep 7627
root      7627  2768  0 04:40 pts/1    00:00:00 ./pid
root      7628  7627  0 04:40 pts/1    00:00:00 /bin/bash
```

可以看到在不同PID namespace中运行的/bin/bash的PID为1。而它的父进程的PID是7627。而在父进程namespace中，可以看到/bin/bash的进程为7268。如果你试图在新的Namespace中去kill某个不同namespace中的进程，则会报错提示进程不存在，达到了进程隔离的目的。

要注意的是，这个时候你在新的namespace中用`ps，top`等命令去查看，会发现7627这个进程是可见的。这与我们在docker容器中看到的不一致，如在我创建的一个redis容器中，用`ps, top`其实是只看得到容器所在namespace的进程的。

```
root@ubuntu:/home/ssj# docker exec -it redistest /bin/bash

root@0b86fb961783:/data# ps -ef
UID        PID  PPID  C STIME TTY          TIME CMD
redis        1     0  0 02:44 ?        00:00:00 redis-server *:6379
root        18     0  0 02:45 ?        00:00:00 /bin/bash
root        25    18  0 02:45 ?        00:00:00 ps -ef
```

这是因为ps命令读取的是`/proc`目录获取的信息，而这个目录我们还没有隔离，所以在新的namespace中可以看到所有的进程，接下来我们会用NS namespace来实现这个隔离。

# 5 NS Namespace
NS namespace也就是挂载点相关的了，在第4节的代码基础上加入`CLONE_NEWNS`的flag，并在子进程挂载 `/proc`目录。修改后创建进程的代码 [ns_ns.c](https://github.com/shishujuan/docker-basis/blob/master/namespace/ns_ns.c), 运行之:

```
root@ubuntu:/home/vagrant/nstest# ./ns_ns
 - [27137] Hello ?
 - [    1] World !
root@In Namespace:/home/vagrant/nstest# ps -ef
UID        PID  PPID  C STIME TTY          TIME CMD
root         1     0  0 20:37 pts/0    00:00:00 /bin/bash
root         3     1  0 20:39 pts/0    00:00:00 ps -ef
root@In Namespace:/home/vagrant/nstest# ls /proc/
1	   bus	     cpuinfo	dma	     filesystems  ioports   kcore      kpagecount  meminfo  mpt		  partitions   softirqs  sysrq-trigger	tty	     vmstat
5	   cgroups   crypto	driver	     fs		  ipmi	    keys       kpageflags  misc     mtrr	  sched_debug  stat	 sysvipc	uptime	     zoneinfo
acpi	   cmdline   devices	execdomains  interrupts   irq	    key-users  loadavg	   modules  net		  self	       swaps	 timer_list	version
buddyinfo  consoles  diskstats	fb	     iomem	  kallsyms  kmsg       locks	   mounts   pagetypeinfo  slabinfo     sys	 timer_stats	vmallocinfo
```
可以看到`ps`命令确实只显示了当前namespace下面的进程了，而且`ls /proc/`命令查看发现`/proc`目录下面的内容也清爽多了。docker使用mount namespace实现了一些文件系统的挂载，原理与这个类似，结合chdir和chroot可以实现一个山寨的docker镜像。

这个时候我们再来看看docker中PID和NS namespace具体的实现(我的docker版本是1.13.1，其他版本可能有所不同)，我这里在宿主机起了一个redis容器名为redistest，通过pstree可以看到进程关系如下：

```
        |-dockerd-+-docker-containerd-+-docker-containerd-shim-+-redis-server---3*[{redis-server}]
        |         |                 |                 `-8*[{docker-containe}]
        |         |                 `-12*[{docker-containe}]
        |         `-19*[{dockerd}]
```
这里对应进程关系就是：
* dockerd进程创建了一个docker-containerd子进程，而docker-contianerd子进程再创建子进程docker-containerd-shim，也就是对应具体容器的进程。
* 容器进程docker-containerd-shim创建容器里面的1号进程redis-server。
* 通过查看`/proc/PID/ns`目录就可以发现，dockerd，dockerd-containerd以及dockerd-containerd-shim的namespace都是一样的，而容器里面的1号进程 redis-server的namespace除了User namespace外，其他的namespace都已经不同。也就是说，从容器里面的1号进程开始，进程的namespace开始隔离。
* **另外注意一点的是**，当你使用 `docker exec -it redistest /bin/bash`命令进入容器的时候，这个`/bin/bash`进程的父进程其实是另外一个 docker-containerd-shim进程，只是`/bin/bash`进程的namespace和redis-server进程一样，所以这个时候你在redistest容器中`ps -ef`，可以看到除了redis-server进程外，还有`/bin/bash`进程。通过exec命令进入容器后，再来看进程关系，是下面这样的:

```
       |-dockerd-+-docker-containerd-+-docker-containerd-shim-+-redis-server---3*[{redis-server}]
        |         |                  |                 `-8*[{docker-containe}]
        |         |                  |-docker-containerd-shim-+-bash
        |         |                  |                 `-8*[{docker-containe}]
        |         |                  `-12*[{docker-containe}]
        |         `-19*[{dockerd}]
```

而在容器在自己的mount namespace中挂载了很多目录，如下面这些：

```
/dev/sda8 on /etc/resolv.conf type ext4 (rw,relatime,data=ordered)
/dev/sda8 on /etc/hostname type ext4 (rw,relatime,data=ordered)
/dev/sda8 on /etc/hosts type ext4 (rw,relatime,data=ordered)
shm on /dev/shm type tmpfs (rw,nosuid,nodev,noexec,relatime,size=65536k)
devpts on /dev/console type devpts (rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=000)
proc on /proc/bus type proc (ro,nosuid,nodev,noexec,relatime)
proc on /proc/fs type proc (ro,nosuid,nodev,noexec,relatime)
proc on /proc/irq type proc (ro,nosuid,nodev,noexec,relatime)
proc on /proc/sys type proc (ro,nosuid,nodev,noexec,relatime)
```

# 6 NET Namespace
NET namespace是指网络上的隔离，通过加入`CLONE_NEWNET`来实现。在讨论这个之前，可以先看看通过`ip`命令如何手动创建network namespace以及veth设备等。veth主要的目的是为了跨NET namespace之间提供一种类似于Linux进程间通信的技术，所以veth总是成对出现，如下面的veth0和veth1。它们位于不同的NET namespace中，在veth设备任意一端接收到的数据，都会从另一端发送出去。veth工作在L2数据链路层，只负责数据传输，不会更改数据包。

```
# Create a "demo" namespace
ip netns add demo

# create a "veth" pair
ip link add veth0 type veth peer name veth1

# and move one to the namespace
ip link set veth1 netns demo

# configure the interfaces (up + IP)
ip netns exec demo ip link set lo up
ip netns exec demo ip link set veth1 up
ip netns exec demo ip addr add 169.254.1.2/30 dev veth1
ip link set veth0 up
ip addr add 169.254.1.1/30 dev veth0
```
执行完成后，我们可以在宿主机里面看到网络设备是这样的:

```
root@ubuntu:/home/vagrant# ip -d link
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default 
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00 promiscuity 0 
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP mode DEFAULT group default qlen 1000
    link/ether 08:00:27:ec:df:9c brd ff:ff:ff:ff:ff:ff promiscuity 0 
3: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP mode DEFAULT group default qlen 1000
    link/ether 08:00:27:57:25:68 brd ff:ff:ff:ff:ff:ff promiscuity 0 
5: veth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP mode DEFAULT group default qlen 1000
    link/ether 62:14:fd:45:f8:0e brd ff:ff:ff:ff:ff:ff promiscuity 0 
    veth 
root@ubuntu:/home/vagrant# ethtool -S veth0
NIC statistics:
     peer_ifindex: 4
```

而在demo这个NET namespace中，看到的网络设备是这样的：

```
root@ubuntu:/home/vagrant# ip netns exec demo ip -d link
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default 
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00 promiscuity 0 
4: veth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP mode DEFAULT group default qlen 1000
    link/ether 6a:7d:49:3f:bc:8e brd ff:ff:ff:ff:ff:ff promiscuity 0 
    veth 
```

这个原理就是先创建一个新的NET namespace名为demo，然后创建一对veth设备，veth0和veth1，接着将veth1移动到namespace demo，而veth0仍然保留在原来的namespace，然后启动对应的veth设备。这样一对veth设备分属于不同的namespace，并可以通信。然后给veth0和veth1设置ip并启动它们。要查看veth的一对设备中另外一个，可以用 `ethtool -S`命令。实现上面功能的代码 [ns_net.c](https://github.com/shishujuan/docker-basis/blob/master/namespace/ns_net.c) ，运行之，如下：

```
root@ubuntu:/home/vagrant/nstest# ./ns_net 
 - [ 2760] Hello ?
 - [    1] World !

### 宿主机namespace
root@ubuntu:/home/vagrant/nstest# ip -d link
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default 
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00 promiscuity 0 
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP mode DEFAULT group default qlen 1000
    link/ether 08:00:27:ec:df:9c brd ff:ff:ff:ff:ff:ff promiscuity 0 
3: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP mode DEFAULT group default qlen 1000
    link/ether 08:00:27:57:25:68 brd ff:ff:ff:ff:ff:ff promiscuity 0 
11: veth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP mode DEFAULT group default qlen 1000
    link/ether ce:95:ad:9e:ee:6b brd ff:ff:ff:ff:ff:ff promiscuity 0 
    veth 
    
### 新的namespace
root@In Namespace:/home/vagrant/nstest# ip -d link
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default 
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00 promiscuity 0 
10: veth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP mode DEFAULT group default qlen 1000
    link/ether 9a:e9:95:53:c3:28 brd ff:ff:ff:ff:ff:ff promiscuity 0 
    veth 
root@In Namespace:/home/vagrant/nstest# ethtool -S veth1
NIC statistics:
     peer_ifindex: 11
```

docker网络分为bridge， host， overlay等几种类型。host就是与主机共用namespace，这里不单独分析了。而bridge就与前面例子中类似，不同的是仅仅有veth容器还无法与外部联通，因此docker借助了网桥技术用于连接不同网段，在L2层进行数据转发，将veth0加入到宿主机的网桥docker0中，并在iptables加入对应的NAT规则，以保证容器可以与外部连通。**注意docker中NET namespace的隔离不是通过ip命令实现的(因为不是所有的内核版本都有ip netns这个高级命令)，而是通过netlink基于操作系统调用的方式实现的。**而overlay网络则是通过vxlan协议实现，对应的veth会桥接到overlay的NET namespace一个br0网桥上。后面再单独分析overlay原理。bridge和overlay网络的一个示意图如下(图来自 [http://techblog.d2-si.eu/2017/04/25/deep-dive-into-docker-overlay-networks-part-1.html](http://techblog.d2-si.eu/2017/04/25/deep-dive-into-docker-overlay-networks-part-1.html))，其中192.168.0.X这个是自定义的overlay网络，而172.18.0.X的则是bridge网络。

![docker网络示意图](http://upload-images.jianshu.io/upload_images/286774-90adaf9176c70563.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)


# 7 USER Namespace
## 7.1 创建新的USER Namespace
加上 `CLONE_NEWUSER` flag可以实现USER namespace的隔离。示例如下(**注意，在debian或者ubuntu中必须设置`/proc/sys/kernel/unprivileged_userns_clone`这个文件值为1，否则无法以普通用户运行带`CLONE_NEWUSER`标记的clone命令**
) 

示例代码 [ns_user.c](https://github.com/shishujuan/docker-basis/blob/master/namespace/ns_user.c)，以普通用户运行之：

```
vagrant@ubuntu:~/nstest$ id -u
1000
vagrant@ubuntu:~/nstest$ id -g
1000
vagrant@ubuntu:~/nstest$ gcc -o ns_user ns_user.c -lcap  
#如果编译报错的话，安装libcap-dev模块，sudo apt-get install libcap-dev
vagrant@ubuntu:~/nstest$ ./user 
eUID = 65534;  eGID = 65534;  capabilities: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend+ep
```

**这里有几点注意的：**

* 其一，从capabilities输出可以看到子进程在它的namespace里面有全部的capability，虽然我们是用普通用户权限运行的程序。当一个新的USER namespace创建的时候，这个namespace的第一个进程就被赋予了全部的capability。capability是为了实现更精细化的权限控制而加入的。(我们以前熟知通过设置文件的SUID位，这样非root用户的可执行文件运行后的euid会成为文件的拥有者ID，比如passwd命令运行起来后有root权限。一旦SUID的文件存在漏洞，便可能被利用而增加安全风险）。查看文件的capability的命令为 `filecap -a`，而查看进程capability的命令为 `pscap -a`(pscap和filecap工具需要安装 `libcap-ng-utils`这个包)。对capability的那串数字解码命令为 `capsh --decode=00000000000000c0`。更多capability的内容见参考资料4。

  对于capability，可以看一个简单的例子便于理解。如ubuntu14.04系统中自带的ping工具，它是有设置SUID位的。这里拷贝ping到我的用户目录下名为anotherping，可以看到它的SUID位是没有了的，运行anotherping，会提示权限错误。这里，我们只要将其加上 `cap_net_raw`权限即可，不需要设置SUID位那么大的权限。

  ```
  vagrant@ubuntu:~$ ls -ls /bin/ping
  44 -rwsr-xr-x 1 root root 44168 May  7  2014 /bin/ping
  vagrant@ubuntu:~$ cp /bin/ping anotherping
  vagrant@ubuntu:~$ ls -ls anotherping 
  44 -rwxr-xr-x 1 vagrant vagrant 44168 Aug 27 03:27 anotherping
  vagrant@ubuntu:~$ ping -c1 www.163.com
  PING 163.xdwscache.ourglb0.com (112.90.246.87) 56(84) bytes of data.
  64 bytes from ns.local (112.90.246.87): icmp_seq=1 ttl=63 time=11.9 ms
  ...
  vagrant@ubuntu:~$ ./anotherping -c1 www.163.com
  ping: icmp open socket: Operation not permitted

  vagrant@ubuntu:~$ sudo setcap cap_net_raw+ep ./anotherping 
  vagrant@ubuntu:~$ ./anotherping -c1 www.163.com
  PING 163.xdwscache.ourglb0.com (112.90.246.87) 56(84) bytes of data.
  64 bytes from ns.local (112.90.246.87): icmp_seq=1 ttl=63 time=12.4 ms
  ...
  ```

* 其二，一个进程的uid和gid在不同的USER namespace是可以不一样的，这需要一个namespace内部映射到namespace外部的映射关系。这样当一个USER namespace中的进程的操作可能影响到外部系统时，可以对这个进程的权限进行检查。如果一个用户ID在USER namespace中没有映射关系，则`getuid()`系统调用会返回 `/proc/sys/kernel/overflowuid`值作为用户ID，这个值默认为65534，就如我们前面程序中输出一样(gid对应的文件名为overflowgid)。

* 其三，尽管通过clone系统调用创建的子进程在新的USER namespace中有所有权限，但是它在`parent user namespace`是没有任何权限的，即便以root身份运行也是一样。`user namespace`的创建可以是嵌套的，一个`user namespace`一定有个`parent user namespace`，可以有零或者多个 `child user namespace`。子进程的`parent user namespace`就是调用`clone()`或者`unshare()`通过`CLONE_NEWUSER`的flag创建新namespace的那个父进程的`user namespace`。


## 7.2 映射uid和gid
创建新的`user namespace`之后第一步就是设置好user和group的映射关系。这个映射通过设置`/proc/PID/uid_map(gid_map)`实现，格式如下：

```
    ID-inside-ns   ID-outside-ns   length
```
不是所有的进程都能随便修改映射文件的，必须同时具备如下条件：

* 修改映射文件的进程必须有PID进程所在user namespace的`CAP_SETUID/CAP_SETGID`权限。进程的capability一般是通过其可执行文件的capability获得。
* 修改映射文件的进程必须是跟PID在同一个user namespace或者PID的parent user namespace。
* 映射文件`uid_map`和`gid_map`只能写入一次，再次写入会报错。

下面来测试下7.1中的例子：

```
#在第一个终端运行 ns_user
vagrant@ubuntu:~/nstest$ ./ns_user x
eUID = 65534;  eGID = 65534; capabilities: = ...ep

#在第二个终端写入该进程对应的uid_map
vagrant@ubuntu:~/nstest$ ps -C ns_user -o 'pid ppid uid comm'
  PID  PPID   UID COMMAND
 8775  8577  1000 ns_user
 8776  8775  1000 ns_user
vagrant@ubuntu:~/nstest$ echo '0 1000 1' > /proc/8776/uid_map

#第一个终端此时输出为：
vagrant@ubuntu:~/nstest$ ./ns_user x
eUID = 0;  eGID = 65534; capabilities: = ...ep

#在第二个终端继续写入gid_map
vagrant@ubuntu:~/nstest$ echo '0 1000 1' > /proc/8776/gid_map

#第一个终端此时输出为：
vagrant@ubuntu:~/nstest$ ./ns_user x
eUID = 0;  eGID = 0; capabilities: = ...ep

```

可以看到，我们在位于`parent user namespace`的bash进程中通过echo命令修改`uid_map`和`gid_map`都是可以成功的。这是因为我的测试环境的`bash`进程具有`CAP_SETUID`和`CAP_SETGID`权限的，查看`/proc/PID/status`可以验证进程的权限或者`getcap`可以验证一个可执行文件的权限，如下验证bash的权限，如果bash原来没有这两个权限，可以通过命令`sudo setcap cap_setgid,cap_setuid+ep /bin/bash`设置:

```
vagrant@ubuntu:~/nstest$ cat /proc/$$/status | egrep 'Cap(Inh|Prm|Eff)'
CapInh:	0000000000000000
CapPrm:	00000000000000c0
CapEff:	00000000000000c0

vagrant@ubuntu:~/nstest$ getcap /bin/bash
/bin/bash = cap_setgid,cap_setuid+ep
```

**这里有个要注意的地方，ubuntu14.04的/bin/bash文件默认就有修改新的user namespace进程的`uid_map`的权限，如果要修改`gid_map`要另外加下`cap_setgid`权限。而其他的可执行文件，默认也是只有`cap_setuid`权限，比如网上很多文章中提到的一个设置user namespace的例子，在ubuntu14.04里面设置gid_map会失败，因为可执行文件没有`cap_setgid`权限，需要加上gid权限才能成功修改`gid_map`。**

看这个例子，代码 [ns_child_exec.c](https://github.com/shishujuan/docker-basis/blob/master/namespace/ns_child_exec.c)，执行后可以发现在新的user namespace里面的bash里面通过echo命令设置uid_map和gid_map都会失败，这是因为当一个非root用户的进程执行execve()时，进程的capability会被清空。于是，子进程虽然有新的user namespace所有的权限集合，但是通过它exevce执行的bash进程以及bash进程的子进程是没有对应的capability的。

```
vagrant@ubuntu:~/nstest$ ./ns_child_exec -U bash
nobody@ubuntu:~/nstest$ id -u  #新的user namespace运行的bash进程
65534
nobody@ubuntu:~/nstest$ id -g
65534
nobody@ubuntu:~/nstest$ echo '0 1000 1' > /proc/$$/uid_map
bash: echo: write error: Operation not permitted
nobody@ubuntu:~/nstest$ echo '0 1000 1' > /proc/$$/gid_map
bash: echo: write error: Operation not permitted
```

为了设置映射文件，因此需要在父进程中设置，示例代码 [userns_child_exec.c](https://github.com/shishujuan/docker-basis/blob/master/namespace/userns_child_exec.c)。注意一点的是，要在userns_child_exec进程中成功设置gid_map文件，需要给可执行文件加上 `cap_setgid权限`，此外，还要保证 `/bin/bash`是有`cap_setgid`权限的：

```
root@ubuntu:~/nstest# setcap cap_setgid+ep ./userns_child_exec
vagrant@ubuntu:~/nstest$ ./userns_child_exec -U -M '0 1000 1' -G '0 1000 1' bash
root@ubuntu:~/nstest# id -u # 新的user namespace
0
root@ubuntu:~/nstest# id -g
0
root@ubuntu:~/nstest# cat /proc/$$/status | egrep 'Cap(Inh|Prm|Eff)'
CapInh:	0000000000000000
CapPrm:	0000003fffffffff
CapEff:	0000003fffffffff
```
最后一点要注意的是，uid_map文件里面的 ID-outside-ns 这个值是根据**当前读取文件的user namespace**生成的，这个是什么意思呢？看下面的例子就明白了。在两个终端里面分别运行 `userns_child_exec`程序，设置不同的ID-inside-ns，运行结果如下所示。也就是说，我们在初始的user namespace创建了2个child user namespace，一个是映射的uid为0，另一个映射的为200，在第一个终端看第二个终端进程对应的映射关系时可以发现`uid_map`值为 `200 0 1`，也就是说第二个user namespace中的进程用户ID映射到了当前user namespace的uid 0，而不是初始的user namespace的1000。从第二个终端里面看第一个终端的进程的uid_map正好反转。当然，你如果在第三个终端从初始的user namespace里面去看uid_map，是跟之前一样的。

```
# 第一个终端，映射 0 -> 1000
vagrant@ubuntu:~/nstest$ ./userns_child_exec -U -M '0 1000 1' -G '0 1000 1' bash 
root@ubuntu:~/nstest# id -u
0
root@ubuntu:~/nstest# id -g
0
root@ubuntu:~/nstest# echo $$
25730
root@ubuntu:~/nstest# cat /proc/$$/uid_map
         0       1000          1
root@ubuntu:~/nstest# cat /proc/26091/uid_map  
       200          0          1

# 第二个终端，映射 200->1000
vagrant@ubuntu:~/nstest$ ./userns_child_exec -U -M '200 1000 1' -G '200 1000 1' bash
I have no name!@ubuntu:~/nstest$ id -u
200
I have no name!@ubuntu:~/nstest$ echo $$
26091
I have no name!@ubuntu:~/nstest$ cat /proc/$$/uid_map 
       200       1000          1
I have no name!@ubuntu:~/nstest$ cat /proc/25730/uid_map 
         0        200          1

# 第三个终端，初始user namespace里面查看映射关系
vagrant@ubuntu:~/nstest$ cat /proc/25730/uid_map 
         0       1000          1
vagrant@ubuntu:~/nstest$ cat /proc/26091/uid_map 
       200       1000          1
```

之前我们提到的docker示例中，没有对user namespace进行隔离。user namespace功能虽然在很早就出现了，但是直到Linux4.3这个功能才稳定。docker1.10之后的版本可以通过在docker daemon启动时加上`--userns-remap=[USERNAME]`来实现USER Namespace的隔离，在实际使用中我们暂时没有用到USER namespace的隔离，不过docker对于CAP很早就有使用的，所以可以看到容器启动的时候如果需要特定功能的需要加`--cap-add SYS_ADMIN，NET_ADMIN`这些参数。

# 8 简单总结
docker使用的不是新技术，但是着实给开发部署以及应用调度带来了很大的便利性。特别是docker的overlay网络可以实现容器之间的跨主机通信，功能很强大。当然docker overlay网络在大规模使用的时候我们项目中也遇到了一些坑，比如在docker1.13.1版本中容器ip在不同主机复用的时候会导致容器无法连通问题，新版本17.05-ce-0 应该已经修复该问题，这个问题在下次分析docker overlay网络原理的时候再细细探讨。

总体来说，docker现在的版本比较稳定，在线上跑了200+个容器，除了overlay网络那个问题外，基本没有出现重大BUG，推荐使用。

# 参考资料
* [https://blog.yadutaf.fr/2014/01/19/introduction-to-linux-namespaces-part-1,2,3,4,5/](https://blog.yadutaf.fr/2013/12/22/introduction-to-linux-namespaces-part-1-uts/)
* [https://lwn.net/Articles/531114/#series_index](https://lwn.net/Articles/531114/#series_index)
* [http://pipul.org/2016/02/create-the-container-virtual-network-by-veth-model/](http://pipul.org/2016/02/create-the-container-virtual-network-by-veth-model/)
* [http://man7.org/linux/man-pages/man7/capabilities.7.html](http://man7.org/linux/man-pages/man7/capabilities.7.html)
* [http://rk700.github.io/2016/10/26/linux-capabilities/](http://rk700.github.io/2016/10/26/linux-capabilities/)
* [http://blog.siphos.be/2013/05/overview-of-linux-capabilities-part-1/](http://blog.siphos.be/2013/05/overview-of-linux-capabilities-part-1/)
* [https://coolshell.cn/articles/17010.html](https://coolshell.cn/articles/17010.html)
