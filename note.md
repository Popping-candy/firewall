```sh
cat /proc/devices | grep chardev


```
### target_1
demo:注册hook函数，注册字符设备,user打印出报文信息
1. netfilter

Hook:
NF_INET_PRE_ROUTING
NF_INET_LOCAL_IN
NF_INET_FORWARD
NF_INET_LOCAL_OUT
NF_INET_POST_ROUTING

RETURN:
NF_DROP
NF_ACCEPT
NF_STOLEN
NF_QUEUE
NF_REPEAT

sk_buff***
skb指针指向sk_buff数据结构，网络堆栈用sk_buff数据结构来描述数据包。这个数据结构在linux/skbuff.h中定义。sk_buff数据结构中最有用的部分就是那三个描述传输层包头、网络层包头以及链路层包头的联合(union)了。这三个联合的名字分别是h、nh以及mac


mknod???
https://blog.csdn.net/weixin_42314225/article/details/81112217

2. 字符设备
