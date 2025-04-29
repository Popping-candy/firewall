#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/udp.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include "linux/types.h"
#include "linux/errno.h"
#include "linux/uaccess.h"
#include "linux/kdev_t.h"
#include <linux/time.h>
#include <linux/semaphore.h>
#include <linux/crc16.h>
#include "firewall.h"
#include "tool.h"

dev_t devid;                // 申请的设备号
struct cdev cdev;           // 内核中使用cdev结构体来描述字符设备
static unsigned cdev_opt;   // 操作符（0写规则，1获取连接表，2获取日志，3获取NAT表）
static char databuf[20480]; // 读写缓冲区
static ssize_t chardev_open(struct inode *inode, struct file *file);
static ssize_t chardev_read(struct file *file, char __user *buf, size_t size, loff_t *ppos);
static ssize_t chardev_write(struct file *file, const char __user *buf, size_t size, loff_t *offt);
static int __init mod_init(void);
static void __exit mod_exit(void);
struct timer_list timer = {
    .function = time_handler};
int firewall_init(void);
unsigned int hook_local_out(void *priv, struct sk_buff *skb, const struct nf_hook_state *state); //netfilter
static const struct file_operations chardev_fops = {
    .open = chardev_open,
    .read = chardev_read,
    .write = chardev_write,
};
static struct nf_hook_ops nfho = {
    .hook = hook_local_out,       // hook处理函数
    .pf = PF_INET,                // 协议类型
    .hooknum = NF_INET_LOCAL_OUT, // hook注册点
    .priority = NF_IP_PRI_FIRST   // 优先级
};
/*
static struct nf_hook_ops nat_in = {
    .hook = hook_nat_in,
    .pf = PF_INET,
    .hooknum = NF_INET_PRE_ROUTING,
    .priority = NF_IP_PRI_NAT_DST};
static struct nf_hook_ops nat_out = {
    .hook = hook_nat_out,
    .pf = PF_INET,
    .hooknum = NF_INET_POST_ROUTING,
    .priority = NF_IP_PRI_NAT_SRC};
*/

bool firewallStatus = 1;

Rule RuleTable[RULE_MAX];
int RuleTable_size = 0;
struct rw_semaphore RuleTable_mutex;

Log Log_Table[LOG_MAX];
int LogTable_size = 0;
int LogTable_pos = 999;
struct semaphore LogTable_mutex;

Connection conHead, conEnd;
unsigned char hashTable[HASH_SIZE] = {0};
int connection_num = 0;
struct rw_semaphore Connection_mutex;
bool default_action = 0;
struct rw_semaphore my_rwsem;

/********************************netfilter*****************************************************/
unsigned int hook_local_out(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *iph = ip_hdr(skb);
    if ((ntohl(iph->saddr) == 2130706433) || (ntohl(iph->daddr) == 2130706433)) //127.0.0.1
        return NF_ACCEPT;

    if (firewallStatus)
    {
        if (packetHandler(skb))
        {
            //printk("ACCEPT: ");
            //print_pkg(skb);
            return NF_ACCEPT;
        }
        else
        {
            //printk("DROP: ");
            //print_pkg(skb);
            return NF_DROP;
        }
    }
    else
        return NF_ACCEPT;
}

int firewall_init(void)
{

    printk("my firewall module loaded.\n");
    printk("MAJOR Number is %d\n", MAJOR(devid));
    printk("MINOR Number is %d\n", MINOR(devid));
    if (!firewallStatus)
        printk("firewall havent opened\n");
    //创建连接表结构
    conHead.next = &conEnd;
    conEnd.next = NULL;
    //初始化读写信号量
    init_rwsem(&RuleTable_mutex);
    init_rwsem(&Connection_mutex);
    //初始化定时器
    timer.expires = jiffies + HZ;
    init_timer(&timer);
    add_timer(&timer);
    return 0;
}
/********************************chardev***********************************************************/
/* 字符设备驱动,先写再读 */
static ssize_t chardev_open(struct inode *inode, struct file *file)
{
    printk("chardev: open\n");
    return 0;
}
unsigned int debug_printConnection(void)
{
    Connection *p = conHead.next;
    while (p != &conEnd)
    {
        uint32_t tmp1 = p->src_ip, tmp2 = p->dst_ip;
        int tmp = hashTable[p->index];
        printk("connection: %u.%u.%u.%u,%u.%u.%u.%u,%d,%d,%d,%d\n",
               IP_DEC(tmp1),
               IP_DEC(tmp2),
               p->src_port,
               p->dst_port,
               p->protocol,
               tmp);
        p = p->next;
    }
    return 0;
}
static ssize_t chardev_read(struct file *file, char __user *buf, size_t size, loff_t *ppos)
{
    int ret = 0;
    if (cdev_opt == OP_GET_NAT)
    {
        ret = RuleTable_size * sizeof(Rule);
        if (ret > size)
        {
            printk("rule: Read Overflow\n");
            return size;
        }
        databuf[0] = RuleTable_size;
        memcpy(databuf + 1, RuleTable, ret);
        ret++;
        copy_to_user(buf, databuf, ret);
        printk("rule: Read %d bytes\n", ret);
    }
    else if (cdev_opt == OP_GET_CONNECT)
    {
        down_read(&Connection_mutex); //lock
        ret = connection_num * (sizeof(Connection) - 4) + 1;
        printk("Connection: Read %d,%d Bytes\n", connection_num, ret);
        Connection *p = conHead.next;
        int d, i = 0;
        databuf[0] = connection_num;
        while (p != &conEnd)
        {
            int time_out = (int)hashTable[p->index];
            memcpy(&databuf[i * 20 + 1], p, 16);
            memcpy(&databuf[i * 20 + 17], &time_out, 4);
            p = p->next;
            i++;
        }
        up_read(&Connection_mutex); //unlock
        ret++;
        copy_to_user(buf, databuf, ret);
    }
    else if (cdev_opt == OP_GET_LOG)
    {
        //lock
        ret = LogTable_size * sizeof(Log);
        databuf[0] = LogTable_size;
        if (ret > size)
        {
            printk("log: Read Overflow\n");
            return size;
        }
        databuf[0] = LogTable_size;
        memcpy(databuf + 1, Log_Table, ret);
        ret++;
        copy_to_user(buf, databuf, ret);
        printk("log: Read %d bytes,size of log = %d\n", ret, sizeof(Log));
        //unlock
    }
    return ret;
}
int debug_printRule(void)
{
    int i = 0;
    for (i = 0; i < RuleTable_size; i++)
    {
        printk("RULE: %u.%u.%u.%u/%d  %u.%u.%u.%u/%d\n",
               IP_DEC(RuleTable[i].src_ip.ip),
               RuleTable[i].src_ip.mask,
               IP_DEC(RuleTable[i].dst_ip.ip),
               RuleTable[i].dst_ip.mask);
    }
    return 0;
}
int debug_log(void)
{
    return 0;
}
static ssize_t chardev_write(struct file *file, const char __user *buf, size_t size, loff_t *offt)
{
    if (size > BUFFER_SIZE)
        return 0;

    copy_from_user(databuf, buf, size);

    cdev_opt = databuf[0]; //先读入操作符
    printk("chardev: write %d byte,cdev_opt = %d\n", size, cdev_opt);
    if (cdev_opt == OP_WRITE_RULE)
    {
        down_write(&RuleTable_mutex); //lock
        RuleTable_size = (size - 1) / sizeof(Rule);
        printk("Get %d rules\n", RuleTable_size);
        memcpy(RuleTable, databuf + 1, size - 1);
        up_write(&RuleTable_mutex); //unlock

        debug_printRule();
    }
    else if (cdev_opt == OP_GET_CONNECT)
    {
        printk("Write opt: Connections\n");
    }
    else if (cdev_opt == OP_GET_LOG)
    {
        printk("Write opt: Log\n");
    }
    else if (cdev_opt == OP_GET_NAT)
    {
        printk("Write opt: NAT\n");
    }
    else if (cdev_opt == OP_FW_OPEN)
    {
        firewallStatus = 1;
        printk("firewall: open\n");
    }
    else if (cdev_opt == OP_FW_CLOSE)
    {
        firewallStatus = 0;
        printk("firewall: close\n");
    }
    else if (cdev_opt == DEFAULT_OPEN)
    {
        default_action == 1;
        printk("firewall: default accept\n");
    }
    else if (cdev_opt == DEFAULT_CLOSE)
    {
        default_action == 0;
        printk("firewall: default drop\n");
    }

    return size;
}
/**************************************************************************************************/
/* 注册模块，内核模块的入口函数 */
static int __init mod_init(void)
{
    nf_register_hook(&nfho);                     //注册netfilter hook
    cdev_init(&cdev, &chardev_fops);             //执行cdev_init函数，将cdev和file_operations关联起来
    alloc_chrdev_region(&devid, 2, 255, MYNAME); //向内核申请主设备号
    cdev_add(&cdev, devid, 255);                 //执行cdev_init函数，将cdev和file_operations关联起来
    firewall_init();
    return 0;
}

static void __exit mod_exit(void)
{
    printk("my firewall module exit ...\n");
    printk("chrdev_exit helloworld exit\n");
    del_timer(&timer);
    nf_unregister_hook(&nfho);
    cdev_del(&cdev);
    unregister_chrdev_region(devid, 255);
}
module_init(mod_init);
module_exit(mod_exit);
MODULE_LICENSE("GPL");             // 描述模块的许可证
MODULE_AUTHOR("wyt");              // 描述模块的作者
MODULE_DESCRIPTION("module test"); // 描述模块的介绍信息
MODULE_ALIAS("alias xxx");         // 描述模块的别名信息

/**************************************************************************************************/