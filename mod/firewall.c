#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include "linux/types.h"
#include "linux/errno.h"
#include "linux/uaccess.h"
#include "linux/kdev_t.h"
#include <linux/time.h>
#include "firewall.h"
#include "tool.h"
#include "my_struct.h"
#define IP_DEC(addr) ((unsigned char *)&addr)[0], \
                     ((unsigned char *)&addr)[1], \
                     ((unsigned char *)&addr)[2], \
                     ((unsigned char *)&addr)[3]
Rule RuleTable[RULE_MAX]; //lock??
int RuleTable_size = 0;
Log log_table[LOG_MAX];
/********************************netfilter*****************************************************/
unsigned int hook_local_out(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct tcphdr *tcph;

    iph = ip_hdr(skb);
    tcph = tcp_hdr(skb);
    //if (iph->protocol == IPPROTO_TCP && tcph->dest == htons(23))
    if (iph->protocol == IPPROTO_TCP)
    {
        Packet my_pack;
        my_pack.src_ip = iph->saddr; //无符号32位整数,大端字节序??
        my_pack.dst_ip = iph->daddr;
        my_pack.src_port = ntohs(tcph->source); //无符号16位整数
        my_pack.dst_port = ntohs(tcph->dest);
        my_pack.protocol = iph->protocol; //无符号8位整数,TCP（6）、UDP（17）、ICMP（1）
        //tcph->
        printk("src_ip:%u.%u.%u.%u,,dst_ip:%u.%u.%u.%u\n", IP_DEC(my_pack.src_ip), IP_DEC(my_pack.dst_ip));
        printk("size_of_tcph:%d||syn:%d\n", sizeof(struct tcphdr), tcph->syn);
        if (pack_num < 4)
        {
            memcpy(pck_buffer + pack_num * sizeof(Packet), &my_pack, sizeof(Packet));
            pack_num++;
        }
        else
        {
            //pack_num = 0;
            printk("overflow");
        }
        check_rule();
        log(skb);
        printk(KERN_INFO "Dropping telnet packet\n");
        return NF_ACCEPT;
    }
    else
        return NF_ACCEPT;
}
/* 
define    struct    memcpy   copy_to_user
&my_pack
memcpy(dst,src,size);
*/
int firewall_init(void)
{
    printk("my firewall module loaded.\n");
    printk("MAJOR Number is %d\n", MAJOR(devid));
    printk("MINOR Number is %d\n", MINOR(devid));
    return 0;
}
int check_rule(void)
{
    return 0;
}
/********************************chardev***********************************************************/
/* 字符设备驱动,先写再读 */
static ssize_t chardev_open(struct inode *inode, struct file *file)
{
    printk(KERN_INFO "chardev open\n");
    return 0;
}

static ssize_t chardev_read(struct file *file, char __user *buf, size_t size, loff_t *ppos)
{
    printk(KERN_INFO "chardev read\n");
    int ret = 0; //???
    if (op_flag == OP_GET_NAT)
    {
        ret = RuleTable_size * sizeof(Rule);
        if (ret > size)
        {
            printk("rule: Read Overflow\n");
            return size;
        }
        copy_to_user(buf, databuf, ret);
        printk("rule: Read %d bytes\n", ret);
    }
    return ret;
    /*
	int ret = 0;

	// 获取连接表
	if (op_flag == OP_GET_CONNECT) {
		// 等待开锁
		while (hashLock)
			;
		// 上锁
		hashLock = 1;
		
		// 返回值大小 = 连接数 * Connection大小
		ret = connection_num * (sizeof(Connection) - 4);
		if (ret > size) {
			printk("Connection: Read Overflow\n");
			return size;
		}

		Connection *p = conHead.next;
		int d, i=0;
		while (p != &conEnd) {
			d = p->src_ip;
			memcpy(&databuf[i * (sizeof(Connection) - 4)], &d, sizeof(unsigned));
			d = p->dst_ip;
			memcpy(&databuf[i * (sizeof(Connection) - 4) + 4], &d, sizeof(unsigned));
			d = p->src_port;
			memcpy(&databuf[i * (sizeof(Connection) - 4) + 8], &d, sizeof(int));
			d = p->dst_port;
			memcpy(&databuf[i * (sizeof(Connection) - 4) + 12], &d, sizeof(int));
			d = p->protocol;
			memcpy(&databuf[i * (sizeof(Connection) - 4) + 16], &d, sizeof(int));
			d = (int)hashTable[p->index];
			memcpy(&databuf[i * (sizeof(Connection) - 4) + 20], &d, sizeof(unsigned));

			p = p->next;
			i++;
		}

		// 开锁
		hashLock = 0;
		copy_to_user(buf, databuf, ret);
		printk("Connection: Read %d bytes\n", ret);
	}
	// 获取日志表
	else if (op_flag == OP_GET_LOG) {
		ret = log_num * sizeof(Log);
		if (ret > size) {
			printk("Log: Read Overflow\n");
			return size;
		}

		memcpy(databuf, logs, ret);
		copy_to_user(buf, databuf, ret);
		printk("Log: Read %d bytes\n", ret);
	}
	// TODO:获取NAT表

	return ret;    
    */
}
static ssize_t chardev_write(struct file *file, const char __user *buf, size_t size, loff_t *offt)
{
    if (size > 20480)
    {
        printk("Write Overflow\n");
        return 20480;
    }

    copy_from_user(databuf, buf, size);
    //先读入操作符
    int opt = 0x03 & databuf[size - 1];

    if (opt == OP_WRITE_RULE)
    { //***
        op_flag = 0;
        RuleTable_size = (size - 1) / sizeof(Rule);
        printk("Get %d rules\n", RuleTable_size);
        memcpy(RuleTable, databuf + 1, size - 1);
    }
    else if (opt == OP_GET_CONNECT)
    {
        op_flag = OP_GET_CONNECT;
        printk("Write Connections\n");
    }
    else if (opt == OP_GET_LOG)
    {
        op_flag = OP_GET_LOG;
        printk("Write Log\n");
    }
    else if (opt == OP_GET_NAT)
    {
        op_flag = OP_GET_NAT;
        printk("Write NAT\n");
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