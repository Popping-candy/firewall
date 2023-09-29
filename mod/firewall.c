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
Rule rule_table[RULE_MAX];//lock??
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
        printk("src_ip:%u.%u.%u.%u,,dst_ip:%u.%u.%u.%u\n",IP_DEC(my_pack.src_ip),IP_DEC(my_pack.dst_ip));
        printk("size_of_tcph:%d||syn:%d\n",sizeof(struct tcphdr),tcph->syn);
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
    //tongbu rule
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
static ssize_t chardev_open(struct inode *inode, struct file *file)
{
    printk(KERN_INFO "chardev open\n");
    return 0;
}

static ssize_t chardev_read(struct file *file, char __user *buf, size_t size, loff_t *ppos)
{
    printk(KERN_INFO "chardev read\n");
    if (size > 100)
    {
        size = 100;
    }
    if (copy_to_user(buf, pck_buffer, size))
    {
        return -EFAULT;
    }
    return size;
}
static ssize_t chardev_write(struct file *file, const char __user *buf, size_t size, loff_t *offt)
{
    printk(KERN_INFO "chardev write\n");
    if (size > 100)
    {
        size = 100;
    }
    if (copy_from_user(char_buffer, buf, size))
    {
        return -EFAULT;
    }
    printk("write %s\n", char_buffer);
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