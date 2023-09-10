#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/cdev.h>
#include <linux/fs.h>

#include "linux/types.h"
#include "linux/errno.h"
#include "linux/uaccess.h"
#include "linux/kdev_t.h"

#include "firewall.h"
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
        my_pack.src_ip = iph->saddr;            //无符号32位整数,大端字节序??
        my_pack.dst_ip = iph->daddr;
        my_pack.src_port = ntohs(tcph->source); //无符号16位整数
        my_pack.dst_port = ntohs(tcph->dest);
        my_pack.protocol = iph->protocol;       //无符号8位整数,TCP（6）、UDP（17）、ICMP（1）
        if (pack_num < 4)
        {
            memcpy(pck_buffer + pack_num * sizeof(Packet), &my_pack, sizeof(Packet));
            pack_num++;
        }
        printk(KERN_INFO "Dropping telnet packet\n");
        return NF_DROP;
    }
    else
        return NF_ACCEPT;
}
/*
五元组 + syn ack fin  tcp??

struct iphdr *ip = ip_hdr(skb);
	pkg.src_ip = ntohl(ip->saddr);??  no  
	pkg.dst_ip = ntohl(ip->daddr);
    ip->protocol == TCP
struct tcphdr *tcp = tcp_hdr(skb);
    pkg.src_port = ntohs(tcp->source);
    pkg.dst_port = ntohs(tcp->dest);
    if ((tcp->syn) && (!tcp->ack))
        syn = 1;
    else
        syn = 0;
*/

/*
define    struct    memcpy   copy_to_user
&my_pack
memcpy(dst,src,size);
*/
int firewall_init(void)
{
    return 0;
}
int check_rule(void)
{
    return 0;
}
/********************************chardev***********************************************************/
static int chardev_open(struct inode *inode, struct file *file)
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
    //netfilter
    printk("my firewall module loaded.\n");
    nf_register_hook(&nfho);
    //chardev
    cdev_init(&cdev, &chardev_fops);             //执行cdev_init函数，将cdev和file_operations关联起来
    alloc_chrdev_region(&devid, 2, 255, MYNAME); //向内核申请主设备号
    cdev_add(&cdev, devid, 255);                 //执行cdev_init函数，将cdev和file_operations关联起来
    printk(KERN_INFO "MAJOR Number is %d\n", MAJOR(devid));
    printk(KERN_INFO "MINOR Number is %d\n", MINOR(devid));
    firewall_init();
    return 0;
}

static void __exit mod_exit(void)
{
    printk("my firewall module exit ...\n");
    nf_unregister_hook(&nfho);
    printk(KERN_INFO "chrdev_exit helloworld exit\n");
    cdev_del(&cdev);
    unregister_chrdev_region(devid, 255);
}
/**************************************************************************************************/