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
#include "firewall.h"
/********************************hook*****************************************************/
unsigned int hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct tcphdr *tcph;

    iph = ip_hdr(skb);
    tcph = (void *)iph + iph->ihl * 4;

    if (iph->protocol == IPPROTO_TCP && tcph->dest == htons(23))
    {
        printk(KERN_INFO "Dropping telnet packet to %d.%d.%d.%d\n",
               ((unsigned char *)&iph->daddr)[0],
               ((unsigned char *)&iph->daddr)[1],
               ((unsigned char *)&iph->daddr)[2],
               ((unsigned char *)&iph->daddr)[3]);
        printk("1111%s", (char *)skb);
        return NF_DROP; //NF_ACCEPT
    }
    else
    {
        return NF_ACCEPT;
    }
}
/********************************chardev***********************************************************/
static int chardev_open(struct inode *inode, struct file *file)
{
    printk(KERN_INFO "chardev open\n");
    return 0;
}

static ssize_t chardev_read(struct file *file, char __user *buf, size_t size, loff_t *ppos)
{
    return 0;
}
/**************************************************************************************************/
static int __init mod_init(void)
{
    printk("my firewall module loaded.\n");
    nf_register_hook(&nfho);
    //chardev
    printk(KERN_INFO "chrdev_init helloworld init\n");
    cdev_init(&cdev, &chardev_fops);
    alloc_chrdev_region(&devid, 2, 255, MYNAME);
    printk(KERN_INFO "MAJOR Number is %d\n", MAJOR(devid));
    printk(KERN_INFO "MINOR Number is %d\n", MINOR(devid));
    cdev_add(&cdev, devid, 255);
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
module_init(mod_init);
module_exit(mod_exit);
