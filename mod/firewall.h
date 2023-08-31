#ifndef _FIREWALL_H
#define _FIREWALL_H
//chardev
#define MYMAJOR 200
#define MYNAME "chardev"

//hook
unsigned int hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
static struct nf_hook_ops nfho = {
    .hook = hook_func,            // hook处理函数
    .pf = PF_INET,                // 协议类型
    .hooknum = NF_INET_LOCAL_OUT, // hook注册点
    .priority = NF_IP_PRI_FIRST   // 优先级
};
//chardev
static int chardev_open(struct inode *inode, struct file *file);
static ssize_t chardev_read(struct file *file, char __user *buf, size_t size, loff_t *ppos);
static const struct file_operations chardev_fops = {
    .open = chardev_open,
    .read = chardev_read,
};
//DEVICE ID
dev_t devid;
struct cdev cdev;

MODULE_LICENSE("GPL");             // 描述模块的许可证
MODULE_AUTHOR("wyt");              // 描述模块的作者
MODULE_DESCRIPTION("module test"); // 描述模块的介绍信息
MODULE_ALIAS("alias xxx");         // 描述模块的别名信息
#endif
