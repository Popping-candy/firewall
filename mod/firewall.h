#ifndef _FIREWALL_H
#define _FIREWALL_H
//chardev
#define MYMAJOR 200
#define MYNAME "chardev_test" //执行 cat /proc/devices显示的名称

//netfilter
unsigned int hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
static struct nf_hook_ops nfho = {
    .hook = hook_func,            // hook处理函数
    .pf = PF_INET,                // 协议类型
    .hooknum = NF_INET_LOCAL_OUT, // hook注册点
    .priority = NF_IP_PRI_FIRST   // 优先级
};
typedef struct
{
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
} Packet;
int pack_num = 0;
//chardev
dev_t devid;      //函数向内核申请下来的设备号
struct cdev cdev; //内核中使用cdev结构体来描述字符设备，在驱动中分配cdev,主要是分配一个cdev结构体与申请设备号
char char_buffer[100];
char pck_buffer[100];
static int chardev_open(struct inode *inode, struct file *file);
static ssize_t chardev_read(struct file *file, char __user *buf, size_t size, loff_t *ppos);
static ssize_t chardev_write(struct file *file, const char __user *buf, size_t size, loff_t *offt);
static const struct file_operations chardev_fops = {
    .open = chardev_open,
    .read = chardev_read,
    .write = chardev_write,
};

MODULE_LICENSE("GPL");             // 描述模块的许可证
MODULE_AUTHOR("wyt");              // 描述模块的作者
MODULE_DESCRIPTION("module test"); // 描述模块的介绍信息
MODULE_ALIAS("alias xxx");         // 描述模块的别名信息
#endif
