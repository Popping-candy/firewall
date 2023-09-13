#ifndef _FIREWALL_H
#define _FIREWALL_H
#define MYMAJOR 200           //chardev
#define MYNAME "chardev_test" //执行 cat /proc/devices显示的名称
#define RULE_MAX 100
#define LOG_MAX 1000

unsigned int hook_local_out(void *priv, struct sk_buff *skb, const struct nf_hook_state *state); //netfilter
static ssize_t chardev_open(struct inode *inode, struct file *file);
static ssize_t chardev_read(struct file *file, char __user *buf, size_t size, loff_t *ppos);
static ssize_t chardev_write(struct file *file, const char __user *buf, size_t size, loff_t *offt);
static int __init mod_init(void);
static void __exit mod_exit(void);
int check_rule(void);
int firewall_init(void);

typedef struct
{
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
} Packet;
typedef struct
{
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    bool action;
} Rule;
typedef struct
{
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    bool action;
} Log;

dev_t devid; //函数向内核申请下来的设备号
Rule rule_table[RULE_MAX];
Log log_table[LOG_MAX];
char char_buffer[100];
char pck_buffer[100];
int pack_num = 0;
struct cdev cdev; //内核中使用cdev结构体来描述字符设备，在驱动中分配cdev,主要是分配一个cdev结构体与申请设备号

static const struct file_operations chardev_fops = {
    .open = chardev_open,
    .read = chardev_read,
    .write = chardev_write,
};
static struct nf_hook_ops nfho = {
    .hook = hook_local_out,      // hook处理函数
    .pf = PF_INET,               // 协议类型
    .hooknum = NF_INET_LOCAL_IN, // hook注册点
    .priority = NF_IP_PRI_FIRST  // 优先级
};

#endif
