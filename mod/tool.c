#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/time.h>

#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include "tool.h"
#include "my_struct.h"
extern Log log_table[LOG_MAX];
int log(struct sk_buff *skb)
{
    struct timeval tv;
    struct tm t;
    struct iphdr *iph;
    struct tcphdr *tcph;
    int i = 1;
    iph = ip_hdr(skb);
    tcph = tcp_hdr(skb);
    log_table[i].src_ip = iph->saddr; //无符号32位整数,大端字节序??
    log_table[i].dst_ip = iph->daddr;
    log_table[i].src_port = ntohs(tcph->source); //无符号16位整数
    log_table[i].dst_port = ntohs(tcph->dest);
    log_table[i].protocol = iph->protocol; //无符号8位整数,TCP（6）、UDP（17）、ICMP（1）

    do_gettimeofday(&tv);
    tv.tv_sec += 8 * 3600;
    time_to_tm(tv.tv_sec, 0, &t);
    printk("[当前时间：%ld-%02d-%02d %02d:%02d:%02d]  ",
           t.tm_year + 1900, t.tm_mon + 1, t.tm_mday,
           t.tm_hour, t.tm_min, t.tm_sec);

    return 0;
}