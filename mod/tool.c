#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/time.h>
#include <linux/in.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/udp.h>
#include <linux/types.h>
#include <linux/crc16.h>
#include "firewall.h"
#include "tool.h"

extern Log Log_Table[LOG_MAX];
extern int LogTable_size;
extern int LogTable_pos;
extern Rule RuleTable[RULE_MAX];
extern int RuleTable_size;
extern struct rw_semaphore RuleTable_mutex;
extern Connection conHead, conEnd;
extern unsigned char hashTable[HASH_SIZE];
extern int connection_num;
extern struct rw_semaphore Connection_mutex;
extern bool default_action;
extern struct timer_list timer;
int log(struct sk_buff *skb, bool action)
{
    if (LogTable_pos == 999)
        LogTable_pos = 0;
    else
        LogTable_pos++;
    if (LogTable_size != 1000)
        LogTable_size++;
    struct timeval tv;
    struct tm t;
    struct iphdr *iph;
    struct tcphdr *tcph;
    iph = ip_hdr(skb);
    tcph = tcp_hdr(skb);
    Log_Table[LogTable_pos].src_ip = ntohl(iph->saddr);
    Log_Table[LogTable_pos].dst_ip = ntohl(iph->daddr);
    Log_Table[LogTable_pos].src_port = ntohs(tcph->source);
    Log_Table[LogTable_pos].dst_port = ntohs(tcph->dest);
    Log_Table[LogTable_pos].protocol = iph->protocol;
    Log_Table[LogTable_pos].action = action;
    do_gettimeofday(&tv);
    tv.tv_sec += 8 * 3600;
    time_to_tm(tv.tv_sec, 0, &t);
    Log_Table[LogTable_pos].tm_sec = t.tm_sec;
    Log_Table[LogTable_pos].tm_min = t.tm_min;
    Log_Table[LogTable_pos].tm_hour = t.tm_hour;
    Log_Table[LogTable_pos].tm_mday = t.tm_mday;
    Log_Table[LogTable_pos].tm_mon = t.tm_mon;
    Log_Table[LogTable_pos].tm_year = t.tm_year;
    return 0;
}

bool packetHandler(struct sk_buff *skb)
{
    Packet aPacket;
    struct iphdr *iph = ip_hdr(skb);
    aPacket.src_ip = ntohl(iph->saddr);
    aPacket.dst_ip = ntohl(iph->daddr);
    //TCP状态检测
    if (iph->protocol == IPPROTO_TCP)
    {
        struct tcphdr *tcph = tcp_hdr(skb);
        aPacket.src_port = ntohs(tcph->source);
        aPacket.dst_port = ntohs(tcph->dest);
        aPacket.protocol = IPPROTO_TCP;

        if ((tcph->syn) && (!tcph->ack)) //SYN
        {
            bool isInLog = 0;
            bool action = matchRule(aPacket, &isInLog);
            if (isInLog)
                log(skb,action);
            if (action)
            {
                addConnection(aPacket);
                return true;
            }
            else
                return false;
        }
        else
        {
            Packet Packet2;
            Packet2.src_ip = aPacket.dst_ip;
            Packet2.dst_ip = aPacket.src_ip;
            Packet2.src_port = aPacket.dst_port;
            Packet2.dst_port = aPacket.src_port;
            Packet2.protocol = IPPROTO_TCP;
            if (findInConnection(aPacket) || findInConnection(Packet2))
                return true;
            else
                return false;
        }
    }
    //UDP状态检测
    else if (iph->protocol == IPPROTO_UDP)
    {
        struct udphdr *udp = udp_hdr(skb);
        aPacket.src_port = ntohs(udp->source);
        aPacket.dst_port = ntohs(udp->dest);
        aPacket.protocol = IPPROTO_UDP;
        Packet Packet2;
        Packet2.src_ip = aPacket.dst_ip;
        Packet2.dst_ip = aPacket.src_ip;
        Packet2.src_port = aPacket.dst_port;
        Packet2.dst_port = aPacket.src_port;
        Packet2.protocol = IPPROTO_UDP;
        if (findInConnection(aPacket) || findInConnection(Packet2))
            return true;
        else
        {
            bool isInLog = 0;
            bool action = matchRule(aPacket, &isInLog);
            if (isInLog)
                log(skb,action);
            if (action)
            {
                addConnection(aPacket);
                return true;
            }
            else
                return false;
        }
    }
    //ICMP状态检测
    else if (iph->protocol == IPPROTO_ICMP)
    {
        aPacket.src_port = 0;
        aPacket.dst_port = 0;
        aPacket.protocol = IPPROTO_ICMP;
        Packet Packet2;
        Packet2.src_ip = aPacket.dst_ip;
        Packet2.dst_ip = aPacket.src_ip;
        Packet2.src_port = aPacket.dst_port;
        Packet2.dst_port = aPacket.src_port;
        Packet2.protocol = IPPROTO_ICMP;
        if (findInConnection(aPacket) || findInConnection(Packet2))
            return true;
        else
        {
            bool isInLog = 0;
            bool action = matchRule(aPacket, &isInLog);
            if (isInLog)
                log(skb,action);
            if (action)
            {
                addConnection(aPacket);
                return true;
            }
            else
                return false;
        }
    }
    else
    {
        struct udphdr *udp = udp_hdr(skb);
        aPacket.protocol = IPPROTO_UDP;

        if (findInConnection(aPacket))
            return true;
        else
        {
            bool isInLog;
            if (matchRule(aPacket, &isInLog))
            {
                addConnection(aPacket);
                return true;
            }
            else
                return false;
        }
    }
}
//add
//192.168.60.1/32 192.168.60.200/25 0 7777 6 0 1
bool matchRule(Packet aPacket, bool *isInLog)
{
    bool action = default_action;
    int i;
    down_read(&RuleTable_mutex); //lock
    for (i = 0; i < RuleTable_size; ++i)
    {
        //uint32_t tmp1 = RuleTable[i].src_ip.ip, tmp2 = RuleTable[i].src_ip.mask, tmp3 = aPacket.src_ip;
        //printk("match %d;|%u,%u,%u,%u|%u,%u,%u,%u|%u,%u,%u,%u|\n", i, IP_DEC(tmp1), IP_DEC(tmp2), IP_DEC(tmp3));
        if ((RuleTable[i].src_ip.ip ^ aPacket.src_ip) & RuleTable[i].src_ip.mask)
            continue;
        if ((RuleTable[i].dst_ip.ip ^ aPacket.dst_ip) & RuleTable[i].dst_ip.mask)
            continue;
        if ((RuleTable[i].protocol != 0) && (RuleTable[i].protocol != aPacket.protocol))
            continue;
        if ((RuleTable[i].src_port != 0) && (RuleTable[i].src_port != aPacket.src_port))
            continue;
        if ((RuleTable[i].dst_port != 0) && (RuleTable[i].dst_port != aPacket.dst_port))
            continue;

        printk("match rule%d succeed action=%d,log=%d\n", i, RuleTable[i].action, RuleTable[i].isInLog);
        *isInLog = RuleTable[i].isInLog;
        action = RuleTable[i].action;
        break;
    }
    up_read(&RuleTable_mutex); //unlock
    return action;
}

bool findInConnection(Packet aPacket)
{
    int index = hash(aPacket);
    bool flag = 1;

    down_read(&Connection_mutex); //lock
    if (hashTable[index])
        hashTable[index] = CONNECT_TIME;
    else
        flag = 0;
    up_read(&Connection_mutex); //unlock

    return flag;
}

void addConnection(Packet aPacket)
{
    Connection *p = (Connection *)kmalloc(sizeof(Connection), GFP_ATOMIC);

    down_write(&Connection_mutex); //lock
    p->src_ip = aPacket.src_ip;
    p->dst_ip = aPacket.dst_ip;
    p->src_port = aPacket.src_port;
    p->dst_port = aPacket.dst_port;
    p->protocol = aPacket.protocol;
    p->index = hash(aPacket);
    p->next = conHead.next;
    conHead.next = p;
    hashTable[p->index] = CONNECT_TIME; //change
    ++connection_num;
    up_write(&Connection_mutex); //unlock
}
//https://www.coder.work/article/169576
int hash(Packet aPacket)
{
    uint16_t crc = 0xFFFF;
    crc = crc16(crc, (const u8 *)&aPacket, 13); //sizeof(Packet)) = 16
    //printk("CRC16: %04x\n", crc);
    return crc;
}

int print_pkg(struct sk_buff *skb)
{
    struct iphdr *iph;
    struct tcphdr *tcph;
    iph = ip_hdr(skb);
    tcph = tcp_hdr(skb);
    Packet my_pack;
    my_pack.src_ip = ntohl(iph->saddr); //无符号32位整数,大端字节序??
    my_pack.dst_ip = ntohl(iph->daddr);
    my_pack.src_port = ntohs(tcph->source); //无符号16位整数
    my_pack.dst_port = ntohs(tcph->dest);
    my_pack.protocol = iph->protocol; //无符号8位整数,TCP（6）、UDP（17）、ICMP（1）

    printk("packet: %u.%u.%u.%u,%u.%u.%u.%u,%d,%d,%d\n", IP_DEC(my_pack.src_ip), IP_DEC(my_pack.dst_ip), my_pack.src_port, my_pack.dst_port, my_pack.protocol);

    return 0;
}

void time_handler(unsigned long x)
{
    Connection *p = conHead.next, *p0 = &conHead;
    while (p != &conEnd)
    {
        hashTable[p->index]--;
        // 超时
        if (!hashTable[p->index])
        {
            p0->next = p->next;
            kfree(p);
            connection_num--;
            p = p0->next;
        }
        else
        {
            p0 = p;
            p = p->next;
        }
    }
    timer.expires = jiffies + HZ;
    add_timer(&timer);
}