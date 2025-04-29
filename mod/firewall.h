#ifndef _FIREWALL_H
#define _FIREWALL_H

#define MYMAJOR 200           //chardev
#define MYNAME "chardev_test" //执行 cat /proc/devices显示的名称
#define IP_DEC(addr) ((unsigned char *)&addr)[3], \
                     ((unsigned char *)&addr)[2], \
                     ((unsigned char *)&addr)[1], \
                     ((unsigned char *)&addr)[0]
#define RULE_MAX 200
#define LOG_MAX 1000
#define BUFFER_SIZE 20480
// 协议号   buyong
#define TCP 6
#define UDP 17
#define ICMP 1
#define ANY 0
#define ICMP_PORT 65530 //???
// 定义常量
#define MAX_RULE_NUM 50
#define MAX_LOG_NUM 100
#define MAX_NAT_NUM 1000
#define HASH_SIZE 65536 //65536
#define CONNECT_TIME 60
// 字符设备操作符
#define OP_WRITE_RULE (char)0
#define OP_GET_CONNECT (char)1
#define OP_GET_LOG (char)2
#define OP_GET_NAT (char)3
#define OP_FW_OPEN (char)6
#define OP_FW_CLOSE (char)7
#define DEFAULT_OPEN (char)8
#define DEFAULT_CLOSE (char)9

typedef struct ipInt
{
    uint32_t ip;
    uint32_t mask;
} ipInt;

typedef struct Packet // any pro =255// any port=0
{
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
} Packet;

typedef struct Rule
{
    ipInt src_ip;
    ipInt dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    bool action;
    bool isInLog;
} Rule;

typedef struct
{
    int tm_sec;  /* Seconds.	[0-60] (1 leap second) */
    int tm_min;  /* Minutes.	[0-59] */
    int tm_hour; /* Hours.	[0-23] */
    int tm_mday; /* Day.		[1-31] */
    int tm_mon;  /* Month.	[0-11] */
    int tm_year; /* Year	- 1900.  */
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    bool action;
} Log;

typedef struct Connection // 连接结构
{
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    int index;
    struct Connection *next;
} Connection;
#endif
