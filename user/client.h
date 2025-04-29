#ifndef _CLIENT_H
#define _CLIENT_H

#define IP_DEC(addr) ((unsigned char *)&addr)[3], \
                     ((unsigned char *)&addr)[2], \
                     ((unsigned char *)&addr)[1], \
                     ((unsigned char *)&addr)[0]

#define PATH2RULE "data/rule.txt"
#define PATH2LOG "data/log.txt"
#define PATH2CDEV "/dev/chardev_test"
typedef struct ipInt
{
    uint32_t ip;
    uint32_t mask;
} ipInt;
typedef struct
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
typedef struct Connection
{
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    int index; //not index but *index
} Connection;
#endif