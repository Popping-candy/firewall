#ifndef _STRUCT_H
#define _STRUCT_H
#define RULE_MAX 100
#define LOG_MAX 1000

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
    struct tm t;
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
    int time;
} Connection;

#endif