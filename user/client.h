#ifndef _CLIENT_H
#define _CLIENT_H

#define IP_DEC(addr) ((unsigned char *)&addr)[0], \
                     ((unsigned char *)&addr)[1], \
                     ((unsigned char *)&addr)[2], \
                     ((unsigned char *)&addr)[3]
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

#endif