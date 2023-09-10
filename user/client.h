#ifndef _CLIENT_H
#define _CLIENT_H

typedef struct
{
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
} Packet;

char wbuffer[100];
char rbuffer[100];

int the_other();
int print_pack(Packet my_pack);












#endif