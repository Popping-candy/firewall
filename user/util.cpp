#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <stdint.h>
#include <getopt.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include "client.h"
#include "util.h"
int IPstr2IPint(const char *ipStr, unsigned int *ip, unsigned int *mask)
{
    // init
    int p = -1, count = 0;
    unsigned int len = 0, tmp = 0, r_mask = 0, r_ip = 0, i;
    for (i = 0; i < strlen(ipStr); i++)
    {
        if (!(ipStr[i] >= '0' && ipStr[i] <= '9') && ipStr[i] != '.' && ipStr[i] != '/')
        {
            return -1;
        }
    }
    // 获取掩码
    for (i = 0; i < strlen(ipStr); i++)
    {
        if (p != -1)
        {
            len *= 10;
            len += ipStr[i] - '0';
        }
        else if (ipStr[i] == '/')
            p = i;
    }
    if (len > 32 || (p >= 0 && p < 7))
    {
        return -1;
    }
    if (p != -1)
    {
        if (len)
            r_mask = 0xFFFFFFFF << (32 - len);
    }
    else
        r_mask = 0xFFFFFFFF;
    // 获取IP
    for (i = 0; i < (p >= 0 ? p : strlen(ipStr)); i++)
    {
        if (ipStr[i] == '.')
        {
            r_ip = r_ip | (tmp << (8 * (3 - count)));
            tmp = 0;
            count++;
            continue;
        }
        tmp *= 10;
        tmp += ipStr[i] - '0';
        if (tmp > 256 || count > 3)
            return -2;
    }
    r_ip = r_ip | tmp;
    *ip = r_ip;
    *mask = r_mask;
    return 0;
}

int IPint2IPstr(unsigned int ip, unsigned int mask, char *ipStr)
{
    unsigned int i, ips[4], maskNum = 32;
    if (ipStr == NULL)
    {
        return -1;
    }
    if (mask == 0)
        maskNum = 0;
    else
    {
        while ((mask & 1u) == 0)
        {
            maskNum--;
            mask >>= 1;
        }
    }
    for (i = 0; i < 4; i++)
    {
        ips[i] = ((ip >> ((3 - i) * 8)) & 0xFFU);
    }
    sprintf(ipStr, "%u.%u.%u.%u/%u", ips[0], ips[1], ips[2], ips[3], maskNum);
    return 0;
}

int the_other(char rbuffer[100])
{
    int fd = open("/dev/chardev_test", O_RDWR);
    int fd_data = open("data", O_RDWR);
    if (fd == -1)
    {
        perror("open_dev");
        return 0;
    }
    if (fd_data == -1)
    {
        perror("open_data");
        return 0;
    }
    printf("Packet size:%d\n", sizeof(Packet));

    read(fd, rbuffer, 100);

    Packet my_pack, sec_pack;
    mempcpy(&my_pack, rbuffer, sizeof(my_pack));
    mempcpy(&sec_pack, rbuffer + sizeof(my_pack), sizeof(my_pack));
    print_pack(my_pack);
    print_pack(sec_pack);

    close(fd);
    write(fd_data, rbuffer, 100);
    close(fd_data);
    return 0;
}
int print_pack(Packet my_pack)
{
    printf("\nhook a pack:\n");
    printf("src_ip: %d.%d.%d.%d\n", IP_DEC(my_pack.src_ip));
    printf("dst_ip: %d.%d.%d.%d\n", IP_DEC(my_pack.dst_ip));
    printf("src_port:   %d\n", my_pack.src_port);
    printf("dst_port:   %d\n", my_pack.dst_port);
    printf("protocol:   %d\n", my_pack.protocol);
}

int print_menu()
{
    system("clear");
    printf("Firewall user application.\n"
           "请选择:\n"
           "1. rule\n"
           "2. default action\n"
           "3. connection\n"
           "4. log\n"
           "5. net\n"
           "6. out\n");
    return 0;
}