#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fstream>
#include <sstream>

#include <stdint.h>
#include <getopt.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include "client.h"
#include "util.h"
uint32_t IPstr2IPint(const std::string &ip)//big
{
    std::stringstream ss(ip);
    std::string segment;
    uint32_t ipInt = 0;
    int shift = 24; // Start from the leftmost byte.

    while (std::getline(ss, segment, '.'))
    {
        ipInt |= (stoi(segment) & 0xFF) << shift;
        shift -= 8; // Move to the next byte.
    }

    return ipInt;
}
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
    int fd_log = open("./log.txt", O_RDWR);
    if (fd == -1)
    {
        perror("open_dev");
        return 0;
    }
    if (fd_log == -1)
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
    close(fd_log);
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

int rule_init()
{
    //std::ofstream outFile("test.txt");
    //std::ifstream inFile("test.txt");

    std::ifstream fd_rule("data/rule.txt");
    std::string line;
    std::vector<Rule> Rule_table;
    if (fd_rule.is_open())
    {
        while (getline(fd_rule, line))
        {
            std::stringstream ss(line);
            Rule ft;
            std::string srcIP, destIP;

            ss >> srcIP >> destIP >> ft.src_port >> ft.dst_port >> ft.protocol >> ft.action;
            ft.src_ip = IPstr2IPint(srcIP);//1.2.3.4
            ft.dst_ip = IPstr2IPint(destIP);
            Rule_table.push_back(ft);

            printf("src_ip: %d.%d.%d.%d\n", IP_DEC(ft.src_ip));//4.3.2.1
            printf("dst_ip: %d.%d.%d.%d\n", IP_DEC(ft.dst_ip));

            std::cout << "srcIP: " << srcIP << " ";
            std::cout << "destIP: " << destIP << " ";
            std::cout << "srcPort: " << ft.src_port << " ";
            std::cout << "destPort: " << ft.dst_port << " ";
            std::cout << "destPort: " << ft.protocol << " ";
            std::cout << "protocol: " << ft.action << std::endl;
        }

        fd_rule.close();
    }
    return 0;
}
/*
    std::ofstream fd_rule("data/rule.txt");
    if (fd_rule.is_open())
    {
        fd_rule << "Hello, World!\n";
        fd_rule << "This is a test.\n";
        fd_rule.close();
    }
    */