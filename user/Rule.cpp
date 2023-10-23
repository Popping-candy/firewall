#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <stdint.h>

#include <string.h>
#include <string>
#define IP_DEC(addr) ((unsigned char *)&addr)[0], \
                     ((unsigned char *)&addr)[1], \
                     ((unsigned char *)&addr)[2], \
                     ((unsigned char *)&addr)[3]
typedef struct ipInt
{
    uint32_t ip;
    uint32_t mask;
} ipInt;

struct FirewallRule
{
    ipInt src_ip;
    ipInt dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    bool action;
};
//this----small---right;;netfliter----big---zhijue
ipInt IPstr2IPint(const std::string &ip)
{
    ipInt resultIp = {0, 0};
    std::string ip_Srt;
    std::string mask_Srt;
    std::stringstream ssInput(ip);

    std::getline(ssInput, ip_Srt, '/');
    std::getline(ssInput, mask_Srt, '/');

    std::stringstream ss(ip_Srt);
    std::string segment;

    int shift = 0;
    while (std::getline(ss, segment, '.'))
    {
        resultIp.ip |= stoi(segment) << shift;
        shift += 8;
    }
    //mask
    int len = stoi(mask_Srt);
    for (int i = 0; i < len; i++)
    {
        resultIp.mask += 1;
        resultIp.mask = resultIp.mask << 1;
    }
    resultIp.mask = resultIp.mask << 32 - len - 1;
    return resultIp;
}
std::string IPint2IPstr(ipInt IPint)
{
    //mask
    int len;
    uint32_t mask = IPint.mask;
    for (len = 32; len > 0; len--)
    {
        if (mask % 2 == 0)
            mask >>= 1;
        else
            break;
    }
    std::string IPstr;
    char str[20];
    sprintf(str, "%u.%u.%u.%u/%u", IP_DEC(IPint.ip), len);
    IPstr = str;
    return IPstr;
}
int main()
{
    std::string ipStr = "192.168.60.1/30";

    ipInt epip = IPstr2IPint(ipStr);
    struct FirewallRule arule;
    arule.src_ip = epip;
    std::cout << ipStr << "->" << epip.ip << "mask:" << epip.mask << std::endl;

    std::cout << IPint2IPstr(epip) << std::endl;
    std::cout << IPint2IPstr(arule.src_ip) << std::endl;

    return 0;
}