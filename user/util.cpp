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
using namespace std;
ipInt IPstr2IPint(const string &ip)
{
    ipInt resultIp = {0, 0};
    string ip_Srt;
    string mask_Srt;
    stringstream ssInput(ip);

    getline(ssInput, ip_Srt, '/');
    getline(ssInput, mask_Srt, '/');

    stringstream ss(ip_Srt);
    string segment;

    int shift = 24;
    while (getline(ss, segment, '.'))
    {
        resultIp.ip |= stoi(segment) << shift;
        shift -= 8;
    }
    //mask
    int len = stoi(mask_Srt);
    for (int i = 0; i < len; i++)
    {
        resultIp.mask += 1;
        resultIp.mask = resultIp.mask << 1;
    }
    if (len == 32)
        resultIp.mask += 1;
    else
        resultIp.mask = resultIp.mask << 32 - len - 1;
    return resultIp;
}
string IPint2IPstr(ipInt &IPint)
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
    string IPstr;
    char str[20];
    sprintf(str, "%u.%u.%u.%u/%u", IP_DEC(IPint.ip), len);
    IPstr = str;
    return IPstr;
}
string IPint2IPstrNoMask(uint32_t ip)
{
    string IPstr;
    char str[20];
    sprintf(str, "%u.%u.%u.%u", IP_DEC(ip));
    IPstr = str;
    return IPstr;
}
void printRule(vector<Rule> &RuleTable)
{
    int i = 0;
    printf("Rule:%2d---------------------------------------------------------------------------\n", RuleTable.size());
    for (auto aRule : RuleTable)
    {
        printf("%d.| %-20s| %-20s| %-5d| %-5d| %-5d| %-5d| %-5d|\n",
               i,
               IPint2IPstr(aRule.src_ip).c_str(),
               IPint2IPstr(aRule.dst_ip).c_str(),
               aRule.src_port,
               aRule.dst_port,
               aRule.protocol,
               aRule.action,
               aRule.isInLog);
        printf("----------------------------------------------------------------------------------\n");
        i++;
    }
}
int checkRule(Rule &aRule)
{
    aRule.src_ip.ip;
    aRule.src_ip.mask;
    aRule.dst_ip.ip;
    aRule.dst_ip.mask;
    aRule.src_port;
    aRule.dst_port;
    aRule.protocol;
    aRule.action;
}
int readRulesFromKernel()
{
    // 告诉内核：我要开始读取Logs
    ofstream write2Kernel;
    write2Kernel.open(PATH2CDEV, ios::binary);
    if (!write2Kernel.is_open())
        cout << "ERROR: open cdev" << endl;
    write2Kernel << (char)GET_NAT;
    write2Kernel.close();

    // 开始读取Logs
    cout << "Get rules" << endl;
    char databuf[20480];
    ifstream readFromKernel;
    readFromKernel.open(PATH2CDEV, ios::binary);
    if (!readFromKernel.is_open())
        cout << "ERROR: open cdev" << endl;
    char Rsize = 0;
    readFromKernel.read(&Rsize, 1);
    Rule aRule;
    for (int i = 0; i < Rsize; i++)
    {
        readFromKernel.read(databuf, sizeof(Rule));
        memcpy(&aRule, databuf, sizeof(Rule));
        cout << IPint2IPstr(aRule.src_ip) << " "
             << IPint2IPstr(aRule.dst_ip) << " "
             << aRule.src_port << " "
             << aRule.dst_port << " "
             << (int)aRule.protocol << " "
             << aRule.action << " "
             << aRule.isInLog << endl;
    }
    readFromKernel.close();
}
int print_pack(Packet my_pack)
{
    printf("\nhook a pack:\n");
    printf("src_ip: %d.%d.%d.%d\n", IP_DEC(my_pack.src_ip));
    printf("dst_ip: %d.%d.%d.%d\n", IP_DEC(my_pack.dst_ip));
    printf("src_port:   %d\n", my_pack.src_port);
    printf("dst_port:   %d\n", my_pack.dst_port);
    printf("protocol:   %d\n", my_pack.protocol);
    return 0;
}
void CommandHelp()
{
}
int log_time()
{
    time_t currentTime;
    struct tm *localTime;
    char timeString[100];
    currentTime = time(NULL);
    localTime = localtime(&currentTime);
    strftime(timeString, sizeof(timeString), "%Y-%m-%d %H:%M:%S", localTime);
    printf("当前时间：%s\n", timeString);
    return 0;
}