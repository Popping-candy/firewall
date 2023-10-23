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
std::string IPint2IPstr(ipInt &IPint)
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
int readRulesFromFile(std::vector<Rule> &RuleTable)
{

    std::ifstream fd_rule(PATH2RULE);
    std::string line;

    if (fd_rule.is_open())
    {
        while (getline(fd_rule, line))
        {
            std::stringstream ss(line);
            Rule aRule;
            std::string srcIP, destIP;
            ss >> srcIP >> destIP >> aRule.src_port >> aRule.dst_port >> aRule.protocol >> aRule.action >> aRule.isInLog;
            aRule.src_ip = IPstr2IPint(srcIP);
            aRule.dst_ip = IPstr2IPint(destIP);
            RuleTable.push_back(aRule);
        }

        fd_rule.close();
    }
    else
        return -1;
    return 0;
}
int writeRules2File(std::vector<Rule> &RuleTable)
{
    std::ofstream fd_rule(PATH2RULE);
    if (!fd_rule.is_open())
        return -1;
    for (auto aRule : RuleTable)
    {
        fd_rule << IPint2IPstr(aRule.src_ip) << " "
                << IPint2IPstr(aRule.dst_ip) << " "
                << aRule.src_port << " "
                << aRule.dst_port << " "
                << aRule.protocol << " "
                << aRule.action << " "
                << aRule.isInLog << std::endl;
    }
    fd_rule.close();
}
void printRule(std::vector<Rule> &RuleTable)
{
    // for(auto aRule : RuleTable)
    // for (std::vector<Rule>::iterator it = RuleTable.begin(); it != RuleTable.end(); it++)
    for (auto aRule : RuleTable)
    {
        std::cout << IPint2IPstr(aRule.src_ip) << " "
                  << IPint2IPstr(aRule.dst_ip) << " "
                  << aRule.src_port << " "
                  << aRule.dst_port << " "
                  << aRule.protocol << " "
                  << aRule.action << " "
                  << aRule.isInLog << std::endl;
    }
}
int addRule(std::vector<Rule> &RuleTable)
{
    //new beging
    Rule aRule;
    std::string srcIP, destIP;
    std::string input;
    std::cout << "intput your rule" << std::endl;
    //check()!!
    getline(std::cin, input);
    std::cout << input << std::endl;
    std::stringstream ss(input);

    ss >> srcIP >> destIP >> aRule.src_port >> aRule.dst_port >> aRule.protocol >> aRule.action >> aRule.isInLog;
    aRule.src_ip = IPstr2IPint(srcIP);
    aRule.dst_ip = IPstr2IPint(destIP);
    //new end
    std::cout << "intput position of this rule" << std::endl;
    int index;
    std::cin >> index;
    getchar();
    if (index >= 0 && index <= RuleTable.size())
    {
        RuleTable.insert(RuleTable.begin() + index, aRule);
    }
    else
    {
        std::cout << "error" << std::endl;
    }
    return 0;
}
int removeRule(std::vector<Rule> &RuleTable)
{
    std::cout << "intput position of this rule" << std::endl;
    int index;
    std::cin >> index;
    getchar();
    if (index >= 0 && index <= RuleTable.size())
    {
        RuleTable.erase(RuleTable.begin() + index);
    }
    else
    {
        std::cout << "error" << std::endl;
    }
}
int modifyRule(std::vector<Rule> &RuleTable)
{
    std::cout << "intput position of this rule" << std::endl;
    int index;
    std::cin >> index;
    getchar();

    if (index >= 0 && index < RuleTable.size())
    {
        //new beging
        Rule aRule;
        std::string srcIP, destIP;
        std::string input;
        std::cout << "intput your rule" << std::endl;
        //check()!!
        getline(std::cin, input);
        std::cout << input << std::endl;
        std::stringstream ss(input);

        ss >> srcIP >> destIP >> aRule.src_port >> aRule.dst_port >> aRule.protocol >> aRule.action >> aRule.isInLog;
        aRule.src_ip = IPstr2IPint(srcIP);
        aRule.dst_ip = IPstr2IPint(destIP);
        //new end
        RuleTable[index] = aRule;
        std::cout << "Rule modified successfully." << std::endl;
    }
    else
    {
        std::cerr << "Invalid index. Rule not modified." << std::endl;
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

int commitRule(std::vector<Rule> &RuleTable)
{
    // 告诉内核：我要开始写Rules
    std::ofstream write2Kernel;
    write2Kernel.open("/dev/chardev_test", std::ios::binary);
    write2Kernel << OP_WRITE_RULE;

    for (int i = 0; i < RuleTable.size(); ++i)
    {
        write2Kernel.write((char *)&RuleTable[i], sizeof(Rule));
    }
    write2Kernel.close();

    std::cout << "Commit " << RuleTable.size() << " rules" << std::endl;
}
int readRulesFromKernel()
{
    // 告诉内核：我要开始读取Logs
    std::ofstream write2Kernel;
    write2Kernel.open("/dev/chardev_test", std::ios::binary);
    write2Kernel << OP_GET_NAT;
    write2Kernel.close();

    // 开始读取Logs
    std::cout << "Get logs" << std::endl;
    char databuf[20480];
    std::ifstream readFromKernel;
    readFromKernel.open("/dev/chardev_test", std::ios::binary);

    int i = 0;
    Rule aRule;
    while (readFromKernel.read(databuf, sizeof(Rule)))
    {
        memcpy(&aRule, databuf, sizeof(Rule));
        std::cout << IPint2IPstr(aRule.src_ip) << " "
                  << IPint2IPstr(aRule.dst_ip) << " "
                  << aRule.src_port << " "
                  << aRule.dst_port << " "
                  << aRule.protocol << " "
                  << aRule.action << " "
                  << aRule.isInLog << std::endl;
    }
    readFromKernel.close();
}
void ruleCommand(std::vector<Rule> &RuleTable)
{
    printRule(RuleTable);

    int cmd = -1;
    while (cmd)
    {
        printf("12345\n");
        scanf("%d", &cmd);
        getchar();
        switch (cmd)
        {
        case 1:
            addRule(RuleTable);
            break;
        case 2:
            removeRule(RuleTable);
            break;
        case 3:
            modifyRule(RuleTable);
            break;
        case 4:
            printRule(RuleTable);
            break;
        case 5:
            commitRule(RuleTable);
            readRulesFromKernel();
            break;
        case 0:
            break;
        default:
            printf("error");
            break;
        }
    }
}

int the_other(char rbuffer[100])
{
    int fd = open("/dev/chardev_test", O_RDWR);
    int fd_log = open("./data/log.txt", O_RDWR);
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
    return 0;
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

//std::ofstream outFile("test.txt");
//std::ifstream inFile("test.txt");
/*
    std::ofstream fd_rule("data/rule.txt");
    if (fd_rule.is_open())
    {
        fd_rule << "Hello, World!\n";
        fd_rule << "This is a test.\n";
        fd_rule.close();
    }
*/

void CommandHelp()
{
    std::cout << "wrong command." << std::endl
              << "wrong command." << std::endl
              << "wrong command." << std::endl
              << "wrong command." << std::endl
              << "wrong command." << std::endl
              << "wrong command." << std::endl
              << "uapp <command> <sub-command> [option]" << std::endl;
    printf("wrong command.\n");
    printf("uapp <command> <sub-command> [option]\n");
    printf("commands: rule <add | del | ls | default> [del rule's name]\n");
    printf("          nat  <add | del | ls> [del number]\n");
    printf("          ls   <rule | nat | log | connect>\n");
    exit(0);
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