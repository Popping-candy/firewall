#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fstream>
#include <sstream>
#include <time.h>
#include <stdint.h>
#include <getopt.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include "client.h"
#include "util.h"
using namespace std;

//rule
int readRulesFromFile(vector<Rule> &RuleTable);
int writeRules2File(vector<Rule> &RuleTable);
int addRule(vector<Rule> &RuleTable);
int removeRule(vector<Rule> &RuleTable);
int modifyRule(vector<Rule> &RuleTable);
//kernel
int writeRules2Kernel(vector<Rule> &RuleTable);
int readConnectionsFromKernel();
int readLogFromKernel(vector<Log> &LogTable);
void writeCommand2Kernel(OPT opt);

int main(int argc, char *argv[])
{
    vector<Rule> RuleTable;
    vector<Log> LogTable;
    readRulesFromFile(RuleTable);
    printRule(RuleTable);
    writeRules2Kernel(RuleTable);
    string command;
    while (1)
    {
        cout << ">>>";
        getline(cin, command);

        if ((command == "firewall open") || (command == "open"))
            writeCommand2Kernel(FW_OPEN);
        else if ((command == "firewall close") || (command == "close"))
            writeCommand2Kernel(FW_CLOSE);
        else if ((command == "default accept") || (command == "accept"))
            writeCommand2Kernel(FW_ACCEPT);
        else if ((command == "default drop") || (command == "drop"))
            writeCommand2Kernel(FW_DROP);
        else if ((command == "add rule") || (command == "add"))
            addRule(RuleTable);
        else if ((command == "remove rule") || (command == "remove"))
            removeRule(RuleTable);
        else if ((command == "modify rule") || (command == "modify"))
            modifyRule(RuleTable);
        else if ((command == "ls rule") || (command == "rule"))
            printRule(RuleTable);
        else if (command == "log")
            readLogFromKernel(LogTable);
        else if ((command == "commit rule") || (command == "commit"))
            writeRules2Kernel(RuleTable);
        else if (command == "connect")
            readConnectionsFromKernel();
        else if (command == "exit")
            break;
        else
            cout << "Invalid command" << endl;
    }
    return 0;
}

int readRulesFromFile(vector<Rule> &RuleTable)
{

    ifstream fd_rule(PATH2RULE);
    string line;

    if (fd_rule.is_open())
    {
        while (getline(fd_rule, line))
        {
            stringstream ss(line);
            Rule aRule;
            string srcIP, destIP;
            int protocol;
            ss >> srcIP >> destIP >> aRule.src_port >> aRule.dst_port >> protocol >> aRule.action >> aRule.isInLog;
            aRule.src_ip = IPstr2IPint(srcIP);
            aRule.dst_ip = IPstr2IPint(destIP);
            aRule.protocol = protocol; //???
            RuleTable.push_back(aRule);
        }
        fd_rule.close();
    }
    else
        return -1;
    return 0;
}
int writeRules2File(vector<Rule> &RuleTable)
{
    ofstream fd_rule(PATH2RULE);
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
                << aRule.isInLog << endl;
    }
    fd_rule.close();
}
int addRule(vector<Rule> &RuleTable)
{
    Rule aRule;
    string srcIP, destIP;
    string input;
    cout << "intput your rule" << endl;
    getline(cin, input);
    stringstream ss(input);

    int pro, act, log;
    ss >> srcIP >> destIP >> aRule.src_port >> aRule.dst_port >> pro >> act >> log;
    aRule.protocol = pro;
    aRule.action = act;
    aRule.isInLog = log;
    aRule.src_ip = IPstr2IPint(srcIP);
    aRule.dst_ip = IPstr2IPint(destIP);

    cout << "intput position of this rule" << endl;
    int index;
    cin >> index;
    getchar();
    if (index >= 0 && index <= RuleTable.size())
    {
        RuleTable.insert(RuleTable.begin() + index, aRule);
    }
    else
    {
        cout << "error" << endl;
    }
    return 0;
}
int removeRule(vector<Rule> &RuleTable)
{
    cout << "intput position of this rule" << endl;
    int index;
    cin >> index;
    getchar();
    if (index >= 0 && index <= RuleTable.size())
    {
        RuleTable.erase(RuleTable.begin() + index);
    }
    else
    {
        cout << "error" << endl;
    }
}
int modifyRule(vector<Rule> &RuleTable)
{
    cout << "intput position of this rule" << endl;
    int index;
    cin >> index;
    getchar();

    if (index >= 0 && index < RuleTable.size())
    {
        Rule aRule;
        string srcIP, destIP;
        string input;
        cout << "intput your rule" << endl;
        getline(cin, input);
        stringstream ss(input);

        int pro, act, log;
        ss >> srcIP >> destIP >> aRule.src_port >> aRule.dst_port >> pro >> act >> log;
        aRule.protocol = pro;
        aRule.action = act;
        aRule.isInLog = log;
        aRule.src_ip = IPstr2IPint(srcIP);
        aRule.dst_ip = IPstr2IPint(destIP);
        RuleTable[index] = aRule;
        cout << "Rule modified successfully." << endl;
    }
    else
    {
        cerr << "Invalid index. Rule not modified." << endl;
    }
}
int readConnectionsFromKernel()
{
    // 告诉内核：我要开始读取connections
    writeCommand2Kernel(GET_CONNECT);
    // 开始读取connections
    char databuf[20480];
    ifstream readFromKernel;
    readFromKernel.open(PATH2CDEV, ios::binary);
    if (!readFromKernel.is_open())
        cout << "ERROR: open cdev" << endl;
    char Rsize = 0;

    readFromKernel.read(&Rsize, 1);
    printf("Connection:%2d-------------------------------------------------------\n", Rsize);
    Connection aConnection;
    for (int i = 0; i < Rsize; i++)
    {
        readFromKernel.read(databuf, sizeof(Connection));
        memcpy(&aConnection, databuf, sizeof(Connection));
        uint32_t tmp1 = aConnection.src_ip, tmp2 = aConnection.dst_ip;
        printf("| %-17s| %-17s| %-5d| %-5d| %-5d| %-5ds|\n",
               IPint2IPstrNoMask(tmp1).c_str(),
               IPint2IPstrNoMask(tmp2).c_str(),
               aConnection.src_port,
               aConnection.dst_port,
               aConnection.protocol,
               aConnection.index);
        printf("--------------------------------------------------------------------\n");
    }
    readFromKernel.close();
}
int readLogFromKernel(vector<Log> &LogTable)
{
    // 告诉内核：我要开始读取log
    writeCommand2Kernel(GET_LOG);
    // 开始读取log
    char databuf[20480];
    ifstream readFromKernel;
    readFromKernel.open(PATH2CDEV, ios::binary);
    if (!readFromKernel.is_open())
        cout << "ERROR: open cdev" << endl;
    char Lsize = 0;

    readFromKernel.read(&Lsize, 1);
    printf("Log:%4d------------------------------------------------------------------------------\n", Lsize);
    Log aLog;
    for (int i = 0; i < Lsize; i++)
    {
        readFromKernel.read(databuf, sizeof(Log));
        memcpy(&aLog, databuf, sizeof(Log));
        uint32_t tmp1 = aLog.src_ip, tmp2 = aLog.dst_ip;
        int time;
        printf("| %d-%02d-%02d %02d:%02d:%02d ",
               aLog.tm_year + 1900,
               aLog.tm_mon + 1,
               aLog.tm_mday,
               aLog.tm_hour,
               aLog.tm_min,
               aLog.tm_sec);
        printf("| %-17s| %-17s| %-4d| %-4d| %-4d| %-4d|\n",
               IPint2IPstrNoMask(tmp1).c_str(),
               IPint2IPstrNoMask(tmp2).c_str(),
               aLog.src_port,
               aLog.dst_port,
               aLog.protocol,
               aLog.action);
        printf("--------------------------------------------------------------------------------------\n");
    }
    readFromKernel.close();
}
int writeRules2Kernel(vector<Rule> &RuleTable)
{
    ofstream write2Kernel;
    write2Kernel.open(PATH2CDEV, ios::binary);
    if (!write2Kernel.is_open())
        cout << "ERROR: open cdev" << endl;
    write2Kernel << (char)WRITE_RULE;

    for (int i = 0; i < RuleTable.size(); ++i)
        write2Kernel.write((char *)&RuleTable[i], sizeof(Rule));
    write2Kernel.close();

    cout << "Commit " << RuleTable.size() << " rules" << endl;
    //cout << sizeof(Rule) << endl;
}
void writeCommand2Kernel(OPT opt)
{
    ofstream write2Kernel;
    write2Kernel.open(PATH2CDEV, ios::binary);
    if (!write2Kernel.is_open())
        cout << "ERROR: open cdev" << endl;
    write2Kernel << (char)opt;
    write2Kernel.close();
}