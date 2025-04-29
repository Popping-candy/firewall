#ifndef _UTIL_H
#define _UTIL_H
using namespace std;
// 字符设备操作符
enum OPT
{
    WRITE_RULE = 0,
    GET_CONNECT,
    GET_LOG,
    GET_NAT,
    FW_OPEN=6,
    FW_CLOSE,
    FW_ACCEPT,
    FW_DROP
};
//ip
ipInt
IPstr2IPint(const string &ip);
string IPint2IPstr(ipInt &IPint);
string IPint2IPstrNoMask(uint32_t ip);
//other
int print_pack(Packet my_pack);
void printRule(vector<Rule> &RuleTable);
#endif