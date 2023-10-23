#ifndef _UTIL_H
#define _UTIL_H

// 字符设备操作符
#define OP_WRITE_RULE	0
#define OP_GET_CONNECT	1
#define OP_GET_LOG		2
#define OP_GET_NAT		3
//ip
ipInt IPstr2IPint(const std::string &ip);
std::string IPint2IPstr(ipInt &IPint);
//rule
int readRulesFromFile(std::vector<Rule> &RuleTable);
int writeRules2File(std::vector<Rule> &RuleTable);
void printRule(std::vector<Rule> &RuleTable);
int addRule(std::vector<Rule> &RuleTable);
int removeRule(std::vector<Rule> &RuleTable);
int modifyRule(std::vector<Rule> &RuleTable);
void ruleCommand(std::vector<Rule> &RuleTable);
//next

int the_other(char rbuffer[100]);
int print_pack(Packet my_pack);
int print_menu();

#endif