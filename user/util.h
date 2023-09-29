#ifndef _UTIL_H
#define _UTIL_H


uint32_t IPstr2IPint(const std::string &ip);
int IPstr2IPint(const char *ipStr, unsigned int *ip, unsigned int *mask);
int IPint2IPstr(unsigned int ip, unsigned int mask, char *ipStr);
int the_other(char rbuffer[100]);
int print_pack(Packet my_pack);
int print_menu();
int rule_init();

#endif