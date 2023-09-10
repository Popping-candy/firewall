#ifndef _UTIL_H
#define _UTIL_H



int IPstr2IPint(const char *ipStr, unsigned int *ip, unsigned int *mask);
int IPint2IPstr(unsigned int ip, unsigned int mask, char *ipStr);
int other();
int menu();


#endif