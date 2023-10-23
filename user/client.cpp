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

int main(int argc, char *argv[])
{
    //init
    char wbuffer[100];
    char rbuffer[100];
    std::vector<Rule> RuleTable;
    readRulesFromFile(RuleTable);
    //main loop
    print_menu();
    //read from rule.txt
    int cmd;
    std::string main_cmd;
    bool out = 1;
    while (out)
    {
        scanf("%d", &cmd);
        getchar();
        switch (cmd)
        {
        case 1:
            printf("rule\n");
            ruleCommand(RuleTable);
            break;
        case 2:
            printf("defallt action");
            break;
        case 3:
            printf("connection");
            break;
        case 4:
            system("clear");
            the_other(rbuffer);
            break;
        case 5:
            printf("net");
            break;
        case 6:
            printf("bey\n");
            out = 0;
            break;
        default:
            printf("error");
            break;
        }
        getchar();
        print_menu();
    }
    return 0;
}
