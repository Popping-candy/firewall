#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <getopt.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>

#include "client.h"
#include "util.h"

using namespace std;

int log()
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

int main(int argc, char *argv[])
{
    char wbuffer[100];
    char rbuffer[100];
    //main loop
    print_menu();
    int cmd;
    bool out = 1;
    while (out)
    {
        scanf("%d", &cmd);
        switch (cmd)
        {
        case 1:
            printf("rule");
            break;
        case 2:
            printf("defallt action");
            break;
        case 3:
            printf("connection");
            break;
        case 4:
            system("clear");
            log();
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
        getchar();
        print_menu();
    }
    return 0;
}
