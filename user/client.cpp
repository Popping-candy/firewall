#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <stdint.h>
#include <getopt.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>

#include "client.h"
#include "util.h"

using namespace std;

int main(int argc, char *argv[])
{
    the_other();
}

int the_other()
{
    int fd = open("/dev/chardev_test", O_RDWR);
    int fd_data = open("data", O_RDWR);
    if ((fd == -1) || (fd_data == -1))
    {
        perror("open");
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
    write(fd_data, rbuffer, 100);
    close(fd_data);
    return 0;
}
int print_pack(Packet my_pack)
{
    printf("\nhook a pack:\n");
    printf("src_ip: %d.%d.%d.%d\n",
           ((unsigned char *)&my_pack.src_ip)[0],
           ((unsigned char *)&my_pack.src_ip)[1],
           ((unsigned char *)&my_pack.src_ip)[2],
           ((unsigned char *)&my_pack.src_ip)[3]);
    printf("dst_ip: %d.%d.%d.%d\n",
           ((unsigned char *)&my_pack.dst_ip)[0],
           ((unsigned char *)&my_pack.dst_ip)[1],
           ((unsigned char *)&my_pack.dst_ip)[2],
           ((unsigned char *)&my_pack.dst_ip)[3]);
    printf("src_port:   %d\n", my_pack.src_port);
    printf("dst_port:   %d\n", my_pack.dst_port);
    printf("protocol:   %d\n", my_pack.protocol);
}
