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
using namespace std;
typedef struct
{
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
} Packet;
char wbuffer[100] = "hook?";
char rbuffer[100];
int main(int argc, char *argv[])
{
    printf("user application\n");
    int fd = open("/dev/chardev_test", O_RDWR);
    int fd_data = open("data", O_RDWR);
    if ((fd == -1) || (fd_data == -1))
    {
        perror("open");
        return 0;
    }
    printf("Packet size:%d\n", sizeof(Packet));

    read(fd, rbuffer, 100);
    
    Packet my_pack;
    mempcpy(&my_pack,rbuffer,sizeof(my_pack));
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


    close(fd);
    write(fd_data, rbuffer, 100);
    close(fd_data);
    return 0;
}
