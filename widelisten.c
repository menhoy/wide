#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "unistd.h"
#include "sys/types.h"
//#include "sys/socket.h"
#include "netinet/in.h"
#include "netinet/ip.h"
#include "netinet/ip_icmp.h"
#include "netdb.h"
#include "errno.h"
//#include "arpa/inet.h"
#include "signal.h"
#include "sys/time.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/sockios.h>
int set_promisc(char *interface, int fd) {
        struct ifreq ifr;
        strcpy(ifr.ifr_name, interface);
        if(ioctl(fd, SIOCGIFFLAGS, &ifr) == -1) {
                perror("iotcl()");
                return -1;
        }
        ifr.ifr_flags |= IFF_PROMISC;
        if(ioctl(fd, SIOCSIFFLAGS, &ifr) == -1) {
                perror("iotcl()");
                return -1;
        }
        return 0;
}

int unset_promisc(char *interface, int fd) {
        struct ifreq ifr;
        strcpy(ifr.ifr_name, interface);
        if(ioctl(fd, SIOCGIFFLAGS, &ifr) == -1) {
                perror("iotcl()");
                return -1;
        }
        ifr.ifr_flags &= ~IFF_PROMISC;
        if(ioctl(fd, SIOCSIFFLAGS, &ifr) == -1) {
                perror("iotcl()");
                return -1;
        }
        return 0;
}
void show_hex(unsigned char *buf, int size)
{
    int i;
    if(size <= 0)return;
    if(size > 10240)return;
    printf("show memory from %p in hex:\n", buf);
    for(i = 0; i < size; i++){
        if(0 == (i % 24))printf("%p: ", buf + i);
        printf("%02x ", buf[i]);
        if(7 == (i % 8))printf(" ");
        if(23 == (i % 24))printf("\n");
    }
    printf("\n");
}

int broadCast_eth(int sockfd, unsigned char *buf)
{
    ssize_t st;
    struct ethhdr *pe;

    pe = (struct ethhdr *)buf;
    pe->h_dest[0] = 0xff; 
    pe->h_dest[1] = 0xff; 
    pe->h_dest[2] = 0xff; 
    pe->h_dest[3] = 0xff; 
    pe->h_dest[4] = 0xff; 
    pe->h_dest[5] = 0xff; 
    pe->h_proto = htons(0x7769);
    st = write(sockfd, buf, 128); 
    return 0;
}
unsigned int  package_count = 0;
unsigned char buf[10240]; 

int main(int argc, char *argv[])
{
    int ret, i;
    pid_t pid;
    short proto; 
    struct ifreq ifstruct;
    struct sockaddr_ll sll;
    struct ip *pip;
    struct ether_head *peth;
    struct ethhdr *pe;
    struct timespec rqtp, rmtp;
    int sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(sockfd < 0){
        printf("socket failed.%m\n");
        return -1;
    }
    printf("socket success sockfd %d\n", sockfd);
    if(argc != 2){
        printf("usage:\n%s ethernet-if-name\n", argv[0]);
        return 0;
    }
    printf("buf is %p\n", buf);
    memset( &sll, 0, sizeof(sll) );
    sll.sll_family = AF_PACKET;
    strcpy(ifstruct.ifr_name, argv[1]);
    ret = ioctl(sockfd, SIOCGIFINDEX, &ifstruct);
    if(ret < 0){
        printf("ioctl failed!%m\n");
        return -2;
    }
    sll.sll_ifindex = ifstruct.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);
    if(bind(sockfd, (struct sockaddr *) &sll, sizeof(sll)) == -1 ) {
       perror("bind()");
    }
    printf("bind success!\n");

//    pid = fork(); 
//    if(0 == pid){
        for(i = 0; i < 10000; i++){
            ret = recvfrom(sockfd, buf, 10240, 0, 0, 0);
            if(ret < 0){
                printf("recvfrom failed!%m\n");
                break;
            }
            pe = (struct ethhdr *)buf;
            proto = ntohs(pe->h_proto); 
            if(0x7769 == proto){
                package_count++;
                printf("recvfrom ret %d, proto 0x%04x, i %d, count %u\n", ret, proto, i, package_count);
                if(package_count >= 100)break; 
            }
            //if(ret < 128)show_hex(buf, ret);
        }

/*    } else {
        broadcast msg for group setup.
        printf("Broadcast msg!\n");
        for(i = 0; i < 10; i++){
            broadCast_eth(sockfd, buf);
            rqtp.tv_sec = 1; 
            rqtp.tv_nsec = 0;
            nanosleep(&rqtp, &rmtp);
        }
        printf("package_count is %u\n", package_count);
    }
*/
    return 0;
}

