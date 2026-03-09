#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <unistd.h>

#define ICMP_ECHO 8
#define PACKET_SIZE 64

unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2) sum += *buf++;
    if (len == 1) sum += *(unsigned char*)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

void create_icmp_packet(char *packet, int seq) {
    struct icmphdr *icmp = (struct icmphdr*)packet;
    icmp->type = ICMP_ECHO;
    icmp->code = 0;
    icmp->un.echo.id = getpid();
    icmp->un.echo.sequence = seq;
    icmp->checksum = 0;
    icmp->checksum = checksum(packet, PACKET_SIZE);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <hop-distance> <destination>\n", argv[0]);
        return -1;
    }

    int hop_distance = atoi(argv[1]);
    char *destination = argv[2];

    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        perror("socket error");
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(destination);

    int ttl = 1;
    char packet[PACKET_SIZE];
    struct timeval timeout = {1, 0};
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    while (ttl <= hop_distance) {
        // TTL Setting
        if (setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0) {
            perror("setsockopt TTL error");
            close(sockfd);
            return -1;
        }

        // Create ICMP Packet
        create_icmp_packet(packet, ttl);

        printf("Sending ICMP request with TTL = %d\n", ttl);//try to know how many TTL that in ICMP packet 

        // Send ICMP Echo Request
        if (sendto(sockfd, packet, PACKET_SIZE, 0, (struct sockaddr*)&addr, sizeof(addr)) <= 0) {
            perror("sendto error");
            close(sockfd);
            return -1;
        }

        // Receive Reply
        char recv_buf[PACKET_SIZE];
        struct sockaddr_in recv_addr;
        socklen_t recv_len = sizeof(recv_addr);
        int recv_status = recvfrom(sockfd, recv_buf, PACKET_SIZE, 0, (struct sockaddr*)&recv_addr, &recv_len);
        
        if (recv_status > 0) {
            printf("Hop %d: %s\n", ttl, inet_ntoa(recv_addr.sin_addr));
        } else {
            printf("Hop %d: Request timed out.\n", ttl);
        }

        ttl++;
    }

    close(sockfd);
    return 0;
}
