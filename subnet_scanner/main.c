#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include "fill_packet.h"
#include "pcap.h"


pid_t pid; // Process ID to uniquely identify ICMP requests
char target_ip[16]; // Global variable to store the current target IP

// Function to dynamically get the local IP and subnet mask
void get_local_ip_and_mask(const char *interface, char *local_ip, char *subnet_mask, size_t size) {
    struct ifaddrs *ifaddr, *ifa;

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        exit(1);
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET &&
            strcmp(ifa->ifa_name, interface) == 0) {
            struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;
            struct sockaddr_in *netmask = (struct sockaddr_in *)ifa->ifa_netmask;

            inet_ntop(AF_INET, &addr->sin_addr, local_ip, size);
            inet_ntop(AF_INET, &netmask->sin_addr, subnet_mask, size);
            freeifaddrs(ifaddr);
            return;
        }
    }

    freeifaddrs(ifaddr);
    fprintf(stderr, "Error: Could not find IP or subnet mask for interface %s\n", interface);
    exit(1);
}

// Function to calculate the network range
void calculate_network_range(const char *ip, const char *mask, char *base_ip, unsigned int *start_host, unsigned int *end_host) {
    struct in_addr ip_addr, mask_addr;
    inet_aton(ip, &ip_addr);
    inet_aton(mask, &mask_addr);

    unsigned int network = ntohl(ip_addr.s_addr) & ntohl(mask_addr.s_addr);
    unsigned int broadcast = network | ~ntohl(mask_addr.s_addr);

    snprintf(base_ip, 16, "%d.%d.%d.", (network >> 24) & 0xFF, (network >> 16) & 0xFF, (network >> 8) & 0xFF);

    *start_host = network + 1; // Start from the first host
    *end_host = broadcast - 1; // End at the last host
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s -i <network interface> -t <timeout>\n", argv[0]);
        exit(1);
    }

    const char *interface = NULL;
    int timeout = DEFAULT_TIMEOUT;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            interface = argv[++i];
        } else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
            timeout = atoi(argv[++i]);
        }
    }

    if (!interface) {
        fprintf(stderr, "Error: Network interface not specified\n");
        exit(1);
    }

    char local_ip[16];
    char subnet_mask[16];
    char base_ip[16];
    unsigned int start_host, end_host;

    get_local_ip_and_mask(interface, local_ip, subnet_mask, sizeof(local_ip));
    //printf("Local IP: %s\n", local_ip);
    //printf("Subnet Mask: %s\n", subnet_mask);

    calculate_network_range(local_ip, subnet_mask, base_ip, &start_host, &end_host);
    //printf("Calculated range: %s%u - %s%u\n", base_ip, start_host & 0xFF, base_ip, end_host & 0xFF);

    //printf("Initializing PCAP with interface: %s\n", interface);
	setenv("PCAP_INTERFACE", interface, 1);
    custom_pcap_init(local_ip, timeout);
    //printf("PCAP initialized successfully.\n");

    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        perror("socket");
        exit(1);
    }

    int bufsize = 1024 * 1024; // 1 MB buffer size
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &bufsize, sizeof(bufsize)) < 0) {
        perror("setsockopt");
        exit(1);
    }

    pid = getpid();
    struct sockaddr_in dst;
    unsigned char packet[PACKET_SIZE];

    // Loop through the IP range
    for (unsigned int host = start_host; host <= end_host; host++) {
        snprintf(target_ip, sizeof(target_ip), "%s%u", base_ip, host & 0xFF);

        // Skip the host's own IP
        if (strcmp(target_ip, local_ip) == 0) {
            continue;
        }

        

        memset(packet, 0, sizeof(packet));
        fill_iphdr((struct ip *)packet, target_ip);
        fill_icmphdr((struct icmphdr *)(packet + sizeof(struct ip)));

        memset(&dst, 0, sizeof(dst));
        dst.sin_family = AF_INET;
        dst.sin_addr.s_addr = inet_addr(target_ip);

        printf("PING %s (data size = %d, id = 0x%x, seq = %d , timeout = %d ms)\n",
           target_ip, ICMP_DATA_SIZE, pid & 0xFFFF, host & 0xFFFF, timeout);

        if (sendto(sockfd, packet, sizeof(struct ip) + sizeof(struct icmphdr) + ICMP_DATA_SIZE, 0,
           (struct sockaddr *)&dst, sizeof(dst)) < 0) {
            perror("sendto failed");
            //printf("[ERROR] Failed to send packet to %s\n", target_ip);
            continue;
        } else {
           // printf("[DEBUG] Packet successfully sent to %s\n", target_ip);
        }

        // Add a delay to prevent overloading the network or OS buffer
        usleep(2000000); // 2000 milliseconds

        //printf("Packet sent to %s, waiting for reply...\n", target_ip);

        pcap_get_reply();
        
    }

    close(sockfd);
    return 0;
}

