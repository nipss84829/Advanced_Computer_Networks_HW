#include "fill_packet.h"
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>

/*
 * Helper function to dynamically get the local IP
 * Automatically selects the first non-loopback interface
 */
static void get_local_ip(char *ip_buffer, size_t size) {
    struct ifaddrs *ifaddr, *ifa;
    int found = 0;

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        exit(1);
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET &&
            strcmp(ifa->ifa_name, "lo") != 0) { // Skip loopback interface
            struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;
            inet_ntop(AF_INET, &addr->sin_addr, ip_buffer, size);
            found = 1;
            break;
        }
    }

    freeifaddrs(ifaddr);

    if (!found) {
        fprintf(stderr, "Error: Could not find a valid network interface\n");
        exit(1);
    }
}

/*
 * Fill the IP header for the ICMP packet.
 */
void fill_iphdr(struct ip *ip_hdr, const char *dst_ip) {
    char local_ip[16];
    get_local_ip(local_ip, sizeof(local_ip)); // Dynamically fetch local IP

    ip_hdr->ip_hl = 5;                     // Header length
    ip_hdr->ip_v = 4;                      // IPv4 version
    ip_hdr->ip_tos = 0;                    // Type of service
    ip_hdr->ip_len = htons(PACKET_SIZE);   // Total packet size
    ip_hdr->ip_id = htons(0);              // ID field
    ip_hdr->ip_off = htons(0x4000);        // Don't fragment flag
    ip_hdr->ip_ttl = 1;                    // Time to live
    ip_hdr->ip_p = IPPROTO_ICMP;           // Protocol
    ip_hdr->ip_src.s_addr = inet_addr(local_ip); // Local IP
    ip_hdr->ip_dst.s_addr = inet_addr(dst_ip);   // Destination IP
}

/*
 * Fill the ICMP header for the Echo Request.
 */
void fill_icmphdr(struct icmphdr *icmp_hdr) {
    const char *student_id = "M133040001"; // Replace with your actual student ID
    int data_len = strlen(student_id);    // Length of the data

    // Fill the ICMP header
    icmp_hdr->type = 8;                   // Echo Request (Type 8)
    icmp_hdr->code = 0;                   // Code must be 0
    icmp_hdr->checksum = 0;               // Initialize checksum to 0
    icmp_hdr->un.echo.id = htons(getpid() & 0xFFFF); // Use process ID as identifier
    icmp_hdr->un.echo.sequence = htons(1);          // Sequence number starts at 1

    // Append the student ID as the data payload (part of ICMP header's structure)
    unsigned char *data = (unsigned char *)(icmp_hdr + 1);
    memcpy(data, student_id, data_len);   // Copy the student ID
    memset(data + data_len, 0, ICMP_DATA_SIZE - data_len); // 確保數據對齊

    // Calculate the checksum for the ICMP header including the data
    icmp_hdr->checksum = fill_cksum(icmp_hdr);
}

/*
 * Calculate checksum for ICMP header and data.
 * The `icmp_hdr` is passed, and the `ICMP_DATA_SIZE` is pre-defined.
 */
u16 fill_cksum(struct icmphdr *icmp_hdr) {
    unsigned short *buffer = (unsigned short *)icmp_hdr;
    unsigned int sum = 0;
    int len = sizeof(struct icmphdr) + strlen((char *)(icmp_hdr + 1)); // 動態計算數據長度

    while (len > 1) {
        sum += *buffer++;
        len -= 2;
    }

    if (len == 1) { // 如果還有剩餘的 1 字節
        sum += *(unsigned char *)buffer;
    }

    // 折疊高 16 位到低 16 位
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    return ~sum; // 返回補碼
}



