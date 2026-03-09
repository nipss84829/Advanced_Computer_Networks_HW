#include "pcap.h"
#include <sys/types.h>
#include <pcap/pcap.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h> // For gettimeofday

extern pid_t pid;       // Process ID to uniquely identify ICMP requests
extern char target_ip[]; // Current target IP

static char *net;
static char *mask;

static char filter_string[FILTER_STRING_SIZE] = "";

static pcap_t *p; // Pointer to pcap session
static struct pcap_pkthdr *hdr;
static int pcap_timeout = 1500; // Default timeout in milliseconds

/*
 * Initialize pcap for capturing ICMP replies.
 */
void custom_pcap_init(const char *dst_ip, int timeout) {
    pcap_timeout = timeout;
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 netp, maskp;
    struct in_addr addr;
    struct bpf_program fcode;

    const char *dev = getenv("PCAP_INTERFACE");
    if (dev == NULL) {
        fprintf(stderr, "Error: Network interface not specified. Use -i <interface> in main.\n");
        exit(1);
    }
    //printf("Using network interface: %s\n", dev);

    if (pcap_lookupnet(dev, &netp, &maskp, errbuf) == -1) {
        fprintf(stderr, "Error looking up net: %s\n", errbuf);
        exit(1);
    }

    addr.s_addr = netp;
    net = inet_ntoa(addr);
    addr.s_addr = maskp;
    mask = inet_ntoa(addr);

    p = pcap_open_live(dev, 8000, 1, timeout, errbuf);
    if (!p) {
        fprintf(stderr, "Error opening pcap: %s\n", errbuf);
        exit(1);
    }

    // ³]¸m«Dªý¶ë¼Ò¦¡
    if (pcap_setnonblock(p, 1, errbuf) == -1) {
        fprintf(stderr, "Error setting pcap to non-blocking mode: %s\n", pcap_geterr(p));
        exit(1);
    }
    //printf("PCAP set to non-blocking mode.\n");

    snprintf(filter_string, FILTER_STRING_SIZE, "icmp and dst host %s", dst_ip);
    if (pcap_compile(p, &fcode, filter_string, 0, maskp) == -1) {
        fprintf(stderr, "pcap_compile error: %s\n", pcap_geterr(p));
        exit(1);
    }
    if (pcap_setfilter(p, &fcode) == -1) {
        fprintf(stderr, "pcap_setfilter error: %s\n", pcap_geterr(p));
        exit(1);
    }
    //printf("PCAP initialized on interface: %s\n", dev);
}


/*
 * Capture and process an ICMP Echo Reply.
 */
#include <time.h>

int pcap_get_reply(void) {
    const u_char *packet;
    struct ip *ip_hdr;
    struct icmphdr *icmp_hdr;
    int result;
    struct timespec start, now, reply_time;
    long elapsed_ns = 0; // Elapsed time in nanoseconds

    // Get the starting time
    clock_gettime(CLOCK_MONOTONIC, &start);

    while (elapsed_ns < pcap_timeout * 1000000L) { // Convert timeout to nanoseconds
        result = pcap_next_ex(p, &hdr, &packet);

        // Get the current time
        clock_gettime(CLOCK_MONOTONIC, &now);
        elapsed_ns = (now.tv_sec - start.tv_sec) * 1000000000L + (now.tv_nsec - start.tv_nsec);

        if (result == 0) {
            // No packet captured, continue waiting
            usleep(1000); // Small delay to avoid CPU overload
            continue;
        } else if (result == -1) {
            fprintf(stderr, "Error capturing packet: %s\n", pcap_geterr(p));
            return 0;
        } else if (result == 1) {
            // Packet captured
            if (hdr->len < sizeof(struct ether_header) + sizeof(struct ip)) {
                fprintf(stderr, "Captured packet too short. Ignoring.\n");
                continue;
            }

            // Skip Ethernet header
            packet += sizeof(struct ether_header);

            // Parse IP header
            ip_hdr = (struct ip *)packet;
            int ip_hdr_len = ip_hdr->ip_hl * 4;

            if (ip_hdr_len < 20) {
                fprintf(stderr, "Invalid IP header length. Ignoring.\n");
                continue;
            }

            // Parse ICMP header
            icmp_hdr = (struct icmphdr *)(packet + ip_hdr_len);

            // Check if the packet matches the ICMP Echo Reply
            if (icmp_hdr->type == ICMP_ECHOREPLY && ntohs(icmp_hdr->un.echo.id) == pid) {
                char source_ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &ip_hdr->ip_src, source_ip, INET_ADDRSTRLEN);

                // Get the reply time
                clock_gettime(CLOCK_MONOTONIC, &reply_time);
                long response_time_ns = (reply_time.tv_sec - start.tv_sec) * 1000000000L +
                                        (reply_time.tv_nsec - start.tv_nsec);

                // Convert nanoseconds to milliseconds and print
                printf("    Reply from %s: id=0x%x, seq=%d, time=%.5f ms\n",
                       source_ip, ntohs(icmp_hdr->un.echo.id),
                       ntohs(icmp_hdr->un.echo.sequence), response_time_ns / 1000000.0);

                return 1; // Successfully captured reply
            }
        }
    }

    printf("    Destination unreachable\n");
    return 0; // No valid ICMP reply received
}












