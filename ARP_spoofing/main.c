#include <netinet/if_ether.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include "arp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <arpa/inet.h>
#include <unistd.h>  // for geteuid()

/* 
 * Change "enp2s0f5" to your device name (e.g. "eth0"), when you test your hoework.
 * If you don't know your device name, you can use "ifconfig" command on Linux.
 * You have to use "enp2s0f5" when you ready to upload your homework.
 */
#define DEVICE_NAME "enp0s3"

/*
 * You have to open two socket to handle this program.
 * One for input , the other for output.
 */
void print_help() {
    printf("Usage:\n");
    printf("1) ./arp -l -a\n");
    printf("2) ./arp -l <filter_ip_address>\n");
    printf("3) ./arp -q <query_ip_address>\n");
    printf("4) ./arp <fake_mac_address> <target_ip_address>\n");
}


int main(int argc, char *argv[])
{	// check superuser or not
	if (geteuid() != 0) {
        fprintf(stderr, "ERROR: You must be root to use this tool!\n");
        return 1;//return 1 means something wrong here
    }
	printf("[ARP sniffer and spoof program ]\n");

	//print help list-----------------------------------------------------------------
	if (argc == 2 && strcmp(argv[1], "-help") == 0) {// print help
        print_help();
        return 0;
    }

	int sockfd_recv = 0, sockfd_send = 0;
	struct sockaddr_ll sa;
	struct ifreq req;
	struct in_addr myip;
	

	// Open a recv socket in data-link layer.
	if((sockfd_recv = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
	{
		perror("open recv socket error");
		exit(1);
	}
	
	//capture packet---------------------------------------------------------------------------
    if (argc == 3 && strcmp(argv[1], "-l") == 0 && strcmp(argv[2], "-a") == 0) {//to discriminate operation
        // catch all arp packets
		printf("### ARP sniffer mode ###\n");
        capture_arp_packets(sockfd_recv, NULL);
        return 0;
    } else if (argc == 3 && strcmp(argv[1], "-l") == 0) {
        // catch arp packet with specific ip
		printf("### ARP sniffer mode ###\n");
        capture_arp_packets(sockfd_recv, argv[2]);
        return 0;
    }

	// Open a send socket in data-link layer.--------------------------------------------------
	if((sockfd_send = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
	{
		perror("open send socket error");
		exit(sockfd_send);
	}
	//send arp request
	if (argc == 3 && strcmp(argv[1], "-q") == 0) {
		printf("### ARP query mode ###\n");
        char *query_ip = argv[2];
        
        char source_ip[INET_ADDRSTRLEN];
        char source_mac[18];  

        get_local_ip(DEVICE_NAME, source_ip);
        get_local_mac(DEVICE_NAME, source_mac);

        
        send_arp_request(sockfd_send, query_ip, source_ip, source_mac);

        //capture ARP packet to check if the specific ARP reply
        capture_arp_reply_packets(sockfd_recv, query_ip);  

        return 0;
    }
	//send ARP reply
	if (argc == 3) {
		printf("### ARP spoof mode ###\n");
        char *fake_mac = argv[1];   // fake MAC 
    	char *target_ip = argv[2];  // target IP 
    	char source_ip[INET_ADDRSTRLEN];
    	char source_mac[18];  

    	
    	get_local_ip(DEVICE_NAME, source_ip);
   		get_local_mac(DEVICE_NAME, source_mac);
    
    	/*printf("Fake MAC: %s\n", fake_mac);
    	printf("Source MAC: %s\n", source_mac);
		printf("target ip: %s\n", target_ip );
    	printf("Source ip: %s\n", source_ip);*/ //for debug

    	
    	capture_and_reply_arp_packets(sockfd_recv, sockfd_send, target_ip, fake_mac, source_ip, source_mac);

    	return 0;
    } else {
        fprintf(stderr, "Invalid arguments.\n");
        print_help();
        return 1;
    }

    fprintf(stderr, "Invalid arguments.\n");
	/*
	 * Use recvfrom function to get packet.
	 * recvfrom( ... )
	 */



	
	
	
	
	/*
	 * Use ioctl function binds the send socket and the Network Interface Card.
`	 * ioctl( ... )
	 */
	
	

	
	// Fill the parameters of the sa.



	
	/*
	 * use sendto function with sa variable to send your packet out
	 * sendto( ... )
	 */
	
	
	


	return 0;
}

