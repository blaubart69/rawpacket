#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <unistd.h>
#include <net/ethernet.h>
//#include <linux/ip.h>
#include <linux/if.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>

// #define MY_DEST_MAC0	0xAA
// #define MY_DEST_MAC1	0xBB
// #define MY_DEST_MAC2	0xCC
// #define MY_DEST_MAC3	0xDD
// #define MY_DEST_MAC4	0xEE
// #define MY_DEST_MAC5	0xFF

// pi2 dc:a6:32:ac:86:df
#define MY_DEST_MAC0	0xdc
#define MY_DEST_MAC1	0xa6
#define MY_DEST_MAC2	0x32
#define MY_DEST_MAC3	0xac
#define MY_DEST_MAC4	0x86
#define MY_DEST_MAC5	0xdf

// Checksum calculation function
unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

// Function to create and send a raw UDP packet
void send_raw_udp_packet(const char *source_ip, const char *dest_ip, int source_port, int dest_port, const char *data) {
    int sock;
    char packet[4096];
    struct ether_header *eh   = (struct ether_header *) (packet + 0                                                     );
    struct iphdr        *iph  = (struct iphdr        *) (packet + sizeof(struct ether_header)                           );
    struct udphdr       *udph = (struct udphdr       *) (packet + sizeof(struct ether_header) + sizeof(struct iphdr)    );
    struct sockaddr_in sin;
    int one = 1;
    const int *val = &one;

    // Create a raw socket
    //if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
    if ((sock = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }
    /*
    // Socket options
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
        perror("Setting socket option failed");
        exit(EXIT_FAILURE);
    }*/

	struct ifreq if_idx;
	struct ifreq if_mac;
    char ifName[IFNAMSIZ];

    strcpy(ifName, "enp2s0");

   /* Get the index of the interface to send on */
	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, ifName, IFNAMSIZ-1);
	if (ioctl(sock, SIOCGIFINDEX, &if_idx) < 0)
	    perror("SIOCGIFINDEX");

	/* Get the MAC address of the interface to send on */
	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, ifName, IFNAMSIZ-1);
	if (ioctl(sock, SIOCGIFHWADDR, &if_mac) < 0)
	    perror("SIOCGIFHWADDR");

    // Clear the packet buffer
    memset(packet, 0, 4096);

    // ethernet header
    eh->ether_shost[0] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[0];
	eh->ether_shost[1] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[1];
	eh->ether_shost[2] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[2];
	eh->ether_shost[3] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[3];
	eh->ether_shost[4] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[4];
	eh->ether_shost[5] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[5];
	eh->ether_dhost[0] = MY_DEST_MAC0;
	eh->ether_dhost[1] = MY_DEST_MAC1;
	eh->ether_dhost[2] = MY_DEST_MAC2;
	eh->ether_dhost[3] = MY_DEST_MAC3;
	eh->ether_dhost[4] = MY_DEST_MAC4;
	eh->ether_dhost[5] = MY_DEST_MAC5;
    /* Ethertype field */
	eh->ether_type = htons(ETH_P_IP);

    // IP Header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    
    uint16_t iph_total_len = sizeof(struct iphdr) + sizeof(struct udphdr) + strlen(data);
    {
        uint16_t iph_total_len_htons = htons(iph_total_len);
        
        printf("iph_total_len: %u (0x%04X), htons(iph_total_len); %u (0x%04X);sizeof(struct iphdr): %u, sizeof(struct udphdr): %u, strlen(data): %u\n", 
            (unsigned int)iph_total_len, 
            (unsigned int)iph_total_len, 
            (unsigned int)(iph_total_len_htons),
            (unsigned int)(iph_total_len_htons),
            (unsigned int)sizeof(struct iphdr),
            (unsigned int)sizeof(struct udphdr),
            (unsigned int)strlen(data) );

        iph->tot_len =  iph_total_len_htons;
    }
    iph->id = htonl(54321);
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_UDP;
    iph->check = 0; // Set to 0 before calculating checksum
    iph->saddr = inet_addr(source_ip);
    iph->daddr = inet_addr(dest_ip);

    // IP checksum
    //iph->check = checksum((unsigned short *) packet, iph->tot_len);
    //iph->check = checksum((unsigned short *) packet, iph_total_len);
    iph->check = htons(0x39F3);

    // UDP Header
    udph->source = htons(source_port);
    udph->dest = htons(dest_port);
    udph->len = htons(sizeof(struct udphdr) + strlen(data));
    udph->check = 0; // Leave checksum 0 now, filled later by pseudo header

    // Copy data to packet
    memcpy(packet + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr), data, strlen(data));


    // Destination address
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr(dest_ip);

    struct sockaddr_ll socket_address;
    /* Index of the network device */
	socket_address.sll_ifindex = if_idx.ifr_ifindex;
	/* Address length*/
	socket_address.sll_halen = ETH_ALEN;
	/* Destination MAC */
	socket_address.sll_addr[0] = MY_DEST_MAC0;
	socket_address.sll_addr[1] = MY_DEST_MAC1;
	socket_address.sll_addr[2] = MY_DEST_MAC2;
	socket_address.sll_addr[3] = MY_DEST_MAC3;
	socket_address.sll_addr[4] = MY_DEST_MAC4;
	socket_address.sll_addr[5] = MY_DEST_MAC5;

    // Send the packet
    //if (sendto(sock, packet, iph->tot_len, 0, (struct sockaddr *) &sin, sizeof(sin)) < 0) {
    size_t bytes_to_sent = sizeof(struct ether_header) + iph_total_len;
    if (sendto(sock, packet, bytes_to_sent, 0, (struct sockaddr*) &socket_address, sizeof(struct sockaddr_ll)) < 0) {


 // if (sendto(sockfd, sendbuf, tx_len, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)

        perror("Send failed");
        exit(EXIT_FAILURE);
    }

    close(sock);
    //free(pseudo_packet);
    printf("Packet sent successfully!\n");
}

int main(int argc, char *argv[]) {
    const char *source_ip = "192.168.0.103";
    const char *dest_ip = "192.168.0.6";
    int source_port = 12345;
    int dest_port = 27000;
    const char *data = "Hello, this is a raw UDP packet!";

    send_raw_udp_packet(source_ip, dest_ip, source_port, dest_port, data);

    return 0;
}


    /*

    // Pseudo header for UDP checksum
    struct pseudo_header {
        u_int32_t source_address;
        u_int32_t dest_address;
        u_int8_t placeholder;
        u_int8_t protocol;
        u_int16_t udp_length;
    } pseudo_header;

    pseudo_header.source_address = inet_addr(source_ip);
    pseudo_header.dest_address = inet_addr(dest_ip);
    pseudo_header.placeholder = 0;
    pseudo_header.protocol = IPPROTO_UDP;
    pseudo_header.udp_length = htons(sizeof(struct udphdr) + strlen(data));

    int pseudo_packet_size = sizeof(struct pseudo_header) + sizeof(struct udphdr) + strlen(data);
    char *pseudo_packet = malloc(pseudo_packet_size);

    memcpy(pseudo_packet, (char *) &pseudo_header, sizeof(struct pseudo_header));
    memcpy(pseudo_packet + sizeof(struct pseudo_header), udph, sizeof(struct udphdr) + strlen(data));

    udph->check = checksum((unsigned short *) pseudo_packet, pseudo_packet_size);

    */
