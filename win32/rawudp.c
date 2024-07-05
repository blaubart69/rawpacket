#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <winsock2.h>
#include <Ws2tcpip.h>
#include <stdint.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "Packet.lib")

// Ethernet header
struct ethhdr {
    uint8_t h_dest[6];
    uint8_t h_source[6];
    uint16_t h_proto;
};

// IPv4 header
struct iphdr {
    unsigned char ihl : 4, version : 4;
    unsigned char tos;
    unsigned short tot_len;
    unsigned short id;
    unsigned short frag_off;
    unsigned char ttl;
    unsigned char protocol;
    unsigned short check;
    unsigned long saddr;
    unsigned long daddr;
};

// UDP header
struct udphdr {
    unsigned short source;
    unsigned short dest;
    unsigned short len;
    unsigned short check;
};

// Pseudo header for UDP checksum calculation
struct pseudo_header {
    unsigned long saddr;
    unsigned long daddr;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short udplength;
};

// Checksum function
unsigned short checksum(void* b, int len) {
    unsigned short* buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char*)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

// Function to convert MAC address string to bytes
void mac_str_to_bytes(const char* mac_str, uint8_t* mac_bytes) {
    sscanf_s(mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &mac_bytes[0], &mac_bytes[1], &mac_bytes[2], &mac_bytes[3], &mac_bytes[4], &mac_bytes[5]);
}

// Function to list all available network interfaces
void list_interfaces() {
    pcap_if_t* alldevs;
    pcap_if_t* d;
    char errbuf[PCAP_ERRBUF_SIZE];
    int i = 0;

    // Initialize Npcap
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        return;
    }

    // List all devices
    for (d = alldevs; d; d = d->next) {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }

    if (i == 0) {
        printf("\nNo interfaces found! Make sure Npcap is installed.\n");
    }

    pcap_freealldevs(alldevs);
}

int main(int argc, char* argv[]) {
    if (argc == 2 && strcmp(argv[1], "-l") == 0) {
        list_interfaces();
        return 0;
    }

    if (argc != 8) {
        fprintf(stderr, "Usage: %s <src_ip> <dst_ip> <src_port> <dst_port> <src_mac> <dst_mac> <interface_num>\n", argv[0]);
        fprintf(stderr, "       %s -l (to list interfaces)\n", argv[0]);
        return 1;
    }

    char src_ip[16];
    char dst_ip[16];
    int src_port;
    int dst_port;
    char src_mac_str[18];
    char dst_mac_str[18];
    int interface_num;

    strncpy_s(src_ip, sizeof(src_ip), argv[1], _TRUNCATE);
    strncpy_s(dst_ip, sizeof(dst_ip), argv[2], _TRUNCATE);
    src_port = atoi(argv[3]);
    dst_port = atoi(argv[4]);
    strncpy_s(src_mac_str, sizeof(src_mac_str), argv[5], _TRUNCATE);
    strncpy_s(dst_mac_str, sizeof(dst_mac_str), argv[6], _TRUNCATE);
    interface_num = atoi(argv[7]);

    pcap_if_t* alldevs;
    pcap_if_t* d;
    int i = 0;
    pcap_t* handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    char* dev = NULL;

    // Initialize Npcap
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        return 1;
    }

    // Select the interface
    for (d = alldevs, i = 0; i < interface_num - 1; d = d->next, i++);

    dev = d->name;

    // Open the network device for packet capture
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        pcap_freealldevs(alldevs);
        return 1;
    }

    // Data to be sent
    char data[] = "Hello, World!";
    int data_len = sizeof(data);

    // Ethernet header
    struct ethhdr eth;
    uint8_t src_mac[6];
    uint8_t dest_mac[6];
    mac_str_to_bytes(src_mac_str, src_mac);
    mac_str_to_bytes(dst_mac_str, dest_mac);
    
    //uint8_t src_mac[6] = { 0x00, 0x0C, 0x29, 0x3E, 0x7E, 0xE9 };  // Source MAC address, change as necessary
    memcpy(eth.h_source, src_mac, 6);
    memcpy(eth.h_dest, dest_mac, 6);
    
    eth.h_proto = htons(0x0800);  // Protocol type (IP)

    // IP header
    struct iphdr iph;
    iph.ihl = 5;
    iph.version = 4;
    iph.tos = 0;
    iph.tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + data_len);
    iph.id = htons(54321);
    iph.frag_off = 0;
    iph.ttl = 255;
    iph.protocol = IPPROTO_UDP;
    iph.check = 0;
    inet_pton(AF_INET, src_ip, &iph.saddr);
    inet_pton(AF_INET, dst_ip, &iph.daddr);

    // UDP header
    struct udphdr udph;
    udph.source = htons(src_port);
    udph.dest = htons(dst_port);
    udph.len = htons(sizeof(struct udphdr) + data_len);
    udph.check = 0;

    // Data part
    char* packet_data = (char*)malloc(sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + data_len);
    memset(packet_data, 0, sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + data_len);
    memcpy(packet_data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr), data, data_len);

    // Construct the complete packet
    char* packet = (char*)malloc(sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + data_len);
    memset(packet, 0, sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + data_len);
    memcpy(packet, &eth, sizeof(struct ethhdr));
    memcpy(packet + sizeof(struct ethhdr), &iph, sizeof(struct iphdr));
    memcpy(packet + sizeof(struct ethhdr) + sizeof(struct iphdr), &udph, sizeof(struct udphdr));
    memcpy(packet + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr), data, data_len);

    // Pseudo header
    struct pseudo_header psh;
    psh.saddr = iph.saddr;
    psh.daddr = iph.daddr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_UDP;
    psh.udplength = udph.len;

    int psize = sizeof(struct pseudo_header) + sizeof(struct udphdr) + data_len;
    char* pseudogram = (char*)malloc(psize);
    memcpy(pseudogram, &psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), &udph, sizeof(struct udphdr) + data_len);

    // UDP checksum calculation
    //udph.check = checksum((unsigned short*)pseudogram, psize);
    udph.check = 0;


    // IP checksum calculation
    iph.check = checksum((unsigned short*)&iph, sizeof(struct iphdr));

    // Update checksums in the packet
    memcpy(packet + sizeof(struct ethhdr), &iph, sizeof(struct iphdr));
    memcpy(packet + sizeof(struct ethhdr) + sizeof(struct iphdr), &udph, sizeof(struct udphdr));

    // Send the packet
    if (pcap_sendpacket(handle, (const u_char*)packet, sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + data_len) != 0) {
        fprintf(stderr, "Error sending the packet: %s\n", pcap_geterr(handle));
        return 1;
    }

    printf("Packet sent.\n");

    // Cleanup
    free(packet_data);
    free(packet);
    free(pseudogram);
    pcap_close(handle);
    pcap_freealldevs(alldevs);

    return 0;
}
