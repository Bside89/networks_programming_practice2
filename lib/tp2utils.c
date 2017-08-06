//
// Created by darkwolf on 28/07/17.
//

#include "tp2utils.h"
#include <stdio.h>
#include <netinet/ether.h>
#include <arpa/inet.h>


#define CHECK_FLAG(flag, position) (flag & (1 << position))


void print_ethernet_header(const eth_hdr_t *eth) {

    uint16_t protocol;
    printf("[Ethernet] ");
    printf(ether_ntoa((const struct ether_addr *) &eth->ether_shost));
    printf(" > ");
    printf(ether_ntoa((const struct ether_addr *) &eth->ether_dhost));
    putchar(' ');

    protocol = ntohs(eth->ether_type);
    switch (protocol) {
        case ETHERTYPE_IP:
            printf("(IPv4)");
            break;
        case ETHERTYPE_ARP:
            printf("(ARP)");
            break;
        case ETHERTYPE_REVARP:
            printf("(RARP)");
            break;
        case ETHERTYPE_IPV6:
            printf("(IPv6)");
            break;
        default:
            printf("(Other protocol)");
            break;
    }
    printf(" [0x%04x]\n", protocol);
}


void print_ip_header(const ip_hdr_t *ip) {
    printf("[IPv%d] ", ip->ip_v);
    printf("Header size: %d, ", IP_HSIZE(ip));
    printf("Total size: %d, ", ntohs(ip->ip_len));
    printf("Id: 0x%04x, ", ip->ip_id);
    printf("Fragm. offset: %d, ", ip->ip_off);
    printf("TTL: %d, ", ip->ip_ttl);
    printf("Protocol: ");
    switch (ip->ip_p) {
        case IPPROTO_TCP:
            printf("TCP");
            break;
        case IPPROTO_UDP:
            printf("UDP");
            break;
        default:
            printf("(Prther than TCP or UDP)");
            break;
    }
    printf(" [0x%02x], ", ip->ip_p);
    printf("Header checksum: 0x%04x", ntohs(ip->ip_sum));
    putchar('\n');
    printf("[IPv%d] ", ip->ip_v);
    printf(inet_ntoa(ip->ip_src));
    printf(" > ");
    printf(inet_ntoa(ip->ip_dst));
    putchar('\n');
}


void print_tcp_header(const tcp_hdr_t *tcp) {

    static const char *flags_labels[] = {"FIN", "SYN", "RST", "PSH", "ACK", "URG"};

    int i, print_separator = 0;

    printf("[TCP] ");
    printf("Port: ");
    printf("%u > ", ntohs(tcp->th_sport));
    printf("%u, ", ntohs(tcp->th_dport));
    printf("Seq. num.: %u, ", ntohl(tcp->th_seq));
    if (tcp->th_flags & TH_ACK) // ACK is set
        printf("Ack. num.: %u, ", ntohl(tcp->th_ack));
    printf("Header size: %u bytes, ", TH_HSIZE(tcp));
    printf("FLAGS: ");
    for (i = 0; i < 6; i++) {
        if (CHECK_FLAG(tcp->th_flags, i)) {
            if (print_separator)
                putchar('+');
            else
                print_separator = 1;
            printf("%s", flags_labels[i]);
        }
    }
    printf(", ");
    printf("Window size: %u, ", ntohs(tcp->th_win));
    printf("Checksum: 0x%06x", ntohs(tcp->th_sum));
    if (tcp->th_flags & TH_URG) {
        printf(", ");
        printf("Urgent pointer: %u", tcp->th_urp);
    } else
        putchar('.');
    putchar('\n');
}


void print_udp_header(const udp_hdr_t *udp) {
    printf("[UDP] ");
    printf("Port: ");
    printf("%d > ", ntohs(udp->uh_sport));
    printf("%d, ", ntohs(udp->uh_dport));
    printf("Size: %d, ", ntohs(udp->uh_ulen));
    printf("Checksum: 0x%06x.", ntohs(udp->uh_sum));
    putchar('\n');
}


void print_payload(const u_char *payload, const int size_payload) {
    printf("[Payload (%d bytes)]\n", size_payload);
    if (size_payload > 0 && payload != NULL) {
        const u_char *temp_pointer = payload;
        int byte_count = 0;
        while (byte_count++ < size_payload) {
            printf("%c", *temp_pointer);
            temp_pointer++;
        }
        putchar('\n');
    }
}


void print_packet(packet_t *packet, int pck_num, int pck_size) {
    if (!packet->is_ipv4) {
        return;
    }
    if (!packet->is_tcp && !packet->is_udp) {
        return;
    }
    puts(MINOR_DIV_LINE);
    printf("Packet number:\t<%d>\n", pck_num);
    printf("Packet length:\t%d bytes.\n", pck_size);
    puts(MINOR_DIV_LINE);
    print_ethernet_header(packet->eth_header);
    puts(MINOR_DIV_LINE);
    print_ip_header(packet->ipv4_header);
    puts(MINOR_DIV_LINE);
    if (packet->is_tcp)
        print_tcp_header(packet->tcp_header);
    else if (packet->is_udp)
        print_udp_header(packet->udp_header);
    if (packet->print_payload) {
        puts(MINOR_DIV_LINE);
        print_payload(packet->payload, packet->size_payload);
    }
    puts(MINOR_DIV_LINE);
    puts(DIV_LINE);
}
