//
// Created by darkwolf on 28/07/17.
//

#include "tp2utils.h"
#include <stdio.h>
#include <netinet/ether.h>
#include <stdlib.h>
#include <arpa/inet.h>


void print_ethernet_header(const ethernet_hdr_t *eth) {

    uint16_t protocol;
    puts(MINOR_DIV_LINE);
    printf("[Ethernet] ");
    printf(ether_ntoa((const struct ether_addr *) &eth->ether_shost));
    printf(" > ");
    printf(ether_ntoa((const struct ether_addr *) &eth->ether_dhost));
    putchar(' ');

    protocol = ntohs(eth->ether_type);
    switch(protocol) {
        case ETHERTYPE_IP:
            printf("(IPv4)");
            break;
        case ETHERTYPE_ARP:
            printf("(ARP)");
            break;
        case ETHERTYPE_REVARP:
            printf("(RARP)");
            break;
        default:
            exit(1);
    }
    printf(" [0x%04x]\n", protocol);
    puts(MINOR_DIV_LINE);
}


void print_ip_header(const ip_hdr_t *ip) {
    puts(MINOR_DIV_LINE);
    printf("[IPv%d] ", ip->ip_version);
    printf("Header size: %d, ", IP_IHL(ip));
    printf("Total size: %d, ", ip->ip_len);
    printf("Id: 0x%04x, ", ip->ip_id);
    printf("Fragm. offset: %d, ", ip->ip_fragment_offset);
    printf("TTL: %d, ", ip->ip_ttl);
    printf("Protocol: ");
    switch(ip->ip_p) {
        case IPPROTO_TCP:
            printf("TCP");
            break;
        case IPPROTO_UDP:
            printf("UDP\n");
            return;
        default:
            exit(1);
    }
    printf(" [0x%02x], ", ip->ip_p);
    printf("Header checksum: 0x%04x", ip->ip_sum);
    putchar('\n');
    printf("[IPv%d] ", ip->ip_version);
    printf(inet_ntoa(ip->ip_src));
    printf(" > ");
    printf(inet_ntoa(ip->ip_dst));
    putchar('\n');
    puts(MINOR_DIV_LINE);
}


void print_tcp_header(const tcp_hdr_t *tcp) {
    puts(MINOR_DIV_LINE);
    printf("[TCP] ");
    printf("Port: ");
    printf("%d > ", ntohs(tcp->th_sport));
    printf("%d, ", ntohs(tcp->th_dport));
    printf("Seq. num.: %"PRIu32", ", ntohl(tcp->th_seq));
    printf("Ack. num.: %"PRIu32", ", ntohl(tcp->th_ack));
    printf("Header size: %d bytes, ", TH_OFF(tcp));
    printf("Window size: %d, ", tcp->th_win);
    printf("Checksum: 0x%06x.", tcp->th_sum);
    putchar('\n');
    puts(MINOR_DIV_LINE);
}


void print_udp_header(const udp_hdr_t *udp) {
    puts(MINOR_DIV_LINE);
    printf("[UDP] ");
    printf("Port: ");
    printf("%d > ", ntohs(udp->uh_sport));
    printf("%d, ", ntohs(udp->uh_dport));
    printf("Size: %d, ", udp->uh_ulen);
    printf("Checksum: 0x%06x.", udp->uh_sum);
    putchar('\n');
    puts(MINOR_DIV_LINE);
}