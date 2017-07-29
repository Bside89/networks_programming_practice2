//
// Created by darkwolf on 28/07/17.
//

#include "tp2utils.h"
#include <stdio.h>
#include <netinet/ether.h>
#include <stdlib.h>
#include <arpa/inet.h>


void print_ethernet_header(const sniff_ethernet *eth) {

    uint16_t protocol;
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
}


void print_ip_header(const sniff_ip *ip) {

    printf("[IPv4] ");
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
    putchar('\n');
    printf("[IPv4] ");
    printf(inet_ntoa(ip->ip_src));
    printf(" > ");
    printf(inet_ntoa(ip->ip_dst));
    putchar('\n');
}


void print_tcp_header(const sniff_tcp *tcp) {
    printf("[TCP] ");
    printf("Port: ");
    printf("%d", ntohs(tcp->th_sport));
    printf(" > ");
    printf("%d", ntohs(tcp->th_dport));
    putchar('\n');
}
