//
// Created by darkwolf on 28/07/17.
//

#ifndef TP2_TP2UTILS_H
#define TP2_TP2UTILS_H

#include <unitypes.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <pcap.h>
#include "common.h"

#define ETHERNET_HEADER_SIZE    14  // Ethernet headers are always exactly 14 bytes
#define IP_HEADER_MIN_SIZE      20  // IP headers are at least 20 bytes
#define TCP_HEADER_MIN_SIZE     20  // TCP headers are at least 20 bytes
#define UDP_HEADER_SIZE         8   // UDP headers are always exactly 8 bytes


/* Ethernet header */
typedef struct ether_header eth_hdr_t;

/* IP header */
typedef struct ip ip_hdr_t;

#define IP_HSIZE(ip) (4*(ip)->ip_hl)

/* TCP header */
typedef struct tcphdr tcp_hdr_t;

#define TH_HSIZE(tcp) (4*(tcp)->th_off)

/* UDP header */
typedef struct udphdr udp_hdr_t;


/* Info packet */
typedef struct {
    uint32_t        num;
    eth_hdr_t       *eth_header;
    ip_hdr_t        *ip_header;
    union {
        tcp_hdr_t   *tcp_header;
        udp_hdr_t   *udp_header;
    };
    u_char          *payload;
    uint32_t        size_payload;
    short int       is_ipv4, is_tcp, is_udp, print_payload; // Flags
} packet_t;


typedef struct {
    packet_t            info;
    struct pcap_pkthdr  line_header;
    u_char              content[BUFSIZ];
} packet_dump_line_t;


void print_packet(packet_t *packet, int pck_size);

void print_ethernet_header(const eth_hdr_t *eth);

void print_ip_header(const ip_hdr_t *ip);

void print_tcp_header(const tcp_hdr_t *tcp);

void print_udp_header(const udp_hdr_t *udp);

void print_payload(const u_char *payload, const int size_payload);


#endif //TP2_TP2UTILS_H
