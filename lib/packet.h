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
#include <time.h>
#include "common.h"

#define ETHERNET_HEADER_SIZE    14  // Ethernet headers are always exactly 14 bytes
#define IP_HEADER_MIN_SIZE      20  // IP headers are at least 20 bytes
#define TCP_HEADER_MIN_SIZE     20  // TCP headers are at least 20 bytes
#define UDP_HEADER_SIZE         8   // UDP headers are always exactly 8 bytes
#define PAYLOAD_MAX_SIZE        BUFSIZ  - ETHERNET_HEADER_SIZE \
                                        - IP_HEADER_MIN_SIZE \
                                        - UDP_HEADER_SIZE

typedef struct ether_header eth_hdr_t;  // Ethernet header
typedef struct ip           ip_hdr_t;   // IP header
typedef struct tcphdr       tcp_hdr_t;  // TCP header
typedef struct udphdr       udp_hdr_t;  // UDP header

#define IP_HSIZE(ip) (4*(ip)->ip_hl)    // Calculate IP header size
#define TH_HSIZE(tcp) (4*(tcp)->th_off) // Calculate TCP header size

typedef struct {    /* Info packet */
    uint32_t        num;
    eth_hdr_t       eth_header;
    ip_hdr_t        ip_header;
    union {
        tcp_hdr_t   tcp_header;
        udp_hdr_t   udp_header;
    };
    u_char          payload[PAYLOAD_MAX_SIZE];
    uint32_t        size_ip;
    uint32_t        size_transport;
    uint32_t        size_payload;
    short int       is_ipv4, is_tcp, is_udp, print_payload; // Flags
} packet_t;

typedef struct {        /* Complete packet */
    packet_t            info;               // Processed info
    struct pcap_pkthdr  line_header;        // Packet pcap header
    struct timespec     timedelta;          // Time diff with the previous packet
    short int           info_is_completed;  // Flag
    u_char              content[BUFSIZ];    // Packet content
} packet_dump_line_t;

void pkt_timeval_wrapper(struct timeval, struct timeval, struct timespec *);
void pkt_print_packet(packet_dump_line_t *);
void pkt_print_ethernet_header(const eth_hdr_t *);
void pkt_print_ip_header(const ip_hdr_t *);
void pkt_print_tcp_header(const tcp_hdr_t *);
void pkt_print_udp_header(const udp_hdr_t *);
void pkt_print_payload(const u_char *, const int);

#endif //TP2_TP2UTILS_H
