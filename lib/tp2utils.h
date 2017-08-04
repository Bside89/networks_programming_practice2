//
// Created by darkwolf on 28/07/17.
//

#ifndef TP2_TP2UTILS_H
#define TP2_TP2UTILS_H

#include <unitypes.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include "common.h"

#define ETHERNET_HEADER_SIZE 14     // Ethernet headers are always exactly 14 bytes
#define IP_HEADER_MIN_SIZE 20       // IP headers are at least 20 bytes
#define TCP_HEADER_MIN_SIZE 20      // TCP headers are at least 20 bytes
#define UDP_HEADER_SIZE 8           // UDP headers are always exactly 8 bytes


typedef struct ether_header ethernet_hdr_t;

/* IP header */
typedef struct {
# if __BYTE_ORDER == __LITTLE_ENDIAN
    u_char          ip_ihl      :4;
    u_char          ip_version  :4;
    u_char          ip_ecn      :2;
    u_char          ip_dscp     :6;
# elif __BYTE_ORDER == __BIG_ENDIAN
    u_char          ip_version  :4;
    u_char          ip_ihl      :4;
    u_char          ip_dscp     :6;
    u_char          ip_ecn      :2;
#endif
    u_short         ip_len;
    u_short         ip_id;
# if __BYTE_ORDER == __LITTLE_ENDIAN
    u_short         ip_fragment_offset  :13;
    u_char          ip_flags_mf         :1;
    u_char          ip_flags_df         :1;
    u_char          ip_flags_rf         :1;
# elif __BYTE_ORDER == __BIG_ENDIAN
    u_char          ip_flags_rf         :1;
    u_char          ip_flags_df         :1;
    u_char          ip_flags_mf         :1;
    u_short         ip_fragment_offset  :13;
#endif
    u_char          ip_ttl;
    u_char          ip_p;
    u_short         ip_sum;
    struct in_addr  ip_src;
    struct in_addr  ip_dst;
} ip_hdr_t;

#define IP_IHL(ip) ((ip)->ip_ihl*4)


typedef struct {
    u_short th_sport;
    u_short th_dport;
    u_int   th_seq;
    u_int   th_ack;
# if __BYTE_ORDER == __LITTLE_ENDIAN
    u_char th_flag_ns   :1;
    u_char th_reserved  :3;
    u_char th_offset    :4;
    u_char th_flag_fin  :1;
    u_char th_flag_syn  :1;
    u_char th_flag_rst  :1;
    u_char th_flag_psh  :1;
    u_char th_flag_ack  :1;
    u_char th_flag_urg  :1;
    u_char th_flag_ece  :1;
    u_char th_flag_cwr  :1;
# elif __BYTE_ORDER == __BIG_ENDIAN
    u_char th_offset    :4;
    u_char th_reserved  :3;
    u_char th_flag_ns   :1;
    u_char th_flag_cwr  :1;
    u_char th_flag_ece  :1;
    u_char th_flag_urg  :1;
    u_char th_flag_ack  :1;
    u_char th_flag_psh  :1;
    u_char th_flag_rst  :1;
    u_char th_flag_syn  :1;
    u_char th_flag_fin  :1;
#endif
    u_short th_win;
    u_short th_sum;
    u_short th_urp;
} tcp_hdr_t;

#define TH_OFF(tcp) ((tcp)->th_offset*4)


typedef struct {
    u_short	uh_sport;
    u_short	uh_dport;
    u_short	uh_ulen;
    u_short	uh_sum;
} udp_hdr_t;


typedef struct {
    ethernet_hdr_t *eth_header;
    ip_hdr_t *ipv4_header;
    tcp_hdr_t *tcp_header;
    udp_hdr_t *udp_header;
    u_char *payload;
    int size_payload;
    short int is_ipv4, is_tcp, is_udp, print_payload; // Flags
} packet_t;


void print_packet(packet_t *packet, int pck_num, int pck_size);

void print_ethernet_header(const ethernet_hdr_t *eth);

void print_ip_header(const ip_hdr_t *ip);

void print_tcp_header(const tcp_hdr_t *tcp);

void print_udp_header(const udp_hdr_t *udp);

void print_payload(const u_char *payload, const int size_payload);


#endif //TP2_TP2UTILS_H
