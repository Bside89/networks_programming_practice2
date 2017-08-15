//
// Created by darkwolf on 05/08/17.
//

#include <libzvbi.h>
#include <string.h>
#include "common.h"
#include "modules.h"
#include "packet.h"
#include "debug.h"
#include "tp2opt.h"

int pipefd[PIPES_QTT][2];

short print_payload_flag;
short shutdown_flag;

void *ethernet_handler(void *arg) {
    /* Read from pipe (from Main) -- CHECKED
     * Format ethernet header
     * Write on pipe to IP -- CHECKED
     * */
    packet_dump_line_t buf;
    ssize_t r;
    eth_hdr_t *eth;
#if DEBUG >= 2
    puts("Initializing ethernet_handler...");
#endif
    while (!shutdown_flag) {
        // Read from Main
        memset(&buf, 0, sizeof(buf));
        r = read(pipefd[MAIN_ETH][READ], &buf, sizeof(buf));
        if (r <= 0) {
#if DEBUG >= 1
            perror("ethernet_handler: read");
#endif
            break;
        }
        // Format
        eth = (eth_hdr_t*)(buf.content);
        buf.info.is_ipv4 = ntohs(eth->ether_type) == ETHERTYPE_IP;
        memcpy(&buf.info.eth_header, eth, ETHERNET_HEADER_SIZE);
        // Write to IP
        r = write(pipefd[ETH_IP][WRITE], &buf, sizeof(buf));
        if (r <= 0) {
#if DEBUG >= 1
            perror("ethernet_handler: write");
#endif
            break;
        }
    }
#if DEBUG >= 2
    puts("Closing ethernet_handler...");
#endif
    return NULL;
}

void *ip_handler(void *arg) {
    /* Read from pipe (from Ethernet)
     * Format IP header
     * Write on pipe to TCP or UDP
     * */
    packet_dump_line_t buf;
    ssize_t r;
    ip_hdr_t *ip;
#if DEBUG >= 2
    puts("Initializing ip_handler...");
#endif
    while (!shutdown_flag) {
        // Read from Ethernet
        memset(&buf, 0, sizeof(buf));
        r = read(pipefd[ETH_IP][READ], &buf, sizeof(buf));
        if (r <= 0) {
#if DEBUG >= 1
            perror("ip_handler: read");
#endif
            break;
        }
        // Format
        ip = (ip_hdr_t*)(buf.content + ETHERNET_HEADER_SIZE);
        buf.info.size_ip = IP_HSIZE(ip);
        if (buf.info.size_ip < IP_HEADER_MIN_SIZE) {
            printf("Invalid IP header length: %u bytes.\n", buf.info.size_ip);
            break;
        }
        buf.info.is_ipv4 = 1;
        memcpy(&buf.info.ip_header, ip, buf.info.size_ip);
        switch (ip->ip_p) {
            case IPPROTO_TCP:
                // Write to TCP
                r = write(pipefd[IP_TCP][WRITE], &buf, sizeof(buf));
                if (r <= 0) {
#if DEBUG >= 1
                    perror("ip_handler: write (TCP)");
#endif
                    break;
                }
                break;
            case IPPROTO_UDP:
                // Write to UDP
                r = write(pipefd[IP_UDP][WRITE], &buf, sizeof(buf));
                if (r <= 0) {
#if DEBUG >= 1
                    perror("ip_handler: write (UDP)");
#endif
                    break;
                }
                break;
            default:
                // IPPROTO_ICMP or IPPROTO_IP etc.
                return NULL;
        }
    }
#if DEBUG >= 2
    puts("Closing ip_handler...");
#endif
    return NULL;
}

void *tcp_handler(void *arg) {
    /* Read from pipe (from IP)
     * Format TCP header
     * Write on pipe to Presentation
     * */
    packet_dump_line_t buf;
    ssize_t r;
    tcp_hdr_t *tcp;
#if DEBUG >= 2
    puts("Initializing tcp_handler...");
#endif
    while (!shutdown_flag) {
        // Read from IP
        memset(&buf, 0, sizeof(buf));
        r = read(pipefd[IP_TCP][READ], &buf, sizeof(buf));
        if (r <= 0) {
#if DEBUG >= 1
            perror("tcp_handler: read");
#endif
            break;
        }
        // Format
        tcp = (tcp_hdr_t*)(buf.content + ETHERNET_HEADER_SIZE
                           + buf.info.size_ip);
        buf.info.size_transport = (uint32_t) TH_HSIZE(tcp);
        buf.info.is_tcp = 1;
        memcpy(&buf.info.tcp_header, tcp, buf.info.size_transport);
        // Write to Presentation
        r = write(pipefd[TCP_PRST][WRITE], &buf, sizeof(buf));
        if (r <= 0) {
#if DEBUG >= 1
            perror("tcp_handler: write");
#endif
            break;
        }
    }
#if DEBUG >= 2
    puts("Closing tcp_handler...");
#endif
    return NULL;
}

void *udp_handler(void *arg) {
    /* Read from pipe (from IP)
     * Format UDP header
     * Write on pipe to Presentation
     * */
    packet_dump_line_t buf;
    ssize_t r;
    udp_hdr_t *udp;
#if DEBUG >= 2
    puts("Initializing udp_handler...");
#endif
    while (!shutdown_flag) {
        // Read from IP
        memset(&buf, 0, sizeof(buf));
        r = read(pipefd[IP_UDP][READ], &buf, sizeof(buf));
        if (r <= 0) {
#if DEBUG >= 1
            perror("udp_handler: read");
#endif
            break;
        }
        // Format
        udp = (udp_hdr_t*)(buf.content + ETHERNET_HEADER_SIZE
                           + buf.info.size_ip);
        buf.info.size_transport = UDP_HEADER_SIZE;
        buf.info.is_udp = 1;
        memcpy(&buf.info.udp_header, udp, buf.info.size_transport);
        // Write to Presentation
        r = write(pipefd[UDP_PRST][WRITE], &buf, sizeof(buf));
        if (r <= 0) {
#if DEBUG >= 1
            perror("udp_handler: write");
#endif
            break;
        }
    }
#if DEBUG >= 2
    puts("Closing udp_handler...");
#endif
    return NULL;
}

void* presentation_handler(void *arg) {
    /* Read from pipe (multiplex between TCP and UDP)
     * Send signal to Output
     * Write on pipe to Output
     * */
    packet_dump_line_t buf;
    ssize_t r;
    u_char *payload;
    fd_set active_fd_set, read_fd_set;
    FD_ZERO(&active_fd_set);
    FD_SET(pipefd[TCP_PRST][READ], &active_fd_set);
    FD_SET(pipefd[UDP_PRST][READ], &active_fd_set);
#if DEBUG >= 2
    puts("Initializing presentation_handler...");
#endif
    while (!shutdown_flag) {
        read_fd_set = active_fd_set;
        if (select(FD_SETSIZE, &read_fd_set, NULL, NULL, NULL) < 0) {
#if DEBUG >= 1
            perror("presentation_handler: select");
#endif
            break;
        }
        memset(&buf, 0, sizeof(buf));
        if (FD_ISSET(pipefd[TCP_PRST][READ], &read_fd_set)) { // Received TCP
            // Handle TCP packet
            r = read(pipefd[TCP_PRST][READ], &buf, sizeof(buf));
            if (r <= 0) {
#if DEBUG >= 1
                perror("presentation_handler: write (TCP)");
#endif
                break;
            }
        } else if (FD_ISSET(pipefd[UDP_PRST][READ], &read_fd_set)) { // Received UDP
            // Handle UDP packet
            r = read(pipefd[UDP_PRST][READ], &buf, sizeof(buf));
            if (r <= 0) {
#if DEBUG >= 1
                perror("presentation_handler: write (UDP)");
#endif
                break;
            }
            payload = (u_char *) (buf.content + ETHERNET_HEADER_SIZE
                                  + buf.info.size_ip + buf.info.size_transport);
            buf.info.size_payload = ntohs(buf.info.ip_header.ip_len)
                                    - (buf.info.size_ip + buf.info.size_transport);
            buf.info.print_payload = 1;
            memcpy(buf.info.payload, payload, buf.info.size_payload);
            buf.info_is_completed = 1;
        } else { // Undefined behaviour
            fprintf(stderr, "Undefined behaviour on select().\n");
            return NULL;
        }
        // Write to Output
        r = write(pipefd[PRST_OUTPUT][WRITE], &buf, sizeof(buf));
        if (r <= 0) {
#if DEBUG >= 1
            perror("presentation_handler: write");
#endif
            break;
        }
    }
#if DEBUG >= 2
    puts("Closing presentation_handler...");
#endif
    return NULL;
}

void *screen_output_handler(void *arg) {
    /* Read from pipe (from Presentation)
     * Output result in screen
     * Write to Filewriter or free memory
     * */
    packet_dump_line_t buf;
    ssize_t r;
    pa_opt options = *((pa_opt*) arg);
#if DEBUG >= 2
    puts("Initializing screen_output_handler...");
#endif
    while (!shutdown_flag) {
        // Read from Presentation
        memset(&buf, 0, sizeof(buf));
        r = read(pipefd[PRST_OUTPUT][READ], &buf, sizeof(buf));
        if (r <= 0) {
#if DEBUG >= 1
            perror("screen_output_handler: read");
#endif
            break;
        }
        // Format, output to screen
        buf.info.print_payload = print_payload_flag;
        pkt_print_packet(&buf);
    }
#if DEBUG >= 2
    puts("Closing screen_output_handler...");
#endif
    return NULL;
}

int start_pipes() {
    int i;
    for (i = 0; i < PIPES_QTT; i++) {
        if (pipe(pipefd[i]) < 0) {
#if DEBUG >= 1
            perror("start_pipes: pipe");
#endif
            return -1;
        }
    }
    return 0;
}

void close_modules() {
    ssize_t r;
    int i;
    for (i = 0; i < PIPES_QTT; i++) {
        r = write(pipefd[i][WRITE], '\0', 0);
#if DEBUG >= 2
        if (r <= 0)
            printf("Can't send shutdown byte to thread #%d\n", i);
#endif
    }
    for (i = 0; i < PIPES_QTT; i++) {
        close(pipefd[i][READ]);
        close(pipefd[i][WRITE]);
    }
}
