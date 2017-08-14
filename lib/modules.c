//
// Created by darkwolf on 05/08/17.
//

#include <libzvbi.h>
#include "modules.h"
#include "packet.h"
#include "debug.h"

int pipefd[PIPES_QTT][2];

void *ethernet_handler(void *arg) {
    /* Read from pipe (from Main) -- CHECKED
     * Format ethernet header
     * Write on pipe to IP -- CHECKED
     * */
    packet_dump_line_t *buf;
    ssize_t r;
    while (1) {
        // Read from Main
        r = read(pipefd[MAIN_ETH][0], &buf, sizeof(buf));
        if (r <= 0) {
#if DEBUG >= 1
            perror("ethernet_handler: read");
#endif
            break;
        }
        // Format
        // Write to IP
        r = write(pipefd[ETH_IP][1], &buf, sizeof(buf));
        if (r <= 0) {
#if DEBUG >= 1
            perror("ethernet_handler: write");
#endif
            break;
        }
    }
    return NULL;
}

void *ip_handler(void *arg) {
    /* Read from pipe (from Ethernet)
     * Format IP header
     * Write on pipe to TCP or UDP
     * */
    packet_dump_line_t *buf;
    ssize_t r;
    while (1) {
        // Read from Ethernet
        r = read(pipefd[ETH_IP][0], &buf, sizeof(buf));
        if (r <= 0) {
#if DEBUG >= 1
            perror("ip_handler: read");
#endif
            break;
        }
        // Format
        if (r == 1) {           // TODO edit temp conditional r == 1
            // Write to TCP
            r = write(pipefd[IP_TCP][1], &buf, sizeof(buf));
            if (r <= 0) {
#if DEBUG >= 1
                perror("ip_handler: write (TCP)");
#endif
                break;
            }
        } else if (r == 2) {    // TODO edit temp conditional r == 2
            // Write to UDP
            r = write(pipefd[IP_UDP][1], &buf, sizeof(buf));
            if (r <= 0) {
#if DEBUG >= 1
                perror("ip_handler: write (UDP)");
#endif
                break;
            }
        }
    }
    return NULL;
}

void *tcp_handler(void *arg) {
    /* Read from pipe (from IP)
     * Format TCP header
     * Write on pipe to Presentation
     * */
    packet_dump_line_t *buf;
    ssize_t r;
    while (1) {
        // Read from IP
        r = read(pipefd[IP_TCP][0], &buf, sizeof(buf));
        if (r <= 0) {
#if DEBUG >= 1
            perror("tcp_handler: read");
#endif
            break;
        }
        // Format
        // Write to Presentation
        r = write(pipefd[TCP_PRST][1], &buf, sizeof(buf));
        if (r <= 0) {
#if DEBUG >= 1
            perror("tcp_handler: write");
#endif
            break;
        }
    }
    return NULL;
}

void *udp_handler(void *arg) {
    /* Read from pipe (from IP)
     * Format UDP header
     * Write on pipe to Presentation
     * */
    packet_dump_line_t *buf;
    ssize_t r;
    while (1) {
        // Read from IP
        r = read(pipefd[IP_UDP][0], &buf, sizeof(buf));
        if (r <= 0) {
#if DEBUG >= 1
            perror("udp_handler: read");
#endif
            break;
        }
        // Format
        // Write to Presentation
        r = write(pipefd[UDP_PRST][1], &buf, sizeof(buf));
        if (r <= 0) {
#if DEBUG >= 1
            perror("udp_handler: write");
#endif
            break;
        }
    }
    return NULL;
}

void* presentation_handler(void *arg) {
    /* Read from pipe (multiplex between TCP and UDP)
     * Send signal to Output
     * Write on pipe to Output
     * */
    packet_dump_line_t *buf;
    ssize_t r;
    fd_set active_fd_set, read_fd_set;
    FD_ZERO(&active_fd_set);
    FD_SET(pipefd[TCP_PRST][0], &active_fd_set);
    FD_SET(pipefd[UDP_PRST][0], &active_fd_set);
    while (1) {
        read_fd_set = active_fd_set;
        if (select(FD_SETSIZE, &read_fd_set, NULL, NULL, NULL) < 0) {
#if DEBUG >= 1
            perror("presentation_handler: select");
#endif
            break;
        }
        if (FD_ISSET(pipefd[TCP_PRST][0], &read_fd_set)) { // Received TCP
            // Handle TCP packet
        } else if (FD_ISSET(pipefd[UDP_PRST][0], &read_fd_set)) { // Received UDP
            // Handle UDP packet
        } else { // Undefined behaviour

        }
        // Write to Output
        r = write(pipefd[PRST_OUTPUT][1], &buf, sizeof(buf));
        if (r <= 0) {
#if DEBUG >= 1
            perror("presentation_handler: write");
#endif
            break;
        }
    }
    return NULL;
}

void *screen_output_handler(void *arg) {
    /* Read from pipe (from Presentation)
     * Output result in screen
     * Free memory allocated by package
     * */
    packet_dump_line_t *buf;
    ssize_t r;
    while (1) {
        // Read from Presentation
        r = read(pipefd[PRST_OUTPUT][0], &buf, sizeof(buf));
        if (r <= 0) {
#if DEBUG >= 1
            perror("screen_output_handler: read");
#endif
            break;
        }
        // Format, output to screen
        // Free memory allocated
    }
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
