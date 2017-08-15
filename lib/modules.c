//
// Created by darkwolf on 05/08/17.
//

#include <libzvbi.h>
#include "common.h"
#include "modules.h"
#include "packet.h"
#include "debug.h"
#include "tp2opt.h"

int pipefd[PIPES_QTT][2];

void *ethernet_handler(void *arg) {
    /* Read from pipe (from Main) -- CHECKED
     * Format ethernet header
     * Write on pipe to IP -- CHECKED
     * */
    packet_dump_line_t *buf;
    ssize_t r;
    puts("Initializing ethernet_handler...");
    while (1) {
        // Read from Main
        r = read(pipefd[MAIN_ETH][READ], &buf, sizeof(buf));
        if (r <= 0) {
#if DEBUG >= 1
            perror("ethernet_handler: read");
#endif
            break;
        }
        // Format
        // Write to IP
        r = write(pipefd[ETH_IP][WRITE], &buf, sizeof(buf));
        if (r <= 0) {
#if DEBUG >= 1
            perror("ethernet_handler: write");
#endif
            break;
        }
    }
    puts("Closing ethernet_handler...");
    return NULL;
}

void *ip_handler(void *arg) {
    /* Read from pipe (from Ethernet)
     * Format IP header
     * Write on pipe to TCP or UDP
     * */
    packet_dump_line_t *buf;
    ssize_t r;
    puts("Initializing ip_handler...");
    while (1) {
        // Read from Ethernet
        r = read(pipefd[ETH_IP][READ], &buf, sizeof(buf));
        if (r <= 0) {
#if DEBUG >= 1
            perror("ip_handler: read");
#endif
            break;
        }
        // Format
        if (r == 1) {           // TODO edit temp conditional r == 1
            // Write to TCP
            r = write(pipefd[IP_TCP][WRITE], &buf, sizeof(buf));
            if (r <= 0) {
#if DEBUG >= 1
                perror("ip_handler: write (TCP)");
#endif
                break;
            }
        } else if (r == 2) {    // TODO edit temp conditional r == 2
            // Write to UDP
            r = write(pipefd[IP_UDP][WRITE], &buf, sizeof(buf));
            if (r <= 0) {
#if DEBUG >= 1
                perror("ip_handler: write (UDP)");
#endif
                break;
            }
        }
    }
    puts("Closing ip_handler...");
    return NULL;
}

void *tcp_handler(void *arg) {
    /* Read from pipe (from IP)
     * Format TCP header
     * Write on pipe to Presentation
     * */
    packet_dump_line_t *buf;
    ssize_t r;
    puts("Initializing tcp_handler...");
    while (1) {
        // Read from IP
        r = read(pipefd[IP_TCP][READ], &buf, sizeof(buf));
        if (r <= 0) {
#if DEBUG >= 1
            perror("tcp_handler: read");
#endif
            break;
        }
        // Format
        // Write to Presentation
        r = write(pipefd[TCP_PRST][WRITE], &buf, sizeof(buf));
        if (r <= 0) {
#if DEBUG >= 1
            perror("tcp_handler: write");
#endif
            break;
        }
    }
    puts("Closing tcp_handler...");
    return NULL;
}

void *udp_handler(void *arg) {
    /* Read from pipe (from IP)
     * Format UDP header
     * Write on pipe to Presentation
     * */
    packet_dump_line_t *buf;
    ssize_t r;
    puts("Initializing udp_handler...");
    while (1) {
        // Read from IP
        r = read(pipefd[IP_UDP][READ], &buf, sizeof(buf));
        if (r <= 0) {
#if DEBUG >= 1
            perror("udp_handler: read");
#endif
            break;
        }
        // Format
        // Write to Presentation
        r = write(pipefd[UDP_PRST][WRITE], &buf, sizeof(buf));
        if (r <= 0) {
#if DEBUG >= 1
            perror("udp_handler: write");
#endif
            break;
        }
    }
    puts("Closing udp_handler...");
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
    FD_SET(pipefd[TCP_PRST][READ], &active_fd_set);
    FD_SET(pipefd[UDP_PRST][READ], &active_fd_set);
    puts("Initializing presentation_handler...");
    while (1) {
        read_fd_set = active_fd_set;
        if (select(FD_SETSIZE, &read_fd_set, NULL, NULL, NULL) < 0) {
#if DEBUG >= 1
            perror("presentation_handler: select");
#endif
            break;
        }
        if (FD_ISSET(pipefd[TCP_PRST][READ], &read_fd_set)) { // Received TCP
            // Handle TCP packet
        } else if (FD_ISSET(pipefd[UDP_PRST][READ], &read_fd_set)) { // Received UDP
            // Handle UDP packet
        } else { // Undefined behaviour

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
    puts("Closing presentation_handler...");
    return NULL;
}

void *screen_output_handler(void *arg) {
    /* Read from pipe (from Presentation)
     * Output result in screen
     * Write to Filewriter or free memory
     * */
    packet_dump_line_t *buf;
    ssize_t r;
    pa_opt options = *((pa_opt*) arg);
    puts("Initializing screen_output_handler...");
    while (1) {
        // Read from Presentation
        r = read(pipefd[PRST_OUTPUT][READ], &buf, sizeof(buf));
        if (r <= 0) {
#if DEBUG >= 1
            perror("screen_output_handler: read");
#endif
            break;
        }
        // Format, output to screen

        if (options.rw_mode_opt == WRITE) {
            // Write packet to Filewriter
            r = write(pipefd[OUTPUT_WRITER][WRITE], &buf, sizeof(buf));
            if (r <= 0) {
#if DEBUG >= 1
                perror("screen_output_handler: write");
#endif
                break;
            }
        } else {
            // Free allocated memory
            //pkt_free(&buf);
        }
    }
    puts("Closing screen_output_handler...");
    return NULL;
}

/*void *filewriter_handler(void *arg) {
    /* Read from pipe (from Output)
     * Write packet in file
     * Free memory allocated by package
     * */
    /*packet_dump_line_t *buf;
    ssize_t r;
    while (1) {
        r = read(pipefd[OUTPUT_WRITER][READ], &buf, sizeof(buf));
        if (r <= 0) {
#if DEBUG >= 1
            perror("filewriter_handler: read");
#endif
            break;
        }
        // Write packet in file
        //pkt_free(&buf); // Free memory
    }
    return NULL;
}*/

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
    int i;
    for (i = 0; i < PIPES_QTT; i++)
        write(pipefd[i][WRITE], '\0', 0);
    for (i = 0; i < PIPES_QTT; i++) {
        close(pipefd[i][READ]);
        close(pipefd[i][WRITE]);
    }
}
