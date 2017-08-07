//
// Created by darkwolf on 05/08/17.
//

#include <libzvbi.h>
#include "modules.h"


int pipefd[PIPES_QTT][2];


void *ethernet_handler(void *arg) {

    /* Read from pipe (from Main)
     * Format ethernet header
     * Write on pipe to IP */
    return NULL;
}


void *ip_handler(void *arg) {
    /* Read from pipe (from Ethernet)
     * Format IP header
     * Write on pipe to TCP or UDP */
    return NULL;
}


void *tcp_handler(void *arg) {
    /* Read from pipe (from IP)
     * Format TCP header
     * Write on pipe to Output */
    return NULL;
}


void *udp_handler(void *arg) {
    /* Read from pipe (from IP)
     * Format UDP header
     * Write on pipe to Output */
    return NULL;
}


void *screen_output_handler(void *arg) {
    /* Read from pipe (multiplex between TCP and UDP)
     * Output result in screen
     * Free memory allocated by package */
    return NULL;
}


int start_pipes() {
    int i;
    for (i = 0; i < PIPES_QTT; i++) {
        if (pipe(pipefd[i]) < 0)
            return -1;
    }
    return 0;
}
