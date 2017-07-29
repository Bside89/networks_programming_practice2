#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <signal.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include "lib/tp2opt.h"
#include "lib/tp2utils.h"

#define THREADS_SIZE 7


// Flag that indicate if it is time to shutdown (switched by signal handler)
volatile int is_exit = 0;

// Global pcap handler
pcap_t *handle;


void pcap_myhandler(u_char*, const struct pcap_pkthdr*, const u_char*);

void sigint_handler(int);

void pcap_debug();


int main(int argc, char *argv[]) {

    pa_opt options;

    pthread_t threads[THREADS_SIZE];
    int threads_counter = 0;

    char errbuf[PCAP_ERRBUF_SIZE];
    char filter[] = "";
    bpf_u_int32 mask;
    bpf_u_int32 net;
    struct bpf_program fp;
    const u_char* packet;
    int npackets = -1;

    signal(SIGINT, sigint_handler);

    // Set options for application
    if (paopt_set(argc, argv, &options) < 0) {
        fprintf(stderr, "A error occurred. Exiting application.\n");
        return EXIT_FAILURE;
    }

    // Get IPv4 number and netmask for device
    if (pcap_lookupnet(options.interface_name, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
                options.interface_name, errbuf);
        net = mask = 0;
    }

    // Open pcap for sniffing
    handle = pcap_open_live(options.interface_name, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n",
                options.interface_name, errbuf);
        return 2;
    }

    if (pcap_compile(handle, &fp, filter, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n",
                filter, pcap_geterr(handle));
        return 2;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n",
                filter, pcap_geterr(handle));
        return 2;
    }

    if (options.debug_opt)
        pcap_debug();

    pcap_loop(handle, npackets, pcap_myhandler, NULL);
    pcap_close(handle);

    printf("\n\nClosing program.\n\n");

    return EXIT_SUCCESS;
}


void pcap_myhandler(u_char* args, const struct pcap_pkthdr* header,
                    const u_char* packet) {

    static int count = 1;

    const sniff_ethernet *ethernet;
    const sniff_ip *ip;
    const sniff_tcp *tcp;
    const char *payload;

    int size_ip, size_tcp, size_payload;

    printf("\nPacket number %d:\n", count++);

    /* define ethernet header */
    ethernet = (struct ether_header*)(packet);

    print_ethernet_header(ethernet);

    /* define/compute ip header offset */
    ip = (sniff_ip*)(packet + TP2_SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4;
    if (size_ip < TP2_MIN_SIZE_IP) {
        printf("Invalid IP header length: %u bytes\n", size_ip);
        return;
    }

    /* determine protocol */
    switch(ip->ip_p) {
        case IPPROTO_TCP:
            break;
        case IPPROTO_UDP:
            return;
        case IPPROTO_ICMP:
            return;
        case IPPROTO_IP:
            return;
        default:
            return;
    }
    print_ip_header(ip);

    /* define/compute tcp header offset */
    tcp = (sniff_tcp*)(packet + TP2_SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp)*4;
    if (size_tcp < 20) {
        printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
        return;
    }

    print_tcp_header(tcp);

    /* define/compute tcp payload (segment) offset */
    payload = (u_char *)(packet + TP2_SIZE_ETHERNET + size_ip + size_tcp);

    /* compute tcp payload (segment) size */
    size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

    /*
     * Print payload data; it might be binary, so don't just
     * treat it as a string.
     */
    if (size_payload > 0) {
        printf("   Payload (%d bytes):\n", size_payload);
        //printf(payload);
    }
}


void sigint_handler(int signum) {
    is_exit = 1;
    pcap_breakloop(handle);
}


void pcap_debug() {

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevsp, *device;

    if (pcap_findalldevs(&alldevsp , errbuf) < 0) {
        fprintf(stderr, "Error finding devices: %s", errbuf);
        exit(EXIT_FAILURE);
    }

    //Print the available devices
    puts("| ----------------------------------------- |");
    puts("| Available devices for packet sniffing:");
    int count = 1;
    for (device = alldevsp; device != NULL; device = device->next) {
        printf("| %d.\t%s --- %s\n" , count++, device->name, device->description);
    }
    puts("| ----------------------------------------- |");
}