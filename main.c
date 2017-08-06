#include <stdlib.h>
#include <pcap.h>
#include <signal.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <string.h>
#include "lib/tp2opt.h"
#include "lib/tp2utils.h"

#define THREADS_SIZE 7


// Flag that indicate if it is time to shutdown (switched by signal handler)
volatile int is_exit = 0;

// Global pcap handler
pcap_t *handle;

pa_opt options;


void pcap_myhandler(u_char*, const struct pcap_pkthdr*, const u_char*);

void sigint_handler(int);

void pcap_debug();


int main(int argc, char *argv[]) {

    pthread_t threads[THREADS_SIZE];
    int threads_counter = 0;

    char errbuf[PCAP_ERRBUF_SIZE];
    char filter[] = "ip";
    bpf_u_int32 mask;
    bpf_u_int32 net;
    struct bpf_program fp;
    const u_char* packet;
    int npackets = -1;

    signal(SIGINT, sigint_handler);

    puts(DIV_LINE);

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
        exit(EXIT_FAILURE);
    }

    /* make sure we're capturing on an Ethernet device [2] */
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "%s is not an Ethernet\n", options.interface_name);
        exit(EXIT_FAILURE);
    }

    if (pcap_compile(handle, &fp, filter, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n",
                filter, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n",
                filter, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    if (options.debug_opt)
        pcap_debug();

    pcap_loop(handle, npackets, pcap_myhandler, NULL);
    pcap_freecode(&fp);
    pcap_close(handle);

    printf("\n\nClosing program.\n\n");

    return EXIT_SUCCESS;
}


void pcap_myhandler(u_char* args, const struct pcap_pkthdr* header,
                    const u_char* packet) {

    static unsigned int count = 1;

    packet_t p;
    uint32_t size_ip;
    uint32_t size_tcp_udp;

    memset(&p, 0, sizeof(p));

    p.num = count++;

    p.eth_header = (eth_hdr_t*)(packet);
    p.is_ipv4 = ntohs(p.eth_header->ether_type) == ETHERTYPE_IP;

    /* define/compute ip header offset */
    p.ip_header = (ip_hdr_t*)(packet + ETHERNET_HEADER_SIZE);
    size_ip = IP_HSIZE(p.ip_header);
    if (size_ip < IP_HEADER_MIN_SIZE) {
        printf("Invalid IP header length: %u bytes.\n", size_ip);
        return;
    }

    /* determine protocol */
    switch (p.ip_header->ip_p) {
        case IPPROTO_TCP:
            /* define/compute tcp header offset */
            p.tcp_header = (tcp_hdr_t*)(packet + ETHERNET_HEADER_SIZE + size_ip);
            size_tcp_udp = (uint32_t) TH_HSIZE(p.tcp_header);
            p.is_tcp = 1;
            if (size_tcp_udp < TCP_HEADER_MIN_SIZE) {
                printf("Invalid TCP header length: %u bytes.\n", size_tcp_udp);
                return;
            }
            break;
        case IPPROTO_UDP:
            p.udp_header = (udp_hdr_t *)(packet + ETHERNET_HEADER_SIZE + size_ip);
            size_tcp_udp = UDP_HEADER_SIZE;
            p.is_udp = 1;
            break;
        default:
            // IPPROTO_ICMP or IPPROTO_IP etc.
            return;
    }

    if (options.print_payload_opt) {
        p.payload = (u_char *) (packet + ETHERNET_HEADER_SIZE + size_ip + size_tcp_udp);
        p.size_payload = ntohs(p.ip_header->ip_len) - (size_ip + size_tcp_udp);
        p.print_payload = 1;
    }
    print_packet(&p, header->len);
}


void sigint_handler(int signum) {
    is_exit = 1;
    pcap_breakloop(handle);
}


void pcap_debug() {

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevsp, *device;

    puts(MINOR_DIV_LINE);

    if (pcap_findalldevs(&alldevsp , errbuf) < 0) {
        fprintf(stderr, "Error finding devices: %s", errbuf);
        exit(EXIT_FAILURE);
    }

    //Print the available devices
    puts("Available devices for packet sniffing:\n");
    int count = 1;
    for (device = alldevsp; device != NULL; device = device->next)
        printf("%02d.\t%9.9s ---- %s\n", count++, device->name, device->description);
    pcap_freealldevs(alldevsp);
    puts(MINOR_DIV_LINE);
    puts(DIV_LINE);
}
