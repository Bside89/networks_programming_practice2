#include "lib/modules.h"
#include "lib/tp2opt.h"
#include "lib/packet.h"
#include "lib/debug.h"
#include <stdlib.h>
#include <signal.h>
#include <string.h>

#define THREADS_SIZE 6


// Flag that indicate if it is time to shutdown (switched by signal handler)
//volatile int is_exit = 0;

// Global pcap handler
pcap_t *pcaphandle;

pa_opt opts;

int pipefd[PIPES_QTT][2];

void pcap_myhandler(u_char*, const struct pcap_pkthdr*, const u_char*);

void sigint_handler(int);

void sigtstp_handler(int);

void pcap_debug(void);

int main(int argc, char *argv[]) {
    pthread_t threads[THREADS_SIZE];
    char errbuf[PCAP_ERRBUF_SIZE];
    char filter[] = "ip";
    bpf_u_int32 mask;
    bpf_u_int32 net;
    struct bpf_program fp;
    int npackets = -1;

    signal(SIGINT, sigint_handler);
    signal(SIGTSTP, sigtstp_handler);

    puts(DIV_LINE);

#if DEBUG >= 2
    puts(START_DEBUG);
    printf("Int size (reference):  %zu\n", sizeof(int));
    printf("Packet struct size:    %zu\n", sizeof(packet_t));
    printf("Packet pointer size:   %zu\n", sizeof(packet_t*));
    printf("Pkthdr struct size:    %zu\n", sizeof(struct pcap_pkthdr));
    printf("Packet dump line size: %zu\n", sizeof(packet_dump_line_t));
    printf("Packet dump pointer:   %zu\n", sizeof(packet_dump_line_t*));
    puts(END_DEBUG);
    puts(DIV_LINE);
#endif

    // Set options for application
    if (paopt_set(argc, argv, &opts) < 0) {
        fprintf(stderr, "A error occurred. Exiting application.\n");
        return EXIT_FAILURE;
    }
    // Get IPv4 number and netmask for device
    if (pcap_lookupnet(opts.interface_name, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
                opts.interface_name, errbuf);
        net = mask = 0;
    }
    // Open pcap for sniffing
    pcaphandle = pcap_open_live(opts.interface_name, BUFSIZ, 1, 1000, errbuf);
    if (pcaphandle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n",
                opts.interface_name, errbuf);
        exit(EXIT_FAILURE);
    }
    // Make sure we're capturing on an Ethernet device
    if (pcap_datalink(pcaphandle) != DLT_EN10MB) {
        fprintf(stderr, "%s is not an Ethernet\n", opts.interface_name);
        exit(EXIT_FAILURE);
    }
    // Compile filter
    if (pcap_compile(pcaphandle, &fp, filter, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n",
                filter, pcap_geterr(pcaphandle));
        exit(EXIT_FAILURE);
    }
    // Install filter
    if (pcap_setfilter(pcaphandle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n",
                filter, pcap_geterr(pcaphandle));
        exit(EXIT_FAILURE);
    }
    // Debug
    if (opts.debug_opt) pcap_debug();

    // Main loop
    pcap_loop(pcaphandle, npackets, pcap_myhandler, NULL);

    // Free & close
    pcap_freecode(&fp);
    pcap_close(pcaphandle);

    printf("\n\nClosing program.\n\n");
    return EXIT_SUCCESS;
}

void pcap_myhandler(u_char* args, const struct pcap_pkthdr* header,
                    const u_char* packet) {
    static unsigned int count = 1;
    packet_dump_line_t *d;
    uint32_t size_ip, size_tu;

    pkt_init(&d);
    pkt_bind(d, header, packet);

    // TODO from here, alloc "d" in heap and send over to the modules

    d->info.num = count++;
    d->info.eth_header = (eth_hdr_t*)(d->content);
    d->info.is_ipv4 = ntohs(d->info.eth_header->ether_type) == ETHERTYPE_IP;

    // Define/compute IP header offset
    d->info.ip_header = (ip_hdr_t*)(d->content + ETHERNET_HEADER_SIZE);
    size_ip = IP_HSIZE(d->info.ip_header);
    if (size_ip < IP_HEADER_MIN_SIZE) {
        printf("Invalid IP header length: %u bytes.\n", size_ip);
        return;
    }

    // Determine protocol
    switch (d->info.ip_header->ip_p) {
        case IPPROTO_TCP:
            // Define/compute TCP header offset
            d->info.tcp_header = (tcp_hdr_t*)(d->content + ETHERNET_HEADER_SIZE
                                             + size_ip);
            size_tu = (uint32_t) TH_HSIZE(d->info.tcp_header);
            d->info.is_tcp = 1;
            if (size_tu < TCP_HEADER_MIN_SIZE) {
                printf("Invalid TCP header length: %u bytes.\n", size_tu);
                return;
            }
            break;
        case IPPROTO_UDP:
            // Define/compute UDP header offset
            d->info.udp_header = (udp_hdr_t*)(d->content + ETHERNET_HEADER_SIZE
                                              + size_ip);
            size_tu = UDP_HEADER_SIZE;
            d->info.is_udp = 1;
            break;
        default:
            // IPPROTO_ICMP or IPPROTO_IP etc.
            return;
    }
    if (opts.print_payload_opt) {
        d->info.payload = (u_char *) (d->content + ETHERNET_HEADER_SIZE
                                     + size_ip + size_tu);
        d->info.size_payload = ntohs(d->info.ip_header->ip_len) - (size_ip +
                size_tu);
        d->info.print_payload = 1;
    }
    pkt_print_packet(&d->info, d->line_header.len);
    pkt_free(&d);
}

void sigint_handler(int signum) {
    //is_exit = 1;
    pcap_breakloop(pcaphandle);
}

void sigtstp_handler(int signum) {
    opts.print_payload_opt = !opts.print_payload_opt;
}

void pcap_debug() {

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevsp, *device;
    puts(MINOR_DIV_LINE);
    if (pcap_findalldevs(&alldevsp , errbuf) < 0) {
        fprintf(stderr, "Error finding devices: %s", errbuf);
        exit(EXIT_FAILURE);
    }
    // Print the available devices
    puts("Available devices for packet sniffing:\n");
    int count = 1;
    for (device = alldevsp; device != NULL; device = device->next)
        printf("%02d.\t%9.9s \t %s\n", count++,
               device->name, device->description);
    // TODO here occurs MEMORY LEAK (in pcap_freealldevs)
    pcap_freealldevs(alldevsp);
    puts(MINOR_DIV_LINE);
    puts(DIV_LINE);
}
