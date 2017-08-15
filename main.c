#include "lib/common.h"
#include "lib/modules.h"
#include "lib/tp2opt.h"
#include "lib/packet.h"
#include "lib/debug.h"
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

// Flag that indicate if it is time to shutdown (switched by signal handler)
//volatile int is_exit = 0;

// Global pcap handler
pcap_t *pcaphandle;

pa_opt opts;

int pipefd[PIPES_QTT][2];

short print_payload_flag;
short shutdown_flag;

void pcap_myhandler(u_char*, const struct pcap_pkthdr*, const u_char*);

void sigint_handler(int);

void sigtstp_handler(int);

void pcap_debug(void);

int main(int argc, char *argv[]) {
    pthread_t threads[THREADS_SIZE];
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 mask;
    bpf_u_int32 net;
    struct bpf_program fp;
    int npackets = -1;
    pcap_dumper_t *dumpfile = NULL;

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

    // Set flags
    print_payload_flag = opts.print_payload_opt;
    shutdown_flag = 0;

    // Get IPv4 number and netmask for device
    if (pcap_lookupnet(opts.interface_name, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
                opts.interface_name, errbuf);
        net = mask = 0;
    }
    // Open pcap for sniffing
    if (opts.rw_mode_opt == WRITE)
        pcaphandle = pcap_open_live(opts.interface_name, BUFSIZ, 1, 1000, errbuf);
    else
        pcaphandle = pcap_open_offline(opts.file_path, errbuf);
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
    // TODO concat <args> defined by user as parameter to filter
    if (pcap_compile(pcaphandle, &fp, opts.filter, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n",
                opts.filter, pcap_geterr(pcaphandle));
        exit(EXIT_FAILURE);
    }
    // Install filter
    if (pcap_setfilter(pcaphandle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n",
                opts.filter, pcap_geterr(pcaphandle));
        exit(EXIT_FAILURE);
    }
    if (opts.rw_mode_opt == WRITE) {
        dumpfile = pcap_dump_open(pcaphandle, opts.file_path);
        if (dumpfile == NULL) {
            fprintf(stderr, "Error opening output file.\n");
            exit(EXIT_FAILURE);
        }
    }
    // Debug
    // DISABLED due to memory leak on pcap_freealldevs()
    //if (opts.debug_opt) pcap_debug();

    // Initialize threads
    start_pipes();
    pthread_create(&threads[0], NULL, ethernet_handler, NULL);
    pthread_create(&threads[1], NULL, ip_handler, NULL);
    pthread_create(&threads[2], NULL, tcp_handler, NULL);
    pthread_create(&threads[3], NULL, udp_handler, NULL);
    pthread_create(&threads[4], NULL, presentation_handler, NULL);
    pthread_create(&threads[5], NULL, screen_output_handler, (void*) &opts);

    // Main loop
    pcap_loop(pcaphandle, npackets, pcap_myhandler, (unsigned char*) dumpfile);

    // Free & close resources
    pcap_freecode(&fp);
    pcap_close(pcaphandle);
    if (opts.rw_mode_opt == WRITE) {
        pcap_dump_close(dumpfile);
        printf("Saved file as %s.\n", opts.file_path);
    }
    sleep(2);
    printf("\n\n");
    puts("Closing threads...");
    close_modules();
    int i;
    for (i = 0; i < THREADS_SIZE; i++)
        if (i != 4) // TODO temporary; remove as soon as possible
            pthread_join(threads[i], NULL);
    puts("Closing program...");
    printf("\n");
    return EXIT_SUCCESS;
}

void pcap_myhandler(u_char* dumpfile, const struct pcap_pkthdr* header,
                    const u_char* packet) {
    static unsigned int is_first_packet = 1;
    static struct timeval elapsed_time = {0, 0};
    packet_dump_line_t d;

    memset(&d, 0, sizeof(d));
    memcpy(&d.line_header, header, sizeof(d.line_header));
    memcpy(&d.content, packet, BUFSIZ);

    if (is_first_packet) {
        is_first_packet = 0;
    } else {
        pkt_timeval_wrapper(d.line_header.ts, elapsed_time, &d.timedelta);
    }
    elapsed_time = d.line_header.ts;
    if (opts.rw_mode_opt == WRITE) {
        pcap_dump(dumpfile, header, packet);
    } else if (opts.print_irt) {
        nanosleep(&d.timedelta, NULL);
    }
    write(pipefd[MAIN_ETH][WRITE], &d, sizeof(d));
}

void sigint_handler(int signum) {
    shutdown_flag = 1;
    pcap_breakloop(pcaphandle);
}

void sigtstp_handler(int signum) {
    print_payload_flag = !print_payload_flag;
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
