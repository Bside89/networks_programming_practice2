//
// Created by darkwolf on 02/07/17.
//

#ifndef TP1_TP1OPT_H
#define TP1_TP1OPT_H

#include <unistd.h>

// Options (getopt)

#define GETOPT_OPTIONS "w:r:i:fd"

#define OPT_WRITE 'w'
#define OPT_READ 'r'

#define OPT_INTERFACE_NAME 'i'

#define OPT_PRINT_LOAD 'f'

#define OPT_DEBUG 'd'

#define PAOPT_OPTION_NOT_VALID -1

typedef enum { READ = 0, WRITE } paopt_rw_mode;


/* Struct containing infos about options chosen by user at startup
 * */
typedef struct {
    paopt_rw_mode rw_mode_opt;
    char filepath[256];
    char interface_name[16];
    int print_load_opt;
    int process_ethernet;
    int process_ipv4;
    int process_tcp;
    int process_udp;
    int debug_opt;
} pa_opt;


int paopt_set(int argc, char **argv, pa_opt *ns);


#endif //TP1_TP1OPT_H
