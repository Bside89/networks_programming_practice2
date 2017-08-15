#ifndef TP1_TP1OPT_H
#define TP1_TP1OPT_H

#include <unistd.h>
#include <stdint.h>
#include <limits.h>
#include "common.h"

// Options (getopt)

#define GETOPT_OPTIONS          "w:r:i:fd"
#define OPT_WRITE               'w'
#define OPT_READ                'r'
#define OPT_INTERFACE_NAME      'i'
#define OPT_PRINT_PAYLOAD       'f'
#define OPT_DEBUG               'd'

#define PAOPT_OPTION_NOT_VALID  -1

#define INTERFACE_SIZE          16
#define FILTER_SIZE             256
#define FILTER_DEFAULT_ARGS     "ip and (tcp or udp)"

/* Struct containing infos about options chosen by user at startup */
typedef struct {
    rw_key_t    rw_mode_opt;
    char        file_path[PATH_MAX];
    char        interface_name[INTERFACE_SIZE];
    char        filter[FILTER_SIZE];
    short int   print_payload_opt;
    short int   debug_opt;
} pa_opt;

int paopt_set(int, char **, pa_opt *);

#endif //TP1_TP1OPT_H
