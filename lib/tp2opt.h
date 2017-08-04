#ifndef TP1_TP1OPT_H
#define TP1_TP1OPT_H

#include <unistd.h>
#include <stdint.h>
#include <limits.h>
#include "common.h"

// Options (getopt)

#define GETOPT_OPTIONS "w:r:i:fd"

#define OPT_WRITE 'w'
#define OPT_READ 'r'

#define OPT_INTERFACE_NAME 'i'

#define OPT_PRINT_PAYLOAD 'f'

#define OPT_DEBUG 'd'

#define PAOPT_OPTION_NOT_VALID -1

typedef enum { READ = 0, WRITE } paopt_rw_mode;


/* Struct containing infos about options chosen by user at startup
 * */
typedef struct {
    paopt_rw_mode rw_mode_opt;
    char filepath[PATH_MAX];
    char interface_name[16];
    int print_payload_opt;
    int debug_opt;
} pa_opt;


int paopt_set(int argc, char **argv, pa_opt *ns);


#endif //TP1_TP1OPT_H
