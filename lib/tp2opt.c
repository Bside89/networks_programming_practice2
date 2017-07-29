#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "tp2opt.h"


void paopt_debug(pa_opt *o);

int netopt_is_option_valid(int mode);


int paopt_set(int argc, char **argv, pa_opt *o) {

    int c;
    short rw_set = 0, i_set = 0, f_set = 0, db_set = 0;

    o->debug_opt = 0;

    opterr = 0;

    while ((c = getopt (argc, argv, GETOPT_OPTIONS)) != -1) {
        switch (c) {
            case OPT_WRITE:
                if (!netopt_is_option_valid(rw_set))
                    return PAOPT_OPTION_NOT_VALID;
                o->rw_mode_opt = WRITE;
                strcpy(o->filepath, optarg);
                rw_set = 1;
                break;
            case OPT_READ:
                if (!netopt_is_option_valid(rw_set))
                    return PAOPT_OPTION_NOT_VALID;
                o->rw_mode_opt = READ;
                strcpy(o->filepath, optarg);
                rw_set = 1;
                break;
            case OPT_INTERFACE_NAME:
                if (!netopt_is_option_valid(i_set))
                    return PAOPT_OPTION_NOT_VALID;
                strcpy(o->interface_name, optarg);
                i_set = 1;
                break;
            case OPT_PRINT_LOAD:
                if (!netopt_is_option_valid(f_set))
                    return PAOPT_OPTION_NOT_VALID;
                o->print_load_opt = 1;
                f_set = 1;
                break;
            case OPT_DEBUG:
                if (!netopt_is_option_valid(db_set))
                    return PAOPT_OPTION_NOT_VALID;
                o->debug_opt = 1;
                db_set = 1;
                break;
            case '?':
                if (isprint(optopt))
                    fprintf(stderr, "Unknown option '-%c'.\n", optopt);
                else
                    fprintf(stderr, "Unknown option character '\\x%x'.\n", optopt);
                return PAOPT_OPTION_NOT_VALID;
            default:
                exit(EXIT_FAILURE);
        }
    }
    if (argc - optind > 0) { // Has optional <args>
        puts("Has optional arguments <args>. Ignoring for awhile.");
        /*
        int i, j;
        for (i = optind; i < argc; index++) {
            for (j = 0; j < 4; j++) {
                if (!strcmp(argv[i], a[j])) {

                }
            }
            printf("Opt: '%s'\n", argv[i]);
        }*/
    }
    if (o->debug_opt)
        paopt_debug(o);

    return 0;
}


int netopt_is_option_valid(int mode) {
    if (mode) {
        fprintf(stderr, "Invalid options combinations.\n");
        return 0;
    }
    return 1;
}


void paopt_debug(pa_opt *o) {
    const char *answer[2] = {"no", "yes"};
    const char *rwmode[2] = {"read", "write"};
    puts("| ----------------------------------------- |");
    puts("| ************ PACKET ANALYZER ************ |");
    puts("| ----------------------------------------- |");
    printf("| File mode: \t\t%s\n", rwmode[o->rw_mode_opt]);
    printf("| File path: \t\t%s\n", o->filepath);
    printf("| Interface name: \t%s\n", o->interface_name);
    printf("| Print packet load: \t%s\n", answer[o->print_load_opt]);
    puts("| ----------------------------------------- |");
}
