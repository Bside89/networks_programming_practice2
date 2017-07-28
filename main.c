#include <stdio.h>
#include <stdlib.h>
#include "lib/tp2opt.h"

int main(int argc, char *argv[]) {

    pa_opt options;

    if (paopt_set(argc, argv, &options) < 0) {
        fprintf(stderr, "A error occurred. Exiting application.\n");
        return EXIT_FAILURE;
    }

    printf("Hello, World!\n");
    return EXIT_SUCCESS;
}
