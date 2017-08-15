//
// Created by darkwolf on 05/08/17.
//

#ifndef TP2_LAYERS_H
#define TP2_LAYERS_H

#include <unistd.h>
#include "modules/pipes.h"

void*   ethernet_handler(void *);
void*   ip_handler(void *);
void*   tcp_handler(void *);
void*   udp_handler(void *);
void*   presentation_handler(void *);
void*   screen_output_handler(void *);
void*   filewriter_handler(void *);
int     start_pipes(void);

#endif //TP2_LAYERS_H
