//
// Created by darkwolf on 05/08/17.
//

#ifndef TP2_LAYERS_H
#define TP2_LAYERS_H

#include <unistd.h>
#include "modules/pipes.h"


void* ethernet_handler(void *arg);

void* ip_handler(void *arg);

void* tcp_handler(void *arg);

void* udp_handler(void *arg);

void* screen_output_handler(void *arg);

int start_pipes();


#endif //TP2_LAYERS_H
