//
// Created by darkwolf on 05/08/17.
//

#ifndef TP2_LAYERS_H
#define TP2_LAYERS_H


extern int main_eth_pipe[2];
extern int eth_ip_pipe[2];
extern int ip_tcp_pipe[2];
extern int ip_udp_pipe[2];
extern int tcp_output_pipe[2];
extern int udp_output_pipe[2];


void* ethernet_handler(void *arg);

void* ip_handler(void *arg);

void* tcp_handler(void *arg);

void* udp_handler(void *arg);

void* screen_output_handler(void *arg);


#endif //TP2_LAYERS_H
