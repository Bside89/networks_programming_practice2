//
// Created by darkwolf on 07/08/17.
//

#ifndef TP2_PIPES_H
#define TP2_PIPES_H

#define PIPES_QTT 8

enum pipes_t { MAIN_ETH = 0, ETH_IP, IP_TCP, IP_UDP,
                TCP_PRST, UDP_PRST, PRST_OUTPUT, OUTPUT_WRITER };

extern int pipefd[PIPES_QTT][2];

#endif //TP2_PIPES_H
