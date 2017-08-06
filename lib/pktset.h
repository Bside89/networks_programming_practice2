//
// Created by darkwolf on 05/08/17.
//

#ifndef TP2_PKTLIST_H
#define TP2_PKTLIST_H


#include <unitypes.h>
#include <stdio.h>
#include <pcap.h>


struct _pktlist {
    struct pcap_pkthdr info;
    u_char pckt[BUFSIZ];
};


#endif //TP2_PKTLIST_H
