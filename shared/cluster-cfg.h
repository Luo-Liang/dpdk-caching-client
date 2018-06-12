/*
 * Cluster configuration header
 */
#ifndef _CLUSTER_CFG_H
#define _CLUSTER_CFG_H

#include <rte_ether.h>

#define IPV4_ADDR_LEN 4

struct endhost {
    int id;
    uint8_t mac[ETHER_ADDR_LEN];
    uint8_t ip[IPV4_ADDR_LEN];
} __attribute__((packed));

int get_endhost_id (struct ether_addr addr);
struct endhost* get_endhost(int id);

#endif /* _CLUSTER_CFG_H */
