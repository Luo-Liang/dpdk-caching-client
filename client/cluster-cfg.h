/*
 * Cluster configuration header
 */
#ifndef _CLUSTER_CFG_H
#define _CLUSTER_CFG_H

#define ETHER_ADDR_LEN 6
#define IP_ADDR_LEN 4

struct ether_addr {
    uint8_t addr_bytes[ETHER_ADDR_LEN]; 
} __attribute__((packed));

int get_endhost_id (struct ether_addr addr);

#endif /* _CLUSTER_CFG_H */
