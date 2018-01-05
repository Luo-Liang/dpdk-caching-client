/*
 * Cluster configuration
 */
#include <stdint.h>
#include <string.h>
#include "cluster-cfg.h"

struct endhost cluster[] = {
    { // n29
        .id = 0,
        .mac = {0x3c, 0xfd, 0xfe, 0xaa, 0xd1, 0xe0},
        .ip = {0x0a, 0x03, 0x00, 0x1d}
    },

    { // n30
        .id = 1,
        .mac = {0x68, 0x05, 0xca, 0x33, 0x13, 0x40},
        .ip = {0x0a, 0x03, 0x00, 0x1e}
    },

    { // n36
        .id = 1,
        .mac = {0x02, 0xaf, 0x01, 0x8b, 0xb5, 0x00},
        .ip = {0x0a, 0x03, 0x00, 0x24}
    }
};

int
get_endhost_id (struct ether_addr addr)
{
    uint8_t i;

    for (i = 0; i < sizeof(cluster)/sizeof(struct endhost); i++) {
        if (!memcmp(cluster[i].mac, addr.addr_bytes, ETHER_ADDR_LEN)) {
            return cluster[i].id;
        }
    }

    return -1;
}

struct endhost*
get_endhost (int id)
{
    return &cluster[id];
}
