/*
 * Cluster configuration
 */
#include <stdint.h>
#include <string.h>
#include "cluster-cfg.h"

typedef struct _endhost {
    int id;
    uint8_t mac[ETHER_ADDR_LEN];
    uint8_t ip[IP_ADDR_LEN];
} __attribute__((packed)) endhost;

endhost cluster[] = {
    { // n29
        .id = 0,
        .mac = {0x3c, 0xfd, 0xfe, 0xaa, 0xd1, 0xe0},
        .ip = {0x0a, 0x03, 0x00, 0x1d}
    },

    { // n30
        .id = 1,
        .mac = {0x3c, 0xfd, 0xfe, 0xaa, 0xd1, 0xe1},
        .ip = {0x0a, 0x03, 0x00, 0x1e}
    }
};

int
get_endhost_id (struct ether_addr addr)
{
    int i;

    for (i = 0; i < sizeof(cluster)/sizeof(endhost); i++) {
        if (!memcmp(cluster[i].mac, addr.addr_bytes, ETHER_ADDR_LEN)) {
            return cluster[i].id;
        }
    }

    return -1;
}
