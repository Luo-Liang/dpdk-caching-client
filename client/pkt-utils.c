/*
 * Packet utilities
 */
#include <stdint.h>
#include "pkt-utils.h"

/* Header Marcos */
#define ETHER_HEADER_LEN 14
#define IP_HEADER_LEN 20
#define UDP_HEADER_LEN 8

/* Payload Marcos */
#define ECHO_REQ_SIZE 4

uint16_t
pkt_size (enum pkt_type type)
{
    uint16_t ret;

    ret = ETHER_HEADER_LEN + IP_HEADER_LEN + UDP_HEADER_LEN;

    switch (type) {
        case ECHO: ret += ECHO_REQ_SIZE; break;
        default: break;
    }

    return ret;
}

int
pkt_header_build(char *pkt_ptr,
                 int src_id,
                 int des_id)
{
    return 0;
}

int
pkt_data_build(char *pkt_ptr,
               enum pkt_type type)
{
    return 0;
}
