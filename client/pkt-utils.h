/*
 * Packet utilities header
 */
#ifndef _PKT_UTILS_H
#define _PKT_UTILS_H

#include <stdint.h>

enum pkt_type {
    ECHO,
};

uint16_t pkt_size (enum pkt_type);
int pkt_header_build();
int pkt_data_build();

#endif /* _PKT_UTILS_H */
