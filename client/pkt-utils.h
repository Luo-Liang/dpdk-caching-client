/*
 * Packet utilities header
 */
#ifndef _PKT_UTILS_H
#define _PKT_UTILS_H

#include <stdint.h>

enum pkt_type {
    ECHO,
};

uint16_t pkt_size (enum pkt_type type);
int pkt_header_build(char *pkt_ptr, int src_id, int des_id);
int pkt_data_build(char *pkt_ptr, enum pkt_type type);

#endif /* _PKT_UTILS_H */
