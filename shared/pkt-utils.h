/*
 * Packet utilities header
 */
#ifndef _PKT_UTILS_H
#define _PKT_UTILS_H

#include <stdint.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <string>
#include <cassert>
#include <cstdio>
#include "dpdk-helpers.h"

struct udphdr
{
  u_short uh_sport; /* source port */
  u_short uh_dport; /* destination port */
  short uh_ulen;    /* udp length */
  u_short uh_sum;   /* udp checksum */
};

void MACFromString(std::string str, uint8_t bytes[6]);
void IPFromString(std::string str, uint8_t bytes[4]);

uint16_t pkt_size(enum pkt_type type);
void pkt_build(char *pkt_ptr,
               endhost &src,
               endhost &des,
               enum pkt_type type,
               uint8_t tid,
               bool manualCksum);
void pkt_set_attribute(struct rte_mbuf *buf, bool manualCksum);
void pkt_client_data_build(char *pkt_ptr, enum pkt_type type);
int pkt_client_process(struct rte_mbuf *buf, enum pkt_type type, uint32_t);
uint16_t udp_checksum(udphdr *, uint32_t, uint32_t);
int pkt_server_process(struct rte_mbuf *buf,
                       enum pkt_type type);
void pkt_dump(struct rte_mbuf *buf);
uint32_t
ip_2_uint32(uint8_t ip[]);
void InitializePayloadConstants();
#endif /* _PKT_UTILS_H */
