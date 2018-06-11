/*
 * Packet utilities
 */
#include <stdint.h>

#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_memcpy.h>

#include "../cluster-cfg/cluster-cfg.h"
#include "pkt-utils.h"

/* Marcos */
#define ETHER_HEADER_LEN 14
#define IP_HEADER_LEN 20
#define UDP_HEADER_LEN 8
#define UDP_SRC_PORT 13253
#define UDP_DES_PORT 13253

/* Common Header */
struct common_hdr {
    struct ether_hdr ether;
    struct ipv4_hdr ip;
    struct  udp_hdr udp;
} __attribute__((packed));

/* Application Headers */
//#define ECHO_PAYLOAD_LEN 1024
//#define ECHO_PAYLOAD_LEN 64
#define ECHO_PAYLOAD_LEN 4
struct echo_hdr {
    struct common_hdr pro_hdr;
    char payload[ECHO_PAYLOAD_LEN];
} __attribute__((packed));

uint16_t
pkt_size (enum pkt_type type)
{
    uint16_t ret;

    ret = ETHER_HEADER_LEN + IP_HEADER_LEN + UDP_HEADER_LEN;

    switch (type) {
        case ECHO: ret += ECHO_PAYLOAD_LEN; break;
        default: break;
    }

    return ret;
}

static inline uint32_t
ip_2_uint32(uint8_t ip[])
{
    uint32_t myip = 0;
    myip = (ip[3] << 24) + (ip[2] << 16) + (ip[1] << 8) + ip[0];

    return myip;
}

uint16_t udp_checksum(udphdr *p_udp_header, /*size_t len,*/ uint32_t src_addr, uint32_t dest_addr)
{
  uint16_t *buf = (uint16_t*)p_udp_header;
  uint16_t *ip_src = (uint16_t*)&src_addr, *ip_dst = (uint16_t*)&dest_addr;
  uint32_t sum;
  size_t length = p_udp_header->uh_ulen;
  size_t len = length;
  // Calculate the sum
  sum = 0;
  while (len > 1)
    {
      sum += *buf++;
      if (sum & 0x80000000)
	sum = (sum & 0xFFFF) + (sum >> 16);
      len -= 2;
    }

  if (len & 1)
    // Add the padding if the packet lenght is odd
    sum += *((uint8_t*)buf);

  // Add the pseudo-header
  sum += *(ip_src++);
  sum += *ip_src;

  sum += *(ip_dst++);
  sum += *ip_dst;

  sum += htons(IPPROTO_UDP);
  sum += htons(length);

  // Add the carries
  while (sum >> 16)
    sum = (sum & 0xFFFF) + (sum >> 16);

  // Return the one's complement of sum
  return (uint16_t)~sum;
}


void
pkt_header_build(char *pkt_ptr,
                 int src_id,
                 int des_id, 
                 enum pkt_type type,
                 uint8_t tid)
{
    struct common_hdr *myhdr = (struct common_hdr *)pkt_ptr;
    struct endhost *mysrc = get_endhost(src_id);
    struct endhost *mydes = get_endhost(des_id);

    // Ethernet header
    rte_memcpy(myhdr->ether.d_addr.addr_bytes, mydes->mac, ETHER_ADDR_LEN);
    rte_memcpy(myhdr->ether.s_addr.addr_bytes, mysrc->mac, ETHER_ADDR_LEN);
    myhdr->ether.ether_type = htons(ETHER_TYPE_IPv4);
    udphdr uhdr;
    // IP header
    myhdr->ip.version_ihl = 0x45;
    myhdr->ip.total_length = pkt_size(type) - ETHER_HEADER_LEN;
    myhdr->ip.packet_id = (uint16_t)random();
    myhdr->ip.fragment_offset = 0;
    myhdr->ip.time_to_live = 64;
    myhdr->ip.next_proto_id = IPPROTO_UDP;
    //myhdr->ip.hdr_checksum = 0;
    myhdr->ip.hdr_checksum = rte_ipv4_cksum(&myhdr->ip);
    myhdr->ip.src_addr = ip_2_uint32(mysrc->ip);
    myhdr->ip.dst_addr = ip_2_uint32(mydes->ip);
    //printf("building a udp packet from ip = %d.%d.%d.%d to %d.%d.%d.%d\n", mysrc->ip[0], mysrc->ip[1], mysrc->ip[2], mysrc->ip[3], mydes->ip[0], mydes->ip[1], mydes->ip[2], mydes->ip[3]); 
    // UDP header
    myhdr->udp.src_port = uhdr.uh_sport = UDP_SRC_PORT + tid;
    myhdr->udp.dst_port = uhdr.uh_dport = UDP_DES_PORT;
    myhdr->udp.dgram_len = uhdr.uh_ulen = pkt_size(type) - ETHER_HEADER_LEN - IP_HEADER_LEN;// - 
        //UDP_HEADER_LEN;
    myhdr->udp.dgram_cksum = uhdr.uh_sum = 0;
    //myhdr->udp.dgram_cksum = udp_checksum(&uhdr, myhdr->ip.src_addr, myhdr->ip.dst_addr);
    //printf("ip checksum = %d, udp checksum = %d\n", myhdr->ip.hdr_checksum, myhdr->udp.dgram_cksum);
}

void
pkt_set_attribute(struct rte_mbuf *buf)
{
  buf->ol_flags |=  PKT_TX_IPV4 | PKT_TX_UDP_CKSUM | PKT_TX_IP_CKSUM;
    buf->l2_len = sizeof(struct ether_hdr);
    buf->l3_len = sizeof(struct ipv4_hdr);
}

void
pkt_client_data_build(char *pkt_ptr,
                      enum pkt_type type)
{
    if (type == ECHO) {
        struct echo_hdr *mypkt = (struct echo_hdr *)pkt_ptr;
        rte_memcpy(mypkt->payload, "ECHO", 4);
    } else {
        // do nothing
    }
}

int pkt_client_process(struct rte_mbuf *buf,
                       enum pkt_type type)
{
    int ret = 0;

    if (type == ECHO) {
        struct echo_hdr *mypkt;

        mypkt = rte_pktmbuf_mtod(buf, struct echo_hdr *);
        if (!memcmp(mypkt->payload, "ACKD", 4)) {
            ret = 1;
        }
    } else {
        // do nothing
    }

    return ret;
}
