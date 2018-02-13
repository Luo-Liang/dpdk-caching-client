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
#define ECHO_PAYLOAD_LEN 46
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

    // IP header
    myhdr->ip.version_ihl = 4 << 4 | 5;
    myhdr->ip.total_length = pkt_size(type) - ETHER_HEADER_LEN;
    myhdr->ip.packet_id = 0;
    myhdr->ip.fragment_offset = 0;
    myhdr->ip.time_to_live = 64;
    myhdr->ip.next_proto_id = 17;
    myhdr->ip.hdr_checksum = 0;
    myhdr->ip.src_addr = ip_2_uint32(mysrc->ip);
    myhdr->ip.dst_addr = ip_2_uint32(mydes->ip);

    // UDP header
    myhdr->udp.src_port = UDP_SRC_PORT + tid;
    myhdr->udp.dst_port = UDP_DES_PORT;
    myhdr->udp.dgram_len = pkt_size(type) - ETHER_HEADER_LEN - IP_HEADER_LEN - 
        UDP_HEADER_LEN;
    myhdr->udp.dgram_cksum = 0;
}

void
pkt_set_attribute(struct rte_mbuf *buf)
{
    buf->ol_flags |= PKT_TX_IP_CKSUM | PKT_TX_IPV4;
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
