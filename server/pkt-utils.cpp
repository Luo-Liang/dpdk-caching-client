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

static inline void
pkt_swap_address(struct common_hdr *comhdr)
{
    uint8_t tmp_mac[ETHER_ADDR_LEN];
    uint32_t tmp_ip;
    uint16_t tmp_udp;

    // Destination addr copy
    rte_memcpy(tmp_mac, comhdr->ether.d_addr.addr_bytes, ETHER_ADDR_LEN);
    tmp_ip = comhdr->ip.dst_addr;
    tmp_udp = comhdr->udp.dst_port;

    // SRC -> DST
    rte_memcpy(comhdr->ether.d_addr.addr_bytes, comhdr->ether.s_addr.addr_bytes,
            ETHER_ADDR_LEN);
    comhdr->ip.dst_addr = comhdr->ip.src_addr;
    comhdr->udp.dst_port = comhdr->udp.src_port;
    
    // DST -> SRC
    rte_memcpy(comhdr->ether.s_addr.addr_bytes, tmp_mac, ETHER_ADDR_LEN);
    comhdr->ip.src_addr = tmp_ip;
    comhdr->udp.src_port = tmp_udp;

    // Clear old checksum
    comhdr->ip.hdr_checksum = 0;
    comhdr->ip.hdr_checksum = rte_ipv4_cksum(&comhdr->ip);
    comhdr->udp.dgram_cksum = 0;
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
  buf->ol_flags |= PKT_TX_UDP_CKSUM | PKT_TX_IPV4 ; /*| PKT_TX_IP_CKSUM |  */
    buf->l2_len = sizeof(struct ether_hdr);
    buf->l3_len = sizeof(struct ipv4_hdr);
}

void
pkt_client_data_build(char *pkt_ptr,
                      enum pkt_type type)
{
    if (type == ECHO) {
        struct echo_hdr *mypkt = (struct echo_hdr *)pkt_ptr;
        rte_memcpy(mypkt->payload, "ECHO", ECHO_PAYLOAD_LEN);
    } else {
        // do nothing
    }
}

int 
pkt_client_process(struct rte_mbuf *buf,
                   enum pkt_type type)
{
    int ret = 0;

    if (type == ECHO) {
        struct echo_hdr *mypkt;

        mypkt = rte_pktmbuf_mtod(buf, struct echo_hdr *);
        if (!memcmp(mypkt->payload, "ACK ", ECHO_PAYLOAD_LEN)) {
            ret = 1;
        }
    } else {
        // do nothing
    }

    return ret;
}

static void
pkt_server_data_build(char *payload,
                      enum pkt_type type)
{
    if (type == ECHO) {
        rte_memcpy(payload, "ACKD", ECHO_PAYLOAD_LEN);
    } else {
        // do nothing
    }
}

int
pkt_server_process(struct rte_mbuf *buf,
                    enum pkt_type type)
{
    int ret = 1;

    if (type == ECHO) {
        struct echo_hdr *mypkt;

        mypkt = rte_pktmbuf_mtod(buf, struct echo_hdr *);
        if (!memcmp(mypkt->payload, "ECHO", ECHO_PAYLOAD_LEN)) {
            pkt_swap_address(&mypkt->pro_hdr);
            pkt_server_data_build(mypkt->payload, type);

            ret = 0;
        }
    } else {
        // do nothing
    }

    return ret;
}

void 
pkt_dump(struct rte_mbuf *buf)
{
    printf("Packet info:\n");
    rte_pktmbuf_dump(stdout, buf, rte_pktmbuf_pkt_len(buf));
}
