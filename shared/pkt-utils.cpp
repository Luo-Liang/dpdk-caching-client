/*
 * Packet utilities
 */
#include <stdint.h>

#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_memcpy.h>
#include "dpdk-helpers.h"
#include "pkt-utils.h"
#include <string>
#include <stdexcept>
#include "zipfian.h"
/* Marcos */
#define ETHER_HEADER_LEN 14
#define IP_HEADER_LEN 20
#define UDP_HEADER_LEN 8
#define UDP_SRC_PORT 1234
#define UDP_DES_PORT 5678
#define MEMCACHED_KEY_LEN 7 //1000000
#define MEMCACHED_READ_HEADER_FMT "\x00\x00\x00\x00\x00\x01\x00\x00get %d\r\n"
#define MEMCACHED_READ_HEADER_FULL_LEN (8 + 3 + 1 + MEMCACHED_KEY_LEN + 1 + 1)
#define MEMCACHED_PAYLOAD_LEN 1024
#define MEMCACHED_PAYLOAD_LEN_STR "1024"
#define MEMCACHED_WRITE_HEADER_FMT "\x00\x00\x00\x00\x00\x01\x00\x00set %d 0 0 " MEMCACHED_PAYLOAD_LEN_STR "\r\n%s\r\n"
#define MEMCACHED_WRITE_HEADER_FULL_LEN (8 + 3 + 1 + MEMCACHED_KEY_LEN + 1 + 1 + 1 + 1 + 1 + 4 + 1 + 1 + MEMCACHED_PAYLOAD_LEN + 1 + 1)
#include <stdarg.h> // For va_start, etc.
#include <memory>   // For std::unique_ptr

std::string string_format(const std::string fmt_str, ...)
{
    int final_n, n = ((int)fmt_str.size()) * 2; /* Reserve two times as much as the length of the fmt_str */
    std::unique_ptr<char[]> formatted;
    va_list ap;
    while (1)
    {
        formatted.reset(new char[n]); /* Wrap the plain char array into the unique_ptr */
        strcpy(&formatted[0], fmt_str.c_str());
        va_start(ap, fmt_str);
        final_n = vsnprintf(&formatted[0], n, fmt_str.c_str(), ap);
        va_end(ap);
        if (final_n < 0 || final_n >= n)
            n += abs(final_n - n + 1);
        else
            break;
    }
    return std::string(formatted.get());
}

void MACFromString(std::string str, uint8_t Bytes[6])
{
    int bytes[6];
    if (std::sscanf(str.c_str(),
                    "%02x:%02x:%02x:%02x:%02x:%02x",
                    &bytes[0], &bytes[1], &bytes[2],
                    &bytes[3], &bytes[4], &bytes[5]) != 6)
    {
        throw std::runtime_error(str + std::string(" is an invalid MAC address"));
    }
    for (int i = 0; i < 6; i++)
    {
        Bytes[i] = (uint8_t)bytes[i];
    }
}

void IPFromString(std::string str, uint8_t Bytes[4])
{
    int bytes[4];
    if (4 != sscanf(str.c_str(), "%d.%d.%d.%d", bytes, bytes + 1, bytes + 2, bytes + 3))
    {
        throw std::runtime_error(str + std::string(" is an invalid IP address"));
    }

    for (int i = 0; i < 4; i++)
    {
        Bytes[i] = (uint8_t)bytes[i];
    }
}

/* Common Header */
struct common_hdr
{
    struct ether_hdr ether;
    struct ipv4_hdr ip;
    struct udp_hdr udp;
} __attribute__((packed));

/* Application Headers */
#define ECHO_PAYLOAD_LEN 5
//int ECHO_PAYLOAD_LEN = 0;
std::string contents;

void InitializePayloadConstants()
{
    if (contents.size() != 0)
        return;
    std::string templatedStr = "PLINK TECHNOLOGIES";

    int len = PAYLOAD_LEN;
    //string_format(std::string(MEMCACHED_READ_HEADER_FMT),

    for (int i = 0; i < len; i++)
    {
        contents += templatedStr.at(i % templatedStr.size());
    }
}

struct CachingHeader
{
    struct common_hdr pro_hdr;
    char payload[PAYLOAD_LEN];
} __attribute__((packed));

uint16_t
pkt_size(enum pkt_type type)
{
    uint16_t ret;
    switch (type)
    {
    case MEMCACHED_READ:
        ret = MEMCACHED_READ_HEADER_FULL_LEN;
        break;
    case MEMCACHED_WRITE:
        ret = MEMCACHED_WRITE_HEADER_FULL_LEN;
        break;
    default:
        assert(false);
    }
    ret += ETHER_HEADER_LEN + IP_HEADER_LEN + UDP_HEADER_LEN;

    return ret;
}

uint32_t
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

    // Clear old checksumcomhdr->ip);
    //comhdr->ip.hdr_checksum = 0;
    //comhdr->udp.dgram_cksum = 0;
    //comhdr->udp.dgram_cksum = rte_ipv4_udptcp_cksum(&comhdr->ip, &comhdr->udp);
}

pkt_type pkt_build(char *pkt_ptr,
               endhost &src,
               endhost &des,
               uint8_t tid,
               bool manualCksum)
{
    common_hdr *myhdr = (struct common_hdr *)pkt_ptr;

    // Ethernet header
    rte_memcpy(myhdr->ether.d_addr.addr_bytes, des.mac, ETHER_ADDR_LEN);
    rte_memcpy(myhdr->ether.s_addr.addr_bytes, src.mac, ETHER_ADDR_LEN);
    myhdr->ether.ether_type = htons(ETHER_TYPE_IPv4);
    // IP header
    myhdr->ip.version_ihl = 0x45;
    myhdr->ip.packet_id = htons(44761);
    myhdr->ip.fragment_offset = htons(1 << 14);
    myhdr->ip.time_to_live = 64;
    myhdr->ip.next_proto_id = IPPROTO_UDP;
    myhdr->ip.src_addr = ip_2_uint32(src.ip);
    myhdr->ip.dst_addr = ip_2_uint32(des.ip);
    myhdr->ip.hdr_checksum = 0;
    //if (manualCksum)
    //{
    //}
    //printf("building a udp packet from ip = %d.%d.%d.%d to %d.%d.%d.%d\n", mysrc->ip[0], mysrc->ip[1], mysrc->ip[2], mysrc->ip[3], mydes->ip[0], mydes->ip[1], mydes->ip[2], mydes->ip[3]);
    // UDP header
    myhdr->udp.src_port = htons(UDP_SRC_PORT + tid);
    myhdr->udp.dst_port = htons(UDP_DES_PORT);
    //UDP_HEADER_LEN;
    //pkt_client_data_build(pkt_ptr, type);
    //myhdr->udp.dgram_cksum = 0;
    //if(manualCksum)
    //{
    //}
    auto type = pkt_client_data_build(pkt_ptr);

    myhdr->ip.total_length = htons(pkt_size(type) - ETHER_HEADER_LEN);
    myhdr->udp.dgram_len = htons(pkt_size(type) - ETHER_HEADER_LEN - IP_HEADER_LEN); // -
    myhdr->ip.hdr_checksum = rte_ipv4_cksum(&myhdr->ip);
    myhdr->udp.dgram_cksum = rte_ipv4_udptcp_cksum(&myhdr->ip, &myhdr->udp); // | 0; // uhdr.uh_sum = htons(0xba29);

    return type;
}

void pkt_set_attribute(struct rte_mbuf *buf, bool manualCksum)
{
    buf->ol_flags |= PKT_TX_IPV4;
    if (manualCksum == false)
    {
        //buf->ol_flags |= PKT_TX_IP_CKSUM;
    }
    buf->l2_len = sizeof(struct ether_hdr);
    buf->l3_len = sizeof(struct ipv4_hdr);
}

//create a zipfian ready key value.
pkt_type pkt_client_data_build(char *pkt_ptr)
{
    double z = ((double)rand() / (RAND_MAX));
    pkt_type type;
    if (z >= 0.95)
    {
        type = pkt_type::MEMCACHED_WRITE;
    }
    else
    {
        type = pkt_type::MEMCACHED_READ;
    }
    int key = zipf(0.99, 1000000);
    //zipf generates a key from 1 to 1M. I don't want to deal with padding to 7 digits
    // so just add 1M
    key += 1000000;
    if (type == pkt_type::MEMCACHED_READ)
    {
        struct CachingHeader *mypkt = (struct CachingHeader *)pkt_ptr;
        //retrieve a zipfian key

        std::string fmtStr(MEMCACHED_READ_HEADER_FMT);
        std::string readPayload = string_format(fmtStr, std::to_string(key));

        rte_memcpy(mypkt->payload, readPayload.c_str(), readPayload.size());
    }
    else if (type == pkt_type::MEMCACHED_WRITE)
    {
        struct CachingHeader *mypkt = (struct CachingHeader *)pkt_ptr;
        //retrieve a zipfian key
        std::string fmtStr(MEMCACHED_WRITE_HEADER_FMT);
        std::string writePayload = string_format(fmtStr, std::to_string(key), contents);

        rte_memcpy(mypkt->payload, writePayload.c_str(), writePayload.size());
    }

    common_hdr *myhdr = (struct common_hdr *)pkt_ptr;
    //myhdr->ip.hdr_checksum = rte_ipv4_cksum(&myhdr->ip);
    //myhdr->udp.dgram_cksum = rte_ipv4_udptcp_cksum(&myhdr->ip, &myhdr->udp); // | 0; // uhdr.uh_sum = htons(0xba29);

    return type;
}

int pkt_client_process(struct rte_mbuf *buf,
                       enum pkt_type type,
                       uint32_t ip)
{
    CachingHeader *mypkt;
    mypkt = rte_pktmbuf_mtod(buf, CachingHeader *);

    if (mypkt->pro_hdr.ip.src_addr != ip)
    {
        return 0;
    }

    int ret = 0;

    mypkt = rte_pktmbuf_mtod(buf, struct CachingHeader *);
    if (type == pkt_type::MEMCACHED_READ)
    {
        if (!memcmp(mypkt->payload, "VALUE", 5))
        {
            ret = 1;
        }
    }
    else if (type == pkt_type::MEMCACHED_WRITE)
    {
        // do nothing
        if (!memcmp(mypkt->payload, "STORED", 5))
        {
            ret = 1;
        }
    }
    else
    {
        assert(false);
    }

    return ret;
}

void pkt_dump(struct rte_mbuf *buf)
{
    printf("Packet info:\n");
    rte_pktmbuf_dump(stdout, buf, rte_pktmbuf_pkt_len(buf));
}
