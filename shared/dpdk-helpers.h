/*
 * Cluster configuration header
 */
#ifndef _CLUSTER_CFG_H
#define _CLUSTER_CFG_H

#include <rte_ethdev.h>
#include <rte_ether.h>
#include <vector>
#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_debug.h>
#include <string>
#include <assert.h>
#include <algorithm>
#include <unordered_map>

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define RX_RING_SIZE 512
#define TX_RING_SIZE 512
#define BATCH_SIZE 36
#define rte_eth_dev_count_avail rte_eth_dev_count
#define IPV4_ADDR_LEN 4

enum pkt_type
{
    ECHO,
};

struct endhost
{
    int id;
    uint8_t mac[ETHER_ADDR_LEN];
    uint8_t ip[IPV4_ADDR_LEN];
} __attribute__((packed));

struct lcore_args
{
    std::vector<endhost> srcs;
    endhost dst;
    enum pkt_type type;
    //the index of this arg in largs*, where a master is also included at 0.
    uint8_t tid;
    //volatile enum benchmark_phase *phase;
    struct rte_mempool *pool;
    std::vector<uint64_t> samples;
    size_t counter;
    std::vector<uint32_t> associatedPorts;
    //std::vector<uint32_t> coreIdx2LCoreId;
    uint32_t CoreID;
    bool master;
    bool AzureSupport;
}; //__attribute__((packed));

int ports_init(struct lcore_args *largs,
               //contains one master thread.
               uint8_t threadCount,
               std::vector<std::string> suppliedIPs,
               std::vector<std::string> suppliedMacs,
               std::vector<std::string> blockedSrcMac);

void CoreIdxMap(std::unordered_map<int, int> &lCore2Idx,
                std::unordered_map<int, int> &idx2LCoreId);

#endif /* _CLUSTER_CFG_H */
