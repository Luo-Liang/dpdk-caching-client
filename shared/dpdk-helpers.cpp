/*
 * Cluster configuration
 */
#include <stdint.h>
#include <string.h>
#include "dpdk-helpers.h"
#include "pkt-utils.h"

int ports_init(struct lcore_args *largs,
               //contains one master thread.
               uint8_t threadCount,
               std::vector<std::string> suppliedIPs,
               std::vector<std::string> suppliedMacs,
               std::vector<std::string> blockedSrcMac)
{
    if (rte_eal_process_type() != RTE_PROC_PRIMARY)
    {
        printf("[Error] DPDK-ECHO does not support MP.\n");
        return -1;
    }
    rte_eth_conf port_conf_default;
    memset(&port_conf_default, 0, sizeof(rte_eth_conf));
    port_conf_default.rxmode.mq_mode = ETH_MQ_RX_RSS;
    //port_conf_default.rxmode.max_rx_pkt_len = ETHER_MAX_LEN;
    //port_conf_default.rxmode.split_hdr_size = 0;
    //port_conf_default.rxmode.ignore_offload_bitfield = 1;
    //port_conf_default.rx_adv_conf.rss_conf.rss_key = NULL;
    //port_conf_default.rx_adv_conf.rss_conf.rss_hf = ETH_RSS_IP;
    //port_conf_default.txmode.offloads = DEV_TX_OFFLOAD_UDP_CKSUM | DEV_TX_OFFLOAD_IPV4_CKSUM;
    port_conf_default.txmode.mq_mode = ETH_MQ_TX_NONE;
    struct rte_eth_conf port_conf = port_conf_default;
    uint8_t q, rx_rings, tx_rings, nb_ports;
    char bufpool_name[32];

    nb_ports = rte_eth_dev_count_avail();
    printf("Number of ports of the server is %" PRIu8 "\n", nb_ports);
    //assert(nb_ports <= suppliedIPs.size());
    std::vector<int> portids;
    //now assign port to cores.
    assert(nb_ports > 0);
    if (nb_ports > 1)
    {
        printf("Currently only 1 port is supported. setting nb_ports to 1\n");
    }

    //nb_ports = 1;
    for (int i = 0; i < nb_ports; i++)
    {
        ether_addr tmp;
        rte_eth_macaddr_get(i, &tmp);
        char macStr[18];
        snprintf(macStr, sizeof(macStr), "%02x:%02x:%02x:%02x:%02x:%02x",
                 tmp.addr_bytes[0], tmp.addr_bytes[1], tmp.addr_bytes[2], tmp.addr_bytes[3], tmp.addr_bytes[4], tmp.addr_bytes[5]);
        std::string macString(macStr);
        if (std::find(blockedSrcMac.begin(), blockedSrcMac.end(), macString) != blockedSrcMac.end())
        {
            // this interface is blocked.
            continue;
        }
        //this port is not blocked.
        if (std::find(suppliedMacs.begin(), suppliedMacs.end(), macString) == suppliedMacs.end())
        {
            //but this port is not selected :/
            continue;
        }
        //skip largs[0], which is for master.
        int targetThread = -1;
        for (int thread = 0; thread < threadCount; thread++)
        {
            if (largs[thread].master)
                continue;
            if (targetThread == -1 || largs[i].associatedPorts.size() < largs[targetThread].associatedPorts.size())
            {
                targetThread = thread;
            }
            //assign i to the core with minimum of ports.
        }
        portids.push_back(i);
        if (targetThread == -1)
        {
            rte_exit(EXIT_FAILURE, "Bug Check.");
        }
        largs[targetThread].associatedPorts.push_back(i);
    }

    for (int i = 0; i < threadCount; i++)
    {
        sprintf(bufpool_name, "bufpool_%d", i);
        largs[i].pool = rte_pktmbuf_pool_create(bufpool_name,
                                                NUM_MBUFS, MBUF_CACHE_SIZE, 0,
                                                RTE_MBUF_DEFAULT_BUF_SIZE, rte_lcore_to_socket_id(largs[i].CoreID));
        if (largs[i].pool == NULL)
        {
            rte_exit(EXIT_FAILURE, "Error: rte_pktmbuf_pool_create failed\n");
        }
        //largs[i].src_id = (int *)malloc(sizeof(int) * nb_ports);
        largs[i].srcs.resize(largs[i].associatedPorts.size());
        //largs[i].srcMacs.resize(nb_ports);
        for (size_t pidx = 0; pidx < largs[i].associatedPorts.size(); pidx++)
        {
            auto port = largs[i].associatedPorts.at(pidx);
            ether_addr tmp;
            rte_eth_macaddr_get(port, &tmp);
            char macStr[18];
            snprintf(macStr, sizeof(macStr), "%02x:%02x:%02x:%02x:%02x:%02x",
                     tmp.addr_bytes[0], tmp.addr_bytes[1], tmp.addr_bytes[2], tmp.addr_bytes[3], tmp.addr_bytes[4], tmp.addr_bytes[5]);
            std::string macString(macStr);
            bool found = false;
            for (int suppliedIdx = 0; suppliedIdx < suppliedIPs.size(); suppliedIdx++)
            {
                auto testMac = suppliedMacs.at(suppliedIdx);
                if (testMac == macStr)
                {
                    rte_eth_macaddr_get(port, (ether_addr *)largs[i].srcs.at(pidx).mac);
                    //since nb_ports < suppliedIp.size, assign port-th to suppliedIps
                    IPFromString(suppliedIPs.at(suppliedIdx), largs[i].srcs.at(pidx).ip);
                    //largs[i].srcMacs.push_back( = get_endhost_id(myaddr);
                    found = true;
                    break;
                }
            }
            assert(found);
        }
    }

    for (int port : portids)
    {
        //one queue is sufficient for echo?
        rx_rings = tx_rings = 1;
        int retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
        if (retval != 0)
        {
            printf("port init failed. %s. retval = %d\n", rte_strerror(rte_errno), retval);
            return retval;
        }

        rte_eth_rxconf rxqConf;

        //rte_eth_conf* pConf;
        //rte_eth_dev* pDev = &rte_eth_devices[port];
        rte_eth_dev_info devInfo;
        rte_eth_dev_info_get(port, &devInfo);
        rxqConf = devInfo.default_rxconf;
        //pConf = &pDev->data->dev_conf;
        //rxqConf.offloads = pConf->rxmode.offloads;
        /* Configure the Ethernet device of a given port */

        /* Allocate and set up RX queues for a given Ethernet port */
        for (q = 0; q < rx_rings; q++)
        {
            retval = rte_eth_rx_queue_setup(port, q, RX_RING_SIZE,
                                            rte_eth_dev_socket_id(port), &rxqConf, largs[q].pool);
            if (retval < 0)
            {
                return retval;
            }
        }

        rte_eth_txconf txqConf;
        txqConf = devInfo.default_txconf;
        //txqConf.offloads = port_conf.txmode.offloads;
        //txqConf.txq_flags = ETH_TXQ_FLAGS_IGNORE;
        //txqConf.offloads = port_conf.txmode.offloads;
        /* Allocate and set up TX queues for a given Ethernet port */
        for (q = 0; q < tx_rings; q++)
        {
            retval = rte_eth_tx_queue_setup(port, q, TX_RING_SIZE,
                                            rte_eth_dev_socket_id(port), &txqConf);
            if (retval < 0)
            {
                return retval;
            }
        }

        /* Start the Ethernet port */
        retval = rte_eth_dev_start(port);
        if (retval < 0)
        {
            return retval;
        }

        /* Enable RX in promiscuous mode for the Ethernet device */
        rte_eth_promiscuous_enable(port);
    }

    return 0;
}

void CoreIdxMap(std::unordered_map<int, int> &lCore2Idx, std::unordered_map<int, int> &idx2LCoreId)
{
    auto threadnum = rte_lcore_count();
    auto activatedCoreCntr = 0;
    for (int CORE = 0;; CORE++)
    {
        if (rte_lcore_is_enabled(CORE))
        {
            //get its index.
            uint32_t idx = rte_lcore_index(CORE);
            lCore2Idx[CORE] = idx;
            idx2LCoreId[idx] = CORE;
            if (idx >= threadnum)
            {
                rte_exit(EXIT_FAILURE, "%d must be less than threadnum.", idx);
            }
            activatedCoreCntr++;
        }
        if (activatedCoreCntr == threadnum)
        {
            break;
        }
    }
}