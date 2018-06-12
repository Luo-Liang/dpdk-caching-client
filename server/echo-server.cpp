/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/queue.h>
#include <unistd.h>
#include <sys/time.h>

#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_debug.h>
#include <rte_ethdev.h>

#include "../shared/cluster-cfg.h"
#include "../shared/pkt-utils.h"

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define RX_RING_SIZE 512
#define TX_RING_SIZE 512
#define BATCH_SIZE 32
//#define PERF_DEBUG
#define rte_eth_dev_count_avail rte_eth_dev_count
struct lcore_args
{
    int *src_id, des_id;
    enum pkt_type type;
    uint8_t tid;
    //volatile enum benchmark_phase *phase;
    struct rte_mempool *pool;
    char *ifid;
} __attribute__((packed));

struct settings
{
    uint32_t warmup_time;
    uint32_t run_time;
    uint32_t cooldown_time;
} __attribute__((packed));

/*static const struct rte_eth_conf port_conf_default = {
    .rxmode = { 
        .mq_mode = ETH_MQ_RX_RSS,
    },
    .txmode = {
        .mq_mode = ETH_MQ_TX_NONE,
    },
    .rx_adv_conf = {
        .rss_conf = {
            .rss_hf = ETH_RSS_NONFRAG_IPV4_UDP,
        },
    },
    .fdir_conf = {
        .mode = RTE_FDIR_MODE_NONE,
    },
};*/

static inline int
port_init(struct lcore_args *largs,
          uint8_t threadnum)
{
    rte_eth_conf port_conf_default;
    port_conf_default.rxmode.mq_mode = ETH_MQ_RX_RSS;
    port_conf_default.txmode.mq_mode = ETH_MQ_TX_NONE;
    port_conf_default.rx_adv_conf.rss_conf.rss_hf = ETH_RSS_NONFRAG_IPV4_UDP;
    port_conf_default.fdir_conf.mode = RTE_FDIR_MODE_NONE;
    struct rte_eth_conf port_conf = port_conf_default;
    uint8_t q, rx_rings, tx_rings;
    int retval, i;
    char bufpool_name[32];
    struct ether_addr myaddr;
    uint16_t port = 65535;

    /*numports = rte_eth_dev_count_avail();
    printf("Number of ports of the server is %"PRIu8 "\n", numports);

    for(i = 0; i < numports; i++)
    {
        struct rte_eth_dev_info redi;
        rte_eth_dev_info_get(i, &redi);
        printf("finding device: %s\n", redi.device->name);
        if(strcmp(redi.device->name, largs->ifid) == 0)
        {
            printf("found device %s\n", largs->ifid);
            port = i;
            break;
        }
    }

    if(port == -1)
    {
        printf("cannot find requested device %s\n", largs->ifid);
        exit(-1);
    }
    numports
    for (i = 0; i < threadnum; i++) {
        largs[i].tid = i;
        sprintf(bufpool_name, "bufpool_%d", i);
        largs[i].pool = rte_pktmbuf_pool_create(bufpool_name,
                    NUM_MBUFS * threadnum, MBUF_CACHE_SIZE, 0,
                    RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
        if (largs[i].pool == NULL) {
            rte_exit(EXIT_FAILURE, "Error: rte_pktmbuf_pool_create failed\n");
        }
        largs[i].src_id = (int *)malloc(sizeof(int) * nb_ports);
        for (port = 0; port < nb_ports; port++) {
            rte_eth_macaddr_get(port, &myaddr);
            largs[i].src_id[port] = get_endhost_id(myaddr);
        }
    }*/

    int nb_ports = rte_eth_dev_count_avail();
    printf("Number of ports of the server is %" PRIu8 "\n", nb_ports);

    for (i = 0; i < threadnum; i++)
    {
        largs[i].tid = i;
        sprintf(bufpool_name, "bufpool_%d", i);
        largs[i].pool = rte_pktmbuf_pool_create(bufpool_name,
                                                NUM_MBUFS * threadnum, MBUF_CACHE_SIZE, 0,
                                                RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
        if (largs[i].pool == NULL)
        {
            rte_exit(EXIT_FAILURE, "Error: rte_pktmbuf_pool_create failed %d\n", rte_errno);
        }
        largs[i].src_id = (int *)malloc(sizeof(int) * nb_ports);
        for (port = 0; port < nb_ports; port++)
        {
            rte_eth_macaddr_get(port, &myaddr);
            largs[i].src_id[port] = get_endhost_id(myaddr);
        }
    }

    for (port = 0; port < nb_ports; port++)
    {
        rx_rings = tx_rings = threadnum;

        /* Configure the Ethernet device of a given port */
        retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
        if (retval != 0)
        {
            return retval;
        }

        /* Allocate and set up RX queues for a given Ethernet port */
        for (q = 0; q < rx_rings; q++)
        {
            retval = rte_eth_rx_queue_setup(port, q, RX_RING_SIZE,
                                            rte_eth_dev_socket_id(port), NULL, largs[q].pool);
            if (retval < 0)
            {
                return retval;
            }
        }

        /* Allocate and set up TX queues for a given Ethernet port */
        for (q = 0; q < tx_rings; q++)
        {
            retval = rte_eth_tx_queue_setup(port, q, TX_RING_SIZE,
                                            rte_eth_dev_socket_id(port), NULL);
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

static int
lcore_execute(__attribute__((unused)) void *arg)
{
    int n;
    struct lcore_args *myarg;
    uint8_t queue;
    struct rte_mbuf *bufs[BATCH_SIZE];
    struct rte_mbuf *response[BATCH_SIZE];
    int drops[BATCH_SIZE];
    uint16_t bsz, i, j, port, nb_ports;

#ifdef PERF_DEBUG
    struct timeval start, end;
    static unsigned long long send_elapsed = 0, send_cnt = 0;
    static unsigned long long recv_elapsed = 0, recv_cnt = 0;
#endif

    myarg = (struct lcore_args *)arg;
    queue = myarg->tid;
    bsz = BATCH_SIZE;
    nb_ports = rte_eth_dev_count_avail();

    printf("Server worker %" PRIu8 " started\n", myarg->tid);

    do
    {
#ifdef PERF_DEBUG
        gettimeofday(&start, NULL);
#endif

        for (port = 0; port < nb_ports; port++)
        {
            /* Receive and process requests */
            if ((n = rte_eth_rx_burst(port, queue, bufs, bsz)) < 0)
            {
                rte_exit(EXIT_FAILURE, "Error: rte_eth_rx_burst failed\n");
            }
#ifdef PERF_DEBUG
            gettimeofday(&end, NULL);
            recv_elapsed += ((end.tv_sec * 1000000 + end.tv_usec) -
                             (start.tv_sec * 1000000 + start.tv_usec));
            if ((!(recv_cnt % 1000000)) && (recv_cnt != 0) && (recv_cnt < 10000000))
            {
                printf("recv time %lf\n",
                       (recv_elapsed + 0.0) / (recv_cnt + 0.0));
            }
#endif

            for (i = 0; i < n; i++)
            {
                drops[i] = pkt_server_process(bufs[i], myarg->type);
            }

            for (i = 0, j = 0; i < n; i++)
            {
                if (drops[i])
                {
                    rte_pktmbuf_free(bufs[i]);
                }
                else
                {
                    response[j++] = bufs[i];

#ifdef PERF_DEBUG
                    recv_cnt++;
#endif
                }
            }

#ifdef PERF_DEBUG
            gettimeofday(&start, NULL);
#endif

            i = 0;
            while (i < j)
            {
                n = rte_eth_tx_burst(port, queue, response + i, j - i);
                i += n;
            }
        }

#ifdef PERF_DEBUG
        gettimeofday(&end, NULL);
        send_elapsed += ((end.tv_sec * 1000000 + end.tv_usec) -
                         (start.tv_sec * 1000000 + start.tv_usec));
        send_cnt += j;
        if ((!(send_cnt % 1000000)) && (send_cnt != 0) &&
            (send_cnt < 10000000))
        {
            printf("send time is %lf\n",
                   (send_elapsed + 0.0) / (recv_cnt + 0.0));
        }
#endif
    } while (1);

    return 0;
}

int main(int argc, char **argv)
{
    int ret, i;
    unsigned lcore_id;
    uint8_t threadnum;
    struct lcore_args *largs;

    /* Initialize the Environment Abstraction Layer (EAL) */
    ret = rte_eal_init(argc, argv);
    if (ret < 0)
    {
        rte_exit(EXIT_FAILURE, "Error: cannot init EAL\n");
    }
    argc -= ret;
    argv += ret;

    /* Initialize application args */
    if (argc != 2)
    {
        printf("Usage: %s <server type>\n", argv[0]);
        printf("Server Type:\n");
        printf("\t0 -> ECHO server\n");
        //printf("Interface identifier.\n");
        //printf("Specify a list of interfaces separated by comma.\n");
        rte_exit(EXIT_FAILURE, "Error: invalid arguments\n");
    }
    InitializePayloadConstants();
    /* Initialize NIC ports */
    threadnum = rte_lcore_count() - 1;
    largs = (lcore_args*)calloc(threadnum, sizeof(*largs));
    for (i = 0; i < threadnum; i++)
    {
        largs[i].tid = i;
        largs[i].type = (pkt_type)atoi(argv[1]);
    }
    port_init(largs, threadnum);

    /* call lcore_execute() on every slave lcore */
    RTE_LCORE_FOREACH_SLAVE(lcore_id)
    {
        rte_eal_remote_launch(lcore_execute, (void *)(largs + lcore_id - 1),
                              lcore_id);
    }

    printf("Master core performs maintainence\n");
    rte_eal_mp_wait_lcore();

    free(largs);
    return 0;
}
