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

#include "cluster-cfg.h"
#include "pkt-utils.h"

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define RX_RING_SIZE 512
#define TX_RING_SIZE 512
#define BATCH_SIZE 32

struct lcore_args {
    int src_id, des_id;
    enum pkt_type type;
    uint8_t tid;
    volatile enum benchmark_phase *phase;
    struct rte_mempool *pool;
} __attribute__((packed));

struct settings{
    uint32_t warmup_time;
    uint32_t run_time;
    uint32_t cooldown_time;
} __attribute__((packed));

static const struct rte_eth_conf port_conf_default = {
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
};

/*
 * FIXME: Only initialize port 0 using global settings
 */
const uint8_t myport = 0;
static inline int
port_init(struct lcore_args *largs, 
          uint8_t threadnum)
{
    struct rte_eth_conf port_conf = port_conf_default;
    uint8_t q, rx_rings, tx_rings, nb_ports;
    int retval, i;
    char bufpool_name[32];
    struct ether_addr myaddr;

    // Just check
    nb_ports = rte_eth_dev_count();
    printf("Number of ports of the server is %"PRIu8 "\n", nb_ports);

    // More initialization
    rte_eth_macaddr_get(myport, &myaddr);
    for (i = 0; i < threadnum; i++) {
        largs[i].tid = i;
        largs[i].src_id = get_endhost_id(myaddr);

        sprintf(bufpool_name, "bufpool_%d", i);
        largs[i].pool = rte_pktmbuf_pool_create(bufpool_name,
                    NUM_MBUFS * threadnum, MBUF_CACHE_SIZE, 0,
                    RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
        if (largs[i].pool == NULL) {
            rte_exit(EXIT_FAILURE, "Error: rte_pktmbuf_pool_create failed\n");
        }
    }

    rx_rings = tx_rings = threadnum;
    /* Configure the Ethernet device of a given port */
    retval = rte_eth_dev_configure(myport, rx_rings, tx_rings, &port_conf);
    if (retval != 0) {
        return retval;
    }

    /* Allocate and set up RX queues for a given Ethernet port */
    for (q = 0; q < rx_rings; q++) {
        retval = rte_eth_rx_queue_setup(myport, q, RX_RING_SIZE,
                rte_eth_dev_socket_id(myport), NULL, largs[q].pool);
        if (retval < 0) {
            return retval;
        }
    }

    /* Allocate and set up TX queues for a given Ethernet port */
    for (q = 0; q < tx_rings; q++) {
        retval = rte_eth_tx_queue_setup(myport, q, TX_RING_SIZE,
                rte_eth_dev_socket_id(myport), NULL);
        if (retval < 0) {
            return retval;
        }
    }

    /* Start the Ethernet port */
    retval = rte_eth_dev_start(myport);
    if (retval < 0) {
        return retval;
    }

    /* Enable RX in promiscuous mode for the Ethernet device */
    rte_eth_promiscuous_enable(myport);

    return 0;
}

static int
lcore_execute(__attribute__((unused)) void *arg)
{
    int n;
    struct lcore_args *myarg;
    uint8_t queue;
    struct rte_mbuf *bufs[BATCH_SIZE];
    uint16_t bsz, i, j;

    myarg = (struct lcore_args *)arg;
    queue = myarg->tid;
    bsz = BATCH_SIZE;

    printf("Server worker %"PRIu8 " started\n", myarg->tid);

    do {
        /* Receive and process requests */
        if ((n = rte_eth_rx_burst(myport, queue, bufs, bsz)) < 0) {
            rte_exit(EXIT_FAILURE, "Error: rte_eth_rx_burst failed\n");
        }

        for (i = 0; i < n; i++) {
            pkt_server_process(bufs[i], myarg->type);
        }

        i = 0;
        j = n;

        while (i < j) {
            n = rte_eth_tx_burst(myport, queue, bufs + i, j - i);
            i += n;
        }
    } while (1);

	return 0;
}

int
main(int argc, char **argv)
{
	int ret, i;
	unsigned lcore_id;
    uint8_t threadnum;
    struct lcore_args *largs;

    /* Initialize the Environment Abstraction Layer (EAL) */
	ret = rte_eal_init(argc, argv);
	if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Error: cannot init EAL\n");
    }
    argc -= ret;
    argv += ret;

    /* Initialize application args */
    if (argc != 3) {
        printf("Usage: %s <server type>\n", argv[0]);
        printf("Server Type:\n");
        printf("\t0 -> ECHO server\n");
        rte_exit(EXIT_FAILURE, "Error: invalid arguments\n");
    }

    /* Initialize NIC ports */
    threadnum = rte_lcore_count() - 1;
    largs = calloc(threadnum, sizeof(*largs));
    for (i = 0; i < threadnum; i++) {
        largs[i].tid = i;
        largs[i].type = atoi(argv[1]);
    }
    port_init(largs, threadnum);

    /* call lcore_execute() on every slave lcore */
    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        rte_eal_remote_launch(lcore_execute, (void *)(largs + lcore_id -1), 
                lcore_id);
    }

    printf("Master core performs maintainence\n");
	rte_eal_mp_wait_lcore();

    free(largs);
	return 0;
}
