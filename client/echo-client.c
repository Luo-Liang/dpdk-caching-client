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

#include "../cluster-cfg/cluster-cfg.h"
#include "pkt-utils.h"

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define RX_RING_SIZE 512
#define TX_RING_SIZE 512
#define BATCH_SIZE 36

enum benchmark_phase {
    BENCHMARK_WARMUP,
    BENCHMARK_RUNNING,
    BENCHMARK_COOLDOWN,
    BENCHMARK_DONE,
} __attribute__((aligned(64)));

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
};

/* 
 * Performance statistics
 */
uint64_t tot_proc_pkts = 0, tot_elapsed = 0;

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
    struct rte_mempool *pool;
    volatile enum benchmark_phase *phase;
    struct rte_mbuf *bufs[BATCH_SIZE];
    uint16_t bsz, i;
    char *pkt_ptr;
    struct timeval start, end;
    uint64_t elapsed;

    myarg = (struct lcore_args *)arg;
    queue = myarg->tid;
    pool = myarg->pool;
    phase = myarg->phase;
    bsz = BATCH_SIZE;

    do {
        gettimeofday(&start, NULL);

        /* Receive and process responses */
        do {
            if ((n = rte_eth_rx_burst(myport, queue, bufs, bsz)) < 0) {
                rte_exit(EXIT_FAILURE, "Error: rte_eth_rx_burst failed\n");
            }

            for (i = 0; i < n; i++) {
                if ((*phase == BENCHMARK_RUNNING) && 
                        pkt_client_process(bufs[i], myarg->type)) {
                    __sync_fetch_and_add(&tot_proc_pkts, 1);
                }
            }

            for (i = 0; i < n; i++) {
                rte_pktmbuf_free(bufs[i]);
            }

        } while (n == bsz); // More packets in the RX queue

        /* Prepare and send requests */
        for (i = 0; i < bsz; i++) {
            if ((bufs[i] = rte_pktmbuf_alloc(pool)) == NULL) {
                break;
            }
        }
        n = i;

        for (i = 0; i < n; i++) {
            pkt_ptr = rte_pktmbuf_append(bufs[i], pkt_size(myarg->type));
            pkt_header_build(pkt_ptr, myarg->src_id, myarg->des_id, 
                    myarg->type, queue);
            pkt_set_attribute(bufs[i]);
            pkt_client_data_build(pkt_ptr, myarg->type);
        }

        i = rte_eth_tx_burst(myport, queue, bufs, n);
        /* free non-sent buffers */
        for (; i < n; i++) {
            rte_pktmbuf_free(bufs[i]);
        }

        gettimeofday(&end, NULL);
        elapsed = (end.tv_sec - start.tv_sec) * 1000000 + 
            (end.tv_usec - start.tv_usec);

        if (*phase == BENCHMARK_RUNNING) {
            tot_elapsed += elapsed;
        }

    } while (*phase != BENCHMARK_DONE);
    printf("worker %"PRIu8 " done\n", myarg->tid);

	return 0;
}

int
main(int argc, char **argv)
{
	int ret, i;
	unsigned lcore_id;
    uint8_t threadnum;
    struct lcore_args *largs;
    volatile enum benchmark_phase phase;
    struct settings mysettings = {
        .warmup_time = 5,
        .run_time = 20,
        .cooldown_time = 5,
    };

    /* Initialize the Environment Abstraction Layer (EAL) */
	ret = rte_eal_init(argc, argv);
	if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Error: cannot init EAL\n");
    }
    argc -= ret;
    argv += ret;

    /* Initialize application args */
    if (argc != 3) {
        printf("Usage: %s <type> <dest ID>\n", argv[0]);
        printf("Packet Type:\n");
        printf("\t0 -> ECHO\n");
        printf("Destination ID:\n");
        printf("\t0 -> nyala\n");
        printf("\t1 -> okapi\n");
        printf("\t2 -> guanaco\n");
        printf("\t3 -> hippopotamus\n");
        printf("\t4 -> dikdik\n");
        printf("\t5 -> fossa\n");
        rte_exit(EXIT_FAILURE, "Error: invalid arguments\n");
    }

    /* Initialize NIC ports */
    threadnum = rte_lcore_count() - 1;
    largs = calloc(threadnum, sizeof(*largs));
    for (i = 0; i < threadnum; i++) {
        largs[i].tid = i;
        largs[i].phase = &phase;
        largs[i].type = atoi(argv[1]);
        largs[i].des_id = atoi(argv[2]);
    }
    port_init(largs, threadnum);

    /* Start applications */
    printf("Starting Workers\n");
    phase = BENCHMARK_WARMUP;
    if (mysettings.warmup_time) {
        sleep(mysettings.warmup_time);
        printf("Warmup done\n");
    }

    /* call lcore_execute() on every slave lcore */
    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        rte_eal_remote_launch(lcore_execute, (void *)(largs + lcore_id -1), 
                lcore_id);
    }

    phase = BENCHMARK_RUNNING;
    sleep(mysettings.run_time);

    if (mysettings.cooldown_time) {
        printf("Starting cooldown\n");
        phase = BENCHMARK_COOLDOWN;
        sleep(mysettings.cooldown_time);
    }

    phase = BENCHMARK_DONE;
    printf("Benchmark done\n");

	rte_eal_mp_wait_lcore();
    /* print status */
    printf("Latency is %lf us\n", (tot_elapsed + 0.0) / (tot_proc_pkts + 0.0));
    printf("Throughput is %lf reqs/s\n", (tot_proc_pkts + 0.0) / 
            (mysettings.run_time + 0.0));

    free(largs);
	return 0;
}
