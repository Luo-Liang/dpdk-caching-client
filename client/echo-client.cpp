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

#define __STDC_FORMAT_MACROS 1

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/queue.h>
#include <unistd.h>
#include <sys/time.h>
#include <string>
#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_debug.h>
#include <rte_ethdev.h>
#include <vector>
#include <unordered_map>
#include <iostream>
#include <fstream>
#include "../shared/dpdk-helpers.h"
#include "../shared/pkt-utils.h"
#include "../shared/argparse.h"

// enum benchmark_phase
// {
//     BENCHMARK_WARMUP,
//     BENCHMARK_RUNNING,
//     BENCHMARK_COOLDOWN,
//     BENCHMARK_DONE,
// } __attribute__((aligned(64)));

uint64_t tot_proc_pkts = 0, tot_elapsed = 0;
std::unordered_map<uint32_t, uint32_t> lCore2Idx;
/*static inline void 
pkt_dump(struct rte_mbuf *buf)
{
    printf("Packet info:\n");
    rte_pktmbuf_dump(stdout, buf, rte_pktmbuf_pkt_len(buf));
}*/

static int
lcore_execute(void *arg)
{
    struct lcore_args *myarg;
    uint8_t queue;
    struct rte_mempool *pool;
    //volatile enum benchmark_phase *phase;
    //receive buffers.
    struct rte_mbuf *rbufs[BATCH_SIZE];
    struct timeval start, end;
    uint64_t elapsed;

    myarg = (struct lcore_args *)arg;
    queue = 0; //myarg->tid; one port is only touched by one processor for dpdk-echo.
    //one port probably needs to be touched by multiple procs in real app.
    pool = myarg->pool;
    //phase = myarg->phase;
    //bsz = BATCH_SIZE;
    if (myarg->associatedPorts.size() == 0)
    {
        printf("Thread %d has finished executing.\n", myarg->tid);
        return 0;
    }

    if (myarg->associatedPorts.size() > 1)
    {
        assert(false);
    }

    rte_mbuf *bufPorts[RTE_MAX_ETHPORTS];
    char *pktPtrPorts[RTE_MAX_ETHPORTS];
    pkt_type pktTypesPorts[RTE_MAX_ETHPORTS];
    int port2Id[RTE_MAX_ETHPORTS]; 
    for (int i = 0; i < myarg->associatedPorts.size(); i++)
    {
        auto port = myarg->associatedPorts.at(i);
        //let me create a batch of packets that i will be using all the time, which is one.
        auto pBuf = rte_pktmbuf_alloc(pool);
        if (pBuf == NULL)
        {
            rte_exit(EXIT_FAILURE, "Error: pktmbuf pool allocation failed.");
        }
        rte_mbuf_refcnt_set(pBuf, myarg->counter);
        auto pkt_ptr = rte_pktmbuf_append(pBuf, PAYLOAD_LEN);

        bufPorts[port] = pBuf;
        pktPtrPorts[port] = pkt_ptr;
        port2Id[port] = i;
    }
    uint32_t expectedRemoteIp = ip_2_uint32(myarg->dst.ip);
    while (myarg->samples.size() < myarg->counter)
    {
        for (auto port : myarg->associatedPorts)
        {
            /* Receive and process responses */
            //send a single packet and wait for response.
            /* Prepare and send requests */
            auto pBuf = bufPorts[port];
            auto pktBuf = pktPtrPorts[port];

            pkt_build(pktBuf, myarg->srcs.at(port2Id[port]), myarg->dst, queue, myarg->AzureSupport);
            pkt_set_attribute(pBuf, myarg->AzureSupport);

            //pktTypesPorts[port] = pkt_client_data_build(pktBuf);
            //pkt_dump(bufs[i]);
            if (0 > rte_eth_tx_burst(port, queue, &pBuf, 1))
            {
                rte_exit(EXIT_FAILURE, "Error: cannot tx_burst packets");
            }
            gettimeofday(&start, NULL);
            /* free non-sent buffers */
            bool found = false;
            while (found == false)
            {
                int recv = 0;
                if ((recv = rte_eth_rx_burst(port, queue, rbufs, BATCH_SIZE)) < 0)
                {
                    rte_exit(EXIT_FAILURE, "Error: rte_eth_rx_burst failed\n");
                }

                gettimeofday(&end, NULL);
                for (int i = 0; i < recv; i++)
                {
                    if (pkt_client_process(rbufs[i], pktTypesPorts[port], expectedRemoteIp))
                    {
                        found = true;
                        //__sync_fetch_and_add(&tot_proc_pkts, 1);
                        elapsed = (end.tv_sec - start.tv_sec) * 1000000 +
                                  (end.tv_usec - start.tv_usec);
                        myarg->samples.push_back(elapsed);
                    }
                }

                for (int i = 0; i < recv; i++)
                {
                    rte_pktmbuf_free(rbufs[i]);
                }

                //what if the packet is lost??
                long timeDelta = (long)(end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec);
                if (timeDelta > 1000000)
                {
                    //1 sec is long enough for us to tell the packet is lost.
                    found = true;
                    //this will trigger a resend.
                    if (myarg->samples.size() == myarg->counter - 1)
                    {
                        myarg->samples.push_back(timeDelta);
                    }
                }
                //but what about server is turned off, because it thinks it sent the last message?
                //but that last messagfe is lost? i cannot resend forever.
            }
        }
    }
    printf("Thread %d has finished executing.\n", myarg->tid);
    return 0;
}

int main(int argc, char **argv)
{
    unsigned lcore_id;
    uint8_t threadnum;
    struct lcore_args *largs;

    /* Initialize the Environment Abstraction Layer (EAL) */
    int ret = rte_eal_init(argc, argv);
    if (ret < 0)
    {
        rte_exit(EXIT_FAILURE, "Error: cannot init EAL\n");
    }
    argc -= ret;
    argv += ret;

    /* Initialize application args */
    /*if (argc != 4)
    {
        printf("Usage: %s <type> <dest IP> <dest MAC>\n", argv[0]);
        rte_exit(EXIT_FAILURE, "Error: invalid arguments\n");
    }*/

    ArgumentParser ap;
    ap.addArgument("--srcIps", '+', false);
    ap.addArgument("--srcMacs", '+', false);
    ap.addArgument("--dstIp", 1, false);
    ap.addArgument("--dstMac", 1, false);
    ap.addArgument("--samples", 1, false);
    ap.addArgument("--sid", 1, true);
    ap.addArgument("--did", 1, true);
    ap.addArgument("--blocked", true);
    ap.addArgument("--output", 1, true);
    //enable Windows Azure support
    ap.addArgument("--az", 1, true);

    ap.parse(argc, (const char **)argv);

    std::vector<std::string> srcips = ap.retrieve<std::vector<std::string>>("srcIps");
    std::vector<std::string> srcMacs = ap.retrieve<std::vector<std::string>>("srcMacs");
    if (srcips.size() != srcMacs.size())
    {
        rte_exit(EXIT_FAILURE, "specify same number of ips and macs.");
    }
    endhost destination;
    destination.id = 9367;
    IPFromString(ap.retrieve<std::string>("dstIp"), destination.ip);
    MACFromString(ap.retrieve<std::string>("dstMac"), destination.mac);

    size_t samples = atoi(ap.retrieve<std::string>("samples").c_str());
    if (samples == -1)
    {
        rte_exit(EXIT_FAILURE, "what is %s?", ap.retrieve<std::string>("samples").c_str());
    }
    InitializePayloadConstants();
    /* Initialize NIC ports */
    threadnum = rte_lcore_count();
    if (threadnum < 2)
    {
        rte_exit(EXIT_FAILURE, "use -c -l?! give more cores.");
    }
    largs = (lcore_args *)calloc(threadnum, sizeof(*largs));

    std::unordered_map<int, int> lCore2Idx;
    std::unordered_map<int, int> Idx2LCore;
    CoreIdxMap(lCore2Idx, Idx2LCore);
    bool MSFTAZ = false;
    if (ap.count("az") > 0)
    {
        MSFTAZ = false;
    }
    for (int idx = 0; idx < threadnum; idx++)
    {
        int CORE = Idx2LCore.at(idx);
        largs[idx].CoreID = CORE;
        largs[idx].tid = idx;
        //largs[idx].type = pkt_type::ECHO; //(pkt_type)atoi(argv[1]);
        largs[idx].dst = destination;
        largs[idx].counter = samples;
        largs[idx].master = rte_get_master_lcore() == largs[idx].CoreID;
        largs[idx].AzureSupport = MSFTAZ;
    }
    std::vector<std::string> blockedIFs;
    if (ap.count("blocked") > 0)
    {
        blockedIFs = ap.retrieve<std::vector<std::string>>("blocked");
    }
    ret = ports_init(largs, threadnum, srcips, srcMacs, blockedIFs);
    if (ret != 0)
    {
        printf("port init failed. %s.\n", rte_strerror(rte_errno));
    }

    /* Start applications */
    printf("Starting Workers\n");
    // phase = BENCHMARK_WARMUP;
    // if (mysettings.warmup_time)
    // {
    //     sleep(mysettings.warmup_time);
    //     printf("Warmup done\n");
    // }

    /* call lcore_execute() on every slave lcore */
    RTE_LCORE_FOREACH_SLAVE(lcore_id)
    {
        rte_eal_remote_launch(lcore_execute, (void *)(&largs[lCore2Idx.at(lcore_id)]),
                              lcore_id);
    }

    //sleep(mysettings.run_time);

    // if (mysettings.cooldown_time)
    // {
    //     printf("Starting cooldown\n");
    //     phase = BENCHMARK_COOLDOWN;
    //     sleep(mysettings.cooldown_time);
    // }

    // printf("Benchmark done\n");

    rte_eal_mp_wait_lcore();
    printf("All threads have finished executing.\n");

    /* print status */
    if (ap.count("output") > 0)
    {
        if (ap.count("sid") == 0 || ap.count("did") == 0)
        {
            rte_exit(EXIT_FAILURE, "if output is specified, sid and did must also be specified");
        }
        auto file = ap.retrieve<std::string>("output");
        std::string appHeader("BENCHMARK:DPDK_ECHO;SELF_TEST_OPTION:FALSE;DIMENSION:${totalClients};VALUE:AVG;PREPROCESS:0");
        std::ofstream ofile;
        ofile.open(file);
        for (int i = 0; i < threadnum; i++)
        {
            for (auto t : largs[i].samples)
            {
                //from, to, ping result
                ofile << ap.retrieve<std::string>("sid") << ","
                      << ap.retrieve<std::string>("did") << ","
                      << t
                      << std::endl;
            }
        }
        ofile.close();
        printf("file written to %s\r\n", file.c_str());
    }
    else
    {
        //compute min, max latency.
        uint64_t min = UINT64_MAX, max = 0, avg = 0;
        size_t cntr = 0;
        for (int i = 0; i < threadnum; i++)
        {
            for (auto t : largs[i].samples)
            {
                //from, to, ping result
                min = std::min(min, t);
                max = std::max(max, t);
                avg += t;
            }
            cntr += largs[i].samples.size();
        }
        printf("MIN = %d, MAX = %d, AVG = %d\n", (int)min, (int)max, (int)(avg / cntr));
    }
    free(largs);
    return 0;
}
