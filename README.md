A simple dpdk-echo example.

Echo results with 46 bytes packets on Sampa machines, which 
has 2 Intel 6-core Intel Xeon X5650 (2.67GHz) processors, and 
24G memory. The server is hard to saturate bandwidth using 
small packets.

(1) 1-server-thread
                    Latency(us)     Throughput(reqs/s)
1-client-thread     0.17            5.6M
2-client-thread     0.20            9.5M    
3-client-thread     0.29            9.5M

(2) 2-server-thread
                    Latency(us)     Throughput(reqs/s)
1-client-thread     0.18            5.5M
2-client-thread     0.17            11.1M    
3-client-thread     0.21            13.3M
4-client-thread     0.29            12.7M
