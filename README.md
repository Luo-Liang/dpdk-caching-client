A simple dpdk-echo example.

# Sampa cluster performance
Each sampa machine has 2 Intel 6-core Intel Xeon X5650 (default 2.67GHz)
processors and 24G memory. This server is quite hard to saturate
bandwidth using small packets (46 bytes payload).

## 1-server-thread
                    Latency(us)     Throughput(reqs/s)
1-client-thread     0.17            5.6M
2-client-thread     0.20            9.5M    

## 2-server-thread
                    Latency(us)     Throughput(reqs/s)
1-client-thread     0.18            5.5M
2-client-thread     0.17            11.1M    

# System animal cluster (zookeeper) performance
Each zookeeper machine has 1 Intel Xeon E5-2680 v3 (default 2.50GHz) 
processor and 64G memory. This server is quite easy to saturate 
bandwidth using small packets.

## 1-server-thread (46B)
                    Latency(us)     Throughput(reqs/s)
1-client-thread     0.09            11.1M

## 1-server-thread (64B)
                    Latency(us)     Throughput(reqs/s)
1-client-thread     0.10            9.6M

## 1-server-thread (1024B)
                    Latency(us)     Throughput(reqs/s)
1-client-thread     0.86            1.1M
