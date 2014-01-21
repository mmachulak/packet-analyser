#!/bin/bash

nohup tcpdump -i eth0 -w tcpdumpTest/NetMon-%s.pcap -G 30;
