#!/usr/bin/env python3
# -*- coding: UTF=8 -*-

import logging
logging.getLogger("scapy.runtime").setLevel(logging.CRITICAL)
from scapy.all import sr1, TCP, IP, send, RandShort
from datetime import datetime
import os

class PortScanner:
    ports = [80, 81, 82, 83, 84, 88, 8080, 8888, 23, 22]
    start_clock = datetime.now()
    SYNACK = 0x12
    RSTACK = 0x14

    def __init__(self):
        self.check_root()

    def check_root(self):
        if not os.geteuid() == 0:
            print("Run as root.")
            exit(1)

    def scan_port(self, host, port):
        srcport = RandShort() # Generate Port Number
        SYNACKpkt = sr1(IP(dst = host)/TCP(sport = srcport, dport = port, flags = "S"))
        pktflags = SYNACKpkt.getlayer(TCP).flags

        RSTpkt = IP(dst = host)/TCP(sport = srcport, dport = port, flags = "R")
        send(RSTpkt)

        if pktflags == self.SYNACK:
            return True
        else:
            return False

    def scan_host(self, host):
        open_ports = []

        for port in self.ports:
            open_port = self.scan_port(host, port)
            if open_port:
                open_ports.append(port)

        return [host, open_ports]

if __name__ == "__main__":
    scanner = PortScanner()
    ip = "192.168.0.1"
    print(scanner.scan_host(ip))
