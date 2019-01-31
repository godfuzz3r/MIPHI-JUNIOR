#!/usr/bin/env python3
# -*- coding: UTF=8 -*-

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import sr1, TCP, IP, send, RandShort
from datetime import datetime
import ipaddress
import threading
from queue import Queue

HEADER = '\033[95m'
OKBLUE = '\033[94m'
OKGREEN = '\033[92m'
WARNING = '\033[93m'
FAIL = '\033[91m'
ENDC = '\033[0m'
BOLD = '\033[1m'
UNDERLINE = '\033[4m'

class PortscanThread(threading.Thread):
    ports = [80, 8080, 8081, 23]
    start_clock = datetime.now()
    SYNACK = 0x12
    RSTACK = 0x14

    def __init__(self, queue, out, verbose=True):
        threading.Thread.__init__(self)
        self.queue = queue
        self.out = out
        self.verbose = verbose

    def run(self):
        while True:
            ip = self.queue.get()
            open_ports = self.ScanPorts(ip)

            if open_ports:
                if self.verbose:
                    self.show_info(ip, open_ports)
                self.out.put((ip, open_ports))

            self.queue.task_done()

    def ScanPorts(self, host, timeout=1):
        open_ports = []
        srcport = RandShort()

        for dport in self.ports:
        	SYNACKpkt = sr1(IP(dst=host) /
        			TCP(sport=srcport, dport=dport, flags="S"),
        			timeout=timeout, verbose=0)
        	if not SYNACKpkt:
        		continue

        	pktflags = SYNACKpkt.getlayer(TCP).flags
        	RSTpkt = IP(dst = host)/TCP(sport = srcport, dport = dport, flags = "R")
        	send(RSTpkt, verbose=0)
        	if pktflags == self.SYNACK:
        		open_ports.append(dport)

        if open_ports:
            return open_ports
        else:
            return False

    def ScanPort(self, host, port):
        srcport = RandShort()
        SYNACKpkt = sr1(IP(dst = host) /
                        TCP(sport = srcport, dport = port, flags = "S"), timeout=1, verbose=0)
        if not SYNACKpkt:
            return "Unreachable"

        pktflags = SYNACKpkt.getlayer(TCP).flags

        RSTpkt = IP(dst = host)/TCP(sport = srcport, dport = port, flags = "R")
        send(RSTpkt, verbose=0)
        if pktflags == self.SYNACK:
            return "Open"
        else:
            return False

    def show_info(self, ip, ports):
        print(  BOLD + WARNING + "\tHost:" + ENDC +
                "\t{}\n\t".format(ip) +
                BOLD + WARNING + "Ports:" + ENDC +
                "\t{}".format(", ".join(map(str, ports))),
                end = "\n\n"    )

        #print("\tPorts:\t%s" % ", ".join(map(str, open_ports)), end="\n\n")


class PortScanner:
    def __init__(self, num_threads=10, verbose=True):
        self.num_threads = num_threads
        self.verbose = verbose

    def scan(self, ip_range):
        """ Принимает список ip-адресов для сканирования,
            возвращает список хостов с открытыми портами в формате
            [ (ip, [port1, port2]), (ip, [port1, port2]), ... ]
        """
        if self.verbose:
            print(HEADER + BOLD + OKBLUE + "Performing port scan..." + ENDC)
            print(HEADER + "-"*40 + ENDC)

        queue = Queue()
        out = Queue()

        for i in range(self.num_threads):
            t = PortscanThread(queue, out, verbose=self.verbose)
            t.setDaemon(True)
            t.start()

        for ip in ip_range:
            queue.put(ip)

        queue.join()
        out = [ip for ip in out.queue]

        if self.verbose:
            if not len(out):
                print(WARNING + BOLD + "\nDevices with open ports are not found. Exiting...\n" + ENDC)
                exit(1)

            print(HEADER + "-"*40 + ENDC, end="\n\n")
        return out


if __name__ == "__main__":
    import sys
    scanner = PortScanner(verbose=True, num_threads=1)
    #ip = "192.168.0.1,192.168.0.2,192.168.0.100"
    ip = sys.argv[1]
    print(ip)
    #exit()
    out = scanner.scan([ip])
    print(out)
