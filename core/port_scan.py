#!/usr/bin/env python3
# -*- coding: UTF=8 -*-

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import sr1, TCP, IP, send, RandShort
from datetime import datetime
import ipaddress
import threading
from queue import Queue

class PortscanThread(threading.Thread):
    ports = [80, 8080, 23]
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
                    print("Host:\t%s" % ip)
                    print("Ports:\t%s" % ", ".join(map(str, open_ports)), end="\n\n")
                self.out.put((ip, open_ports))

            self.queue.task_done()

    def ScanPorts(self, host):
        open_ports = []
        for port in self.ports:
            port_status = self.ScanPort(host, port)
            if port_status is "Unreachable":
                return False
            elif port_status is "Open":
                open_ports.append(port)

        if open_ports:
            return open_ports
        else:
            return False

    def ScanPort(self, host, port):
        srcport = RandShort()
        SYNACKpkt = sr1(IP(dst = host)/TCP(sport = srcport, dport = port, flags = "S"), timeout=1, verbose=0)
        if not SYNACKpkt:
            return "Unreachable"

        pktflags = SYNACKpkt.getlayer(TCP).flags

        RSTpkt = IP(dst = host)/TCP(sport = srcport, dport = port, flags = "R")
        send(RSTpkt, verbose=0)
        if pktflags == self.SYNACK:
            return "Open"
        else:
            return False


class PortScanner:
    def __init__(self, num_threads=10, verbose=True):
        self.num_threads = num_threads
        self.verbose = verbose

        if self.verbose:
            print("Performing port scan...")
            print("-"*40)

    def scan(self, ip_range):
        """ Принимает список ip-адресов для сканирования,
            возвращает список хостов с открытыми портами в формате
            [ (ip, [port1, port2]), (ip, [port1, port2]), ... ]
        """
        queue = Queue()
        out = Queue()

        for i in range(self.num_threads):
            t = PortscanThread(queue, out, verbose=self.verbose)
            t.setDaemon(True)
            t.start()

        for ip in ip_range:
            queue.put(ip)

        queue.join()
        if self.verbose:
            print("-"*40, end="\n\n")
        return [ip for ip in out.queue]

    def get_ip_range(self, network):
        # преобразование данных типа "ip_first-ip_last", "ip/mask", "ip1, ip2, ip3", "ip" в список ip-адресов
        if "-" in network:
            ip_first, ip_last = network.strip(" ").split("-")
            addresess = ipaddress.summarize_address_range(
                                                            ipaddress.IPv4Address(ip_first),
                                                            ipaddress.IPv4Address(ip_last))
            addresess = sum([list(cidr) for cidr in addresess], [])
            return (str(ip) for ip in addresess)

        if "/" in network:
            addresess = network[:network.rindex(".")] + ".0"+network[network.rindex("/"):]
            return (str(ip) for ip in ipaddress.IPv4Network(addresess))

        if "," or ", " in network:
            return (ip for ip in network.replace(", ", ",").split(","))

        return [network]

if __name__ == "__main__":
    import sys
    scanner = PortScanner(verbose=True, num_threads=1)
    #ip = "192.168.0.1,192.168.0.2,192.168.0.100"
    ip = sys.argv[1]
    print(ip)
    #exit()
    out = scanner.scan([ip])
    print(out)
