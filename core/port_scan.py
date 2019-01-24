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
    ports = [80, 8080, 23, 22]
    start_clock = datetime.now()
    SYNACK = 0x12
    RSTACK = 0x14

    def __init__(self, queue, out):
        threading.Thread.__init__(self)
        self.queue = queue
        self.out = out

    def run(self):
        while True:
            ip = self.queue.get()
            open_ports = self.ScanPorts(ip)

            if open_ports:
                print(ip, open_ports)
                self.out.put((ip, open_ports))

            self.queue.task_done()

    def ScanPorts(self, host):
        open_ports = []
        for port in self.ports:
            if self.ScanPort(host, port):
                open_ports.append(port)

        if open_ports:
            return open_ports
        else:
            return False

    def ScanPort(self, host, port):
        srcport = RandShort()
        SYNACKpkt = sr1(IP(dst = host)/TCP(sport = srcport, dport = port, flags = "S"))
        pktflags = SYNACKpkt.getlayer(TCP).flags

        RSTpkt = IP(dst = host)/TCP(sport = srcport, dport = port, flags = "R")
        send(RSTpkt)
        if pktflags == self.SYNACK:
            return True
        else:
            return False


class PortScanner:
    def __init__(self, num_threads=10):
        self.num_threads = num_threads

    def scan(self, ip_range):
        ip_range = self.get_ip_range(ip_range)
        queue = Queue()
        out = Queue()

        for i in range(self.num_threads):
            t = PortscanThread(queue, out)
            t.setDaemon(True)
            t.start()

        for ip in ip_range:
            queue.put(ip)

        queue.join()
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
    scanner = PortScanner()
    ip = "192.168.0.1,192.168.0.103"
    print(scanner.scan(ip))
