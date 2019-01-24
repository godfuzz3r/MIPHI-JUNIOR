#!/usr/bin/env python3
# -*- coding: UTF=8 -*-

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import ipaddress
import threading
from queue import Queue
import pdb

class PingThread(threading.Thread):
    def __init__(self, queue, out, timeout=0.5):
        self.TIMEOUT = timeout
        threading.Thread.__init__(self)
        self.queue = queue
        self.out = out

    def run(self):
        while True:
            ip = self.queue.get()
            dst_ip = self.icmp_ping(ip)
            if dst_ip:
                self.out.put(dst_ip)
            self.queue.task_done()

    def icmp_ping(self, ip):
        packet = IP(dst=ip, ttl=20)/ICMP()
        reply = sr1(packet, timeout=self.TIMEOUT, verbose=0)
        if reply:
            return reply.src
        else:
            return False

class PingScanner:
    def __init__(self, num_threads=10):
        self.num_threads = num_threads

    def scan(self, ip_range):
        ip_range = self.get_ip_range(ip_range)
        queue = Queue()
        out = Queue()

        for i in range(self.num_threads):
            t = PingThread(queue, out)
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
    scanner = PingScanner()
    print(scanner.scan("192.168.0.100-192.168.0.103"))
