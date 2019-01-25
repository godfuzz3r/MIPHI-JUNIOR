#!/usr/bin/env python3
# -*- coding: UTF=8 -*-

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import IP, ICMP, sr1
import ipaddress
import threading
from queue import Queue


class PingThread(threading.Thread):
    def __init__(self, queue, out, timeout=0.5, verbose=True):
        threading.Thread.__init__(self)
        self.TIMEOUT = timeout
        self.queue = queue
        self.out = out
        self.verbose = verbose

    def run(self):
        while True:
            ip = self.queue.get()
            dst_ip = self.icmp_ping(ip)

            if dst_ip:
                if self.verbose:
                    print(dst_ip)
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
    def __init__(self, num_threads=10, verbose=True):
        self.num_threads = num_threads
        self.verbose = verbose

    def scan(self, ip_range):
        if self.verbose:
            print("Performing PING scan...")
            print("-"*40)
            
        queue = Queue()
        out = Queue()

        for i in range(self.num_threads):
            t = PingThread(queue, out, verbose=self.verbose)
            t.setDaemon(True)
            t.start()

        for ip in ip_range:
            queue.put(ip)

        queue.join()
        if self.verbose:
            print("-"*40, end="\n\n")
        return [ip for ip in out.queue]


if __name__ == "__main__":
    scanner = PingScanner(num_threads=40, verbose=True)
    scanner.scan("192.168.0.1/24")
