#!/usr/bin/env python3
# -*- coding: UTF=8 -*-

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import IP, ICMP, sr1
import ipaddress
import threading
from queue import Queue
import sys

HEADER = '\033[95m'
OKBLUE = '\033[94m'
OKGREEN = '\033[92m'
WARNING = '\033[93m'
FAIL = '\033[91m'
ENDC = '\033[0m'
BOLD = '\033[1m'
UNDERLINE = '\033[4m'

class PingThread(threading.Thread):
    def __init__(self, queue, out, timeout=1, verbose=True):
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
        reply = sr1(IP(dst=ip)/ICMP(), timeout=self.TIMEOUT, verbose=0)

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
            print(HEADER + BOLD + OKBLUE + "Performing PING scan..." + ENDC)
            print(HEADER + "-"*40 + ENDC)

        queue = Queue()
        out = Queue()

        for i in range(min(self.num_threads, len(ip_range))):
            t = PingThread(queue, out, verbose=self.verbose)
            t.setDaemon(True)
            t.start()

        for ip in ip_range:
            queue.put(ip)

        queue.join()

        out = [ip for ip in out.queue]
        if self.verbose:
            print(HEADER + "-"*40 + ENDC)
            print(BOLD + WARNING + "Found {} active hosts".format(len(out)) + ENDC, end="\n\n")

        return out


if __name__ == "__main__":
    scanner = PingScanner(num_threads=40, verbose=True)
    scanner.scan([sys.argv[1]])
