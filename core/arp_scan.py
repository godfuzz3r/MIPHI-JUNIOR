#!/usr/bin/env python3
# -*- coding: UTF=8 -*-

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import srp
from scapy.all import Ether, ARP, conf
import ipaddress
import re

class ArpScanner:
    def __init__(self):
        pass

    def scan(self, ip_range):
        ip_range = self.get_ip_range(ip_range)
        ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_range), timeout=2, verbose=0)

        collection = []
        for snd, rcv in ans:
            result = rcv.sprintf(r"%ARP.psrc% %Ether.src%").split()
            collection.append(result)
        return collection

    def get_ip_range(self, network):
        # преобразование данных типа first_ip-last_ip в список ip-адресов
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
    scanner = ArpScanner()
    print(scanner.scan("192.168.0.1"))
