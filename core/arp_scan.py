#!/usr/bin/env python3
# -*- coding: UTF=8 -*-

import os
from scapy.all import srp
from scapy.all import Ether, ARP, conf
import ipaddress


class ArpScanner:
    def __init__(self):
        self.check_root()

    def check_root(self):
        if not os.geteuid() == 0:
            print("Run as root.")
            exit(1)

    def scan(self, iprange):
        ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=iprange), timeout=2)

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
            network = network[:network.rindex(".")]+".0"+network[network.rindex("/"):]
            return (str(ip) for ip in ipaddress.IPv4Network(network))

        return [network]

if __name__ == "__main__":
    scanner = ArpScanner()
    ip_range = scanner.get_ip_range("192.168.0.4-192.168.0.107")
    print(scanner.scan(ip_range))
