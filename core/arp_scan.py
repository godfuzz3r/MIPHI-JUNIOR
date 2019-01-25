#!/usr/bin/env python3
# -*- coding: UTF=8 -*-

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import srp
from scapy.all import Ether, ARP, conf
import ipaddress
import re
from core.mac_vendor import MacParser

class ArpScanner:
    def __init__(self, verbose=True):
        self.verbose = verbose

    def scan(self, ip_range):
        """ Принимает на вход список ip-адресов для сканирования,
            возвращает список работающих хостов в формате
            [ [ip, macaddr], [ip, macaddr], ... ]
        """
        if self.verbose:
                print("Performing ARP scan...")
                print("-"*40)

        ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_range), timeout=2, verbose=0)

        collection = []
        for snd, rcv in ans:
            result = rcv.sprintf(r"%ARP.psrc% %Ether.src%").split()
            if self.verbose:
                self.show_info(result)
            collection.append(result)

        if self.verbose:
            print("-"*40, end="\n\n")
        return collection

    def show_info(self, data=False):
        mac_parser = MacParser()

        ip, mac = data
        vendor = mac_parser.search(mac)
        print("%s\t%s\t%s" % (ip, mac, vendor))


if __name__ == "__main__":
    scanner = ArpScanner(verbose=True)
    out = scanner.scan(["192.168.0.1"])
    print(out)
