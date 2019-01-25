#!/usr/bin/env python3
# -*- coding: UTF=8 -*-

import scapy.config
import scapy.layers.l2
import scapy.route
import math
import ipaddress
from core.arp_scan import ArpScanner
from core.ping_scan import PingScanner
from core.port_scan import PortScanner

class NetworkScanner:
    def __init__(self, scanner_type=False, num_threads=20, verbose=True):
        self.verbose = verbose
        self.num_threads = num_threads
        self.scanner_type = scanner_type

    def scan(self, network=False):
        scanner_type = self.scanner_type
        local_network = self.get_local_network()

        if not network:
            network = local_network
            if not network:
                print("Can't find network")
                return False

        ip_range = self.get_ip_range(network)

        if not scanner_type:
                    # если в списке ip-адресов есть адрес, не принадлежащий локальной сети,
                    # в которйо находится сканер, то примевыбратьнить PING-сканирование
            scanner_type = "arp"
            for ip in self.get_ip_range(network):
                if ip in self.get_ip_range(local_network):
                    continue
                else:
                    scanner_type = "ping"
                    break
        else:
            scanner_type = scanner_type.lower()

        if scanner_type == "arp":
            scanner = ArpScanner(verbose=True)
        elif scanner_type == "ping":
            scanner = PingScanner(self.num_threads, verbose=True)

        #active_hosts = scanner.scan(ip_range)
        if scanner_type == "arp":
            active_hosts, macaddreses = list(zip(*scanner.scan(ip_range)))
        else:
            active_hosts = scanner.scan(ip_range)

        port_scanner = PortScanner(num_threads=self.num_threads, verbose=self.verbose)
        ports = port_scanner.scan(active_hosts)

        return ports

    def get_local_network(self):
        for network, netmask, _, interface, address in scapy.config.conf.route.routes:
            if network == 0 or interface == 'lo' or address == '127.0.0.1' or address == '0.0.0.0':
                continue

            if netmask <= 0 or netmask == 0xFFFFFFFF:
                continue

            net = self.to_CIDR_notation(network, netmask)

            if net:
                return net
            else:
                return False

        return False

    def to_CIDR_notation(self, bytes_network, bytes_netmask):
        network = scapy.utils.ltoa(bytes_network)
        netmask = self.long2net(bytes_netmask)
        net = "%s/%s" % (network, netmask)
        if netmask < 16:
            logger.warn("%s is too big. skipping" % net)
            return None

        return net

    def long2net(self, arg):
        if (arg <= 0 or arg >= 0xFFFFFFFF):
            raise ValueError("illegal netmask value", hex(arg))
        return 32 - int(round(math.log(0xFFFFFFFF - arg, 2)))

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
    scanner = NetworkScanner(scanner_type="arp", num_threads=20, verbose=True)
    scanner.scan()
