#!/usr/bin/env python3
# -*- coding: UTF=8 -*-

import scapy.config
import scapy.layers.l2
import scapy.route
import math
import socket
import re, struct
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
            if not local_network:
                return False
            else:
                network = local_network

        ip_range = self.get_ip_range(network)

        if not scanner_type:
                    # если в списке ip-адресов есть адрес, не принадлежащий локальной сети,
                    # в которой находится сканер, то примевыбратьнить PING-сканирование
            scanner_type = "arp"
            for ip in self.get_ip_range(network):
                if ip in self.get_ip_range(local_network):
                    continue
                else:
                    scanner_type = "ping"
                    break
        else:
            scanner_type = scanner_type.lower()

        # нужно для использования меньшего количества потоков, если это возможно
        iprange_len = 0
        for ip in self.get_ip_range(network):
            iprange_len += 1

        if scanner_type == "arp":
            scanner = ArpScanner(verbose=True)
        elif scanner_type == "ping":
            scanner = PingScanner(num_threads=min(self.num_threads, iprange_len), verbose=True)

        scan_result = scanner.scan(ip_range)
        if scan_result:
            if scanner_type == "arp":
                active_hosts, macaddreses = list(zip(*scan_result))
            else:
                active_hosts = scan_result
        else:
            return False

        port_scanner = PortScanner(num_threads=min(self.num_threads, iprange_len), verbose=self.verbose)
        ports = port_scanner.scan(active_hosts)

        if scanner_type == "arp":
            data = []
            for ip_ports, macaddr in zip(ports, macaddreses):
                ip, port = ip_ports
                data.append((ip, port, macaddr))
            return data
        else:
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
        if "/" in network:
            ip, cidr = network.split("/")
            cidr = int(cidr)
            host_bits = 32 - cidr

            int_ip = self.ip2int(ip)

            start = (int_ip >> host_bits) << host_bits
            end = start | ((1 << host_bits) - 1)

            #for i in range(start, end+1):
            #    ip_list.append(self.int2ip(i))
            #return ip_list
            for i in range(start, end+1):
                yield self.int2ip(i)

            return

        ip_list = list()
        ip_addresses = re.split("[,]", network)

        for ip in ip_addresses:
            match_ip_range = re.search("[-]", ip)
            if match_ip_range:
                start = ip[:match_ip_range.start()]
                end = ip[match_ip_range.end():]

                for ip_int in range(self.ip2int(start), self.ip2int(end) + 1):
                    #ip_list.append(self.int2ip(ip_int))
                    yield self.int2ip(ip_int)
                return
            else:
                yield ip

        return

    def ip2int(self, addr):
        return struct.unpack("!I", socket.inet_aton(addr))[0]

    def int2ip(self, addr):
        return socket.inet_ntoa(struct.pack("!I", addr))

if __name__ == "__main__":
    scanner = NetworkScanner(scanner_type="arp", num_threads=20, verbose=True)
    scanner.scan()
