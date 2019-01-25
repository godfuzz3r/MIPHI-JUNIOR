#!/usr/bin/env python3

import argparse
from argparse import RawTextHelpFormatter
import os
from core.network_scanner import NetworkScanner

def check_root():
    if not os.geteuid() == 0:
        print("Run as root.")
        exit(1)

def main():
    check_root()
    parser = argparse.ArgumentParser(   description="",
                                        formatter_class=RawTextHelpFormatter,
                                        epilog="""
Usage examples:
                sudo ./%(prog)s
                sudo ./%(prog)s 192.168.0.1/24
                sudo ./%(prog)s 192.168.0.102
                sudo ./%(prog)s 192.168.0.100-192.168.0.110
                sudo ./%(prog)s "192.168.0.1, 192.168.0.100, 192.168.0.103"
                sudo ./%(prog)s -t 40 -s ping"""
                                    )

    parser.add_argument('-s', '--scan_type', help='arp or ping scan', action='store', default=None)
    parser.add_argument('-t', '--threads', help='Number of threads', action='store', default=20)
    parser.add_argument('network', nargs='?', help="ip-range, CIDR, or single ip address", default=None)

    args = parser.parse_args()

    net_scanner = NetworkScanner(scanner_type=args.scan_type, num_threads=args.threads)
    hosts = net_scanner.scan(args.network)
    print(hosts)

if __name__ == "__main__":
    main()
