#!/usr/bin/env python3

import argparse
from argparse import RawTextHelpFormatter
import os
from core.network_scanner import NetworkScanner
from core.fingerprint import FingerPrinter
from core.http_auth import HttpAuth
import core.telnet_auth
import core.cvemitre as cvemitre

HEADER = '\033[95m'
OKBLUE = '\033[94m'
OKGREEN = '\033[92m'
WARNING = '\033[93m'
FAIL = '\033[91m'
ENDC = '\033[0m'
BOLD = '\033[1m'
UNDERLINE = '\033[4m'

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
                sudo ./%(prog)s 192.168.0.1 192.168.0.100 192.168.0.103"
                sudo ./%(prog)s -t 40 -s ping"""
                                    )

    parser.add_argument('-s', '--scan_type', help='arp or ping scan', action='store', default=None)
    parser.add_argument('-t', '--threads', help='Number of threads', action='store', default=20)
    parser.add_argument('network', nargs='*', help="ip-range, CIDR, or single ip address", default=None)

    args = parser.parse_args()

    if len(args.network) == 1:
        network = args.network[0]
    else:
        network = ",".join(args.network)

    net_scanner = NetworkScanner(scanner_type=args.scan_type, num_threads=int(args.threads))
    hosts = net_scanner.scan(network)

    if not hosts:
    	print( BOLD + "No working devices found, exiting..." + ENDC )
    	print( HEADER + "-"*40 + ENDC, end="\n\n" )
    	return 1

    print(HEADER + BOLD + OKBLUE + "Trying to determine IOT devices..." + ENDC)
    print(HEADER + "-"*40 + ENDC)
    fingerpriner = FingerPrinter()

    devices_found = 0
    for host in hosts:
        if len(host) == 3:
            ip, ports, macaddr = host
            device_info = fingerpriner.fingerprint(ip, ports, macaddr)
        else:
            ip, ports = host
            device_info = fingerpriner.fingerprint(ip, ports)

        if not device_info:
            continue
        else:
            devices_found += 1

        http = HttpAuth()
        http.check_default_passwords(ip, ports, device_info["device_vendor"], device_info["device_name"])
        core.telnet_auth.check(device_info)

        print( BOLD + WARNING + "\t[*] " + ENDC + "Checking for device vulnerabilities..." + ENDC)
        device_cve = cvemitre.get_cve(device_info["device_name"])
        if device_cve:
            print( BOLD + FAIL + "\t[!] " + ENDC + BOLD + "Found possible device vulnerabilities:" + ENDC)
            for cve in device_cve:
                print( BOLD + FAIL + "\t\t[+] " + ENDC + BOLD + cve + ENDC)
        else:
            print( BOLD + OKGREEN + "\t[+] " + ENDC + BOLD + "No vulnerabilities found for this device" + ENDC)

        print()

    if not devices_found:
    	print( BOLD + "No working devices found, exiting..." + ENDC )
    print(HEADER + "-"*40 + ENDC)

if __name__ == "__main__":
    main()
