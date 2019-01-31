#!/usr/bin/env python3
from telnetlib import Telnet

HEADER = '\033[95m'
OKBLUE = '\033[94m'
OKGREEN = '\033[92m'
WARNING = '\033[93m'
FAIL = '\033[91m'
ENDC = '\033[0m'
BOLD = '\033[1m'
UNDERLINE = '\033[4m'

default_pwds = {"default": ["admin", "admin"]}
telnet_ports = [23]

def check(device_info):
    for port in device_info["ports"]:
        if port in telnet_ports:

            if not device_info["device_vendor"] in default_pwds.keys():
                login = default_pwds["default"][0]
                password = default_pwds["default"][1]

            else:
                login = default_pwds["device_vendor"][0]
                password = default_pwds["device_vendor"][1]

            print(BOLD + WARNING + "\t[*] " + ENDC + "Checking for default Telnet credentials...")

            conn = Telnet(device_info["ip"], timeout = 1)

            conn.read_until(b":")
            conn.write((login + "\n").encode('ascii'))

            conn.read_until(b":")
            conn.write((password + "\n").encode('ascii'))
            try:
                while 1:
                    r = conn.read_some()
                    if b"> " in r or b"$ " in r or b"# " in r:
                        print(BOLD + FAIL + "\t[!] " + ENDC + BOLD +"Found default Telnet credentials for device:" + ENDC)
                        print(BOLD + "\t\t\t\tLogin:\t\t" + ENDC + login)
                        print(BOLD + "\t\t\t\tPassword:\t" + ENDC + password)
                        print(BOLD + OKBLUE + "\t[*] Recommendation: " + ENDC + BOLD + "Change default login and password in the Telnet shell" + ENDC)
                        print()

                        return login, password
            except:
                pass

            print(BOLD + OKGREEN + "\t[+] " + ENDC + "Telnet credentials is ok")
            print()
            return False

if __name__ == "__main__":
    check(bytes("192.168.0.1".encode('ascii')), [23])
