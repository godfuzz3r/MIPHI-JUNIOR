#!/usr/bin/env python3
# -*- coding: UTF=8 -*-

import requests
import json
from core.mac_vendor import MacParser
import sys
import re
import telnetlib

HEADER = '\033[95m'
OKBLUE = '\033[94m'
OKGREEN = '\033[92m'
WARNING = '\033[93m'
FAIL = '\033[91m'
ENDC = '\033[0m'
BOLD = '\033[1m'
UNDERLINE = '\033[4m'

class FingerPrinter:
    http_ports = [80, 8080]
    telnet_ports = [23]
    adb_ports = [5555]

    def __init__(self, verbose=True):
        self.verbose = verbose
        self.data = json.loads(open("core/data/models.json").read(), encoding="utf-8")
        self.info = {   "ip":               False,
                        "ports":            [],
                        "device_vendor":    False,
                        "device_name":      False,
                        "firmware_ver":     False,
                    }

    def fingerprint(self, ip, ports, macaddr=False):
        self.info["ip"] = ip
        self.info["ports"] = ports

        if macaddr:
            self.macaddr_fingerprint(macaddr)

        for port in ports:
            if port in self.http_ports:
                self.http_fingerprint(ip, port)

            if port in self.telnet_ports and not self.info["device_name"]:
                self.telnet_fingerprint(ip, port)

        if self.info["device_name"]:
            if self.verbose:
                self.show_info()
            return self.info
        else:
            return False

    def macaddr_fingerprint(self, macaddr):
        macparser = MacParser()

        for vendor in self.data.keys():
            if vendor.lower() in macparser.search(macaddr, type="vendor").lower():
                self.info["device_vendor"] = vendor
                break

    def http_fingerprint(self, ip, port):
        device_responce = requests.get("http://%s:%d" % (ip, port))

        headers = device_responce.headers
        html = device_responce.text

        if self.info["device_vendor"]:
            for model in self.data[self.info["device_vendor"]]:
                if model in html or model in str(headers):
                    self.info["device_name"] = model
                    break

        else:
            model_found = False
            for vendor in self.data.keys():
                if model_found:
                    break

                for model in self.data[vendor]:
                    if model in html or model in str(headers):
                        self.info["device_vendor"] = vendor
                        self.info["device_name"] = model

                        model_found = True
                        break

        if self.info["device_vendor"] == "D-Link" and not self.info["firmware_ver"]:
            self.get_dlink_firmware(ip, port, self.info["device_name"])

    def get_dlink_firmware(self, ip, port, model):
        response = requests.get("http://%s:%d" % (ip, port))

        if "Server" in response.headers.keys():
            if model in response.headers["Server"]:
                ver_str = response.headers["Server"].split(model)[1].lower().replace(" ver ", "")
                self.info["firmware_ver"] = ver_str

    def telnet_fingerprint(self, ip, port):
        try:
            connection = telnetlib.Telnet(ip)
            data = connection.read_until(b':')
        except:
            return False

        model_found = False
        for vendor in self.data.keys():
            if model_found:
                break

            for model in self.data[vendor]:
                if model in str(data):
                    self.info["device_vendor"] = vendor
                    self.info["device_name"] = model

                    model_found = True
                    break

        return

    def show_info(self):
        ip = self.info["ip"]
        ports = self.info["ports"]
        device_vendor = self.info["device_vendor"]
        device_name = self.info["device_name"]
        firmware_ver = self.info["firmware_ver"]

        print(  BOLD + OKBLUE + "[+] " + WARNING + "Found device:\t" + ENDC + ip, end="\n\n")

        if device_vendor and device_name:
            print(  BOLD + WARNING + "\tDevice name:\t" + ENDC +
                    BOLD + OKGREEN + "{0} {1}".format( device_vendor, device_name ) + ENDC)

        elif device_vendor:
            print(  BOLD + WARNING + "\tDevice name:\t" + ENDC +
                    BOLD + OKGREEN + device_vendor + ENDC)

        elif device_name:
            print(  BOLD + WARNING + "\tDevice name:\t" + ENDC +
                    BOLD + OKGREEN + device_name + ENDC)

        if firmware_ver:
            print(  BOLD + WARNING + "\tFirmware Ver.:\t" + ENDC +
                    firmware_ver)
        print()


if __name__ == "__main__":
    fingerprinter = FingerPrinter()
    fingerprinter.fingerprint(sys.argv[1], [80])
