#!/usr/bin/env python3
# -*- coding: UTF=8 -*-

import requests
from bs4 import BeautifulSoup as bs

class HTTPFingerPrinter:
    def __init__(self, macaddr=False):
        self.macaddr = macaddr

    def get_data(self, ip, port):
        info = {
            "device_type":  False,      # router, camera, dvr
            "device_name":  False,
            "firmware_ver": False,

        }

        device_responce = requests.get("http://%s:%d" % (ip, port))

        headers = device_responce.headers
        html = device_responce.text

        self.header_matches(headers)

    def header_matches(self, headers):
        pass

    def html_matches(self, html):
        pass
