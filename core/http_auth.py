#!/usr/bin/env python3
import requests
import bs4 as bs
import sys
from requests.auth import HTTPBasicAuth
from requests.auth import HTTPDigestAuth

HEADER = '\033[95m'
OKBLUE = '\033[94m'
OKGREEN = '\033[92m'
WARNING = '\033[93m'
FAIL = '\033[91m'
ENDC = '\033[0m'
BOLD = '\033[1m'
UNDERLINE = '\033[4m'

class HttpAuth:
    http_ports = [80, 8080]

    def __init__(self):
        self.pwd_db = {  "D-Link": ["admin", "admin"],
                    "TP-LINK": ["admin", "admin"],
                    "default": ["admin", "admin"]
                    }
        self.auth_type = False

    def check_default_passwords(self, ip, ports, device_vendor, device_name):
        for dport in ports:
            if dport in self.http_ports:
                port = dport
                break
        else:
            return

        print(BOLD + WARNING + "\t[*] " + ENDC + "Checking for default credentials...")
        self.get_auth_type(ip, port)

        if self.auth_type == "basic":
            creds = self.basic_auth(ip, port, device_vendor)
        elif self.auth_type == "web_login":
            creds = self.web_login(ip, port, device_vendor)

        if creds:
            login, pwd = creds
            print(BOLD + FAIL + "\t[!] " + ENDC + BOLD +"Found default HTTP credentials for device:" + ENDC)
            print(BOLD + "\t\t\t\tLogin:\t\t" + ENDC + login)
            print(BOLD + "\t\t\t\tPassword:\t" + ENDC + pwd)
            print(BOLD + OKBLUE + "\t[*] Recommendation: " + ENDC + BOLD + "Change default login and password in the WEB settins" + ENDC)
            print()
        else:
            print(BOLD + OKGREEN + "\t[+] " + ENDC + "HTTP credentials is ok")
            print()

        return creds

    def get_auth_type(self, ip, port):
        response = requests.get("http://%s:%d/" % (ip, port))
        #print(response.headers)

        if response.status_code != 401 and "WWW-Authenticate" not in response.headers.keys():
            self.auth_type = "web_login"
            return False

        if "Basic" in response.headers["WWW-Authenticate"]:
            self.auth_type = "basic"
            return True
        elif "Digest" in response.headers["WWW-Authenticate"]:
            self.auth_type = "digest"
            return True

    def basic_auth(self, ip, port, vendor):
        if self.pwd_db.get(vendor):
            login = self.pwd_db[vendor][0]
            pwd = self.pwd_db[vendor][1]
        else:
            login = self.pwd_db["default"][0]
            pwd = self.pwd_db["default"][1]

        response = requests.get('http://%s:%d' % (ip, port), auth=HTTPBasicAuth(login, pwd))
        if "WWW-Authenticate" not in response.headers.keys():
            return login, pwd

    def web_login(self, ip, port, vendor):
        if self.pwd_db.get(vendor):
            login = self.pwd_db[vendor][0]
            pwd = self.pwd_db[vendor][1]
        else:
            login = self.pwd_db["default"][0]
            pwd = self.pwd_db["default"][1]

        response = requests.get('http://%s:%d' % (ip, port))
        soup = bs.BeautifulSoup(response.text, "html.parser")

        form = soup.find_all("form")[0]
        url = form["action"]
        enctype = form["enctype"]
        method = form["method"]

        inputs = soup.find_all("input")
        params = {}

        for data_input in inputs:
            if data_input["type"] == "hidden":
                params[data_input["name"]] = data_input["value"]

            elif data_input["type"] == "text":
                if vendor in self.pwd_db.keys():
                    params[data_input["id"]] = self.pwd_db[vendor][0]
                else:
                    params[data_input["id"]] = self.pwd_db["default"][0]

            elif data_input["type"] == "password":
                if vendor in self.pwd_db.keys():
                    params[data_input["id"]] = self.pwd_db[vendor][1]
                else:
                    params[data_input["id"]] = self.pwd_db["default"][1]

        if method == "post":
            response = requests.post("http://%s:%d/%s" % (ip, port, url), data=params, cookies={"client_login": login, "client_password": pwd})
            if "deviceinfo" in response.text:
                return login, pwd

        elif method == "get":
            pass


if __name__ == "__main__":
    http = HttpAuth()
    ip_port = sys.argv[1].replace("http://", "")
    if ":" in ip_port:
        ip, port = ip_port.split(":")
        port = int(port.replace("/", ""))
    else:
        ip = ip_port
        port = 80
    http.check_default_passwords(ip, port, "", "")
