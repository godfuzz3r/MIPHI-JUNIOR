#!/usr/bin/env python3
# -*- coding: UTF=8 -*-


class MacParser:
    MANUF_URL = "https://code.wireshark.org/review/gitweb?p=wireshark.git;a=blob_plain;f=manuf;hb=HEAD"
    DB_PATH = "data/Wireshark_manufacturer_database.txt"

    def __init__(self):
        pass

    def update(self):
        import requests
        print("[*] Updateing Wireshark manufacturer database...")
        data = requests.get(self.MANUF_URL).text
        with open(self.DB_PATH, "w") as file:
            file.write(data)
            file.close()
        print("[+] Done")

    def search(self, mac):
        mac_vendor = mac[:8].upper()

        for line in open(self.DB_PATH):
            if line[0] == "#" or line == "\n":
                continue

            db_data = line.split("\t")

            db_mac = db_data[0]
            db_vendor = db_data[1].strip("\n")

            if len(db_data) == 3:
                if "#" in db_data[2]:
                    db_OUI = db_data[2].split("#")[0]
                else:
                    db_OUI = db_data[2].strip("\n")
            else:
                db_OUI = False

            if mac_vendor == db_mac:
                if db_OUI:
                    return db_OUI
                else:
                    return db_vendor

if __name__ == "__main__":
    parser = MacParser()
    vendor = parser.search("a8:f9:4b:28:57:a1")
    print(vendor)
