#!/usr/bin/env python3
import argparse

def check_root():
    if not os.geteuid() == 0:
        print("Run as root.")
        exit(1)

def main():
    check_root()

if __name__ == "__main__":
    main()
