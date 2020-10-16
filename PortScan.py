#!/usr/bin/python3

import argparse
from scapy.all import *

ports_given = False

def oneScan(host,port):
    print('no dice')

theParser = argparse.ArgumentParser()
theParser.add_argument("host",help="IP address of target machine.")
theParser.add_argument("--ports",help="A list of ports separated by commas, i.e., 9,53,80")
args = theParser.parse_args()
print(args)

if args.ports:
    ports_given = true

if (not ports_given):
    print('No ports given, ports 1-65535 will be probed.')


p=sr1(IP(dst="192.168.207.42")/TCP()/"XXXXXX")
p.show()
