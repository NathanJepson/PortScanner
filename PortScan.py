#!/usr/bin/python3

import argparse
import re
from scapy.all import *

print('\n================================================================')
print('========Starting JEPSON\'S Remarkable PORT SCANNER (2020)========')
print('================================================================\n')

def oneTCPScan(host,port):
    ip=(IP(dst=host))
    port = int(port)
    SYN=sr1(ip/TCP(dport=port,flags="S")/"JUNK_INPUT_MY_DUDES",timeout=1,verbose=0)
    if(not SYN):
        return False
    else:
        #If the machine sends a SYN/ACK packet, that means the port is open
        if(SYN[TCP].flags == 'SA'):
            RST=ip/TCP(dport=port,flags="RA")
            send(RST,verbose=0)
            return True
    return False

def printResult(resultPorts):
    print ('========Scan Results========\n')
    print ('Open ports:')
    for x in resultPorts:
        print (x)
    print('=============================')

print('Extracting input.')
theParser = argparse.ArgumentParser()
theParser.add_argument("host",help="IP address of target machine.")
theParser.add_argument("--ports",help="A list of ports separated by commas, or a range, i.e., 9,53,80 OR 9-99")
theParser.add_argument("--protocol",help="TCP, UDP, or ICMP (TCP being the default)")
args = theParser.parse_args()

host = args.host

protocol = 'TCP'
if args.protocol:
    if (args.protocol.lower() =='tcp' or args.protocol.lower() =='udp' or args.protocol.lower() == 'icmp'):
        protocol = args.protocol.upper()
    else:
        print('Protocol entered is not supported. Try: TCP, UDP, or ICMP')
        exit()

ports_given = False
if args.ports:
    ports_given = True

ports_result = []

#Port list not provided
if (not ports_given):
    print('No ports given, ports 1-65535 will be probed.')
    print('Scanning...')
    for port in range(1024): #Fix me, use 65535
        if (protocol == 'TCP'):
            if (oneTCPScan(host,port) == True):
                ports_result.append(port)
    printResult(ports_result)
    exit()

#Port list is provided
else:
    #Is your 'ports' argument a range?
    x = re.search("^(\d)+-(\d)+$",args.ports)
    if (x):
        ports = port_range = args.ports.split("-")
        upperBound = int(port_range[1])
        lowerBound = int(port_range[0])
        if (lowerBound  > upperBound):
            print('The second element of your range should be greater than the first.')
            exit()
        if (upperBound > 65535 or lowerBound < 1):
            print('Port range can only be between 1 and 65535')
            exit()
        print('Scanning...')
        for port in range (lowerBound,upperBound+1):
            if (protocol == 'TCP'):
                if (oneTCPScan(host,port) == True):
                        ports_result.append(port)
    printResult(ports_result)
    exit()

    #Is your port list a list of integers separated by commas?
    x = re.search("^(\d|,)+$",args.ports)
    if (not x):
        print("Your list of ports does not match the correct syntax (integers separated by commas, e.g., 8,99,100).")
        print("Alternatively, you can use a range, e.g., 9-99")
        exit()
    #Does your port list contain double commas?
    x = re.search("^.*,,.*$",args.ports)
    if (x):
        print("Your list of ports is not in the correct format (integers separated by commas, e.g., 8,99.100).")
        print("Alternatively, you can use a range, e.g., 9-99")
        exit()
    #Split port list into each individual port
    port_array = args.ports.split(",")
    print('Scanning...\n')
    for port in port_array:
        if (port == ''):
            continue
        else:
            if (protocol == 'TCP'):
                if (oneTCPScan(host,port) == True):
                    ports_result.append(port)
            elif (protocol == 'UDP'):
                print('not handled')
            elif (protocol == 'ICMP'):
                print('not handled too')
printResult(ports_result)
