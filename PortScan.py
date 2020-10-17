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

def oneUDPScan(host,port):
    ip=(IP(dst=host))
    port = int(port)
    UDP_PCKT=sr1(ip/UDP(sport=53, dport=port),timeout=1,verbose=0)
    if (UDP_PCKT == None):
        return True
    else:
        if(UDP_PCKT[ICMP]):
            return False
        elif(UDP_PCKT[UDP]):
            return True
        else:
            return False
    return False

def printResult(resultPorts):
    print ('\n========Scan Results========\n')
    print ('Open ports:')
    for x in resultPorts:
        print (x)
    print('=============================')

def scanPortRange(lowerBound,upperBound,tcpudp,prot,host):
    for port in range(lowerBound,upperBound+1):
        if (tcpudp):
            if (oneTCPScan(host,port) == True):
                ports_result.append(str(port) + ' (TCP)')
            if (oneUDPScan(host,port) == True):
                ports_result.append(str(port) + ' (UDP)')
        elif (prot == 'TCP'):
            if (oneTCPScan(host,port) == True):
                ports_result.append(str(port) + ' (TCP)')
        elif (protocol == 'UDP'):
            if (oneUDPScan(host,port) == True):
                ports_result.append(str(port) + ' (UDP)')
    printResult(ports_result)

def scanPortArray(portArray,tcpudp,prot,host):
    for port in port_array:
        if (port == ''):
            continue
        else:
            if (tcpudp):
                if (oneTCPScan(host,port) == True):
                    ports_result.append(str(port) + ' (TCP)')
                if (oneUDPScan(host,port) == True):
                    ports_result.append(str(port) + ' (UDP)')
            elif (prot == 'TCP'):
                if (oneTCPScan(host,port) == True):
                    ports_result.append(str(port) + ' (TCP)')
            elif (prot == 'UDP'):
                if (oneUDPScan(host,port) == True):
                    ports_result.append(str(port) + ' (UDP)')
    printResult(ports_result)

print('Extracting input...\n')
theParser = argparse.ArgumentParser()
theParser.add_argument("host",help="IP address of target machine.")
theParser.add_argument("--ports",help="A list of ports separated by commas, or a range, i.e., 9,53,80 OR 9-99")
theParser.add_argument("--protocol",help="TCP, UDP, or ICMP (TCP being the default).")
theParser.add_argument("--UT",help="Designate if you want to scan for UDP and TCP--and also if you love Utah",action="store_true")
theParser.add_argument("--max",help="Designate if you want to scan all ports through 1-65535 (1-1024 is default)",action="store_true")

args = theParser.parse_args()

if args.max:
    if args.ports:
        print('\nNo need to designate ports if the \'max\' flag is set. Exiting script.')
        exit()

host = args.host

protocol = 'TCP'

if args.protocol:
    if (args.UT == True):
        print('\nNo need to designate protocol if you use the \'UT\' flag. Exiting script because you are silly.')
        exit()
    if (args.protocol.lower() =='tcp' or args.protocol.lower() =='udp' or args.protocol.lower() == 'icmp'):
        protocol = args.protocol.upper()
    else:
        print('Protocol entered is not supported. Try: TCP, UDP, or ICMP')
        exit()

ports_given = False
if args.ports:
    ports_given = True
both_tcp_udp = False
if (args.UT == True):
    both_tcp_udp = True

ports_result = []

#Port list not provided
if (not ports_given):
    upperBound = 1024
    if args.max:
        upperBound = 65535
        print('No ports given, ports 1-65535 will be probed.')
    else:
        print('No ports given, ports 1-1024 will be probed.')
    print('Scanning...')
    scanPortRange(1,upperBound,both_tcp_udp,protocol,host)
    exit()

#Port list is provided
else:
    #Is your 'ports' argument a range (i.e., two integers separated by a dash)?
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
        scanPortRange(lowerBound,upperBound,both_tcp_udp,protocol,host)
        exit()

    #Is your port list a list of integers separated by commas?
    x = re.search("^(\d|,)+$",args.ports)
    if (not x):
        print("Your list of ports does not match the correct syntax (integers separated by commas, e.g., 8,99,100).")
        print("Alternatively, you can use a range, e.g., 9-99")
        exit()
    #Does your comma-separated list contain double commas?
    x = re.search("^.*,,.*$",args.ports)
    if (x):
        print("Your list of ports is not in the correct format (integers separated by commas, e.g., 8,99,100).")
        print("Alternatively, you can use a range, e.g., 9-99")
        exit()
    #Split port list into each individual port
    port_array = args.ports.split(",")
    #Check that every port falls between 1 and 65535
    for port in port_array:
        if (port == ''):
            continue
        if (int(port) < 1 or int(port) > 65535):
            print("Your list of ports must fall in the range of 1 to 65535.")
            exit()
    print('Scanning...\n')
    scanPortArray(port_array,both_tcp_udp,protocol,host)
    exit()
