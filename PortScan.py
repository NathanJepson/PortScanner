#!/usr/bin/python3

import argparse
import re
from scapy.all import *

print('\n================================================================')
print('========Starting JEPSON\'S Remarkable PORT SCANNER (2020)========')
print('================================================================\n')

#This function will scan just one TCP port of a given machine
def oneTCPScan(host,port,givenTimeout):
    ip=(IP(dst=host))
    port = int(port)
    SYN=sr1(ip/TCP(dport=port,flags="S")/"JUNK_INPUT_MY_DUDES",timeout=givenTimeout,verbose=0)
    if(not SYN):
        return False
    else:
        #If the machine sends a SYN/ACK packet, that means the port is open
        if(SYN[TCP].flags == 'SA'):
            RST=ip/TCP(dport=port,flags="RA")
            send(RST,verbose=0)
            return True
    return False

#This fucntion will scan just one UDP port of a given machine
def oneUDPScan(host,port,givenTimeout):
    ip=(IP(dst=host))
    port = int(port)
    UDP_PCKT=sr1(ip/UDP(sport=53, dport=port),timeout=givenTimeout,verbose=0)
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

#Once all the scanning has completed, this function will print out the results
def printResult(resultArray):
    print ('\n========Scan Results========\n')
    for x in resultArray:
        print (x)
    print ('=============================')

#This function will scan all ports of a given range (from lower to upper bounds), based on the protocols designated by the user
def scanPortRange(lowerBound,upperBound,tcpudp,prot,host,result,timeout):
    for port in range(lowerBound,upperBound+1):
        if (tcpudp):
            if (oneTCPScan(host,port,timeout) == True):
                result.append(str(port) + ' (TCP)')
            if (oneUDPScan(host,port,timeout) == True):
                result.append(str(port) + ' (UDP)')
        elif (prot == 'TCP'):
            if (oneTCPScan(host,port,timeout) == True):
                result.append(str(port) + ' (TCP)')
        elif (protocol == 'UDP'):
            if (oneUDPScan(host,port,timeout) == True):
                result.append(str(port) + ' (UDP)')
    return result

#This functions will scan all of the ports in a user's comma-separated-list, based on protocols designated by the user
def scanPortArray(portArray,tcpudp,prot,host,result,timeout):
    for port in port_array:
        #This line below handles an edge case where the first and last elements of an array could contain an empty string
        if (port == ''):
            continue
        else:
            if (tcpudp):
                if (oneTCPScan(host,port,timeout) == True):
                    result.append(str(port) + ' (TCP)')
                if (oneUDPScan(host,port,timeout) == True):
                    result.append(str(port) + ' (UDP)')
            elif (prot == 'TCP'):
                if (oneTCPScan(host,port,timeout) == True):
                    result.append(str(port) + ' (TCP)')
            elif (prot == 'UDP'):
                if (oneUDPScan(host,port,timeout) == True):
                    result.append(str(port) + ' (UDP)')
    return result

#When the --file flag is set, this function will grab all of the hosts from the file that the user designates
def getHosts(fileName):
    result = []
    #The lines below will parse the file line by line
    with open(fileName) as f:
        line = f.readline()
        result.append(str(line.strip())) #.strip() is used to take out newline characters
        while line:
            line = f.readline()
            if (line != ''):
                result.append(str(line.strip()))
    ####Uncomment this line below to print out what IP addresses were read into the scanner from the file
    #print (result)
    return result

print('Extracting input...\n')

#Declare the parser that will be used to handle command-line arguments
theParser = argparse.ArgumentParser()

#The lines below will declare parameters. 'host' is required, while all other arguments are optional
theParser.add_argument("host",help="IP address of target machine. (Or file name when --file is set.)")
theParser.add_argument("--ports",help="A list of ports separated by commas, or a range, i.e., 9,53,80 OR 9-99")
theParser.add_argument("--protocol",help="TCP, UDP, or ICMP (TCP being the default).")
theParser.add_argument("--UT",help="Designate if you want to scan for UDP and TCP--and also if you love Utah",action="store_true")
theParser.add_argument("--max",help="Designate if you want to scan all ports through 1-65535 (1-1024 is default)",action="store_true")
theParser.add_argument("--timeout",help="Set how long you want to wait for packet responses (1 being the default)")
theParser.add_argument("--file",help="When set, the 'host' is actually the name of a file that contains IP addresses on each line.",action="store_true")

#This puts all the arguments in an easily accessible variable
args = theParser.parse_args()

#the 'max' flag will allow ports 1-65535 to be scanned
if args.max:
    if args.ports:
        print('\nNo need to designate ports if the \'max\' flag is set. Exiting script.')
        exit()

#the 'host' variable is set to either the IP address (host) or file name designated by the user
host = args.host

#########Change the line below to set the default protocol##################
protocol = 'TCP' #####DEFAULT

#The below if statement handles the grabbing of protocols designated by the user (but will quit if both the --protocol and --UT flags are set)
if args.protocol:
    if (args.UT == True):
        print('\nNo need to designate protocol if you use the \'UT\' flag. Exiting script because you are silly.')
        exit()
    if (args.protocol.lower() =='tcp' or args.protocol.lower() =='udp' or args.protocol.lower() == 'icmp'):
        protocol = args.protocol.upper()
    else:
        print('Protocol entered is not supported. Try: TCP, UDP, or ICMP')
        exit()

#Use boolean variables to grab whether the --protocol or --UT flags are set; this will make it easier to designate what things to scan later
ports_given = False
if args.ports:
    ports_given = True
both_tcp_udp = False
if (args.UT == True):
    both_tcp_udp = True

#This variable holds the result of the scan, to be printed later
scan_result = []

#This variable holds the hosts to be scanned (IP addresses)
hosts = []

#This handles whether the --file flag is set. If not, then hosts needs just the one host appened to it. Otherwise, grab all hosts from the file designated by the user
if args.file:
    hosts = getHosts(args.host)
else:
    hosts.append(host)

###Change line below to set default timeout value
timeout = 1 #####DEFAULT
if args.timeout:
    timeout = int(args.timeout)
    if (timeout < 1):
        print('Timeout cannot be less than 1 second.')
        exit()

#Case when ports are not provided by user
if (not ports_given):
    #Change the line below to set the default upper bounded port
    upperBound = 1024 ##DEFAULT
    if args.max:
        upperBound = 65535
        print('No ports given, ports 1-65535 will be probed.')
    else:
        print('No ports given, ports 1-1024 will be probed.')
    print('Scanning...')
    #For every host designated by the user, scan every port on them from the lower bound to the upper bound
    for host in hosts:
        scan_result.append("Open ports on " + str(host) + ":")
        scan_result = scanPortRange(1,upperBound,both_tcp_udp,protocol,host,scan_result,timeout)
        scan_result.append('\n')
    printResult(scan_result)
    exit()

#Case when a single port or multiple ports are provided
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
        #for every host designated by the user, scan all ports from the lower bound to the upper bound
        for host in hosts:
            scan_result.append("Open ports on " + str(host) + ":")
            scan_result = scanPortRange(lowerBound,upperBound,both_tcp_udp,protocol,host,scan_result,timeout)
            scan_result.append('\n')
        printResult(scan_result)
        exit()

    #Is your port list a list of integers separated by commas?
    x = re.search("^(\d|,)+$",args.ports)
    if (not x):
        print("Your list of ports does not match the correct syntax (integers separated by commas, e.g., 8,99,100).")
        print("Alternatively, you can use a range, e.g., 9-99")
        exit()
    #Does your comma-separated list contain double commas? One form of input validation.
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
    #For every host designated by the user, scan every port designated by the user's comma-separated list
    for host in hosts:
        scan_result.append("Open ports on " + str(host) + ":")
        scan_result = scanPortArray(port_array,both_tcp_udp,protocol,host,scan_result,timeout)
        scan_result.append('\n')
    printResult(scan_result)
    exit()
