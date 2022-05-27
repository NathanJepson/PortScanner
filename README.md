# PortScanner


Script name: PortScan.py

usage: PortScan.py [-h] [--ports PORTS] [--protocol PROTOCOL] [--UT] [--max] [--timeout TIMEOUT] [--file] host

^NOTICE!!!!!!!  "host" is either the host to be scanned (an IP Address), or the file name if the --file flag is set

Requirements
====================
python3, Scapy

Installation
====================
git clone https://github.com/TheSuddenFlame/PortScannerITC567

Running the Program (Usages)
====================
python3 PortScan.py [options] [host, i.e. 192.168.207.42]

python3 PortScan.py [options] --file [filename]



Notice on UDP Scanning
========================
The UDP scanner in this script is not application specific. In the case that UDP ports are blocked by firewalls, many false positives
could be returned. (UDP ports might be shown to be open that aren't actually open, in other words).



Usage Examples Below
=========================================================

Scanning a Single port:

    python3 PortScan.py --ports 80 192.168.207.42

Scanning Multiple ports (range):

    python3 PortScan.py --ports 1-124 192.168.207.42
    
Scanning Multiple ports (comma-separated list):

    python3 PortScan.py --ports 1,80,443,500 192.168.207.42
    
Choosing a protocol (UDP, TCP, or ICMP):

    python3 PortScan.py --ports 80 --protocol UDP 192.168.207.42
    
    python3 PortScan.py --protocol icmp
    
Scanning for both TCP and UDP

    python3 PortScan.py --UT 192.168.207.42
    
    python3 PortScan.py --ports 1,80,443,500 --UT 192.168.207.42

Scanning all ports from 1-1024:

    python3 PortScan.py 192.168.207.42

Scanning all ports from 1-65535:

    python3 PortScan.py --max 192.168.207.42
    
    python3 PortScan.py --max --file myFile.txt
    
Setting the timeout to 2 seconds (default is 1 second)--you can set it to any integer above 1:

    python3 PortScan.py --ports 1,80,443,500 --timeout 2 192.168.207.42 
    
Grabbing the hosts to scan from a text file with an IP address on each line:

    python3 PortScan.py --ports 1,80,443,500 --file myFile.txt
    
    

Examples with Output
=========================================================
 
Command: 
  
    sudo python3 PortScan.py --ports 7,8,9,123,135,137 --UT --file hosts.txt

Output:

             ================================================================
             ========Starting JEPSON'S Remarkable PORT SCANNER (2020)========
             ================================================================

             Extracting input...

             Scanning...


             ========Scan Results========

             Open ports on 192.168.207.42:
             7 (TCP)
             7 (UDP)
             9 (TCP)
             9 (UDP)
             123 (UDP)
             135 (TCP)
             137 (UDP)


             Open ports on 192.168.207.1:
             7 (UDP)
             8 (UDP)
             9 (UDP)
             123 (UDP)
             135 (TCP)
             135 (UDP)
             137 (UDP)
             =============================
 
 ___________________________________________________________________________________________________________________
 Command: 
     
     sudo python3 PortScan.py --timeout 3 --ports 1-20 --protocol UDP 192.168.207.42
 
 Output: 
 
             ================================================================
             ========Starting JEPSON'S Remarkable PORT SCANNER (2020)========
             ================================================================

             Extracting input...

             Scanning...

             ========Scan Results========

             Open ports on 192.168.207.42:
             7 (UDP)
             9 (UDP)
             13 (UDP)
             17 (UDP)
             19 (UDP)

             =============================

___________________________________________________________________________________________________________________
Command: 

    sudo python3 PortScan.py --protocol ICMP 192.168.207.42

Output:

              ================================================================
              ========Starting JEPSON'S Remarkable PORT SCANNER (2020)========
              ================================================================

              Extracting input...

              Scanning...

              ========Scan Results========

              Results for 192.168.207.42:
              ICMP:  Response type is 0 ...and elapsed time is 0.16832351684570312 ms

              =============================

    
