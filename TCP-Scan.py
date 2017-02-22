import logging
logging.getLogger("scapy").setLevel(1)

import sys
import random
import time
from scapy.all import *

random.seed()

# get args from user
if len(sys.argv) < 3:
    print "ERROR: Invalid number of arguements"
    sys.exit()

if len(sys.argv) == 3:
    srcIP = sys.argv[1]
    destIP = sys.argv[2]

# Loop through well known ports
ports_to_scan = [20,21,22,23,25,80]
scanning_ports = []

for _ in range(len(ports_to_scan)):
    index = random.randint(0,len(ports_to_scan)-1)
    scanning_ports.append(ports_to_scan[index])
    ports_to_scan.remove(ports_to_scan[index])

print "PORT \t STATE"

src_port = RandShort()

for port in scanning_ports:
    # wait
    time.sleep(random.randint(0,15))

    # Send Packet
    tcp_connect_scan_response = sr1(IP(src = srcIP, dst = destIP)/TCP(sport = src_port, dport = port), timeout = 10, verbose = False)

    # print response
    if (str(type(tcp_connect_scan_response)) == "<type 'NoneType'>"):
        print port, "\t Closed"

    if tcp_connect_scan_response.getlayer(TCP).flags == 0x14:
        print port, "\t Closed"

    elif tcp_connect_scan_response.getlayer(TCP).flags == 0x12:
        # Send response
        send(IP(dst=destIP)/TCP(sport=src_port,dport=port,flags="AR"), verbose = False)
        print port, "\t Open"
