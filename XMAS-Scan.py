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

for port in scanning_ports:
    # wait
    # time.sleep(random.randint(0,5))

    # Send Packet
    tcp_connect_scan_response = sr1(IP(src = srcIP, dst = destIP)/TCP(sport = RandShort(), dport = port, flags="FPU"), timeout = 10, verbose=False)

    # print response
    if (str(type(tcp_connect_scan_response)) == "<type 'NoneType'>"):
        print port, "\t Open|Filtered"

    elif tcp_connect_scan_response.haslayer(TCP):
        if tcp_connect_scan_response.getlayer(TCP).flags == 0x14:
            print port,  "\t Closed"
    elif tcp_connect_scan_response.haslayer(ICMP):
        if(int(tcp_connect_scan_response.getlayer(ICMP).type)==3 and int(tcp_connect_scan_response.getlayer(ICMP).code) in [1,2,3,9,10,13]):
            print "Destination returned ICMP packets"
            print port, "\t Filtered"
