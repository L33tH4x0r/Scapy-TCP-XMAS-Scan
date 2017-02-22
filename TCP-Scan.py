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

print "\n"
for port in scanning_ports:
    # Send Packet
    print "Sending packet to ", destIP, " at port ", port, "\n"
    tcp_connect_scan_response = sr1(IP(src = srcIP, dst = destIP)/TCP(sport = RandShort(), dport = port), timeout = 10)

    # print response
    if (str(type(tcp_connect_scan_response)) == "<type 'NoneType'>"):
        print "Packet unreadable"
        print "Port ", port, " is closed", "\n"

    if tcp_connect_scan_response.getlayer(TCP).flags == 0x14:
        print "Destination returned Rest Ack"
        print "Port ", port, " is closed", "\n"

    elif tcp_connect_scan_response.getlayer(TCP).flags == 0x12:
        print "Destination returned Syn Ack"
        print "Port ", port, " is open", "\n"

    time.sleep(random.randint(0,15))
