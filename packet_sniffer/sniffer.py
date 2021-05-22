from scapy.all import *
import socket
import argparse
from os import path


filter = [] # List to prepare capturing filter
protocols_dict = {"tcp":"tcp", "udp":"udp", "icmp":"icmp", "http":"tcp port 80", "https":"tcp port 443", "dns":"udp port 53", "ftp":"tcp port 21"} # Dictionary to translate the protocols to be filtered


'''def print_capture(packet):
    if IP in packet:
        source_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
    if TCP in packet:
        s_port = packet[TCP].sport
        d_port = packet[TCP].dport

        print("[] Received packet from " + str(source_ip) + " source port" + str(s_port))
'''

# Validate the ip address
def valid_ip(addr):
    try:
        socket.inet_aton(addr)
        return True
    except:
        return False 


# To parse src and dst address to create sniffing filter
def filter_prepare(list,type):
    global filter
    list_f = []
    if list != None:
        for i in list:
            if  valid_ip(i):
                list_f.append(f"{type} {i}")
            
            else:
                print("Invalid IP address format")
                exit(1)

        filter.append(" or ".join(list_f))




# Parse command line arguments
parser = argparse.ArgumentParser(description="Packet Sniffing tool. Ensure to run it with $sudo ")
parser.add_argument("--interface", action="store",default=None, type=str, help="Network interface to listen on.")
parser.add_argument("--count", action="store",default=0, type=int, help="Number of captured packets")
parser.add_argument("--output", action="store", type=str,default="sniffed.pcap", help="File name to output the captured packets.")
parser.add_argument("--protocol", action="store", type=str, help="Specify a protocol to listen for.")
parser.add_argument("--src", action="append", help="Packet source IP.")
parser.add_argument("--dst", action="append", help="Packet destination IP.")
parser.add_argument("--filter_file", action="store", type=str, help="File name to get filter from.")

args = parser.parse_args()
print(type(args))

# Extract the filter from a file 
f_file = args.filter_file
if f_file != None and path.exists(f_file):
    with open(f_file,"r") as file:
        filter = file.readline() 

# Extract filter from command line
else:   
    # Take source and destination IP list from the user and format it as BPF filter
    filter_prepare(args.src,"src")
    filter_prepare(args.dst,"dst")

    # Take protocol filter from user args
    proto = args.protocol 

    if proto != None and proto.lower() in protocols_dict:
        filter.append(protocols_dict[proto.lower()])


if not filter:
    filter = None
else: 
    filter = " and ".join(filter)
    print(filter)

# Starting the sniffer
print("[] Starting packet capture...\n ")
try:
    sniffer = sniff(iface=args.interface,count=args.count,filter=filter, prn= lambda x: x.summary())
    wrpcap(args.output,sniffer, append=True)

except Exception as ex:
    print("[] Failed to start sniffer")
    print(ex)