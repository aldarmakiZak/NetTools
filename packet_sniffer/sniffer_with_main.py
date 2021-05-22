###############################################################
#
#
#
#
#
#
################################################################
from scapy.all import *
import socket
import argparse
from os import path


filter = [] # List to prepare capturing filter
protocols_dict = {"tcp":"tcp", "udp":"udp", "icmp":"icmp", "http":"tcp port 80", "https":"tcp port 443", "dns":"udp port 53", "ftp":"tcp port 21"} # Dictionary to translate the protocols to be filtered


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


# Main function in the program
def main(interface,count,output,protocol,src, dst, filter_file):
    global filter
    # Extract the filter from a file
    f_file = filter_file
    if f_file != None and path.exists(f_file):
        with open(f_file,"r") as file:
            filter = file.readline()

    # Extract filter from command line
    else:
        # Take source and destination IP list from the user and format it as BPF filter
        filter_prepare(src,"src")
        filter_prepare(dst,"dst")

        # Take protocol filter from user args
        proto = protocol

        if proto != None and proto.lower() in protocols_dict:
            filter.append(protocols_dict[proto.lower()])


    # final join of the filters list
    if not filter:
        filter = None
    else: 
        filter = " and ".join(filter)
        print(filter)

    # Starting the sniffer
    print("[] Starting packet capture...\n ")
    try:
        sniffer = sniff(iface=interface, count=count, filter=filter, prn= lambda x: x.summary())
        wrpcap(output, sniffer, append=True)

    except Exception as ex:
        print("[] Failed to start sniffer")
        print(ex)


if __name__=="__main__":
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Packet Sniffing tool. Ensure to run it with $sudo ")
    parser.add_argument("--interface", action="store",default=None, type=str, help="Network interface to listen on.")
    parser.add_argument("--count", action="store",default=0, type=int, help="Number of captured packets")
    parser.add_argument("--output", action="store", type=str,default="sniffed.pcap", help="File name to output the captured packets.")
    parser.add_argument("--protocol", action="store", type=str, help="Specify a protocol to listen for.(Support (TCP, UDP, ICMP, HTTP/S, DNS, FTP) )")
    parser.add_argument("--src", action="append", help="Packet source IP.")
    parser.add_argument("--dst", action="append", help="Packet destination IP.")
    parser.add_argument("--filter_file", action="store", type=str, help="File name to get filter from.")

    args = parser.parse_args()
    # Starting main
    main(**vars(args))
