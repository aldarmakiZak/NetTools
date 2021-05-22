# display pcap
# prtocol filters tcp, udp, icmp https, http, ftp 
# source and distination filters
# file size
# visual stats for data 
from scapy import data
from scapy.all import *
import pandas
import seaborn
import matplotlib.pyplot as plt

#print(f"imported {IP().fields_desc} packets")

# packet feilds name layer by layer
def create_dataframe(pcap):
    ether_layer = ['dst_mac', 'src_mac', 'type']
    ip_layer = ['version', 'ihl', 'tos', 'len', 'id', 'ip_flags', 'frag', 'ttl', 'proto', 'ip_chksum', 'src', 'dst', 'ip_options']
    layer_3 = ['sport', 'dport', 'seq', 'ack', 'dataofs', 'reserved', 'flags', 'window', 'chksum', 'urgptr', 'options']
    #udp_layer = ['sport', 'dport', 'len', 'chksum']


    columns_names = ["timestamp"] + ether_layer + ip_layer + layer_3 + ["payload_len","payload"]

    dataframe = pandas.DataFrame(columns=columns_names)

    #ip_feilds = []


    # loop through each packet in the pcap
    for packet in pcap:
        
        raw = []
        raw.append(packet.time)
        
        # add the ethernet layer data to the raw
        for i in ether_layer:
            try:
                if i == "dst_mac":
                    raw.append(packet[Ether].fields["dst"])
                
                elif i == "src_mac":
                    raw.append(packet[Ether].fields["src"])
                else:
                    raw.append(packet[Ether].fields[i])
            
            except:
                # append none if the valuse is not in the packet
                raw.append(None)
        # add the ip layer data to the raw
        
        for i in ip_layer:
            try:
                if i == "ip_flags":
                    raw.append(packet[IP].fields["flags"])
            
                elif i == "ip_chksum":
                    raw.append(packet[IP].fields["chksum"])
            
                elif i == "ip_options":
                    raw.append(len(packet[IP].fields["options"]))
                else:
                    raw.append(packet[IP].fields[i])
            
            except:
                raw.append(None)

        #check layer 3 type (tcp or udp)
        payload_type = type(packet[IP].payload)
        
        # add tcp or udp layer data to the frame
        for i in layer_3:
            try:
                if i == "options":
                    raw.append(len(packet[payload_type].fields["options"]))
                
                else: 
                    raw.append(packet[payload_type].fields[i])
            
            except:
                raw.append(None)

        # add the packet payload to the raw
        raw.append(len(packet[payload_type].payload))
        raw.append(packet[payload_type].payload.original)

        #add the data to the datafrme
        dataframe_add = pandas.DataFrame([raw],columns=columns_names)
        dataframe = pandas.concat([dataframe, dataframe_add],axis=0)

    dataframe = dataframe.reset_index()
    dataframe = dataframe.drop(columns="index")
    return dataframe




#pcap = rdpcap("test.pcap")
#df = create_dataframe(pcap)
#print(df['src'].unique())
#seaborn.set()
#s = df.groupby("src")["payload_len"].sum()
#s.plot(kind='barh',title='Address',figsize=(8,5))
#plt.show()
# print(df.head())
if __name__=="__main__":
        pcap = rdpcap("test.pcap")
        df = create_dataframe(pcap)
    #while True:
        try:
            print("\t**********************************************")
            print("\t********** Network Packet Analyser ***********")
            print("\t**********************************************")
            print("Options: ")
            print("\t 1- Display all packets\n\t 2- Display packets with src ip \n\t 3- Display packets with dst ip \n\t 4- Statistics")
            option = int(input("option: "))
            
            if option == 1:
                print(df[['timestamp','src_mac','dst_mac','len','ttl','src','sport','dst','dport','flags']])
            
            elif option == 2:
               
                srcdata = df.get(df['src'] =='10.0.2.15')
                print(srcdata[['timestamp','src_mac','dst_mac']])
            
            elif option == 4:
                print("\t\t4.1- Display top 5 source ip addresses\n\t\t4.2- Display top 5 distinations\n\t\t4.3- Payload-Time graph \n\t\t4.4 Addresses-Payload graph\n\t\t4.5 Ports-Payload graph")


        except KeyboardInterrupt:
            print("[+]Exiting")
            exit(1)