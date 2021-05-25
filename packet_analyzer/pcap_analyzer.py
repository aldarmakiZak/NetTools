# Program to analyse pcap files
# Usage: 


from pandas.io.formats import style
from scapy.all import *
from datetime import datetime
from os import path
import pandas
import seaborn as sns
import matplotlib.pyplot as plt
import argparse


# set pandas display options
#pandas.set_option("display.max_columns",31)
#pandas.set_option("display.max_rows",100)

# set graph plotting options
#sns.set()
#sns.set_theme(style="ticks", color_codes=True)


# function to create data frames from the pcap file
def create_dataframe(pcap):

    # packet feilds name layer by layer
    ether_layer = ['dst_mac', 'src_mac', 'type']
    ip_layer = ['version', 'ihl', 'tos', 'len', 'id', 'ip_flags', 'frag', 'ttl', 'proto', 'ip_chksum', 'src', 'dst', 'ip_options']
    layer_3 = ['sport', 'dport', 'seq', 'ack', 'dataofs', 'reserved', 'flags', 'window', 'chksum', 'urgptr', 'options']
    #udp_layer = ['sport', 'dport', 'len', 'chksum']

    # build columns name list
    columns_names = ["timestamp"] + ether_layer + ip_layer + layer_3 + ["payload_len","payload"]

    # initialise a dataframe object
    dataframe = pandas.DataFrame(columns=columns_names)
    
    # list to store packet data
    data =[]


    # loop through each packet in the pcap
    for packet in pcap:
        
        row = []
        
        # formate the timestamp in the packet to YY-MM-DD hour:min:sec
        pkt_time = datetime.fromtimestamp(packet.time)
        row.append(pkt_time.strftime("%Y-%m-%d %H:%M:%S")) #packet.time # remove %S 
        
        # add the ethernet layer data to the row
        for i in ether_layer:
            try:
                if i == "dst_mac": # rename dist in the packet to dist_mac
                    row.append(packet[Ether].fields["dst"])
                
                elif i == "src_mac": # rename src in the packet to src_mac
                    row.append(packet[Ether].fields["src"])
                
                else:
                    row.append(packet[Ether].fields[i])
            
            except:
                # append none if the valuse is not in the packet
                row.append(None)
        
        # add the ip layer data to the row 
        for i in ip_layer:
            try:
                # renaming data frame columns to avoid similarity with tcp packet
                if i == "ip_flags":
                    row.append(packet[IP].fields["flags"])
            
                elif i == "ip_chksum":
                    row.append(packet[IP].fields["chksum"])
            
                elif i == "ip_options":
                    row.append(len(packet[IP].fields["options"])) # we are only interested in the length of the options section
                else:
                    row.append(packet[IP].fields[i])
            
            except:
                row.append(None)

        # check layer 3 type (tcp or udp)
        payload_type = type(packet[IP].payload)
        
        # add tcp or udp layer data to the frame.. we will use the same columns for both tcp and udp because tcp has more feilds than udp
        for i in layer_3:
            try:
                if i == "options":
                    row.append(len(packet[payload_type].fields["options"]))
                
                else: 
                    row.append(packet[payload_type].fields[i])
            
            except:
                row.append(None) # append none for the empty fields (for udp packets)

        # add the packet payload to the row
        row.append((len(packet[payload_type].payload)//1000)) # payload length (round to kilobytes)
        row.append(packet[payload_type].payload.original) # payload content

        dict_zip = zip(columns_names,row) # create a zipped list for rows and columns 
        dict_all = dict(dict_zip) # convert the list to dictionary
        data.append(dict_all) 

    dataframe = dataframe.append(data,True) # create the dataframe from the dictionaries list
    
    return dataframe


# print pcap file summary
def pcap_summary(df):
    size = path.getsize("test.pcap")
    
    print("\t\tPcap summary\n")
    print("--------------------------------------------------------------------------")
    print(f"- File size {size}")
    print("--------------------------------------------------------------------------")
    print(f"- Packet count: {str(len(df.index))}\n")
    print("--------------------------------------------------------------------------")
    print(f"- Source ip addresses list: {df['src'].unique()}\n ")
    print("--------------------------------------------------------------------------")
    print(f"- Destination ip addresses list: {df['dst'].unique()}\n")
    print("--------------------------------------------------------------------------")
    print(f"- Peak time: {df['timestamp'].describe()['top']}\n")  ##
    print("--------------------------------------------------------------------------") 
    print(f"-Most visited port number: {df['dport'].describe()['top']}\n")
    print("--------------------------------------------------------------------------")
    print(f"-Most used port number: {df['sport'].describe()['top']} \n")
    print("--------------------------------------------------------------------------")


if __name__=="__main__":
        
        # get file name from command line
        parser = argparse.ArgumentParser(description="Network traffic analyser ")
        parser.add_argument("--file", action="store",default=None, type=str, help="Pcap file to be analysed.")
        args = parser.parse_args()
        pcap_f = args.file
        
        # check that the user inputed valid file 
        if pcap_f != None and path.exists(pcap_f):
            pcap = rdpcap(pcap_f) # load
        
        else:
            print("Please provide a valid pcap file")
            exit(1)

        # create a pandas dataframe from the pcap file
        df = create_dataframe(pcap)
        
        print("\t**********************************************")
        print("\t********** Network Packet Analyser ***********")
        print("\t**********************************************\n")
    
    #program loop
        while True:
            try:
                
                # print the options the user can choose from
                print(f"Imported pcap file with: {str(len(df.index))} packets")
                print("Options: ")
                print("\t 1- Display all packets\n\t 2- Display packets from specific source ip \n\t 3- Display packets with specific destination ip \n\t 4- Statistics \n\t 5- Exit")
                option = int(input("Choose option: "))
                
                # important columns in the packet dataframe
                important_col = ['id','timestamp','src_mac','dst_mac','len','id','ttl','src','sport','dst','dport','flags','payload_len']
                
                # user options handling 
                if option == 1:
                    print(df[important_col])
                    time.sleep(0.5)
                
                elif option == 2:
                    # get the source ip address from the dataframe
                    available_src = df['src'].unique()
                    print("Source IP list:\n", available_src)

                    ip = input("\nChoose source ip address: ")
                    
                    if ip in available_src:
                        srcdata = df.get(df['src'] ==ip)
                        print(srcdata[important_col])
                        continue
                    else:
                        print("Invalid Ip address")
                        exit(1)
                
                elif option == 3:
                    available_src = df['dst'].unique()
                    print("Source IP list:\n", available_src)

                    ip = input("\nChoose destination ip address: ")
                    
                    if ip in available_src:
                        srcdata = df.get(df['dst'] ==ip)
                        print(srcdata[important_col])
                        continue                
                    else:
                        print("Invalid Ip address")
                        exit(1)

                elif option == 5:
                    print("[] Exiting")
                    exit(1)


                elif option == 4:
                    print("\t\t4.1 Show summary of the pcap\n\t\t4.2- Display top 5 source ip addresses\n\t\t4.3- Display top 5 distinations\n\t\t4.4- Payload-Time graph \n\t\t4.5 Source-Destination packets count graph\n\t\t4.6 source port-Payload graph\n\t\t4.7 destination port-Payload graph\n")
                    option1 = input("Choose option: ")
                    
                    if option1 == str("4.1"):
                        pcap_summary(df)

                    elif option1 == str("4.2"):
                        print("Top 5 source ip addresses are: ")
                        print(df.value_counts(['src']).head())

                    elif option1 == str("4.3"):
                        print("Top 5 destination ip addresses are: ")
                        print(df.value_counts(['dst']).head())

                    elif option1 == str("4.4"):
                        # group the data by the timestamp (each second) and sum the payload length 
                        s = df.groupby("timestamp")["payload_len"].sum()
                        # plot the gragh using matplotlib
                        s.plot(kind="line",title='Data exchanged over time')
                        plt.show()

                    elif option1 == str("4.5"):
                        s = df.groupby(["src","dst"])["payload"].size()
                        s.plot(kind = "barh")
                        plt.show()

                    elif option1 == str("4.6"):
                        s = df.groupby("sport")["payload_len"].sum()
                        s.plot(kind="bar",title=' Top source ports used')
                        plt.show()

                    elif option1 == str("4.7"):
                        s = df.groupby("dport")["payload_len"].sum()
                        s.plot(kind="bar",title=' Top destination ports visited')
                        plt.show()

                    else:
                        print("Invalid option")

            # exit if user press ctrl-c            
            except KeyboardInterrupt:
                
                print("[+]Exiting")
                exit(1)