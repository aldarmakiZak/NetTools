# Packet Analyser

## Features:
- Displaying the packets capture as a table where the most important information is shown on the screen
- Display specific IP address packets

- Shows overall statists of the pcap file such as: file size, number of packets, most visited IP address, most visited port

- Visual representations of some of the pcap statistics such as: Payload over time graph, number of packets for each IP address and data entered each port
  
## Installation
1- Install the third party libraries (scapy, pandas, matplotlib) using the commands:
        ```pip3 install scapy```
        ```pip3 install pandas```
    ``` pip3 install matplotlib```

2- The code will require a pcap file generated either using the packet sniffer tool or any other capturing tool or you can use the test.pcap file in the Packet_Analyser directory.

## Runnig Instruction

1- Run the pcap_analyser.py file and specify the pcap file name
        ```python3 packet_analyser.py --file {pacp file}```

2- Then, the program will show an interactive command line interface where the user can choose  between the options