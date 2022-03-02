# Network Security tools #

## Overview
    
    This toolkit is designed to provide help to network admins and learners with testing the security of their networks. It provides a four separate but connected tools that serve the goal of adding more security to the network by analysing, attack simulation and network capturing. 
    
    By using these tools, the user can understand the network traffic flow and what sort of data is transferred between the network devices and detect strange activities. These tools are:  

## 1- Honeypot (Python)

    Simulates **SSH** and **FTP** servers on a machine and trick malicious users to believe that they are real servers and try to connect to them. This will provide information about where the attackers come from and what activities they do on the servers.

## 2- Denial of Service attacker (C)

    Gives the ability to flood the services with traffic to consume all the available resources and block the service that the machine provides. 
    By using this tool, a user can test network services behaviour and responses to DOS attacks and also find the best way to mitigate these types of attacks


## 3- Packet sniffer ( Python)

    Network packets capture to understand the network traffic going through the machine and also can be used to capture the LAN network traffic.

    The tool also support the use of many filters options to make the process more precise and effective. Additionally, users can add their customised filters using the Berkeley Packet Filter (**BPF**) syntax  


## 4- Packer analyzer (Python)

    This tool is designed to complement the packet sniffer as it allows the users to analyse and view the packet capture(pcap) files. This tool provides statistics of a given pcap file and present the data in a visual graph that makes analysing large number of packets easier
