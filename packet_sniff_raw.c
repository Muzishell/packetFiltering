#include<malloc.h>
#include<string.h>
#include<signal.h>
#include<stdbool.h>
#include<sys/socket.h>
#include<sys/types.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include<linux/if_packet.h>
#include<netinet/in.h>
#include<netinet/if_ether.h>    // header ethernet
#include<netinet/ip.h>		// header ip
#include<netinet/udp.h>		// header udp
#include<netinet/tcp.h>
#include<arpa/inet.h>           // Empeche un warning sur inet_ntoa

#include "arg.h"

FILE* log_txt;
int total,tcp,udp,icmp,igmp,other,iphdrlen;

struct sockaddr saddr;
struct sockaddr_in source,dest;

void write_ethernet_header(struct ethhdr* eth) {
	fprintf(log_txt,"\nEthernet Header\n");
	fprintf(log_txt,"\t|-Source Address	: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",eth->h_source[0],eth->h_source[1],eth->h_source[2],eth->h_source[3],eth->h_source[4],eth->h_source[5]);
	fprintf(log_txt,"\t|-Destination Address	: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",eth->h_dest[0],eth->h_dest[1],eth->h_dest[2],eth->h_dest[3],eth->h_dest[4],eth->h_dest[5]);
	fprintf(log_txt,"\t|-Protocol		: %d\n",eth->h_proto);
}

void write_ip_header(struct iphdr* ip) {
	fprintf(log_txt , "\nIP Header\n");

	fprintf(log_txt , "\t|-Version              : %d\n",(unsigned int)ip->version);
	fprintf(log_txt , "\t|-Internet Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)ip->ihl,((unsigned int)(ip->ihl))*4);
	fprintf(log_txt , "\t|-Type Of Service   : %d\n",(unsigned int)ip->tos);
	fprintf(log_txt , "\t|-Total Length      : %d  Bytes\n",ntohs(ip->tot_len));
	fprintf(log_txt , "\t|-Identification    : %d\n",ntohs(ip->id));
	fprintf(log_txt , "\t|-Time To Live	    : %d\n",(unsigned int)ip->ttl);
	fprintf(log_txt , "\t|-Protocol 	    : %d\n",(unsigned int)ip->protocol);
	fprintf(log_txt , "\t|-Header Checksum   : %d\n",ntohs(ip->check));
	fprintf(log_txt , "\t|-Source IP         : %s\n", inet_ntoa(source.sin_addr));
	fprintf(log_txt , "\t|-Destination IP    : %s\n",inet_ntoa(dest.sin_addr));

	printf("\t|-Source IP         : %s\n", inet_ntoa(source.sin_addr));
	printf("\t|-Destination IP    : %s\n",inet_ntoa(dest.sin_addr));
}

struct iphdr* get_ip_header(unsigned char* buffer,int buflen)
{
	struct iphdr *ip = (struct iphdr*)(buffer + sizeof(struct ethhdr));

	iphdrlen =ip->ihl*4;

	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = ip->saddr;
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = ip->daddr;
	return (ip);
}

void payload(unsigned char* buffer,int buflen)
{
	int i=0;
	unsigned char * data = (buffer + iphdrlen  + sizeof(struct ethhdr) + sizeof(struct udphdr));
	fprintf(log_txt,"\nData\n");
	int remaining_data = buflen - (iphdrlen  + sizeof(struct ethhdr) + sizeof(struct udphdr));
	for(i=0;i<remaining_data;i++)
	{
		if(i!=0 && i%16==0)
			fprintf(log_txt,"\n");
		fprintf(log_txt," %.2X ",data[i]);
	}

	fprintf(log_txt,"\n");



}

int tcp_header(unsigned char* buffer,int buflen, struct arg* arg)
{
	struct ethhdr *eth = (struct ethhdr *)(buffer);
	struct iphdr *ip = get_ip_header(buffer, buflen);
	struct tcphdr *tcp = (struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));

	if (arg && arg->sourceMac) {
		char* sourceMac = malloc(sizeof(char*));
		sprintf(sourceMac,"%.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",eth->h_source[0],eth->h_source[1],eth->h_source[2],eth->h_source[3],eth->h_source[4],eth->h_source[5]);
		if (strcmp(sourceMac, arg->sourceMac) != 0)
			printf("Ce n'est pas pareil");
			return -1;
	}

	if (arg && arg->destMac) {
		char* destMac = malloc(sizeof(char*));
		sprintf(destMac,"%.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",eth->h_dest[0],eth->h_dest[1],eth->h_dest[2],eth->h_dest[3],eth->h_dest[4],eth->h_dest[5]);
		if (strcmp(destMac, arg->destMac) != 0)
			return -1;
	}

	if (arg && arg->sourceIp) {
		if (strcmp(inet_ntoa(source.sin_addr), arg->sourceIp) != 0)
			return -1;
	}

	if (arg && arg->destIp) {
		if (strcmp(inet_ntoa(dest.sin_addr), arg->destIp) != 0)
			return -1;
	}

	if (arg->sourcePort) {
		if (ntohs(tcp->source) != arg->sourcePort) {
			return -1;
		}
	}

	if (arg->destPort) {
		if (ntohs(tcp->dest) != arg->destPort) {
			return -1;
		}
	}

	printf("\n\t|TCP Packet|\n");
	fprintf(log_txt,"\n*************************TCP Packet******************************");
   	write_ethernet_header(eth);
  	write_ip_header(ip);

   	fprintf(log_txt , "\nTCP Header\n");
   	fprintf(log_txt , "\t|-Source Port          : %u\n",ntohs(tcp->source));
   	fprintf(log_txt , "\t|-Destination Port     : %u\n",ntohs(tcp->dest));
   	fprintf(log_txt , "\t|-Sequence Number      : %u\n",ntohl(tcp->seq));
   	fprintf(log_txt , "\t|-Acknowledge Number   : %u\n",ntohl(tcp->ack_seq));
   	fprintf(log_txt , "\t|-Header Length        : %d DWORDS or %d BYTES\n" ,(unsigned int)tcp->doff,(unsigned int)tcp->doff*4);
	fprintf(log_txt , "\t|----------Flags-----------\n");
	fprintf(log_txt , "\t\t|-Urgent Flag          : %d\n",(unsigned int)tcp->urg);
	fprintf(log_txt , "\t\t|-Acknowledgement Flag : %d\n",(unsigned int)tcp->ack);
	fprintf(log_txt , "\t\t|-Push Flag            : %d\n",(unsigned int)tcp->psh);
	fprintf(log_txt , "\t\t|-Reset Flag           : %d\n",(unsigned int)tcp->rst);
	fprintf(log_txt , "\t\t|-Synchronise Flag     : %d\n",(unsigned int)tcp->syn);
	fprintf(log_txt , "\t\t|-Finish Flag          : %d\n",(unsigned int)tcp->fin);
	fprintf(log_txt , "\t|-Window size          : %d\n",ntohs(tcp->window));
	fprintf(log_txt , "\t|-Checksum             : %d\n",ntohs(tcp->check));
	fprintf(log_txt , "\t|-Urgent Pointer       : %d\n",tcp->urg_ptr);

	payload(buffer,buflen);

fprintf(log_txt,"*****************************************************************\n\n\n");
return 0;
}

int udp_header(unsigned char* buffer, int buflen, struct arg* arg)
{
		struct ethhdr *eth = (struct ethhdr *)(buffer);
		struct iphdr *ip = get_ip_header(buffer, buflen);
		struct udphdr *udp = (struct udphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));

		if (arg && arg->sourceMac) {
			char* sourceMac = malloc(sizeof(char*));
			sprintf(sourceMac,"%.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",eth->h_source[0],eth->h_source[1],eth->h_source[2],eth->h_source[3],eth->h_source[4],eth->h_source[5]);
			if (strcmp(sourceMac, arg->sourceMac) != 0)
				return -1;
		}

		if (arg && arg->destMac) {
			char* destMac = malloc(sizeof(char*));
			sprintf(destMac,"%.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",eth->h_dest[0],eth->h_dest[1],eth->h_dest[2],eth->h_dest[3],eth->h_dest[4],eth->h_dest[5]);
			if (strcmp(destMac, arg->destMac) != 0)
				return -1;
		}

		if (arg && arg->sourceIp) {
			if (strcmp(inet_ntoa(source.sin_addr), arg->sourceIp) != 0)
				return -1;
		}

		if (arg && arg->destIp) {
			if (strcmp(inet_ntoa(dest.sin_addr), arg->destIp) != 0)
				return -1;
		}

		if (arg->sourcePort) {
			if (ntohs(udp->source) != arg->sourcePort) {
				return -1;
			}
		}

		if (arg->destPort) {
			if (ntohs(udp->dest) != arg->destPort) {
				return -1;
			}
		}

	printf("\n\t|UDP packet|\n");
	fprintf(log_txt,"\n*************************UDP Packet******************************");
	write_ethernet_header(eth);
	write_ip_header(ip);

	fprintf(log_txt,"\nUDP Header\n");

	fprintf(log_txt , "\t|-Source Port    	: %d\n" , ntohs(udp->source));
	fprintf(log_txt , "\t|-Destination Port	: %d\n" , ntohs(udp->dest));
	fprintf(log_txt , "\t|-UDP Length      	: %d\n" , ntohs(udp->len));
	fprintf(log_txt , "\t|-UDP Checksum   	: %d\n" , ntohs(udp->check));

	payload(buffer,buflen);

	fprintf(log_txt,"*****************************************************************\n\n\n");
	return 0;
}

void data_process(unsigned char* buffer,int buflen, struct arg* arg)
{
	struct iphdr *ip = (struct iphdr*)(buffer + sizeof (struct ethhdr));
	++total;

	if (arg && arg->protocol != 0 && arg->protocol != ip->protocol)
		return;

	int returned = 0;
	switch (ip->protocol)    //voir /etc/protocols file
	{

		case 6:
			++tcp;
			returned = tcp_header(buffer,buflen,arg);
			break;

		case 17:
			++udp;
			returned = udp_header(buffer,buflen,arg);
			break;

		default:
			++other;

	}
	if (returned != -1) {
	printf("\n\t|-Stats: TCP: %d  UDP: %d  Other: %d  Total: %d  \n\n",tcp,udp,other,total);
	}
}

struct arg* get_arg(int argc, char **argv) {
	struct arg* arg = malloc(sizeof(struct arg*));

  int index;
  int c;

  opterr = 0;

  while ((c = getopt (argc, argv, "hp:m:n:s:d:t:r")) != -1)
    switch (c)
      {
      case 'p':
        arg->protocol = atoi(optarg);
        break;
      case 'm':
        arg->sourceMac = optarg;
        break;
      case 'n':
        arg->destMac = optarg;
        break;
      case 's':
        arg->sourceIp = optarg;
      case 'd':
        arg->destIp = optarg;
      case 't':
        arg->sourcePort = atoi(optarg);
      case 'r':
        arg->destPort = atoi(optarg);
			case 'h':
	       printf("Usage: ./packet_sniff -p [protocol number] -m [source mac addr] -n [dest mac addr] -s [source ip] -d [dest ip] -t [source port] -r [dest port]\n");
				 return NULL;
      case '?':
        if (optopt == 'c')
          fprintf (stderr, "Option -%c requires an argument.\n", optopt);
        else if (isprint (optopt))
          fprintf (stderr, "Unknown option `-%c'.\n", optopt);
        else
          fprintf (stderr,
                   "Unknown option character `\\x%x'.\n",
                   optopt);
        return NULL;
      default:
        abort ();
      }

  for (index = optind; index < argc; index++)
    printf ("Non-option argument %s\n", argv[index]);
  return arg;
}


int main(int argc, char *argv[])
{

	int sock_r,saddr_len,buflen;

	unsigned char* buffer = (unsigned char *)malloc(65536);
	memset(buffer,0,65536);

	struct arg* arg = get_arg(argc, argv);
	if (arg == NULL) {
		return -1;
	}

	log_txt=fopen("log.txt","w");
	if(!log_txt)
	{
		printf("unable to open log.txt\n");
		return -1;

	}

	printf("starting .... \n");

	sock_r=socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
	if(sock_r<0)
	{
		printf("error in socket\nYou need to run this programm with root");
		return -1;
	}

	while(1)
	{
		saddr_len=sizeof saddr;
		buflen=recvfrom(sock_r,buffer,65536,0,&saddr,(socklen_t *)&saddr_len);


		if(buflen<0)
		{
			printf("error in reading recvfrom function\n");
			return -1;
		}
		fflush(log_txt);
		data_process(buffer,buflen,arg);

	}

	close(sock_r);// Pour close le socket il faut utiliser signal
	printf("DONE!!!!\n");

}
