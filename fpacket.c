#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
struct packet {
  struct iphdr ip;
  struct udphdr udp;
  struct tcphdr tcp;
  char data[512];
};

#define DESTADDR "192.168.1.1"
#define SRCADDR "192.168.11.1"
#define SRCPORT 1337
#define DESTPORT 80

int main(int argc, char *argv[]) {
  struct packet pk;
  struct sockaddr_in daddr;

  int sock;

  if (argc != 2) {
    printf(
        "./fpacket [protocol] (UPD, TCP or Ip) [SrcAddr] [SrcPort] [DestAddr] "
        "[DestPort]\n");
  }

  memset(&pk, 0, sizeof(pk));

  strcat(pk.data, "Hello everybody !");

  /* IP Header */
  pk.ip.protocol = IPPROTO_IP;
  pk.ip.ihl = 5;
  pk.ip.version = 4;
  pk.ip.tos = 0;
  pk.ip.tot_len = htons(sizeof(struct packet));
  pk.ip.id = htons(300);
  pk.ip.frag_off = 0x000;
  pk.ip.ttl = 64;
  pk.ip.check = 0;
  pk.ip.saddr = inet_addr(SRCADDR);
  pk.ip.daddr = inet_addr(DESTADDR);

  if (strcmp(argv[1], "UDP") == 0) {
    /* UDP Header */
    pk.ip.protocol = IPPROTO_UDP;
    pk.udp.source = htons(SRCPORT);
    pk.udp.dest = htons(DESTPORT);
    pk.udp.len = htons(sizeof(pk) - sizeof(pk.ip));
    pk.udp.check = 0;
  }

  if (strcmp(argv[1], "TCP") == 0) {
    /* TCP HEADER */
    pk.ip.protocol = IPPROTO_TCP;
    pk.tcp.source = htons(SRCPORT);
    pk.tcp.dest = htons(DESTPORT);
    pk.tcp.seq = 0;
    pk.tcp.ack_seq = 0;
    pk.tcp.doff = 5;
    pk.tcp.fin = 0;
    pk.tcp.syn = 1;
    pk.tcp.rst = 0;
    pk.tcp.psh = 0;
    pk.tcp.ack = 0;
    pk.tcp.urg = 0;
    pk.tcp.window = htons(5840);
    pk.tcp.check = 0;
    pk.tcp.urg_ptr = 0;
  }

  sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

  daddr.sin_family = AF_INET;
  daddr.sin_addr.s_addr = inet_addr(DESTADDR);
  daddr.sin_port = htons(DESTPORT);
  memset(&daddr.sin_zero, 0, sizeof(daddr.sin_zero));

  sendto(sock, (char *)&pk, sizeof(pk), 0, (struct sockaddr *)&daddr,
         (socklen_t)sizeof(daddr));
  return 0;
}
