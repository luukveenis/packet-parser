#include <stdio.h>
#include <string.h>
#include "util.h"

struct packet initialize_packet(int id) {
  struct packet pkt;
  pkt.id = id;
  pkt.t_udp = 0;
  pkt.t_icmp = 0;

  return pkt;
}

void print_results(struct result res) {
  int i;

  printf("Source node: %s\n", res.ip_src);
  printf("Ultimate destination node: %s\n\n", res.ip_dst);

  for (i = 0; i < res.pkt_c; i++){
    struct packet p = res.pkts[i];
    printf("Original id: %d\n", p.id);
    printf("Packet #: %d\n", i);
    printf("Source IP: %s\n", p.ip_src);
    printf("Destination IP: %s\n", p.ip_dst);
    printf("TTL: %d\n", p.ttl);
    char *type = p.t_udp ? "UDP" : "ICMP";
    printf("Type of packet: %s\n\n", type);
  }

}
