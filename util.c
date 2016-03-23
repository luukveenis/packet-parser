#include <stdio.h>
#include <string.h>
#include "util.h"

#define DEBUG 0

int find_match(struct result*, struct packet);
int new_node(struct result*, char *ip);
int update_protocols(struct result*, struct protocol);

struct packet initialize_packet(int id) {
  struct packet pkt;
  pkt.id = id;
  pkt.t_udp = 0;
  pkt.t_icmp = 0;

  return pkt;
}

/* Scans the packets for the ICMP packet containing the response to the
 * original ping request. The response types might be different depending on
 * the protocol the host is using for traceroute
 */
void find_dest(struct result *res) {
  int i;
  struct packet tmp;

  for (i = 0; i < res->pkt_c; i++) {
    tmp = res->pkts[i];
    /* There are two options for the message type of the final response:
     *  - 0 (ping reply) if the request is using ICMP
     *  - 11 (port unreachable) if the request is using UDP */
    if (tmp.t_icmp && (tmp.icmp_type == 0 || tmp.icmp_type == 11)) {
      strcpy(res->ip_dst, tmp.ip_src);
    }
  }
}

void find_protocols(struct result *res) {
  int i;
  struct packet tmp;

  for (i = 0; i < res->pkt_c; i++) {
    tmp = res->pkts[i];
    if (tmp.t_icmp)
      update_protocols(res, (struct protocol){ 1, "ICMP" });
    else if (tmp.t_udp)
      update_protocols(res, (struct protocol){ 17, "UDP" });
    else
      update_protocols(res, (struct protocol) { tmp.ip_p, "UNKNOWN PROTOCOL" });
  }
}

void find_hops(struct result *res) {
  int i, match;
  struct packet tmp, original;
  struct node nod;

  for (i = 0; i < res->pkt_c; i++) {
    tmp = res->pkts[i];
    if (!strcmp(tmp.ip_dst, res->ip_src)) {
      match = find_match(res, tmp);
      if (match >= 0) {
        /* Get the packet and create an intermediate node for it */
        if (new_node(res, tmp.ip_src)) {
          original = res->pkts[match];
          strcpy(nod.ip, tmp.ip_src);
          nod.dist = original.ttl;
          res->hops[res->hops_c++] = nod;
        }
      }
    }
  }
}

/* Returns 0 if we've already stored this node, 1 otherwise.
 * This is just so we only store unique intermediate hops    */
int new_node(struct result *res, char *ip) {
  int i;
  struct node tmp;

  for (i = 0; i < res->hops_c; i++) {
    tmp = res->hops[i];
    if (!strcmp(tmp.ip, ip)){
      return 0;
    }
  }
  return 1;
}

/* Returns the index of the source packet matching the response
 * ie: the ping request packet matching the response or timeout */
int find_match(struct result *res, struct packet response) {
  int i;
  struct packet tmp;

  for (i = 0; i < res->pkt_c; i++) {
    tmp = res->pkts[i];
    if (!strcmp(tmp.ip_src, res->ip_src) && tmp.ip_id == response.src_id) {
      return i;
    }
  }
  return -1;
}

int update_protocols(struct result *res, struct protocol prot) {
  int i;
  struct protocol tmp;

  for (i = 0; i < res->prot_c; i++) {
    tmp = res->protocols[i];
    if (tmp.id == prot.id)
      return 0;
  }
  res->protocols[res->prot_c++] = prot;
  return 1;
}

void print_results(struct result res) {
  int i;
  struct packet p;
  struct node n;
  struct protocol prot;

  printf("Source node: %s\n", res.ip_src);
  printf("Ultimate destination node: %s\n\n", res.ip_dst);

  if (DEBUG) {
    for (i = 0; i < res.pkt_c; i++){
      p = res.pkts[i];
      printf("Original id: %d\n", p.id);
      printf("IP ident: %d\n", p.ip_id);
      printf("Packet #: %d\n", i);
      printf("Source IP: %s\n", p.ip_src);
      printf("Destination IP: %s\n", p.ip_dst);
      printf("TTL: %d\n", p.ttl);
      if (p.t_icmp) {
        printf("ICMP type: %d\n", p.icmp_type);
        printf("ICMP code: %d\n", p.icmp_code);
        printf("Src ID: %d\n", p.src_id);
      }
      char *type = p.t_udp ? "UDP" : "ICMP";
      printf("Type of packet: %s\n\n", type);
    }
    printf("========================\n\n");
  }
  printf("The IP addresses of intermediate destination nodes:\n");
  for (i = 0; i < res.hops_c; i++) {
    n = res.hops[i];
    printf("\trouter %d:\t%s\n", n.dist, n.ip);
  }
  printf("\n");
  printf("The values in the protocol field of IP headers:\n");
  for (i = 0; i < res.prot_c; i++) {
    prot = res.protocols[i];
    printf("\t%d:\t%s\n", prot.id, prot.name);
  }
  printf("\n");
}
