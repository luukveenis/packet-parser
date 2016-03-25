#include <stdio.h>
#include <stdlib.h>
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
    if (tmp.t_icmp && (tmp.icmp_type == 0 || tmp.icmp_type == 3)) {
      strcpy(res->ip_dst, tmp.ip_src);
      break;
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
  int i, j, match;
  struct packet tmp, original;
  struct node nod;

  /* Find all the intermediate hops */
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
  /* Sort the nodes in order of increasing hop count
   * Use bubble sort because it's easy and negligible number of items */
  for (i = 0; i < res->hops_c - 1; i++) {
    for (j = i+1; j < res->hops_c; j++) {
      if (res->hops[j].dist < res->hops[i].dist) {
        nod = res->hops[j];
        res->hops[j] = res->hops[i];
        res->hops[i] = nod;
      }
    }
  }
}


void find_fragments(struct result *res) {
  int i, j, fragcount, offset;
  struct packet pkt, tmp;

  /* Scan through packets for those with MF flag set */
  for (i = 0; i < res->pkt_c; i++) {
    pkt = res->pkts[i];
    /* The first of a set of fragments must have offset == 0
     * Otherwise the second may be recognized as a new fragment */
    if (pkt.mf && pkt.offset == 0 && !strcmp(pkt.ip_src, res->ip_src)) {
      fragcount = 1, offset = 0;
      /* Scan through the rest of the packets for the remaining fragments */
      for (j = i+1; j < res->pkt_c; j++) {
        tmp = res->pkts[j];
        /* Check the ID and the source IP */
        if (tmp.ip_id == pkt.ip_id && !strcmp(tmp.ip_src, pkt.ip_src)) {
          fragcount++;
          offset = tmp.offset;
          /* Stop when we've found the last one */
          if (!tmp.mf) break;
        }
      }
      /* Report an error if we can't locate the remaining fragments */
      if (offset == 0 || fragcount == 1) {
        printf("Error finding remaining fragments for packet %d\n", pkt.id);
      } else {
        /* Store the computed data in a struct to display in the results */
        struct fragment frag = { .id = pkt.ip_id, .count = fragcount, .offset = offset };
        res->fragments[res->frag_c++] = frag;
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
  struct fragment frag;

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
  for (i = 0; i < res.frag_c; i++) {
    frag = res.fragments[i];
    printf("The number of fragments created from the original data gram ");
    printf("with IP id = %d is: %d\n", frag.id, frag.count);
    printf("The offset of the last fragment is: %d\n\n", frag.offset);
  }
  printf("\n");
}
