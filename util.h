#ifndef UTIL_H_
#define UTIL_H_

#define MAX_HOPS 30 /* This is the default for traceroute */
#define MAX_STR_LEN 120
#define MAX_PACKETS 1000

#include <sys/types.h>

struct protocol {
  int id;
  char *name;
};

struct packet {
  int id; /* This is the original packet # in the trace file for debugging */
  u_short ip_id;
  u_short src_id;
  char ip_src[MAX_STR_LEN]; /* source IP */
  char ip_dst[MAX_STR_LEN]; /* destination IP */
  u_int8_t t_udp:1;
  u_int8_t t_icmp:1;
  u_int8_t ttl;
  u_int8_t icmp_type;
  u_int8_t icmp_code;
  u_short ip_p;
};

struct node {
  char ip[MAX_STR_LEN]; /* IP of this node */
  int dist; /* Number of hops from source */
};

struct result {
  char ip_src[MAX_STR_LEN];
  char ip_dst[MAX_STR_LEN]; /* destination ip */
  struct packet pkts[MAX_PACKETS]; /* Internal representation of packets */
  int pkt_c; /* Packet count (how many packets  we have) */
  struct node hops[MAX_HOPS];
  int hops_c;         /* number of intermediate hosts */
  struct protocol protocols[MAX_HOPS];
  int prot_c;
};


struct packet initialize_packet(int);
void print_results(struct result);
void find_hops(struct result*);
void find_dest(struct result*);
void find_protocols(struct result*);
#endif
