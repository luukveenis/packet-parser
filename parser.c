#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* My includes */
#include "util.h"

int process_file(pcap_t*, struct result*);
int process_packet(struct packet*, const u_char*, struct timeval, unsigned int);

/* ---------------- Main ----------------*/
int main(int argc, char **argv) {
  char err[PCAP_ERRBUF_SIZE];
  struct result res = { .pkt_c = 0, .hops_c = 0 };
  pcap_t *handle;

  /* We expect exactly one command line argument, the .cap file name */
  if (argc != 2) {
    fprintf(stderr, "Usage: %s <capture-file>\n", argv[0]);
    exit(EXIT_FAILURE);
  }

  /* Try to open the file for processing */
  handle = pcap_open_offline(argv[1], err);
  if (handle == NULL) {
    fprintf(stderr,"%s\n", err);
    exit(EXIT_FAILURE);
  }

  process_file(handle, &res);

  find_dest(&res);
  find_hops(&res);
  find_protocols(&res);
  find_fragments(&res);
  find_rtts(&res);
  print_results(res);

  return 0;
}

/* Processes the contents of a capture file
 * Returns:
 *  -  0 for success
 *  - -1 for failure
 */
int process_file(pcap_t *handle, struct result *res){
  struct pcap_pkthdr header;
  const u_char *packet;
  int pktcounter = 0;
  int start = 0; /* Indicate when traceroute started */

  while ((packet = pcap_next(handle, &header))){
    struct packet pkt = initialize_packet(++pktcounter);
    if (process_packet(&pkt, packet, header.ts, header.caplen)) {
      if (start) {
        res->pkts[res->pkt_c++] = pkt; /* Store the packet internally */
      } else {
        if (pkt.ttl == 1) {
          start = 1;
          res->pkts[res->pkt_c++] = pkt; /* Store the packet internally */
          strcpy(res->ip_src, pkt.ip_src);
        }
      }
    }
  }

  return 0;
}

int process_packet(struct packet* pkt,
    const u_char *packet, struct timeval ts, unsigned int caplen) {
  unsigned int iphdrlen;
  struct ip *ip;
  struct udphdr* udp;
  struct icmp* icmp;

  /* Didn't capture the full ethernet header */
  if (caplen < sizeof(struct ether_header)) {
    printf("Failed to capture full packet\n");
    return 0;
  }

  /* Skip over the Ethernet header. */
  packet += sizeof(struct ether_header);
  caplen -= sizeof(struct ether_header);

  /* Didn't capture a full IP header */
  if (caplen < sizeof(struct ip)) {
    printf("Failed to capture full packet\n");
    return 0;
  }

  ip = (struct ip*) packet;
  iphdrlen = ip->ip_hl * 4; // ip_hl is in 4-byte words

  /* Didn't capture the full IP header with options */
  if (caplen < iphdrlen) {
    printf("Failed to capture full packet\n");
    return 0;
  }

  /* Extract info from IP header */
  pkt->time = (1000 * ts.tv_sec) + (ts.tv_usec / 1000);
  strcpy(pkt->ip_src, inet_ntoa(ip->ip_src));
  strcpy(pkt->ip_dst, inet_ntoa(ip->ip_dst));
  pkt->ttl = ip->ip_ttl;
  pkt->ip_id = ntohs(ip->ip_id);
  pkt->ip_p = ip->ip_p;

  /* Get flags and offset */
  u_short off = ntohs(ip->ip_off);
  pkt->mf = (off & IP_MF) ? 1 : 0;
  pkt->df = (off & IP_DF) ? 1 : 0;
  pkt->offset = (off & IP_OFFMASK) * 8;

  packet += iphdrlen;
  caplen -= iphdrlen;

  /* UDP packet */
  if (ip->ip_p == IPPROTO_UDP) {

    /* Check if we captured full UDP packet */
    if (caplen < sizeof(struct udphdr)) {
      printf("Failed to capture full packet\n");
      return 0;
    }

    udp = (struct udphdr*) packet;
    u_int16_t sport = ntohs(udp->uh_sport);
    u_int16_t dport = ntohs(udp->uh_dport);

    /* Ignore all irrelevant UDP packets
     * Source port 53 is to ignore DNS query responses */
    if (dport < 33434 || dport > 33534 || sport == 53) {
      return 0;
    }
    pkt->t_udp = 1;
  } else if (ip->ip_p == IPPROTO_TCP) {
    return 0;
  } else if (ip->ip_p == IPPROTO_ICMP) {
    if (caplen < sizeof(struct icmp)) {
      printf("Failed to capture full ICMP header\n");
      return 0;
    }

    icmp = (struct icmp*)packet;
    pkt->t_icmp = 1;
    pkt->icmp_type = icmp->icmp_type;
    pkt->icmp_code = icmp->icmp_code;
    if (pkt->icmp_type == 0 || pkt->icmp_type == 8)
      pkt->seq = ntohs(icmp->icmp_hun.ih_idseq.icd_seq);

    packet += 8; /* ICMP header is 8 bytes */
    caplen -= 8;

    if (caplen <= 0) {
      printf("Missing data section of ICMP packet\n");
      return 0;
    }

    ip = (struct ip*) packet;  /* This is the original IP header */
    pkt->src_id = ntohs(ip->ip_id);
  } else {
    return 0;
  }
  return 1;
}
