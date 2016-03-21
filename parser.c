#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
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
  struct result res;
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
    /* printf("Processing packet %d...\n", ++pktcounter); */
    struct packet pkt = initialize_packet(++pktcounter);
    if (process_packet(&pkt, packet, header.ts, header.caplen)) {
      if (start) {
        res->pkts[res->pkt_c++] = pkt; /* Store the packet internally */
      } else {
        if (pkt.ttl == 1) {
          start = 1;
          res->pkts[res->pkt_c++] = pkt; /* Store the packet internally */
          strcpy(res->ip_src, pkt.ip_src);
          strcpy(res->ip_dst, pkt.ip_dst);
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
  strcpy(pkt->ip_src, inet_ntoa(ip->ip_src));
  strcpy(pkt->ip_dst, inet_ntoa(ip->ip_dst));
  pkt->ttl = ip->ip_ttl;

  /* UDP packet */
  if (ip->ip_p == IPPROTO_UDP) {
    /* printf("Protocol: UDP\n\n"); */
    packet += iphdrlen;
    caplen -= iphdrlen;

    /* Check if we captured full UDP packet */
    if (caplen < sizeof(struct udphdr)) {
      printf("Failed to capture full packet\n");
      return 0;
    }

    udp = (struct udphdr*) packet;
    if (ntohs(udp->uh_dport) == 1900) {
      return 0;
    }
    pkt->t_udp = 1;
  } else if (ip->ip_p == IPPROTO_TCP) {
    /* printf("Protocol: TCP\n\n"); */
    return 0;
  } else if (ip->ip_p == IPPROTO_ICMP) {
    pkt->t_icmp = 1;
  } else {
    /* printf("Protocol: %d\n\n", ip->ip_p); */
    return 0;
  }
  return 1;
}
