#include <netinet/if_ether.h>
#include <netinet/ip.h>
/* #include <arpa/inet.h> */
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

int process_file(pcap_t*);
void process_packet(const u_char*, struct timeval, unsigned int);

/* ---------------- Main ----------------*/
int main(int argc, char **argv) {
  char err[PCAP_ERRBUF_SIZE];
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

  process_file(handle);

  return 0;
}

/* Processes the contents of a capture file
 * Returns:
 *  -  0 for success
 *  - -1 for failure
 */
int process_file(pcap_t *handle){
  struct pcap_pkthdr header;
  const u_char *packet;
  int pktcounter = 0;

  while ((packet = pcap_next(handle, &header))){
    printf("Processing packet %d...\n", ++pktcounter);
    process_packet(packet, header.ts, header.caplen);
  }

  return 0;
}

void process_packet(const u_char *packet, struct timeval ts, unsigned int caplen) {
  unsigned int iphdrlen;
  struct ip *ip;

  /* Didn't capture the full ethernet header */
  if (caplen < sizeof(struct ether_header)) {
    printf("Failed to capture full packet\n");
    exit(EXIT_FAILURE);
  }

  /* Skip over the Ethernet header. */
  packet += sizeof(struct ether_header);
  caplen -= sizeof(struct ether_header);

  /* Didn't capture a full IP header */
  if (caplen < sizeof(struct ip)) {
    printf("Failed to capture full packet\n");
    exit(EXIT_FAILURE);
  }

  ip = (struct ip*) packet;
  iphdrlen = ip->ip_hl * 4; // ip_hl is in 4-byte words

  /* Didn't capture the full IP header with options */
  if (caplen < iphdrlen) {
    printf("Failed to capture full packet\n");
    exit(EXIT_FAILURE);
  }

  if (ip->ip_p == IPPROTO_UDP) {
    printf("Protocol: UDP\n\n");
  } else if (ip->ip_p == IPPROTO_TCP) {
    printf("Protocol: TCP\n\n");
  } else if (ip->ip_p == IPPROTO_ICMP) {
    printf("Protocol: ICMP\n\n");
  } else {
    printf("Protocol: %d\n\n", ip->ip_p);
  }
}
