#include <pcap.h>
#include <iostream>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

using namespace std;

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};


void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet);

int main(int argc,char* arg[])
{

  pcap_t *handle;			/* Session handle */
  char *dev;			/* The device to sniff on */
  char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
  struct bpf_program fp;		/* The compiled filter */
  char filter_exp[] = "";	/* The filter expression */
		bpf_u_int32 mask;		/* Our netmask */
		bpf_u_int32 net;		/* Our IP */
		struct pcap_pkthdr header;	/* The header that pcap gives us */
		const u_char *packet;		/* The actual packet */

		/* Define the device */
		dev = pcap_lookupdev(errbuf);
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
			return(2);
		}
		/* Find the properties for the device */
		if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
			fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
			net = 0;
			mask = 0;
		}
		/* Open the session in promiscuous mode */
		handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
		if (handle == NULL) {
			fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
			return(2);
		}
		/* Compile and apply the filter */
		if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
			fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
			return(2);
		}
		if (pcap_setfilter(handle, &fp) == -1) {
			fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
			return(2);
		}
    printf("go!\n");
    pcap_loop(handle,0, got_packet,NULL);

		/* And close the session */
		pcap_close(handle);

  return 0;
}

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet)
{
#define SIZE_ETHERNET 14
  const struct sniff_ethernet *ethernet; /* The ethernet header */
	const struct iphdr *ip; /* The IP header */
	const struct tcphdr *tcp; /* The TCP header */
	const char *payload; /* Packet payload */

	u_int size_ip;
	u_int size_tcp;
  ethernet = (struct sniff_ethernet*)(packet);
    ip = (struct iphdr*)(packet + SIZE_ETHERNET);
	size_ip = (ip->ihl)*4;
	if (size_ip < 20)
    {
      printf("   * Invalid IP header length: %u bytes\n", size_ip);
      return;
  }
  printf("ip address src:%s -> dst:%s\n",inet_ntoa(*(struct in_addr *)&ip->saddr),inet_ntoa(*(struct in_addr *)&ip->daddr));
  if(ip->protocol==6)
    {
      tcp = (struct tcphdr*)(packet + SIZE_ETHERNET + size_ip);
      size_tcp = sizeof(tcphdr);
      if (size_tcp < 20) {
        printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
        return;
      }
      printf("tcp src:%d -> dst:%d\n",tcp->th_sport,tcp->th_dport);
      payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
    }
  else if(ip->protocol==17)
    {
        const struct udphdr *udp;
        udp=(struct udphdr*)(packet + SIZE_ETHERNET);
        printf("udp src:%d->dst:%d\n",udp->uh_sport,udp->uh_dport);
        payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + sizeof(udphdr));

    }
  else
    printf("-\n");
}
