#include <pcap.h>
#include <iostream>
#include <string>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include <thread>
#include <queue>
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

uint32_t transfer_endian(uint32_t bigendian,int size)
{
  uint32_t res=0;
  u_char* t=(u_char*)&bigendian;
  int s=0;
  while(s<size)
  {
    res<<=8;
    res+=*(t++);
    s++;
  }
  return res;
}

class bad_packet{
public:
  time_t c_time;
  string data;
  bad_packet(const string& d)
    {
      time(&c_time);
      data=d;
    }
};
bool operator<(const bad_packet& a,const bad_packet&b)
{
  return a.c_time<b.c_time;
}

priority_queue<bad_packet> data_queue;

#define BUFLEN 512  //Max length of buffer
#define PORT 8888   //The port on which to listen for incoming data
void auto_send()
{
  struct sockaddr_in si_other;
  int s, i, slen = sizeof(si_other) , recv_len;
  //create a UDP socket
  if ((s=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
  {
    return;
  }
  si_other.sin_family = AF_INET;
  si_other.sin_port = htons(PORT);
  si_other.sin_addr.s_addr = inet_addr("10.0.2.1");
  while(1)
  while(!data_queue.empty())
  {
    auto pack=data_queue.top();
    data_queue.pop();
    if(sendto(s, pack.data.c_str(), pack.data.size(), 0, (struct sockaddr*) &si_other, slen)==-1)
      cout<<"wrong!"<<endl;
  }
}
void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet);

int main(int argc,char* arg[])
{
  pcap_t *handle;			/* Session handle */
  char *dev;			/* The device to sniff on */
  char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
  struct bpf_program fp;		/* The compiled filter */
  const char* filter_exp = "";	/* The filter expression */
		bpf_u_int32 mask;		/* Our netmask */
		bpf_u_int32 net;		/* Our IP */
		struct pcap_pkthdr header;	/* The header that pcap gives us */
		const u_char *packet;		/* The actual packet */
        /* Define the device */
        if(argc>1)
          dev=arg[1];
        else
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
        if(argc>2)
          filter_exp=arg[2];

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

    thread th(auto_send);
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
     u_char *payload; /* Packet payload */

	u_int size_ip;
    u_int size_tcp;
    u_int size_udp=sizeof(udphdr);
    ethernet = (struct sniff_ethernet*)(packet);
    ip = (struct iphdr*)(packet + SIZE_ETHERNET);
    size_ip = (ip->ihl)*4;
    if((ip->daddr)>>24 >200 )
      return;
    printf("ip hdr size:%u,total :%04x\n",size_ip,ip->tot_len );
	if (size_ip < 20)
    {
      printf("   * Invalid IP header length: %u bytes\n", size_ip);
      return;
   }
    printf("ip address src:%s",inet_ntoa((struct in_addr ){ip->saddr}));
    printf(" -> dst:%s\n",inet_ntoa((struct in_addr ){ip->daddr}) );
    //  printf("s:%08x\nd:%08x\n",ip->saddr,u_int(ip->daddr));//((u_char*)&ip->saddr)+4));
  if(ip->protocol==6)
    {
      tcp = (struct tcphdr*)(packet + SIZE_ETHERNET + size_ip);
      size_tcp = sizeof(tcphdr);
      if (size_tcp < 20) {
        printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
        return;
      }
      printf("tcp src:%u -> dst:%u\n",tcp->th_sport,tcp->th_dport+1);
      payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
    }
  else if(ip->protocol==17)
    {
        const struct udphdr *udp;
        udp=(struct udphdr*)(packet + SIZE_ETHERNET+ size_ip);
        printf("udp src:%u->dst:%u len:%u\n",
               transfer_endian(udp->source,2),transfer_endian(udp->dest,2),transfer_endian(udp->len,2) );
        payload = (u_char *)(packet + SIZE_ETHERNET+ size_ip + sizeof(udphdr));
        string t=(char*)payload;
        data_queue.push(bad_packet(t));
    }
  else
    printf("-\n");
}
