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
#include <string.h>
#include <unistd.h>
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

struct router_param
{
  int jitter;
  int latency;//ms
  float loss_rate;
  in_addr ip1,ip2;
} Parameter;
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
#define TE(a,b) transfer_endian(a,b)

class bad_ip_packet{
public:
  time_t c_time;
  string data;

  bad_ip_packet(const string& d)
    {
      time(&c_time);
      data=d;
    }
};
bool operator<(const bad_ip_packet& a,const bad_ip_packet&b)
{
  return a.c_time<b.c_time;
}

priority_queue<bad_ip_packet> data_queue;

void auto_send()
{
  int sock,on=1;
  sock = socket(AF_INET , SOCK_RAW , IPPROTO_UDP);
  if(0>setsockopt(sock,IPPROTO_IP,IP_HDRINCL,&on,sizeof(on))){
    perror("IP_HDRINCL failed");
    exit(1);
  }
  struct sockaddr_in target;
  bzero(&target,sizeof(struct sockaddr_in));
  target.sin_family=AF_INET;
  target.sin_port=htons(6666);
  target.sin_addr.s_addr=inet_addr("192.168.56.1");
  while(1)
  while(!data_queue.empty())
  {
    auto t= data_queue.top();
    data_queue.pop();
    cout<<"ip size:"<<t.data.size()<<endl;


   setuid(getpid());
   // if(sendto(sock,t.data.c_str(),t.data.size(),0,(struct sockaddr*)&target,sizeof(struct sockaddr_in))<0)
   if(send(sock,t.data.c_str(),t.data.size(),0)<0)
   {
     printf("error:%d\n",errno);
   };
  }
}
void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet);
void help(){}
int main(int argc,char* argv[])
{
  pcap_t *handle;			/* Session handle */
  char *dev;			/* The device to sniff on */
  char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
  struct bpf_program fp;		/* The compiled filter */
  char filter_exp[100];	/* The filter expression */
  //set parameter
  static const char *optString = "?v:s:d:l::r::j::";
  char opt;
  opt = getopt( argc, argv, optString );
  while( opt != -1 ) {
    switch(opt)
    {
    case 'v':
      dev=optarg;
      break;
    case '?':
      help();
      break;
    case 's':
      cout<<optarg<<endl;
      Parameter.ip1=(struct in_addr){inet_addr(optarg)};
      break;
    case 'd':
      Parameter.ip2=(struct in_addr){inet_addr(optarg)};
      break;
    case 'l':
      sscanf(optarg,"%d",&Parameter.latency);
      break;
    case 'r':
      sscanf(optarg,"%f",&Parameter.loss_rate);
      break;
    case 'j':
      sscanf(optarg,"%d",&Parameter.jitter);
      break;
    }
    opt=getopt( argc, argv, optString );
  }
  sprintf(filter_exp,"udp and (host %s or host %s )",
       inet_ntoa(Parameter.ip1), inet_ntoa(Parameter.ip2));
  cout<<filter_exp<<endl;

  bpf_u_int32 mask;	    /* Our netmask */
  bpf_u_int32 net;		/* Our IP */
  struct pcap_pkthdr header;	/* The header that pcap gives us */
  const u_char *packet;		/* The actual packet */


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
        else
          printf("listen: %s/%s \n",inet_ntoa(in_addr {net}),inet_ntoa(in_addr {mask}) );

		/* Compile and apply the filter */
        if (pcap_compile(handle, &fp, filter_exp,0, net) == -1) {
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

unsigned short check_sum(unsigned short *addr,int len){
  register int nleft=len;
  register int sum=0;
  register short *w=addr;
  short answer=0;

  while(nleft>1)
  {
    sum+=*w++;
    nleft-=2;
  }
  if(nleft==1)
  {
    *(unsigned char *)(&answer)=*(unsigned char *)w;
    sum+=answer;
  }
  sum=(sum>>16)+(sum&0xffff);
  sum+=(sum>>16);
  answer=~sum;
  return(answer);
}
void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet)
{
#define SIZE_ETHERNET 14
    const struct sniff_ethernet *ethernet; /* The ethernet header */
    struct iphdr *ip; /* The IP header */
    u_char *payload; /* Packet payload */
    u_char * dst_ip;
    u_int size_ip;
    ethernet = (struct sniff_ethernet*)(packet);
    ip = (struct iphdr*)(packet + SIZE_ETHERNET);
    size_ip = (ip->ihl)*4;
    if (size_ip < 20)
    {
      printf("   * Invalid IP header length: %u bytes\n", size_ip);
      return;
    }
    printf("ip address src:%s",inet_ntoa((struct in_addr ){ip->saddr}));
    printf(" -> dst:%s\n",inet_ntoa((struct in_addr )     {ip->daddr}) );
    payload = (u_char *)(packet + SIZE_ETHERNET);

  if(ip->protocol==6)
    {
      const struct tcphdr *tcp;        /* The TCP header */
      tcp = (struct tcphdr*)(packet + SIZE_ETHERNET + size_ip);
      printf("tcp src:%u -> dst:%u\n",TE(tcp->th_sport,2),TE(tcp->th_dport+1,2));
    }
  else if(ip->protocol==17)
    {
        const struct udphdr *udp;
        udp=(struct udphdr*)(packet + SIZE_ETHERNET+ size_ip);
        printf("udp src:%u->dst:%u\n",TE(udp->source,2),TE(udp->dest,2));
    }
  else
    printf("-\n");
  in_addr dst;
  if(Parameter.ip1.s_addr == inet_addr((char*)&ip->saddr))
    dst=Parameter.ip2;
  else
    dst=Parameter.ip1;
  char *t=inet_ntoa(dst);
  int ip_size=TE(ip->tot_len,2);
  //memcpy((void *)&ip->daddr,t,4);
  char tmp[4];
  memcpy(tmp,(void*)&ip->daddr,4);
  memcpy((void*)&ip->daddr,(void*)&ip->saddr,4);
  memcpy((void*)&ip->saddr,tmp,4);
  ip->check=0;
  ip->check=check_sum((unsigned short)ip,size_ip);
  cout<<"a---------";
  data_queue.push(bad_ip_packet(string((char*)ip,ip_size)));
}
