#include <pcap.h>
#include <stdio.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "header.h"

void PrintEthernet_H(const u_char* packet);
void PrintIp_H(const u_char* packet);
void PrintTcp_H(const u_char* packet);
void PrintData(const u_char* packet);

struct Data
{
	u_int8_t Data[16];
};

u_int8_t protocol, len;
u_int16_t t_len, type;

int main(int argc, char* argv[]) {
  
  char dev[] = "eth0"; 
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header; 
    const u_char* packet; 
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
   /* for(i=0; i<header->len; i++){
	    if(i%16==0) printf("\n");
	    printf("%02x ", *(packet++));
    }*/
    PrintEthernet_H(packet);
    	if(type==8){
   		 packet+=14;
   		 PrintIp_H(packet);
			 if(protocol==6){
   		 		packet+=len*4;
   		 		PrintTcp_H(packet);
				packet+=t_len;
				PrintData(packet);
			 }
	}
  }
    pcap_close(handle);
    return 0;
  }
      
void PrintEthernet_H(const u_char* packet){
	ethernet_hdr *eh;
	eh =(ethernet_hdr *)packet;
	type = eh->type;
	printf("\n===== Ethernet Header =====\n");
	printf("Dst Mac ");
	for(int i=0; i<6; i++){
	       if(i==5) printf("%02x\n", eh->dst[i]);
	       else printf("%02x:", eh->dst[i]);
	}
	printf("Src Mac ");
	for(int i=0; i<6; i++){
		if(i==5) printf("%02x\n", eh->src[i]);
		else printf("%02x:", eh->src[i]);
	}	
}

void PrintIp_H(const u_char* packet){
	ipv4_hdr *iph;
	iph = (ipv4_hdr *)packet;
	protocol = iph->ip_p;
	len=iph->ip_hl;
	printf("\n===== IP Header =====\n");
	printf("Src ip : %s\n", inet_ntoa(iph->ip_src)); 
	printf("Dst ip : %s\n", inet_ntoa(iph->ip_dst));
}

void PrintTcp_H(const u_char* packet){
	tcp_hdr *tcph;
	tcph = (tcp_hdr *)packet;
	t_len=tcph->th_off;
	printf("\n===== TCP Header =====\n");
	printf("Src port : %u\n", tcph->th_sport);
	printf("Dst port : %u\n", tcph->th_dport);
}

void PrintData(const u_char* packet){
	Data *Dt;
	Dt=(Data *)packet;
	printf("\n=====Data print=====\n");
	for(int i=0; i<16; i++) printf("%02x ", Dt->Data[i]);
}

