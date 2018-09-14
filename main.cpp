#include <pcap.h>
#include <stdio.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#define LIBNET_LIL_ENDIAN 1
#include "header.h"

void usage() {
	printf("syntax: pcap_test <interface>\n");
	printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
	if(argc != 2) {
		usage();
		return -1;
	}
  
  char * dev = argv[1]; 
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
    int d_len;
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("\n%u bytes captured\n", header->caplen);
   /* for(i=0; i<header->len; i++){
	    if(i%16==0) printf("\n");
	    printf("%02x ", *(packet++));
    }*/
    struct ethernet_hdr *eh = (struct ethernet_hdr *)packet;
    printf("\n===== Ethernet Header =====\n");
    printf("Dst Mac ");
    for(int i=0; i<6; i++)
    {
	    if(i==5) printf("%02x\n", eh->dst[i]);
	    else printf("%02x:", eh->dst[i]);
    }
    printf("Src Mac ");
    for(int i=0; i<6; i++)
    {
	    if(i==5) printf("%02x", eh->src[i]);
	    else printf("%02x:", eh->src[i]);
    }
    if(ntohs(eh->type)==ETHERTYPE_IP)
    {
	    struct ipv4_hdr *iph = (struct ipv4_hdr *)(packet+sizeof(struct ethernet_hdr));
	    printf("\n===== IP Header =====\n");
	    printf("Src ip : %s\n", inet_ntoa(iph->ip_src));
            printf("Dst ip : %s", inet_ntoa(iph->ip_dst));
	    if(iph->ip_p==6)
	    {
		    struct tcp_hdr *tcph = (struct tcp_hdr *)((uint8_t*)iph+iph->ip_hl*4);
	            printf("\n===== TCP Header =====\n");
	            printf("Src port : %d\n", ntohs(tcph->th_sport));
		    printf("Dst port : %d\n", ntohs(tcph->th_dport));
		    d_len = ntohs(iph->ip_len)-(iph->ip_hl*4)-(tcph->th_off*4);
		    uint8_t *data = (uint8_t*)tcph+tcph->th_off*4; 
		    if(d_len>16) d_len=16;
		    if(d_len>0 && d_len<=16){
		    printf("\n===== Data =====\n");
		    for(int i=0; i<d_len; i++){
			    printf("%02x ", data[i]);
		    }
		    printf("\n");    
		    }
	    	    else printf("\n");
	    }
    }
  }
   
  
	
	
  
    pcap_close(handle);
    return 0;
  }
