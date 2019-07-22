#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

struct ip_addr{
    unsigned int version:4;
    unsigned int ihl:4;
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    uint8_t sip[4];
    uint8_t dip[4];
};

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  int res;
  int tes;
  int yes;
  int ues;
  struct pcap_pkthdr* header;
  const u_char* packet;
  struct ether_header *eth_h;
  struct ip_addr *ip_a;
  struct tcphdr *tcp_h;

  while (res = pcap_next_ex(handle, &header, &packet)) {
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    eth_h = (ether_header *)packet;
    ip_a = (ip_addr *)(packet+14);
    tcp_h = (tcphdr *)(packet+ 14 + (ip_a->ihl*4));

    printf("==============(ethernet)=====================\n");

    int j=0;

    printf("DMAC : ");
            for(int i= 0; i<6; i++){
                printf("%02x", eth_h->ether_dhost[i]);
                if(j==i){
                    if(i==5){

                        break;
                    }
                    printf(":");
                    j=j+1;
            }
        }

    printf("\n");

    int k=0;

    printf("SMAC : ");
            for(int i= 0; i<6; i++){
                printf("%02x", eth_h->ether_shost[i]);
                if(k==i){
                    if(i==5){

                        break;
                    }
                    printf(":");int res;
                    k=k+1;
            }
        }

    printf("\n");

    printf("===============(IP)======================\n");

    int m=0;
    printf("SIP : ");
    for(int l=0; l<4; l++){
    printf("%d", ip_a->sip[l]);
    if(l==m){
        if(m==3){

            break;
        }
        printf(".");int tes;
        m=m+1;
    }
    }

    printf("\n");

    int n=0;
    printf("DIP : ");
    for(int l=0; l<4; l++){
    printf("%d", ip_a->dip[l]);
    if(l==n){
        if(n==3){

            break;
        }
        printf(".");int tes;
        n=n+1;
    }


}
    printf("\n");

    printf("===============(TCP)======================\n");
    printf("SPORT : %d\n", tcp_h->th_sport);
    printf("DPORT : %d\n", tcp_h->th_dport);

    printf("===============(DATA)======================\n");

    const u_char* tmp_len = packet+ 14 + (ip_a->ihl*4) + sizeof(tcp_h);
    for(int a=0; a<10; a++){
        printf("%02X ",*tmp_len++);
    }
    printf("\n");






}
  pcap_close(handle);
  return 0;

}
