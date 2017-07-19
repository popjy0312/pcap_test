#include <pcap.h>
#include <stdio.h>
#include <net/ethernet.h>   /* for struct ether_header */
#include <netinet/ether.h>  /* for ether_ntoa */
#include <netinet/ip.h>     /* for struct ip */
#include <netinet/tcp.h>    /* for struct tcphdr */
#include <arpa/inet.h>      /* for inet_ntoa */
#include <ctype.h>          /* for isprint */
#include <stdint.h>         /* for uint16_t, uint32_t, ... */

int main(int argc, char *argv[])
{
    pcap_t *handle;         /* Session handle */
    char *dev;          /* The device to sniff on */
    struct bpf_program fp;      /* The compiled filter */
    char errbuf[PCAP_ERRBUF_SIZE];  /* Error string */
    char filter_exp[] = "port 80";  /* The filter expression */
    struct pcap_pkthdr* pheader;  /* The header pointer that pcap gives us */
    bpf_u_int32 net;        /* Our IP */
    const u_char *packet;       /* The actual packet */
    struct ether_header* peth_hdr;  /* ehternet header pointer */
    struct ip* pip_hdr;  /* ip header pointer */
    struct tcphdr* ptcp_hdr;   /* tcp header pointer */
    u_char *data;      /* tcp data pointer */
    uint32_t res;    /* check grab packet success */
    uint32_t i;      /* index temp variable */
    uint32_t data_len;  /* length of tcp data */

    if(argc != 2){
        printf("usage : ./pcap interface\n");
        return -1;
    }
    /* Define the device */
    dev = argv[1];
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

    /* Grab a packet */
    while ( (res = pcap_next_ex(handle, &pheader, &packet)) >= 0){
        /* timeout */
        if (res == 0)
            continue;
        /* Print its length */
        printf("Jacked a packet with length of [%d]\n", pheader->len);

        peth_hdr = (struct ether_header*) packet;

        printf("\n****Ethernet Information****\n");
        /* print Source MAC address */
        printf("Ethernet Source MAC address\n");
        printf("%s\n",ether_ntoa((struct ether_addr*)&peth_hdr->ether_shost));

        /* print Dest MAC address */
        printf("Ethernet Dest MAC address\n");
        printf("%s\n",ether_ntoa((struct ether_addr*)&peth_hdr->ether_dhost));

        /* IPv4 */
        if( ntohs(peth_hdr->ether_type) == ETHERTYPE_IP){
            pip_hdr = (struct ip*)(packet + sizeof(struct ether_header));

            printf("\n****IPv4 Information****\n");
            /* print Source IP address */
            printf("Source IP address\n");
            printf("%s\n", inet_ntoa(pip_hdr->ip_src));

            /* print Dest IP address */
            printf("Dest IP address\n");
            printf("%s\n", inet_ntoa(pip_hdr->ip_dst));

            if( pip_hdr->ip_p == IPPROTO_TCP){
                ptcp_hdr = (struct tcphdr*)((char*)pip_hdr + pip_hdr->ip_hl*4);

                printf("\n****TCP Information****\n");
                /* print Source Port */
                printf("TCP Source Port\n");
                printf("%d\n",ntohs(ptcp_hdr->source));

                /* print Dest Port */
                printf("TCP Dest Port\n");
                printf("%d\n",ntohs(ptcp_hdr->dest));

                /* print some data */
                data = (char*)ptcp_hdr + ptcp_hdr->doff*4;

                data_len = (uint32_t)htons(pip_hdr->ip_len) - (uint32_t)pip_hdr->ip_hl*4-(uint32_t)ptcp_hdr->doff*4;
                printf("\n****Data (len: %d)**** \n",data_len);
                for(i=0;i<data_len;i++){
                    printf("%c",isprint(data[i])?data[i]:'.');
                    if(!(i&0x1f ^ 0x1f))    /* new line every 32 bytes */
                        printf("\n");
                }
                printf("\n");
            }
        }

        printf("------------------------------------------------------\n");

    }
    pcap_close(handle);
    return(0);
}
