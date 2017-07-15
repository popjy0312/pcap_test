#include <pcap.h>
#include <stdio.h>
#include <net/ethernet.h>   /* for struct ether_header */
#include <netinet/ip.h>

int main(int argc, char *argv[])
{
    pcap_t *handle;         /* Session handle */
    char *dev;          /* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];  /* Error string */
    struct bpf_program fp;      /* The compiled filter */
    char filter_exp[] = "port 80";  /* The filter expression */
    bpf_u_int32 mask;       /* Our netmask */
    bpf_u_int32 net;        /* Our IP */
    struct pcap_pkthdr* pheader;  /* The header pointer that pcap gives us */
    const u_char *packet;       /* The actual packet */
    struct ether_header* peth_hdr;  /* ehternet header pointer */
    int res;    /* check grab packet success */
    int i;      /* index temp variable */

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

    /* Grab a packet */
    while ( (res = pcap_next_ex(handle, &pheader, &packet)) >= 0){
        /* timeout */
        if (res == 0)
            continue;
        /* Print its length */
        printf("Jacked a packet with length of [%d]\n", pheader->len);
        
        peth_hdr = (struct ether_header*) packet;
        
        /* print Source MAC address */
        printf("Ethernet Source MAC address\n");
        for(i=0;i<ETHER_ADDR_LEN;i++){
            printf("%02x",peth_hdr->ether_shost[i]);
            printf( (i==5)?"\n":":" );
        }
        
        /* print Dest MAC address */
        printf("Ethernet Dest MAC address\n");
        for(i=0;i<ETHER_ADDR_LEN;i++){
            printf("%02x",peth_hdr->ether_dhost[i]);
            printf( (i==5)?"\n":":" );
        }

    }
    pcap_close(handle);
    return(0);
}
