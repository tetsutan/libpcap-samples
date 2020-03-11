// locate in /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk/usr/include
#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>

int main(int argc, char *argv[])
{
    pcap_t *handle;			/* Session handle */
    char *dev;			/* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
    struct bpf_program fp;		/* The compiled filter */
    char filter_exp[] = "tcp and port 8000";	/* The filter expression */
    bpf_u_int32 maskp;		/* Our netmask */
    bpf_u_int32 netp;		/* Our IP */
    char *net; /* dot notation of the network address */
    char *mask;/* dot notation of the network mask    */
    struct in_addr addr;
    struct pcap_pkthdr header;	/* The header that pcap gives us */
    const u_char *packet;		/* The actual packet */

    /* Define the device */
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return(2);
    }
    printf("Device: %s\n", dev);

    /* Find the properties for the device */
    if (pcap_lookupnet(dev, &netp, &maskp, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        netp = 0;
        maskp = 0;
        return 2;
    }

    addr.s_addr = netp;
    net = inet_ntoa(addr);
    if (net == NULL) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        return 2;
    }
    printf("net = %s\n", net);

    addr.s_addr = maskp;
    mask = inet_ntoa(addr);
    if (mask == NULL) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        return 2;
    }

    printf("mask = %s\n", mask);

    /* Open the session in promiscuous mode */
    handle = pcap_open_live(dev, BUFSIZ, 1, 3000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }
    /* Compile and apply the filter */
    if (pcap_compile(handle, &fp, filter_exp, 0, netp) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    /* Grab a packet */
    packet = pcap_next(handle, &header);
    /* Print its length */
    printf("Jacked a packet with capture length of [%d]\n", header.caplen);


    /* And close the session */
    pcap_close(handle);
    return(0);
}
