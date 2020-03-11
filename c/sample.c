
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>

int main(int argc, char **argv) {
    char *dev, errbuf[PCAP_ERRBUF_SIZE];

    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "ディバイスが見つかりませんでした: %s\n", errbuf);
        exit(1);
    }
    printf("ディバイス: %s\n", dev);
    return 0;

}
