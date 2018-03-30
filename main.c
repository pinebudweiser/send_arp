#include <stdio.h>
#include <stdint.h>
#include <pcap/pcap.h>
#include <libnet.h>
#include <pthread.h>

int *get_recover_time(pcap_t* pkDescriptor);

int main(int argc, char** argv)
{
    struct libnet_802_3_hdr* ETH;
    struct libnet_arp_hdr* ARP;
    char* interface;


    if (argc != 3)
    {
        printf("Usage : send_arp <interface><sender ip><target ip>");
        return 1;
    }
    interface = argv[1];

    return 0;
}

int *get_recover_time(pcap_t* pkDescriptor)
{
    char* buf;
    struct pcap_pkthdr* pktHeader;
    pcap_next_ex(pkDescriptor, &pktHeader, &buf);

    while(1)
    {

    }
}
