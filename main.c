#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <pcap/pcap.h>
#include <libnet.h>
#include <pthread.h>


typedef struct libnet_802_3_hdr ETH;
typedef struct libnet_arp_hdr ARP;
int* get_recover_time(pcap_t* pkDescriptor);
char* get_interface_mac(char* interface);

int main(int argc, char** argv)
{
    ETH ethHeader;
    char* interface;

    if (argc != 4)
    {
        printf("Usage : send_arp <interface> <sender ip> <target ip>");
        return 1;
    }
    // Init
    interface = argv[1];
    ARP reqHeader = {ARPHRD_ETHER,ETHERTYPE_IP,6,4,ARPOP_REQUEST};

    return 0;
}

int *get_recover_time(pcap_t* pkDescriptor)
{
    char* buf;
    struct pcap_pkthdr* pktHeader;
    //pcap_next_ex(pkDescriptor, &pktHeader, &buf);

    return 0;
}
char* get_interface_mac(char* interface)
{
    FILE* fileDescriptor;
    char cmdBuffer[100];
    static char stringMAC[20];

    sprintf(cmdBuffer, "ip link show %s | awk '/ether/{printf $2}' > mac", interface);
    system(cmdBuffer);
    fileDescriptor = fopen("mac", "r");
    fgets(stringMAC, 18, fileDescriptor);
    system("rm -rf mac");
    fclose(fileDescriptor);
    return stringMAC;
}
