#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <libnet.h>
#include <pcap.h>
#include <pthread.h>
#include <arpa/inet.h>

#define SIMPLE_SENDER_MAC   {sender_mac[0],sender_mac[1],sender_mac[2],sender_mac[3],sender_mac[4],sender_mac[5]}
#define TIME_OUT            0xFF
#define MAX_IP_PACKET_SIZE  0xFFFF
#define NON_PROMISCUOUS     0

typedef struct libnet_802_3_hdr ETH;
typedef struct libnet_arp_hdr ARP;

int* get_recover_time(pcap_t* pkDescriptor);
char* get_interface_mac(char* interface);
uint8_t* str_to_mac(char* str);
uint32_t str_to_ip(char* str1);

int main(int argc, char** argv)
{
    char*   interface;
    char    errBuf[PCAP_ERRBUF_SIZE];
    uint8_t* sender_mac;
    uint32_t sender_ip, target_ip;
    uint8_t packet[42];
    pcap_t* pktDescriptor;

    if (argc != 4)
    {
        printf("Usage : send_arp <interface><register ip><target ip>\n");
        return 1;
    }
    // Initialize
    interface = argv[1];
    sender_mac = str_to_mac(get_interface_mac(interface));
    sender_ip = str_to_ip(argv[2]);
    target_ip = str_to_ip(argv[3]);

    ETH ethHeader = {
        "\xFF\xFF\xFF\xFF\xFF\xFF",
        SIMPLE_SENDER_MAC,
        htons(ETHERTYPE_ARP)
    };
    ARP reqHeader = {
        htons(ARPHRD_ETHER),htons(ETHERTYPE_IP),
        6,4,htons(ARPOP_REQUEST),
        SIMPLE_SENDER_MAC, htonl(sender_ip),
        {0,0,0,0,0,0}, htonl(target_ip)
    };

    pktDescriptor = pcap_open_live(interface, MAX_IP_PACKET_SIZE, NON_PROMISCUOUS, TIME_OUT, errBuf);

    if (!pktDescriptor)
    {
        printf(" [err] Can't open device. reason : %s\n", errBuf);
        return 1;
    }

    memcpy(packet, &ethHeader, 14);
    memcpy(packet+14, &reqHeader, 28);

    if (pcap_sendpacket(pktDescriptor, packet, 42))
    {
       printf("error!");
    }
    pcap_close(pktDescriptor);

    return 0;
}
uint8_t* str_to_mac(char* str)
{
    static uint8_t arr[6];

    sscanf(str,"%02x:%02x:%02x:%02x:%02x:%02x"
           ,&arr[0],&arr[1],&arr[2],&arr[3],&arr[4],&arr[5]);

    return arr;
}
uint32_t str_to_ip(char* str)
{
    uint8_t arr[4];
    uint32_t ipValue = 0;

    sscanf(str,"%d.%d.%d.%d"
           ,&arr[0],&arr[1],&arr[2],&arr[3]);
    ipValue = (arr[0]<<24) + (arr[1]<<16) + (arr[2]<<8) + (arr[3]);
    /*
    ipValue += (arr[0]<<24);
    ipValue += (arr[1]<<16);
    ipValue += (arr[2]<<8);
    ipValue += (arr[3]);
    */
    return ipValue;
}

int* get_recover_time(pcap_t* pktDescriptor)
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
