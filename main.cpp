#include <iostream>
#include <pcap.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include "net/if.h"
#include <cstdio>
#include <string.h>
#include "sys/ioctl.h"
#define broads=0xFFFFFFFF;
using namespace std;

class Eths
{
public:
    uint8_t destination[6];
    uint8_t source[6];
    uint16_t eth_type;
};
class Arps
{
public:
    uint16_t hartype;
    uint16_t protype;
    uint8_t hardsize;
    uint8_t prosize;
    uint16_t opcode;
    uint8_t sendermac[6];
    uint8_t senderip[4];
    uint8_t targetmac[6];
    uint8_t targetip[4];
};
unsigned char cMacAddr[8]; // Server's MAC address
static int GetSvrMacAddress( char *pIface )
{
    int nSD; // Socket descriptor
    struct ifreq sIfReq; // Interface request
    struct if_nameindex *pIfList; // Ptr to interface name index
    struct if_nameindex *pListSave; // Ptr to interface name index

    //
    // Initialize this function
    //
    pIfList = (struct if_nameindex *)NULL;
    pListSave = (struct if_nameindex *)NULL;
#ifndef SIOCGIFADDR
    // The kernel does not support the required ioctls
    return( 0 );
#endif

    //
    // Create a socket that we can use for all of our ioctls
    //
    nSD = socket( PF_INET, SOCK_STREAM, 0 );
    if ( nSD < 0 )
    {
        // Socket creation failed, this is a fatal error
        printf( "File %s: line %d: Socket failed\n", __FILE__, __LINE__ );
        return( 0 );
    }

    //
    // Obtain a list of dynamically allocated structures
    //
    pIfList = pListSave = if_nameindex();

    //
    // Walk thru the array returned and query for each interface's
    // address
    //
    for ( pIfList; *(char *)pIfList != 0; pIfList++ )
    {
        //
        // Determine if we are processing the interface that we
        // are interested in
        //
        if ( strcmp(pIfList->if_name, pIface) )
            // Nope, check the next one in the list
            continue;
        strncpy( sIfReq.ifr_name, pIfList->if_name, IF_NAMESIZE );

        //
        // Get the MAC address for this interface
        //
        if ( ioctl(nSD, SIOCGIFHWADDR, &sIfReq) != 0 )
        {
            // We failed to get the MAC address for the interface
            printf( "File %s: line %d: Ioctl failed\n", __FILE__, __LINE__ );
            return( 0 );
        }
        memmove( (void *)&cMacAddr[0], (void *)&sIfReq.ifr_ifru.ifru_hwaddr.sa_data[0], 6 );
        break;
    }

    //
    // Clean up things and return
    //

    // if_freenameindex( pListSave );    ??
    // close( nSD ); ??
    return( 1 );
}

int main( int argc, char * argv[] )
{
    uint8_t gatemac[6];
    Arps* arp;
    char *dev;
    dev="ens33";
    struct pcap_pkthdr *header;
    bzero( (void *)&cMacAddr[0], sizeof(cMacAddr) );
    if ( !GetSvrMacAddress(dev) )
    {
        // We failed to get the local host's MAC address
        printf( "Fatal error: Failed to get local host's MAC address\n" );
    }
    printf( "HWaddr %02X:%02X:%02X:%02X:%02X:%02X\n",
            cMacAddr[0], cMacAddr[1], cMacAddr[2],
            cMacAddr[3], cMacAddr[4], cMacAddr[5] );

    //up to Mac

    int res;
    u_char packet[42];
    Eths *eth;
    const u_char *repacket;
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);//피캣오픈픈
    if (handle == NULL) {

        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }
    for(int i=0;i<6;i++)
        packet[i]=255;
    for(int i=6;i<12;i++)
        packet[i]=cMacAddr[i-6];
    packet[12]=8;
    packet[13]=6;
    //eth setting
    packet[14]=0;
    packet[15]=1;
    packet[16]=8;
    packet[17]=0;
    packet[18]=6;
    packet[19]=4;
    packet[20]=0;
    packet[21]=1;
    for(int i=22;i<28;i++)
        packet[i]=packet[i-16];
    //senderip
    packet[28]=192;
    packet[29]=168;
    packet[30]=92;
    packet[31]=2;
    for(int i=32;i<6;i++)
        packet[i]=0;
    packet[38]=192;
    packet[39]=168;
    packet[40]=92;
    packet[41]=137;



    if (pcap_sendpacket(handle, packet, sizeof( packet )) != 0)
        printf("error\n");
    while((res = pcap_next_ex(handle, &header,&repacket)) >= 0){

        if(res == 0)
        {
             printf("skips\n");
            if (pcap_sendpacket(handle, packet, sizeof( packet )) != 0)

                printf("error\n");
            /* Timeout elapsed */
            continue;
        }
        if(packet!=NULL)
        {
            eth=(Eths*)packet;
            if(ntohs(eth->eth_type)==1544)
            {
                arp=(Arps*)(packet+14);
                for(int i=0;i<6;i++)
                    gatemac[i]=arp->sendermac[i];
                for(int i=0;i<6;i++)
                    printf("macmac : %02x ,",gatemac[i]);
            }
        }
    }

    return 0;
}



