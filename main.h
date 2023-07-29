#include <cstdio>
#include <pcap.h>
#include "getAddress.cpp"
#include "ethhdr.h"
#include "arphdr.h"
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>

#pragma pack(push, 1)
struct EthArpPacket final
{
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage()
{
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}