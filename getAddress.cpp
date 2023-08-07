#include "getAddress.h"

int getMACAddress(const char *interfaceName, unsigned char *macAddress)
{
	int sockfd;
	struct ifreq ifr;

	// 소켓 생성
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0)
	{
		perror("socket");
		return -1;
	}

	// 인터페이스 이름 설정
	strncpy(ifr.ifr_name, interfaceName, IFNAMSIZ - 1);
	ifr.ifr_name[IFNAMSIZ - 1] = '\0';

	// MAC 주소 가져오기
	if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) == -1)
	{
		perror("ioctl");
		close(sockfd);
		return -1;
	}

	// MAC 주소 복사
	memcpy(macAddress, ifr.ifr_hwaddr.sa_data, 6);

	close(sockfd);
	return 0;
}


int getIPAddress(const char *interfaceName, char *ipAddress)
{
	int sockfd;
	struct ifreq ifr;

	// 소켓 생성
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0)
	{
		perror("socket");
		return -1;
	}

	// 인터페이스 이름 설정
	strncpy(ifr.ifr_name, interfaceName, IFNAMSIZ - 1);
	ifr.ifr_name[IFNAMSIZ - 1] = '\0';

	// IP 주소 가져오기
	if (ioctl(sockfd, SIOCGIFADDR, &ifr) == -1)
	{
		perror("ioctl");
		close(sockfd);
		return -1;
	}

	// IP 주소 복사
	struct sockaddr_in *addr_in = (struct sockaddr_in *)&ifr.ifr_addr;
	const char *ip = inet_ntoa(addr_in->sin_addr);
	memcpy(ipAddress, ip, 16);

	close(sockfd);
	return 0;
}