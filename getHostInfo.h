#include <stdio.h>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>

void getHostInfo(const char *, Ip *, Mac *);
bool getHostIpAddress(const char *, Ip *);
bool getHostMacAddress(const char *, Mac *);