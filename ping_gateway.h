#ifndef _PING_GATEWAY_H
#define _PING_GATEWAY_H

#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <unistd.h>
#include <error.h>
#include <string>

using std::string;

#define IPVERSION 4
#define ICMP_DATA_LEN 56

int packping(int sendsqe);
ushort checksum(unsigned char *buf, int len);
int decodepack(char *buf, int len);
float timesubtract(struct timeval *begin, struct timeval *end);
int get_gateway_addr(char *gateway_addr);

int GetGatewayAddr(char* gatewayAddr, string& devfile);
int PackPing(char* sendbuf, int seq);
ushort CheckSum(unsigned char* buf, int len);
int DecodePingPacket(char* buf, int len);
float TimeDiff(struct timeval* begin, struct timeval* end);

#endif
