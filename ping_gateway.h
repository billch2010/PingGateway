#ifndef _PING_GATEWAY_H
#define _PING_GATEWAY_H

#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <unistd.h>
#include <error.h>

#define IPVERSION 4
#define ICMP_DATA_LEN 56

int packping(int sendsqe);
ushort checksum(unsigned char *buf, int len);
int decodepack(char *buf, int len);
float timesubtract(struct timeval *begin, struct timeval *end);
int get_gateway_addr(char *gateway_addr);

#endif