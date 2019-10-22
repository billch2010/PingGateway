#include "ping_gateway.h"
#include <stdio.h>
#include <string.h>
#include <netdb.h>            // struct icpmhdr, struct iphdr , gethostbyname, hostent
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/time.h>
#include <ctype.h>
#include <signal.h>

#include <iostream>
#include <vector>
#include <map>
#include <string>
#include <fstream>
//#include <ifstream>


using namespace std;

int main(int argc, char const *argv[])
{
    if(argc != 2){
        fprintf(stderr, "Usage: ping <remote_hostname>\n", argv[0]);
        exit(1);
    }

char gateway[32] = {0};
//string devfile = "\/etc\/sysconfig\/network-scripts\/ifcfg-eth1";
string devfile = "/etc/sysconfig/network-scripts/ifcfg-eth1";
GetGatewayAddr(gateway, devfile);
cout << "eth1 gateway: " << gateway << endl;

get_gateway_addr(gateway);
cout << "eth1 gateway: " << gateway << endl;

    int on = 1;
    int pid;

    char sendbuf[1024];          // 用来存放将要发送的ip数据包
    struct sockaddr_in sockaddr, recvsock;
    int sockaddr_len = sizeof(struct sockaddr);
    struct hostent *host;
    int sockfd;
    int ping_time = 5;
    memset(&sockaddr, 0, sizeof(struct sockaddr));
    if((sockaddr.sin_addr.s_addr = inet_addr(argv[1])) == INADDR_NONE){
        // 说明输入的主机名不是点分十进制,采用域名方式解析
        if((host = gethostbyname(argv[1])) == NULL){
            fprintf(stderr, "ping %s , 未知的名称!\n", argv[1]);
            exit(1);
        }
        sockaddr.sin_addr = *(struct in_addr *)(host->h_addr);
    }
    sockaddr.sin_family = AF_INET;


    // 创建原始套接字 SOCK_RAW 协议类型 IPPROTO_ICMP
    if((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1){
        fprintf(stderr, "%s\n", strerror(errno));
//        return -1;
    }

    setuid(getpid());
    pid = getpid();

    // 发包操作
    printf("PINGing %s %d data send.\n", argv[1], ICMP_DATA_LEN);
    int i = 1;
    int recvDataLen;
    int sendDatalen;
    char recvbuf[1024];
    while(ping_time--){
        int packlen = PackPing(sendbuf, i++);
        if((sendDatalen = sendto(sockfd, sendbuf, packlen,0, (struct sockaddr *)&sockaddr, sizeof(sockaddr))) < 0){
             fprintf(stderr, "send ping package %d error, %s\n", i, strerror(errno));
             continue ;
        }

        if((recvDataLen = recvfrom(sockfd, recvbuf, sizeof(recvbuf), 0, (struct sockaddr *)&recvsock, (socklen_t*)&sockaddr_len)) == -1){
            fprintf(stderr, "recvmsg error, %s\n", strerror(errno));
             continue ;
        }
//
//        if((recvDataLen = recvfrom(sockfd, recvbuf, sizeof(recvbuf), 0, (struct sockaddr *)&recvsock, (socklen_t*)&sockaddr_len)) == -1){
//            fprintf(stderr, "recvmsg error, %s\n", strerror(errno));
//            continue;
//        }
        DecodePingPacket(recvbuf, recvDataLen);
        sleep(1);
    }


    return 0;
}

// 发送ping数据包
int PackPing(char* sendbuf, int seq){
    struct icmp *icmp_hdr;  // icmp头部指针
    icmp_hdr = (struct icmp *)sendbuf;
    icmp_hdr->icmp_type = ICMP_ECHO;
    icmp_hdr->icmp_code = 0;
    icmp_hdr->icmp_hun.ih_idseq.icd_id = getpid();
    icmp_hdr->icmp_hun.ih_idseq.icd_seq = seq;
    memset(icmp_hdr->icmp_data, 0, ICMP_DATA_LEN);
    gettimeofday((struct timeval *)icmp_hdr->icmp_data, NULL);

    int icmp_total_len = 8 + ICMP_DATA_LEN;

    icmp_hdr->icmp_cksum = 0;
    icmp_hdr->icmp_cksum = CheckSum((unsigned char *)(sendbuf), icmp_total_len);

    return icmp_total_len;
}

int DecodePingPacket(char *buf, int len){
    struct iphdr *ip_hdr;
    struct icmp *icmp_hdr;
    int iph_lenthg;
    float rtt; // 往返时间  
    struct timeval end; // 接收报文时的时间戳

    ip_hdr = (struct iphdr *)buf;
    // ip头部长度
    iph_lenthg = ip_hdr->ihl<<2;
    
    icmp_hdr = (struct icmp *)(buf + iph_lenthg);

    // icmp报文的长度
    len -= iph_lenthg;
    if(len < 8){
        fprintf(stderr, "Icmp package length less 8 bytes , error!\n");
        return -1;
    }

    // 确认是本机发出的icmp报文的响应
    if(icmp_hdr->icmp_type != ICMP_ECHOREPLY || icmp_hdr->icmp_hun.ih_idseq.icd_id != getpid()){
        fprintf(stderr, "Don't send to us!");
        return -1;
    }
    gettimeofday(&end, NULL);
    rtt = timesubtract((struct timeval *)&icmp_hdr->icmp_data, &end);
//    printf("Received %d bytes from %s, ttl = %d, rtt = %f ms, icmpseq = %d \n", len, inet_ntoa(recvsock.sin_addr),ip_hdr->ttl, rtt, icmp_hdr->icmp_seq);
    printf("Received %d bytes, ttl = %d, rtt = %f ms, icmpseq = %d \n", len, ip_hdr->ttl, rtt, icmp_hdr->icmp_seq);

    return 0;
}

// 计算时间差
float timesubtract(struct timeval *begin, struct timeval *end){
    int n;// 先计算两个时间点相差多少微秒
    n = ( end->tv_sec - begin->tv_sec ) * 1000000
        + ( end->tv_usec - begin->tv_usec );
    // 转化为毫秒返回
    return (float) (n / 1000);
}

float TimeDiff(struct timeval *begin, struct timeval *end){
    int n;// 先计算两个时间点相差多少微秒
    n = ( end->tv_sec - begin->tv_sec ) * 1000000
        + ( end->tv_usec - begin->tv_usec );
    // 转化为毫秒返回
    return (float) (n / 1000);
}

// 校验和生成
ushort CheckSum(unsigned char *buf, int len){
    unsigned int sum=0;
    unsigned short *cbuf;

    cbuf=(unsigned short *)buf;

    while(len>1){
        sum+=*cbuf++;
        len-=2;
    }

    if(len)
        sum+=*(unsigned char *)cbuf;

    sum=(sum>>16)+(sum & 0xffff);
    sum+=(sum>>16);

    return ~sum;
}

int get_gateway_addr(char *gateway_addr)
{
    char buff[256];
    int  nl = 0 ;
    struct in_addr gw;
    int flgs, ref, use, metric;
    unsigned long int d,g,m;
    unsigned long addr;
    
    FILE *fp = NULL;
    
    fp = fopen("/proc/net/route", "r");
    if (fp == NULL)
    {
        return -1;
    }
        
    nl = 0 ;
    memset(buff, 0,sizeof(buff));
    while( fgets(buff, sizeof(buff), fp) != NULL ) 
    {
        if(nl) 
        {
            int ifl = 0;
            while(buff[ifl]!=' ' && buff[ifl]!='\t' && buff[ifl]!='\0')
                ifl++;
            buff[ifl]=0;    /* interface */
            if(sscanf(buff+ifl+1, "%lx%lx%X%d%d%d%lx",
                   &d, &g, &flgs, &ref, &use, &metric, &m)!=7) 
            {
                fclose(fp);
                return -2;
            }

            ifl = 0;        /* parse flags */
            //if(flgs&RTF_UP) 
            //{            
                gw.s_addr   = g;
                    
                if(d==0)
                {
                    strcpy(gateway_addr, inet_ntoa(gw));
                    fclose(fp);
                    return 0;
                }                
            //}
        }
        nl++;
    }    
    
    if(fp)
    {
        fclose(fp);
        fp = NULL;
    }
    
    return    -1;
}

static int split_string(const string& str,vector<string>& vec,const string& deli)
{
    vec.clear();
    if(str.empty())
    {
        return 0;
    }

    string::size_type idxA=0,idxB=0;
    while(idxB != string::npos)
    {
        idxB = str.find(deli,idxA);
        if(idxB != string::npos)
        {
            vec.push_back(str.substr(idxA,idxB-idxA));
            idxB += deli.size();
        }
        else
        {
            vec.push_back(str.substr(idxA,str.size()-idxA));
        }
        idxA = idxB;
    }

    return vec.size();
}

static std::istream& safeGetline(std::istream& is, std::string& t)
{
    t.clear();

    // The characters in the stream are read one-by-one using a std::streambuf.
    // That is faster than reading them one-by-one using the std::istream.
    // Code that uses streambuf this way must be guarded by a sentry object.
    // The sentry object performs various tasks,
    // such as thread synchronization and updating the stream state.

    std::istream::sentry se(is, true);
    std::streambuf* sb = is.rdbuf();

    for(;;) {
        int c = sb->sbumpc();
        if (c == '\n')
        {
            return is;
        }
        else if (c == '\r')
        {
            return is;
        }
        else if (c == std::streambuf::traits_type::eof())
        {
            if(t.empty())
                is.setstate(std::ios::eofbit);
            return is;
        }
        else
        {
            t += (char)c;
        }
    }
}

void readFile(const string& filePath, map<string, string>& fileConf, string deli)
{
    std::string path = filePath;

    ifstream ifs(path);
    if(!ifs) {
        printf("failed to open the file :%s.", path.c_str());
        return;
    }

    fileConf.clear();
    std::string s;

    vector<string> tmp;
    while(!safeGetline(ifs, s).eof())
    {
        split_string(s, tmp, deli);
        if (tmp.size() != 2)
        {
            continue;
        }
        fileConf.insert(make_pair(tmp[0], tmp[1]));
        printf("get conf %s\t\t\t%s\t%s\n", tmp[0].c_str(), deli.c_str(), tmp[1].c_str());

        s = "";
    }

    printf("\n\n");
}

int GetGatewayAddr(char* gatewayAddr, string& devfile)
{
	if (devfile.empty()) return -1;
	map<string, string> infos;
	readFile(devfile, infos, "=");
	
	map<string, string>::iterator iter;
	iter = infos.find("GATEWAY");
	if (iter == infos.end()) {
		fprintf(stderr, "GATEWAY not found in %s", devfile.c_str());
		return -1;
	}
	string strGateway = iter->second.substr(1, iter->second.length() -2);	
        memcpy(gatewayAddr, strGateway.c_str(), strGateway.length()+1);
	return 0;
}
