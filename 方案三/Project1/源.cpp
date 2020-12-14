#define WIN32
#include<WinSock2.h>
#include "pcap.h"
#include <iomanip>
#include<stdio.h>
#include<time.h>
#include<fstream>
#include<iostream>
#include<conio.h>
#pragma comment(lib,"ws2_32.lib")
using namespace std;

#define MAX_PRINT 80
#define MAX_LINE 16
ofstream OpenTxt("Capture.txt");//打开一个叫做"Capture"的txt文件
int ipNum = 0;//定义一个全局变量来对ip进行计数


//以太网协议格式
struct ether_header
{
	u_int8_t ether_dhost[6]; //目的Mac地址   
	u_int8_t ether_shost[6]; //源Mac地址   
	u_int16_t ether_type;    //协议类型   
};


struct ip_header//IPv4的首部
{
#if defined(WORDS_BIENDIAN)   
	u_int8_t   ip_version : 4,
		ip_header_length : 4;
#else   
	//由于字节序的缘故，这里定义的时候需要反过来
	u_int8_t   ip_header_length : 4,//首部长度
		ip_version : 4;//版本
#endif   
	u_int8_t    ip_tos;//服务类型
	u_int16_t   ip_length;//总长度
	u_int16_t   ip_id;//标识
	u_int16_t   ip_off;//标志(3bit)+片偏移(13bit)
	u_int8_t    ip_ttl;//ttl
	u_int8_t    ip_protocol;//协议
	u_int16_t   ip_checksum;//首部校验和
	struct in_addr ip_souce_address;//源地址
	struct in_addr ip_destination_address;//目的地址
};


/* 回调函数原型 */
void ip_protool_packet_callback(u_char*, const struct pcap_pkthdr*, const u_char*);

void ethernet_protocol_packet_callback(u_char* argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content)
{
	u_short ethernet_type;
	struct ether_header* ethernet_protocol;
	u_char* mac_string;


	ethernet_protocol = (struct ether_header*)packet_content;//获得数据包内容   
	ethernet_type = ntohs(ethernet_protocol->ether_type);//获得以太网类型   
	/*
	0x0800 : IP协议
	0x0806 : ARP协议
	0x8035 : RARP协议
	*/


	if (ethernet_type == 0x0800)//分析IP协议   
	{
		ip_protool_packet_callback(argument, packet_header, packet_content);
	}
	ipNum++;
	
}


void ip_protool_packet_callback(u_char* argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content)
{
	struct ip_header* ip_protocol;
	u_int header_length;
	u_int offset;
	u_char tos;
	u_int16_t checksum;
	//MAC首部是14位的，加上14位得到IP协议首部   
	ip_protocol = (struct ip_header*) (packet_content + 14);//以太网头部长度
	checksum = ntohs(ip_protocol->ip_checksum);
	tos = ip_protocol->ip_tos;
	offset = ntohs(ip_protocol->ip_off);
	


	///打印IP数据报头信息
	OpenTxt << "--------------IP协议--------------" << endl;
	OpenTxt << "  版本号         \t" << int(ip_protocol->ip_version) << endl;
	OpenTxt << "  首部长度       \t" << int(ip_protocol->ip_header_length) << endl;
	OpenTxt << "  区分服务       \t" << (int)ntohs(tos) << endl;
	OpenTxt << "  总长度         \t" << (int)ntohs(ip_protocol->ip_length) << endl;
	OpenTxt << "  标识           \t" << (int)ntohs(ip_protocol->ip_id) << endl;
	OpenTxt << "  标志           \t" << setw(1) << setfill('0') << (int)((ntohs(ip_protocol->ip_off) & 0xE000) >> 13) << endl;
	OpenTxt << "  片偏移           \t" << setw(4) << setfill('0') << (int)(ntohs(ip_protocol->ip_off) & 0x1FFF) << endl;
	OpenTxt << "  生存时间       \t" << int(ip_protocol->ip_ttl) << endl;
	OpenTxt << "  协议       \t\t" << setw(2) << setfill('0') << int(ip_protocol->ip_protocol) << endl;
	OpenTxt << "  首部校验和         \t" << setw(4) << setfill('0') << (int)ntohs(checksum) << endl;
	OpenTxt << "  源地址      \t" << (inet_ntoa)(ip_protocol->ip_souce_address) << endl;
	OpenTxt << "  目的地址        \t" << (inet_ntoa)(ip_protocol->ip_destination_address) << endl;
	OpenTxt << endl;

}


int main()
{
	pcap_t* fp;
	pcap_if_t* alldev, * d;
	char errbuf[3000];
	u_char user[3000];
	int retval, i, inum;
	bpf_u_int32 net_mask; //掩码地址   
	bpf_u_int32 net_ip;  //网络地址   
	struct bpf_program bpf_filter;//BPF过滤规则   
	char bpf_filter_string[] = "ip";


	//获取设备列表
	retval = pcap_findalldevs(&alldev, errbuf);
	
	//打印设备列表
	if (retval == -1)
	{
		printf("find all devs failed\n");
	}
	i = 0;
	for (d = alldev; d != NULL; d = d->next)
	{
		printf("%d. %s", i, d->name);
		i++;
		if (d->description == NULL)
		{
			printf("description: none\n");

		}
		else
		{
			printf("description: %s\n", d->description);
		}
	}
	if (i == 0)
	{
		printf("no network dev avaliable\n");
	}
	printf("\nEnter a number:（ 0 ~ %d )",i - 1);
	scanf("%d", &inum);

	// 跳转到已选设备 
	for (d = alldev, i = 0; i < inum; d = d->next, i++);
		
	//打开适配器
	memset(errbuf, 0, sizeof(errbuf));
	fp = pcap_open_live(d->name, 65535, 1, 1000, errbuf);
	if (fp == NULL)
	{
		printf("open failed\n");
	}
	
	pcap_lookupnet(d->name, &net_ip, &net_mask, errbuf);
	pcap_compile(fp, &bpf_filter, bpf_filter_string, 0, net_mask);
	pcap_setfilter(fp, &bpf_filter);
	time_t start = time(NULL);
	time_t end = time(NULL);
	cout << "可以选择按下回车终止(可能会有延迟），也可以选择等待60s:" << endl;
	do {
		retval = pcap_loop(fp, 1, ethernet_protocol_packet_callback, user);
		//pcap_loop(fp, 1, ethernet_protocol_packet_callback,NULL);
		end = time(NULL);
		if (kbhit())
			break;
	} while (difftime(end, start) <= 60);
OpenTxt << "IP的个数 : " << ipNum << endl;

	return 0;
}
