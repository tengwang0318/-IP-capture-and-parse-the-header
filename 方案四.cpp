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

ofstream Open_txt("ip_capture.txt");//打开一个叫做ip_capture的txt文本
int ip_num = 0;//定义一个全局变量进行统计IP数据报的个数


//以太网协议格式
struct ethernet_header {
	u_int8_t ether_dhost[6];//目的以太网地址
	u_int8_t ether_shost[6];//源以太网地址
	u_int16_t ether_type;//以太网类型
};
/* 4字节的IP地址 */
typedef struct ip_address
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
} ip_address;

/* IPv4 首部 */
typedef struct ip_header
{
	//u_char  ver_ihl;        // 版本 (4 bits) + 首部长度 (4 bits)

	u_char  ihl : 4, ver : 4;///注意：由于字节序的缘故，这里定义的时候需要反过来
	u_char  tos;            // 服务类型
	u_short tlen;           // 总长
	u_short identification; // 标识
	u_short flags_fo;       // 标志位 (3 bits) + 段偏移量 (13 bits)

	u_char  ttl;            // 存活时间
	u_char  proto;          // 协议
	u_short crc;            // 首部校验和
	ip_address  saddr;      // 源地址
	ip_address  daddr;      // 目的地址
	u_int   op_pad;         // 选项与填充
} ip_header;


typedef struct tcp_header
{
	u_short sport;
	u_short dport;
	u_long seq;
	u_long ack;
	//u_short doff:4,hlen:4,fin:1,syn:1,rst:1,psh:1,ack:1,urg:1;
	u_short all;
	u_short win;
	u_short crc;
	u_short urgp;
	u_long op_pd;

}tcp_header;


/* 回调函数原型 */
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);

void ethernet_protocol_packet_callback(u_char* argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content)
{
	u_short ethernet_type;/*以太网协议类型*/
	struct ethernet_header* ethernet_protocol;/*以太网协议变量*/
	u_char* mac_string;
	ethernet_protocol = (struct ethernet_header*) packet_content;/*获得一太网协议数据内容*/
	ethernet_type = ntohs(ethernet_protocol->ether_type); /*获得以太网类型*/
	if (ethernet_type == 0x0800) //0x8000时为IP协议包
		ip_num++;
	

	switch (ethernet_type)////0x8000时为IP协议包
	{
	case 0x0800:
		/*如果上层是IPv4ip协议,就调用分析ip协议的函数对ip包进行分析*/
		packet_handler(argument, packet_header, packet_content);
		break;
	default:break;
	}

}

int main()
{
	pcap_if_t* alldevs;
	pcap_if_t* d;
	int inum;
	int i = 0;
	pcap_t* adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask;



	char packet_filter[] = "ip and tcp";
	struct bpf_program fcode;

	/* 获得设备列表 */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* 打印列表 */
	for (d = alldevs; d; d = d->next)
	{
		printf("\n%d. %s", ++i, d->name);
		if (d->description)
			printf("\n(%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	printf("Enter the interface number (1-%d):", i);
	scanf("%d", &inum);

	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* 跳转到已选设备 */
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	/* 打开适配器 */
	if ((adhandle = pcap_open(d->name,  // 设备名
		65536,     // 要捕捉的数据包的部分
		// 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
		PCAP_OPENFLAG_PROMISCUOUS,         // 混杂模式
		1000,      // 读取超时时间
		NULL,      // 远程机器验证
		errbuf     // 错误缓冲池
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* 检查数据链路层，为了简单，只考虑以太网 */
	if (pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}

	if (d->addresses != NULL)
		/* 获得接口第一个地址的掩码 */
		netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* 如果接口没有地址，那么我们假设一个C类的掩码 */
		netmask = 0xffffff;


	//编译过滤器
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0)
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}

	//设置过滤器
	if (pcap_setfilter(adhandle, &fcode) < 0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("\nlistening on %s...\n", d->description);

	/* 释放设备列表 */
	pcap_freealldevs(alldevs);
	
	/* 开始捕捉 */
	time_t start = time(NULL);
	time_t end = time(NULL);
	cout << "可以选择按下回车终止(可能由于网络原因，会有延迟），也可以选择等待60s:" << endl;
	for (;difftime(end, start) <= 60;)
	{
		pcap_loop(adhandle, 1, ethernet_protocol_packet_callback, NULL);
		end = time(NULL);
		if (kbhit())
			goto loop;
	}
loop:	Open_txt << "IP的个数 : " << ip_num << endl;
	return 0;
}





/* 回调函数，当收到每一个数据包时会被libpcap所调用 */
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	ip_header* ih;
	tcp_header* th;
	u_int ip_len;
	u_short sport, dport;



	/* 获得IP数据包头部的位置 */
	ih = (ip_header*)(pkt_data + 14); //以太网头部长度


	
	/*
	///打印IP数据报头信息
	cout << "  版本号         " << int(ih->ver) << endl;
	cout << "  首部长度       " << int(ih->ihl) << endl;
	cout << "  服务质量       " << ntohs(ih->tos) << endl;
	cout << "  总长度         " << ntohs(ih->tlen) << endl;
	cout << "  标识          " << ntohs(ih->identification) << endl;
	cout << "  标志          " << setw(1) << setfill('0') << ((ntohs(ih->flags_fo) & 0xE000) >> 13) << endl;
	cout << "  偏移          " << setw(4) << setfill('0') << (ntohs(ih->flags_fo) & 0x1FFF) << endl;
	cout << "  生存时间       " << int(ih->ttl) << endl;
	cout << "  协议类型       " << setw(2) << setfill('0') << int(ih->proto) << endl;
	cout << "  校验和         " << setw(4) << setfill('0') << ntohs(ih->crc) << endl;

	printf("源地址:\t%d.%d.%d.%d -> 目的地址: %d.%d.%d.%d\n",
		ih->saddr.byte1, ih->saddr.byte2, ih->saddr.byte3, ih->saddr.byte4,
		ih->daddr.byte1, ih->daddr.byte2, ih->daddr.byte3, ih->daddr.byte4);
	cout << endl;
	cout << endl;

	*/

	///打印IP数据报头信息
	Open_txt << "--------------IP协议--------------" << endl;
	Open_txt << "  版本号         \t" << int(ih->ver) << endl;
	Open_txt << "  首部长度       \t" << int(ih->ihl) << endl;
	Open_txt << "  区分服务       \t" << (int)ntohs(ih->tos) << endl;
	Open_txt << "  总长度         \t" << (int)ntohs(ih->tlen) << endl;
	Open_txt << "  标识           \t" << (int)ntohs(ih->identification) << endl;
	Open_txt << "  标志           \t" << setw(1) << setfill('0') << (int)((ntohs(ih->flags_fo) & 0xE000) >> 13) << endl;
	Open_txt << "  片偏移           \t" << setw(4) << setfill('0') << (int)(ntohs(ih->flags_fo) & 0x1FFF) << endl;
	Open_txt << "  生存时间       \t" << int(ih->ttl) << endl;
	Open_txt << "  协议      \t\t" << setw(2) << setfill('0') << int(ih->proto) << endl;
	Open_txt << "  首部校验和         \t" << setw(4) << setfill('0') << (int)ntohs(ih->crc) << endl;
	Open_txt << "  源地址        \t" << (int)ih->saddr.byte1 << "." << (int)ih->saddr.byte2 << "." << (int)ih->saddr.byte3 << "." << (int)ih->saddr.byte4  << endl;
	Open_txt <<	"  目的地址       \t" << (int)ih->daddr.byte1 << "." << (int)ih->daddr.byte2 << "." << (int)ih->daddr.byte3 << "." << (int)ih->daddr.byte4 << endl;
	Open_txt << endl;


}
