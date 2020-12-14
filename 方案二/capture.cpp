#define WIN32
#define _CRT_SECURE_NO_WARNINGS
#include<fstream>
#include<stdio.h> 
#include<iostream>
#include<iomanip>
#include"pcap.h" 
#include"remote-ext.h" 
#include<conio.h>
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "wpcap.lib")

using namespace std;

ofstream txt("capture.txt");//打开一个名字为caputre的txt文件

int num = 0;//定义全局变量来记录ip的个数
// 以太网协议格式的定义 
typedef struct ether_header {
	u_char ether_dhost[6];      // 目标地址 
	u_char ether_shost[6];      // 源地址 
	u_short ether_type;         // 以太网类型 
}ether_header;

// 用户保存4字节的IP地址 
typedef struct ip_address{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;


// 用于保存IPV4的首部 

typedef struct ip_header{

#ifdef WORDS_BIGENDIAN	
	u_char ip_version : 4, header_length : 4;
#else 
	u_char header_length : 4, ip_version : 4;
#endif 
	u_char ver_ihl;     // 版本以及首部长度，各(4bit) ,由于字节序的缘故，这里定义的时候需要反过来
	u_char tos;         // 服务类型 
	u_short tlen;       // 总长度 
	u_short identification;     // 标识
	u_short offset;         //标志(3bit)+片偏移(13bit)
	u_char ttl;         // ttl
	u_char proto;       // 协议
	u_short checksum;       // 首部校验和 
	ip_address saddr;   //源地址 
	ip_address daddr;   //目的地址 
	u_int op_pad;       //可选填充字段 
}ip_header;


// 回调函数，当收到每一个数据包时会被libpcap所调用 
void ip_protocol_packet_handle(u_char* argument,const struct pcap_pkthdr* packet_header,const u_char* packet_content)
{

	struct ip_header* ip_protocol;
	u_int header_length;//版本+首部长度
	u_char tos;//服务类型
	u_short checksum;//首部校验和
	ip_address saddr;//源地址
	ip_address daddr;//目的地址
	u_char ttl;//ttl
	u_short tlen;//总长度
	u_short identification;//标识
	u_short offset;//标志(3bit)+片偏移(13bit)
	
	//MAC首部是14位的，加上14位得到IP首部  
	ip_protocol = (struct ip_header*)(packet_content + 14); //以太网头部长度
	//解析ip
	header_length = ip_protocol->header_length * 4;
	offset = ntohs(ip_protocol->offset);
	
	txt << "*************IP协议*************" << endl;
	txt << "  版本号         \t" << int(ip_protocol->ip_version) << endl;
	txt << "  首部长度       \t" << int(ip_protocol->header_length) << endl;
	txt << "  区分服务       \t" << (int)ntohs(ip_protocol->tos) << endl;
	txt << "  总长度         \t" << (int)ntohs(ip_protocol->tlen) << endl;
	txt << "  标识           \t" << (int)ntohs(ip_protocol->identification) << endl;
	txt << "  标志           \t" << setw(1) << setfill('0') << (int)((ntohs(ip_protocol->offset) & 0xE000) >> 13) << endl;
	txt << "  片偏移           \t" << setw(4) << setfill('0') << (int)(ntohs(ip_protocol->offset) & 0x1FFF) << endl;
	txt << "  生存时间       \t" << int(ip_protocol->ttl) << endl;
	txt << "  协议      \t\t" << setw(2) << setfill('0') << int(ip_protocol->proto) << endl;
	txt << "  首部校验和         \t" << setw(4) << setfill('0') << (int)ntohs((ip_protocol->checksum)) << endl;
	txt << "  源地址        \t" << (int)ip_protocol->saddr.byte1 << "." << (int)ip_protocol->saddr.byte2 << "." << (int)ip_protocol->saddr.byte3 << "." << (int)ip_protocol->saddr.byte4 << endl;
	txt << "  目的地址       \t" << (int)ip_protocol->daddr.byte1 << "." << (int)ip_protocol->daddr.byte2 << "." << (int)ip_protocol->daddr.byte3 << "." << (int)ip_protocol->daddr.byte4 << endl;
	txt << endl;

}




void ethernet_protocol_packet_handle(u_char* argument,const struct pcap_pkthdr* packet_header,const u_char* packet_content)
{
	u_short ethernet_type;      // 以太网类型 
	struct ether_header* ethernet_protocol;     // 以太网协议变量 
	u_char* mac_string;         // 以太网地址 
	ethernet_protocol = (struct ether_header*)packet_content;       //获取以太网数据内容 
	ethernet_type = ntohs(ethernet_protocol->ether_type);   // 获取以太网类型 

	if (ethernet_type == 0x800)
		num++;
	/*
		0x0800 : IP协议
		0x0806 : ARP协议
		0x8035 : RARP协议
		*/
	switch (ethernet_type) {
	case 0x0800:
		ip_protocol_packet_handle(argument, packet_header, packet_content);
		break;
	default:
		break;
	}

}



int main() {
	pcap_if_t* alldevs;
	pcap_if_t* d;
	pcap_t* adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	int inum;
	int i = 0;
	u_int netmask;
	char packet_filter[] = "ip and tcp";
	struct bpf_programfcode;
	int res;
	struct pcap_pkthdr* header;
	struct tm* ltime;
	const u_char* pkt_data;
	char timestr[16];
	struct bpf_program fcode;

	ip_header* ih;

	// 获得设备列表pcap_findalldevs_ex() 

	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
		fprintf(stderr, "Errorin pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}


	//打印设备列表
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description) 
		{
			printf("(%s)\n", d->description);
		}

		else
		{
			printf("No description available\n");
		}
	}



	if (i == 0)
	{
		printf("\nNo interface found!Make sure WinPcap is installed\n");
		return -1;
	}
	printf("Enter the interface number(1-%d):", i);
	scanf_s("%d", &inum);
	if (inum < 1 || inum > i) {
		printf("\nInterface number out of range.\n");
		pcap_freealldevs(alldevs);
		return -1;
	}

	// 跳转到该设备
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);
	//打开适配器 
	// 设备名，要捕捉的数据包的部分（65536保证能捕获到不同数据链路层上的每个数据包的全部内容），混杂模式，读取超时时间，错误缓冲池 

	if ((adhandle = pcap_open_live(d->name,// 设备名
		65536,	  // 要捕捉的数据包的部分,65535保证能捕获到不同数据链路层上的每个数据包的全部内容
		1,		 // 混杂模式
		1000,	 // 读取超时时间 
		errbuf	 //错误缓冲池 
	)) == NULL)
	{
		fprintf(stderr, "\nUnableto open the adapter.%s is not supported by WinPcap\n", errbuf);
		pcap_freealldevs(alldevs);
		return -1;

	}
	// 检查数据链路层（只考虑了以太网） 

	if (pcap_datalink(adhandle) != DLT_EN10MB) {
		fprintf(stderr, "\nThisprogram works only on Ethernet networks.\n");
		pcap_freealldevs(alldevs);
		return -1;
	}

	if (d->addresses != NULL) {
		//获得接口的第一个地址的掩码 
		netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	}
	else {
		netmask = 0xffffff;
	}

	
		// 编译过滤器
		if(pcap_compile(adhandle, &fcode,packet_filter, 1, netmask) < 0) 
		{
			fprintf(stderr, "\nUnable tocompile the packet filter.Check the syntax\n");
			pcap_freealldevs(alldevs);
			return -1;
		}
		// 设置过滤器
		if(pcap_setfilter(adhandle, &fcode)< 0) 
		{
			fprintf(stderr, "\nError settingthe filter.\n");
			pcap_freealldevs(alldevs);
			return -1;
		}

		printf("\nlistenting on %s...\n",d->description);

		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
	

		/* 开始捕捉 */
		time_t begin = time(NULL);
		time_t end = time(NULL);
		cout << "可以选择按下回车终止（可能会有延迟），也可以选择等待60s:" << endl;
		do {
			pcap_loop(adhandle, 1, ethernet_protocol_packet_handle, NULL);
			end = time(NULL);
			if (kbhit())
				break;
		} while (difftime(end, begin) <= 60);
		txt << "IP的个数 : " << num << endl;
	return 0;
}

	
   
 
