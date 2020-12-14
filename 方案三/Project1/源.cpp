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
ofstream OpenTxt("Capture.txt");//��һ������"Capture"��txt�ļ�
int ipNum = 0;//����һ��ȫ�ֱ�������ip���м���


//��̫��Э���ʽ
struct ether_header
{
	u_int8_t ether_dhost[6]; //Ŀ��Mac��ַ   
	u_int8_t ether_shost[6]; //ԴMac��ַ   
	u_int16_t ether_type;    //Э������   
};


struct ip_header//IPv4���ײ�
{
#if defined(WORDS_BIENDIAN)   
	u_int8_t   ip_version : 4,
		ip_header_length : 4;
#else   
	//�����ֽ����Ե�ʣ����ﶨ���ʱ����Ҫ������
	u_int8_t   ip_header_length : 4,//�ײ�����
		ip_version : 4;//�汾
#endif   
	u_int8_t    ip_tos;//��������
	u_int16_t   ip_length;//�ܳ���
	u_int16_t   ip_id;//��ʶ
	u_int16_t   ip_off;//��־(3bit)+Ƭƫ��(13bit)
	u_int8_t    ip_ttl;//ttl
	u_int8_t    ip_protocol;//Э��
	u_int16_t   ip_checksum;//�ײ�У���
	struct in_addr ip_souce_address;//Դ��ַ
	struct in_addr ip_destination_address;//Ŀ�ĵ�ַ
};


/* �ص�����ԭ�� */
void ip_protool_packet_callback(u_char*, const struct pcap_pkthdr*, const u_char*);

void ethernet_protocol_packet_callback(u_char* argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content)
{
	u_short ethernet_type;
	struct ether_header* ethernet_protocol;
	u_char* mac_string;


	ethernet_protocol = (struct ether_header*)packet_content;//������ݰ�����   
	ethernet_type = ntohs(ethernet_protocol->ether_type);//�����̫������   
	/*
	0x0800 : IPЭ��
	0x0806 : ARPЭ��
	0x8035 : RARPЭ��
	*/


	if (ethernet_type == 0x0800)//����IPЭ��   
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
	//MAC�ײ���14λ�ģ�����14λ�õ�IPЭ���ײ�   
	ip_protocol = (struct ip_header*) (packet_content + 14);//��̫��ͷ������
	checksum = ntohs(ip_protocol->ip_checksum);
	tos = ip_protocol->ip_tos;
	offset = ntohs(ip_protocol->ip_off);
	


	///��ӡIP���ݱ�ͷ��Ϣ
	OpenTxt << "--------------IPЭ��--------------" << endl;
	OpenTxt << "  �汾��         \t" << int(ip_protocol->ip_version) << endl;
	OpenTxt << "  �ײ�����       \t" << int(ip_protocol->ip_header_length) << endl;
	OpenTxt << "  ���ַ���       \t" << (int)ntohs(tos) << endl;
	OpenTxt << "  �ܳ���         \t" << (int)ntohs(ip_protocol->ip_length) << endl;
	OpenTxt << "  ��ʶ           \t" << (int)ntohs(ip_protocol->ip_id) << endl;
	OpenTxt << "  ��־           \t" << setw(1) << setfill('0') << (int)((ntohs(ip_protocol->ip_off) & 0xE000) >> 13) << endl;
	OpenTxt << "  Ƭƫ��           \t" << setw(4) << setfill('0') << (int)(ntohs(ip_protocol->ip_off) & 0x1FFF) << endl;
	OpenTxt << "  ����ʱ��       \t" << int(ip_protocol->ip_ttl) << endl;
	OpenTxt << "  Э��       \t\t" << setw(2) << setfill('0') << int(ip_protocol->ip_protocol) << endl;
	OpenTxt << "  �ײ�У���         \t" << setw(4) << setfill('0') << (int)ntohs(checksum) << endl;
	OpenTxt << "  Դ��ַ      \t" << (inet_ntoa)(ip_protocol->ip_souce_address) << endl;
	OpenTxt << "  Ŀ�ĵ�ַ        \t" << (inet_ntoa)(ip_protocol->ip_destination_address) << endl;
	OpenTxt << endl;

}


int main()
{
	pcap_t* fp;
	pcap_if_t* alldev, * d;
	char errbuf[3000];
	u_char user[3000];
	int retval, i, inum;
	bpf_u_int32 net_mask; //�����ַ   
	bpf_u_int32 net_ip;  //�����ַ   
	struct bpf_program bpf_filter;//BPF���˹���   
	char bpf_filter_string[] = "ip";


	//��ȡ�豸�б�
	retval = pcap_findalldevs(&alldev, errbuf);
	
	//��ӡ�豸�б�
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
	printf("\nEnter a number:�� 0 ~ %d )",i - 1);
	scanf("%d", &inum);

	// ��ת����ѡ�豸 
	for (d = alldev, i = 0; i < inum; d = d->next, i++);
		
	//��������
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
	cout << "����ѡ���»س���ֹ(���ܻ����ӳ٣���Ҳ����ѡ��ȴ�60s:" << endl;
	do {
		retval = pcap_loop(fp, 1, ethernet_protocol_packet_callback, user);
		//pcap_loop(fp, 1, ethernet_protocol_packet_callback,NULL);
		end = time(NULL);
		if (kbhit())
			break;
	} while (difftime(end, start) <= 60);
OpenTxt << "IP�ĸ��� : " << ipNum << endl;

	return 0;
}
