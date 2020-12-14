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

ofstream Open_txt("ip_capture.txt");//��һ������ip_capture��txt�ı�
int ip_num = 0;//����һ��ȫ�ֱ�������ͳ��IP���ݱ��ĸ���


//��̫��Э���ʽ
struct ethernet_header {
	u_int8_t ether_dhost[6];//Ŀ����̫����ַ
	u_int8_t ether_shost[6];//Դ��̫����ַ
	u_int16_t ether_type;//��̫������
};
/* 4�ֽڵ�IP��ַ */
typedef struct ip_address
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
} ip_address;

/* IPv4 �ײ� */
typedef struct ip_header
{
	//u_char  ver_ihl;        // �汾 (4 bits) + �ײ����� (4 bits)

	u_char  ihl : 4, ver : 4;///ע�⣺�����ֽ����Ե�ʣ����ﶨ���ʱ����Ҫ������
	u_char  tos;            // ��������
	u_short tlen;           // �ܳ�
	u_short identification; // ��ʶ
	u_short flags_fo;       // ��־λ (3 bits) + ��ƫ���� (13 bits)

	u_char  ttl;            // ���ʱ��
	u_char  proto;          // Э��
	u_short crc;            // �ײ�У���
	ip_address  saddr;      // Դ��ַ
	ip_address  daddr;      // Ŀ�ĵ�ַ
	u_int   op_pad;         // ѡ�������
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


/* �ص�����ԭ�� */
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);

void ethernet_protocol_packet_callback(u_char* argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content)
{
	u_short ethernet_type;/*��̫��Э������*/
	struct ethernet_header* ethernet_protocol;/*��̫��Э�����*/
	u_char* mac_string;
	ethernet_protocol = (struct ethernet_header*) packet_content;/*���һ̫��Э����������*/
	ethernet_type = ntohs(ethernet_protocol->ether_type); /*�����̫������*/
	if (ethernet_type == 0x0800) //0x8000ʱΪIPЭ���
		ip_num++;
	

	switch (ethernet_type)////0x8000ʱΪIPЭ���
	{
	case 0x0800:
		/*����ϲ���IPv4ipЭ��,�͵��÷���ipЭ��ĺ�����ip�����з���*/
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

	/* ����豸�б� */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* ��ӡ�б� */
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
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* ��ת����ѡ�豸 */
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	/* �������� */
	if ((adhandle = pcap_open(d->name,  // �豸��
		65536,     // Ҫ��׽�����ݰ��Ĳ���
		// 65535��֤�ܲ��񵽲�ͬ������·���ϵ�ÿ�����ݰ���ȫ������
		PCAP_OPENFLAG_PROMISCUOUS,         // ����ģʽ
		1000,      // ��ȡ��ʱʱ��
		NULL,      // Զ�̻�����֤
		errbuf     // ���󻺳��
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n");
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* ���������·�㣬Ϊ�˼򵥣�ֻ������̫�� */
	if (pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		return -1;
	}

	if (d->addresses != NULL)
		/* ��ýӿڵ�һ����ַ������ */
		netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* ����ӿ�û�е�ַ����ô���Ǽ���һ��C������� */
		netmask = 0xffffff;


	//���������
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0)
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		return -1;
	}

	//���ù�����
	if (pcap_setfilter(adhandle, &fcode) < 0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("\nlistening on %s...\n", d->description);

	/* �ͷ��豸�б� */
	pcap_freealldevs(alldevs);
	
	/* ��ʼ��׽ */
	time_t start = time(NULL);
	time_t end = time(NULL);
	cout << "����ѡ���»س���ֹ(������������ԭ�򣬻����ӳ٣���Ҳ����ѡ��ȴ�60s:" << endl;
	for (;difftime(end, start) <= 60;)
	{
		pcap_loop(adhandle, 1, ethernet_protocol_packet_callback, NULL);
		end = time(NULL);
		if (kbhit())
			goto loop;
	}
loop:	Open_txt << "IP�ĸ��� : " << ip_num << endl;
	return 0;
}





/* �ص����������յ�ÿһ�����ݰ�ʱ�ᱻlibpcap������ */
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	ip_header* ih;
	tcp_header* th;
	u_int ip_len;
	u_short sport, dport;



	/* ���IP���ݰ�ͷ����λ�� */
	ih = (ip_header*)(pkt_data + 14); //��̫��ͷ������


	
	/*
	///��ӡIP���ݱ�ͷ��Ϣ
	cout << "  �汾��         " << int(ih->ver) << endl;
	cout << "  �ײ�����       " << int(ih->ihl) << endl;
	cout << "  ��������       " << ntohs(ih->tos) << endl;
	cout << "  �ܳ���         " << ntohs(ih->tlen) << endl;
	cout << "  ��ʶ          " << ntohs(ih->identification) << endl;
	cout << "  ��־          " << setw(1) << setfill('0') << ((ntohs(ih->flags_fo) & 0xE000) >> 13) << endl;
	cout << "  ƫ��          " << setw(4) << setfill('0') << (ntohs(ih->flags_fo) & 0x1FFF) << endl;
	cout << "  ����ʱ��       " << int(ih->ttl) << endl;
	cout << "  Э������       " << setw(2) << setfill('0') << int(ih->proto) << endl;
	cout << "  У���         " << setw(4) << setfill('0') << ntohs(ih->crc) << endl;

	printf("Դ��ַ:\t%d.%d.%d.%d -> Ŀ�ĵ�ַ: %d.%d.%d.%d\n",
		ih->saddr.byte1, ih->saddr.byte2, ih->saddr.byte3, ih->saddr.byte4,
		ih->daddr.byte1, ih->daddr.byte2, ih->daddr.byte3, ih->daddr.byte4);
	cout << endl;
	cout << endl;

	*/

	///��ӡIP���ݱ�ͷ��Ϣ
	Open_txt << "--------------IPЭ��--------------" << endl;
	Open_txt << "  �汾��         \t" << int(ih->ver) << endl;
	Open_txt << "  �ײ�����       \t" << int(ih->ihl) << endl;
	Open_txt << "  ���ַ���       \t" << (int)ntohs(ih->tos) << endl;
	Open_txt << "  �ܳ���         \t" << (int)ntohs(ih->tlen) << endl;
	Open_txt << "  ��ʶ           \t" << (int)ntohs(ih->identification) << endl;
	Open_txt << "  ��־           \t" << setw(1) << setfill('0') << (int)((ntohs(ih->flags_fo) & 0xE000) >> 13) << endl;
	Open_txt << "  Ƭƫ��           \t" << setw(4) << setfill('0') << (int)(ntohs(ih->flags_fo) & 0x1FFF) << endl;
	Open_txt << "  ����ʱ��       \t" << int(ih->ttl) << endl;
	Open_txt << "  Э��      \t\t" << setw(2) << setfill('0') << int(ih->proto) << endl;
	Open_txt << "  �ײ�У���         \t" << setw(4) << setfill('0') << (int)ntohs(ih->crc) << endl;
	Open_txt << "  Դ��ַ        \t" << (int)ih->saddr.byte1 << "." << (int)ih->saddr.byte2 << "." << (int)ih->saddr.byte3 << "." << (int)ih->saddr.byte4  << endl;
	Open_txt <<	"  Ŀ�ĵ�ַ       \t" << (int)ih->daddr.byte1 << "." << (int)ih->daddr.byte2 << "." << (int)ih->daddr.byte3 << "." << (int)ih->daddr.byte4 << endl;
	Open_txt << endl;


}
