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

ofstream txt("capture.txt");//��һ������Ϊcaputre��txt�ļ�

int num = 0;//����ȫ�ֱ�������¼ip�ĸ���
// ��̫��Э���ʽ�Ķ��� 
typedef struct ether_header {
	u_char ether_dhost[6];      // Ŀ���ַ 
	u_char ether_shost[6];      // Դ��ַ 
	u_short ether_type;         // ��̫������ 
}ether_header;

// �û�����4�ֽڵ�IP��ַ 
typedef struct ip_address{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;


// ���ڱ���IPV4���ײ� 

typedef struct ip_header{

#ifdef WORDS_BIGENDIAN	
	u_char ip_version : 4, header_length : 4;
#else 
	u_char header_length : 4, ip_version : 4;
#endif 
	u_char ver_ihl;     // �汾�Լ��ײ����ȣ���(4bit) ,�����ֽ����Ե�ʣ����ﶨ���ʱ����Ҫ������
	u_char tos;         // �������� 
	u_short tlen;       // �ܳ��� 
	u_short identification;     // ��ʶ
	u_short offset;         //��־(3bit)+Ƭƫ��(13bit)
	u_char ttl;         // ttl
	u_char proto;       // Э��
	u_short checksum;       // �ײ�У��� 
	ip_address saddr;   //Դ��ַ 
	ip_address daddr;   //Ŀ�ĵ�ַ 
	u_int op_pad;       //��ѡ����ֶ� 
}ip_header;


// �ص����������յ�ÿһ�����ݰ�ʱ�ᱻlibpcap������ 
void ip_protocol_packet_handle(u_char* argument,const struct pcap_pkthdr* packet_header,const u_char* packet_content)
{

	struct ip_header* ip_protocol;
	u_int header_length;//�汾+�ײ�����
	u_char tos;//��������
	u_short checksum;//�ײ�У���
	ip_address saddr;//Դ��ַ
	ip_address daddr;//Ŀ�ĵ�ַ
	u_char ttl;//ttl
	u_short tlen;//�ܳ���
	u_short identification;//��ʶ
	u_short offset;//��־(3bit)+Ƭƫ��(13bit)
	
	//MAC�ײ���14λ�ģ�����14λ�õ�IP�ײ�  
	ip_protocol = (struct ip_header*)(packet_content + 14); //��̫��ͷ������
	//����ip
	header_length = ip_protocol->header_length * 4;
	offset = ntohs(ip_protocol->offset);
	
	txt << "*************IPЭ��*************" << endl;
	txt << "  �汾��         \t" << int(ip_protocol->ip_version) << endl;
	txt << "  �ײ�����       \t" << int(ip_protocol->header_length) << endl;
	txt << "  ���ַ���       \t" << (int)ntohs(ip_protocol->tos) << endl;
	txt << "  �ܳ���         \t" << (int)ntohs(ip_protocol->tlen) << endl;
	txt << "  ��ʶ           \t" << (int)ntohs(ip_protocol->identification) << endl;
	txt << "  ��־           \t" << setw(1) << setfill('0') << (int)((ntohs(ip_protocol->offset) & 0xE000) >> 13) << endl;
	txt << "  Ƭƫ��           \t" << setw(4) << setfill('0') << (int)(ntohs(ip_protocol->offset) & 0x1FFF) << endl;
	txt << "  ����ʱ��       \t" << int(ip_protocol->ttl) << endl;
	txt << "  Э��      \t\t" << setw(2) << setfill('0') << int(ip_protocol->proto) << endl;
	txt << "  �ײ�У���         \t" << setw(4) << setfill('0') << (int)ntohs((ip_protocol->checksum)) << endl;
	txt << "  Դ��ַ        \t" << (int)ip_protocol->saddr.byte1 << "." << (int)ip_protocol->saddr.byte2 << "." << (int)ip_protocol->saddr.byte3 << "." << (int)ip_protocol->saddr.byte4 << endl;
	txt << "  Ŀ�ĵ�ַ       \t" << (int)ip_protocol->daddr.byte1 << "." << (int)ip_protocol->daddr.byte2 << "." << (int)ip_protocol->daddr.byte3 << "." << (int)ip_protocol->daddr.byte4 << endl;
	txt << endl;

}




void ethernet_protocol_packet_handle(u_char* argument,const struct pcap_pkthdr* packet_header,const u_char* packet_content)
{
	u_short ethernet_type;      // ��̫������ 
	struct ether_header* ethernet_protocol;     // ��̫��Э����� 
	u_char* mac_string;         // ��̫����ַ 
	ethernet_protocol = (struct ether_header*)packet_content;       //��ȡ��̫���������� 
	ethernet_type = ntohs(ethernet_protocol->ether_type);   // ��ȡ��̫������ 

	if (ethernet_type == 0x800)
		num++;
	/*
		0x0800 : IPЭ��
		0x0806 : ARPЭ��
		0x8035 : RARPЭ��
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

	// ����豸�б�pcap_findalldevs_ex() 

	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
		fprintf(stderr, "Errorin pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}


	//��ӡ�豸�б�
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

	// ��ת�����豸
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);
	//�������� 
	// �豸����Ҫ��׽�����ݰ��Ĳ��֣�65536��֤�ܲ��񵽲�ͬ������·���ϵ�ÿ�����ݰ���ȫ�����ݣ�������ģʽ����ȡ��ʱʱ�䣬���󻺳�� 

	if ((adhandle = pcap_open_live(d->name,// �豸��
		65536,	  // Ҫ��׽�����ݰ��Ĳ���,65535��֤�ܲ��񵽲�ͬ������·���ϵ�ÿ�����ݰ���ȫ������
		1,		 // ����ģʽ
		1000,	 // ��ȡ��ʱʱ�� 
		errbuf	 //���󻺳�� 
	)) == NULL)
	{
		fprintf(stderr, "\nUnableto open the adapter.%s is not supported by WinPcap\n", errbuf);
		pcap_freealldevs(alldevs);
		return -1;

	}
	// ���������·�㣨ֻ��������̫���� 

	if (pcap_datalink(adhandle) != DLT_EN10MB) {
		fprintf(stderr, "\nThisprogram works only on Ethernet networks.\n");
		pcap_freealldevs(alldevs);
		return -1;
	}

	if (d->addresses != NULL) {
		//��ýӿڵĵ�һ����ַ������ 
		netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	}
	else {
		netmask = 0xffffff;
	}

	
		// ���������
		if(pcap_compile(adhandle, &fcode,packet_filter, 1, netmask) < 0) 
		{
			fprintf(stderr, "\nUnable tocompile the packet filter.Check the syntax\n");
			pcap_freealldevs(alldevs);
			return -1;
		}
		// ���ù�����
		if(pcap_setfilter(adhandle, &fcode)< 0) 
		{
			fprintf(stderr, "\nError settingthe filter.\n");
			pcap_freealldevs(alldevs);
			return -1;
		}

		printf("\nlistenting on %s...\n",d->description);

		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
	

		/* ��ʼ��׽ */
		time_t begin = time(NULL);
		time_t end = time(NULL);
		cout << "����ѡ���»س���ֹ�����ܻ����ӳ٣���Ҳ����ѡ��ȴ�60s:" << endl;
		do {
			pcap_loop(adhandle, 1, ethernet_protocol_packet_handle, NULL);
			end = time(NULL);
			if (kbhit())
				break;
		} while (difftime(end, begin) <= 60);
		txt << "IP�ĸ��� : " << num << endl;
	return 0;
}

	
   
 
