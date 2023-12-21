#pragma once
#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <Winsock2.h>
#include "pcap.h"

extern char ip[10][20];   // ����ip
extern char mask[10][20]; // ����mask
extern BYTE selfmac[6];   // ����mac
extern pcap_t* adhandle;  // ����������
extern BYTE broadcast[6]; // �㲥mac












#pragma pack(1)

// ��̫��֡�ײ�
struct Frame_Header {
	BYTE DesMAC[6];//Ŀ�ĵ�ַ
	BYTE SrcMAC[6];//Դ��ַ
	WORD FrameType;//֡����
};

// IP�����ײ�
struct IP_Header {
	BYTE Ver_HLen;     //IPЭ��汾��IP�ײ����ȣ���4λΪ�汾����4λΪ�ײ��ĳ���
	BYTE TOS;          //��������
	WORD TotalLen;     //�ܳ���
	WORD ID;           //��ʶ
	WORD Flag_Segment; //��־ Ƭƫ��
	BYTE TTL;          //��������
	BYTE Protocol;     //�ϲ�Э��
	WORD Checksum;     //ͷ��У���
	u_int SrcIP;       //ԴIP
	u_int DstIP;       //Ŀ��IP
};

// ARP����
struct ARP {
	Frame_Header FrameHeader;
	WORD HardwareType;//Ӳ������
	WORD ProtocolType;//Э������
	BYTE HLen;//Ӳ����ַ����
	BYTE PLen;//Э���ַ����
	WORD Operation;//��������
	BYTE SendHa[6];//���ͷ�MAC��ַ
	DWORD SendIP;//���ͷ�IP��ַ
	BYTE RecvHa[6];//���շ�MAC��ַ
	DWORD RecvIP;//���շ�IP��ַ
};

// IP����
struct IP {
	Frame_Header FrameHeader;
	IP_Header IPHeader;
};

// ICMP����
struct ICMP {
	Frame_Header FrameHeader;
	IP_Header IPHeader;
	char buf[0x80];
};

#pragma pack()










bool Compare(BYTE a[6], BYTE b[6]);











class arpitem
{
public:
	DWORD ip;
	BYTE mac[6];
};

class ipitem
{
public:
	DWORD sip, dip;
	BYTE smac[6], dmac[6];
};

class Routerlog //��־
{
private:
	int index;    //����
	char type[5]; //���ͣ�arp ip��
	ipitem ip;
	arpitem arp;
	static int num;
	static Routerlog diary[50];
	static FILE* fp;
public:
	Routerlog();
	~Routerlog();
	void WritelogARP(ARP* t);
	void WritelogIP(const char* a, IP* t);
	void print();
};

extern Routerlog LT;