#pragma once
#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <Winsock2.h>
#include "pcap.h"

extern char ip[10][20];   // 本机ip
extern char mask[10][20]; // 本机mask
extern BYTE selfmac[6];   // 本机mac
extern pcap_t* adhandle;  // 监听的网卡
extern BYTE broadcast[6]; // 广播mac












#pragma pack(1)

// 以太网帧首部
struct Frame_Header {
	BYTE DesMAC[6];//目的地址
	BYTE SrcMAC[6];//源地址
	WORD FrameType;//帧类型
};

// IP报文首部
struct IP_Header {
	BYTE Ver_HLen;     //IP协议版本和IP首部长度：高4位为版本，低4位为首部的长度
	BYTE TOS;          //服务类型
	WORD TotalLen;     //总长度
	WORD ID;           //标识
	WORD Flag_Segment; //标志 片偏移
	BYTE TTL;          //生存周期
	BYTE Protocol;     //上层协议
	WORD Checksum;     //头部校验和
	u_int SrcIP;       //源IP
	u_int DstIP;       //目的IP
};

// ARP报文
struct ARP {
	Frame_Header FrameHeader;
	WORD HardwareType;//硬件类型
	WORD ProtocolType;//协议类型
	BYTE HLen;//硬件地址长度
	BYTE PLen;//协议地址长度
	WORD Operation;//操作类型
	BYTE SendHa[6];//发送方MAC地址
	DWORD SendIP;//发送方IP地址
	BYTE RecvHa[6];//接收方MAC地址
	DWORD RecvIP;//接收方IP地址
};

// IP报文
struct IP {
	Frame_Header FrameHeader;
	IP_Header IPHeader;
};

// ICMP报文
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

class Routerlog //日志
{
private:
	int index;    //索引
	char type[5]; //类型（arp ip）
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