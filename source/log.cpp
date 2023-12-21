#include "log.h"

char ip[10][20];   // 本机ip
char mask[10][20]; // 本机掩码
BYTE selfmac[6];   // 本机mac
pcap_t* adhandle;  // 监听的网卡

BYTE broadcast[6] = { 0xff,0xff,0xff,0xff,0xff,0xff };


bool Compare(BYTE a[6], BYTE b[6])
{
	for (int i = 0; i < 6; i++)
	{
		if (a[i] != b[i])
		{
			return 0;
		}
	}
	return 1;
}

Routerlog Routerlog::diary[50] = {};
int Routerlog::num = 0;
FILE* Routerlog::fp = nullptr;
Routerlog LT;

Routerlog::Routerlog()
{
	fp = fopen("log.txt", "a+");//文件以及打开方式
}
Routerlog::~Routerlog()
{
	fclose(fp);
}
void Routerlog::WritelogARP(ARP* t)
{
	fprintf(fp, "ARP\t");
	in_addr addr;
	addr.s_addr = t->SendIP;
	char* temp = inet_ntoa(addr);
	fprintf(fp, "IP:\t");
	fprintf(fp, "%s\t", temp);
	fprintf(fp, "MAC:\t");
	for (int i = 0; i < 6; i++)
	{
		fprintf(fp, "%02x:", t->SendHa[i]);
	}
	fprintf(fp, "\n");
}
void Routerlog::WritelogIP(const char* a, IP* t)
{
	fprintf(fp, "IP\t");
	fprintf(fp, a);
	fprintf(fp, "\t");
	in_addr addr;
	
	fprintf(fp, "源IP：\t");
	addr.s_addr = t->IPHeader.SrcIP;
	char* temp = inet_ntoa(addr);
	fprintf(fp, "%s\t", temp);

	fprintf(fp, "目的IP：\t");
	addr.s_addr = t->IPHeader.DstIP;
	temp = inet_ntoa(addr);
	fprintf(fp, "%s\t", temp);

	fprintf(fp, "源MAC：\t");
	for (int i = 0; i < 6; i++)
		fprintf(fp, "%02x:", t->FrameHeader.SrcMAC[i]);

	fprintf(fp, "目的MAC：\t");
	for (int i = 0; i < 6; i++)
		fprintf(fp, "%02x:", t->FrameHeader.DesMAC[i]);

	fprintf(fp, "\n");
}
void Routerlog::print()
{
	for (int i = 0; i < num; i++)
	{
		printf("%d ", diary[i].index);
		printf("%s\t ", diary[i].type);
		if (strcmp(diary[i].type, "ARP") == 0)
		{
			in_addr addr;
			addr.s_addr = diary[i].arp.ip;
			char* temp = inet_ntoa(addr);
			printf("%s\t", temp);
			for (int i = 0; i < 6; i++)
			{
				printf("%02x.", diary[i].arp.mac[i]);
			}
		}
		else if (strcmp(diary[i].type, "IP") == 0)
		{
			in_addr addr;

			addr.s_addr = diary[i].ip.sip;
			char* temp = inet_ntoa(addr);
			printf("源IP：%s\t", temp);

			addr.s_addr = diary[i].ip.dip;
			temp = inet_ntoa(addr);
			printf("目的IP：%s\t", temp);

			printf("源MAC: ");
			for (int i = 0; i < 6; i++)
			{
				printf("%02x.", diary[i].ip.smac[i]);
			}

			printf("目的MAC: ");
			for (int i = 0; i < 6; i++)
			{
				printf("%02x.", diary[i].ip.dmac[i]);
			}
		}
	}
}