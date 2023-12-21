#include "3_ip.h"

void SetCheckSum(IP* temp)
{
	temp->IPHeader.Checksum = 0;
	unsigned int sum = 0;
	WORD* t = (WORD*)&temp->IPHeader;//16Bѭ���ۼ�
	for (int i = 0; i < sizeof(IP_Header) / 2; i++)
	{
		sum += t[i];
		while (sum >= 0x10000)       //����ع�
		{
			int s = sum >> 16;
			sum -= 0x10000;
			sum += s;
		}
	}
	temp->IPHeader.Checksum = ~sum;  //��λȡ��
}

// ���� IP ͷ���� ICMP ͷ����У���
void SetCheckSum(ICMP* data) {
	// ���� IP ͷ��У���
	data->IPHeader.Checksum = 0;
	uint32_t sum = 0;
	uint16_t* t = (uint16_t*)&data->IPHeader;
	for (int i = 0; i < sizeof(IP_Header) / 2; i++) {
		sum += t[i];
		while (sum >= 0x10000) {
			sum = (sum & 0xFFFF) + (sum >> 16);
		}
	}
	data->IPHeader.Checksum = ~sum;

	// ���� ICMP ͷ��У���
	ICMP* icmpData = (ICMP*)data;
	icmpData->IPHeader.Checksum = 0;
	sum = 0;
	t = (uint16_t*)&icmpData->IPHeader;
	for (int i = 0; i < sizeof(IP_Header) / 2; i++) {
		sum += t[i];
		while (sum >= 0x10000) {
			sum = (sum & 0xFFFF) + (sum >> 16);
		}
	}
	icmpData->IPHeader.Checksum = ~sum;
}

bool CheckSum(IP* temp)
{
	unsigned int sum = 0;
	WORD* t = (WORD*)&temp->IPHeader;
	for (int i = 0; i < sizeof(IP_Header) / 2; i++)
	{
		sum += t[i];
		while (sum >= 0x10000)
		{
			int s = sum >> 16;
			sum -= 0x10000;
			sum += s;
		}
	}
	if (sum == 65535)
	{
		return 1;
	}
	else
	{
		return 0;
	}
}









void analyze_ip(const u_char* pkt_data) {
	IP* data = (IP*)pkt_data;
	LT.WritelogIP("����", data);
	if (CheckSum(data))//���У��Ͳ���ȷ����ֱ�Ӷ��������д���
	{
		// ����ip���ݰ�
		if (data->IPHeader.DstIP == inet_addr(ip[0]) || data->IPHeader.DstIP == inet_addr(ip[1]))
		{
			// todo
		}
		// ת��ip���ݰ�
		else
		{
			int t1 = Compare(data->FrameHeader.DesMAC, broadcast);
			int t2 = Compare(data->FrameHeader.SrcMAC, broadcast);
			if (!t1 && !t2)
			{
				// ����ICMP����
				ICMP* temp_ = (ICMP*)pkt_data;
				ICMP temp = *temp_;
				BYTE mac[6];
				DWORD dstip = data->IPHeader.DstIP;
				DWORD IFip = RT.RouterFind(dstip);
				// û�б���
				if (IFip == -1)
				{
					return;
				}
				// ֱ��Ͷ�ݣ�Ŀ��ip������һ��������Ŀ��IP��MAC
				else if (IFip == 0)
				{
					//���ARP����û���������ݣ�����Ҫ��ȡARP
					if (!AT.FindArp(dstip, mac))
					{
						AT.InsertArp(dstip, mac);
					}
					resend(temp, mac);
				}
				// ��ֱ��Ͷ�ݣ�������һ��IP��MAC
				else
				{
					if (!AT.FindArp(IFip, mac))
					{
						AT.InsertArp(IFip, mac);
					}
					resend(temp, mac);
				}
			}
		}
	}
}


void resend(ICMP data, BYTE desmac[])
{
	IP* temp = (IP*)&data;
	temp->IPHeader.TTL -= 1;
	if (temp->IPHeader.TTL <= 0)
	{
		// ���� ICMP Time Exceeded ���ݰ�
		ICMP icmpTimeExceeded = data;

		// ���� ICMP Type �� Code
		icmpTimeExceeded.IPHeader.Protocol = IPPROTO_ICMP;
		icmpTimeExceeded.buf[0] = 11;  // ICMP ʱ�䳬ʱ��Type��
		icmpTimeExceeded.buf[1] = 0;   // ICMP TTL ���ڣ�Code��

		// ���� ICMP Internet Header + 64 bits of Original Data Datagram Ϊԭʼ IP ͷ��ǰ 8 �ֽڵ�����
		memcpy(icmpTimeExceeded.buf + 4, &temp->IPHeader, sizeof(IP_Header));
		memcpy(icmpTimeExceeded.buf + 4 + sizeof(IP_Header), &temp->FrameHeader, 8);

		// ����֡����Ϊ IP
		icmpTimeExceeded.FrameHeader.FrameType = htons(0x0800);

		// ���� ICMP Time Exceeded ���ݰ���Դ IP ��Ŀ�� IP
		icmpTimeExceeded.IPHeader.DstIP = icmpTimeExceeded.IPHeader.DstIP;
		icmpTimeExceeded.IPHeader.SrcIP = inet_addr("206.1.1.1");

		// ���� ICMP Time Exceeded ���ݰ���Դ MAC ��Ŀ�� MAC
		BYTE tempMAC[6];
		memcpy(tempMAC, icmpTimeExceeded.FrameHeader.SrcMAC, 6);
		memcpy(icmpTimeExceeded.FrameHeader.SrcMAC, icmpTimeExceeded.FrameHeader.DesMAC, 6);
		memcpy(icmpTimeExceeded.FrameHeader.DesMAC, tempMAC, 6);

		// ��������У���
		SetCheckSum(&icmpTimeExceeded);

		// ���� ICMP Time Exceeded ���ݰ�
		int icmpRtn = pcap_sendpacket(adhandle, (const u_char*)&icmpTimeExceeded, sizeof(ICMP));
		if (icmpRtn == 0)
		{
			// LT.WritelogIP("ICMP Time Exceeded", &icmpTimeExceeded);
		}

		return;
	}
	memcpy(temp->FrameHeader.SrcMAC, temp->FrameHeader.DesMAC, 6);//ԴMACΪ����MAC
	memcpy(temp->FrameHeader.DesMAC, desmac, 6);//Ŀ��MACΪ��һ��MAC
	SetCheckSum(temp);//��������У���
	int rtn = pcap_sendpacket(adhandle, (const u_char*)temp, 74);//�������ݱ�
	if (rtn == 0)
	{
		LT.WritelogIP("ת��", temp);
	}
}