#include "3_ip.h"

void SetCheckSum(IP* temp)
{
	temp->IPHeader.Checksum = 0;
	unsigned int sum = 0;
	WORD* t = (WORD*)&temp->IPHeader;//16B循环累加
	for (int i = 0; i < sizeof(IP_Header) / 2; i++)
	{
		sum += t[i];
		while (sum >= 0x10000)       //溢出回滚
		{
			int s = sum >> 16;
			sum -= 0x10000;
			sum += s;
		}
	}
	temp->IPHeader.Checksum = ~sum;  //按位取反
}

// 设置 IP 头部和 ICMP 头部的校验和
void SetCheckSum(ICMP* data) {
	// 计算 IP 头部校验和
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

	// 计算 ICMP 头部校验和
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
	LT.WritelogIP("接收", data);
	if (CheckSum(data))//如果校验和不正确，则直接丢弃不进行处理
	{
		// 接收ip数据包
		if (data->IPHeader.DstIP == inet_addr(ip[0]) || data->IPHeader.DstIP == inet_addr(ip[1]))
		{
			// todo
		}
		// 转发ip数据包
		else
		{
			int t1 = Compare(data->FrameHeader.DesMAC, broadcast);
			int t2 = Compare(data->FrameHeader.SrcMAC, broadcast);
			if (!t1 && !t2)
			{
				// 构造ICMP报文
				ICMP* temp_ = (ICMP*)pkt_data;
				ICMP temp = *temp_;
				BYTE mac[6];
				DWORD dstip = data->IPHeader.DstIP;
				DWORD IFip = RT.RouterFind(dstip);
				// 没有表项
				if (IFip == -1)
				{
					return;
				}
				// 直接投递，目的ip就是下一跳，查找目的IP的MAC
				else if (IFip == 0)
				{
					//如果ARP表中没有所需内容，则需要获取ARP
					if (!AT.FindArp(dstip, mac))
					{
						AT.InsertArp(dstip, mac);
					}
					resend(temp, mac);
				}
				// 非直接投递，查找下一跳IP的MAC
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
		// 构造 ICMP Time Exceeded 数据包
		ICMP icmpTimeExceeded = data;

		// 设置 ICMP Type 和 Code
		icmpTimeExceeded.IPHeader.Protocol = IPPROTO_ICMP;
		icmpTimeExceeded.buf[0] = 11;  // ICMP 时间超时（Type）
		icmpTimeExceeded.buf[1] = 0;   // ICMP TTL 过期（Code）

		// 设置 ICMP Internet Header + 64 bits of Original Data Datagram 为原始 IP 头和前 8 字节的数据
		memcpy(icmpTimeExceeded.buf + 4, &temp->IPHeader, sizeof(IP_Header));
		memcpy(icmpTimeExceeded.buf + 4 + sizeof(IP_Header), &temp->FrameHeader, 8);

		// 设置帧类型为 IP
		icmpTimeExceeded.FrameHeader.FrameType = htons(0x0800);

		// 设置 ICMP Time Exceeded 数据包的源 IP 和目的 IP
		icmpTimeExceeded.IPHeader.DstIP = icmpTimeExceeded.IPHeader.DstIP;
		icmpTimeExceeded.IPHeader.SrcIP = inet_addr("206.1.1.1");

		// 交换 ICMP Time Exceeded 数据包的源 MAC 和目的 MAC
		BYTE tempMAC[6];
		memcpy(tempMAC, icmpTimeExceeded.FrameHeader.SrcMAC, 6);
		memcpy(icmpTimeExceeded.FrameHeader.SrcMAC, icmpTimeExceeded.FrameHeader.DesMAC, 6);
		memcpy(icmpTimeExceeded.FrameHeader.DesMAC, tempMAC, 6);

		// 重新设置校验和
		SetCheckSum(&icmpTimeExceeded);

		// 发送 ICMP Time Exceeded 数据包
		int icmpRtn = pcap_sendpacket(adhandle, (const u_char*)&icmpTimeExceeded, sizeof(ICMP));
		if (icmpRtn == 0)
		{
			// LT.WritelogIP("ICMP Time Exceeded", &icmpTimeExceeded);
		}

		return;
	}
	memcpy(temp->FrameHeader.SrcMAC, temp->FrameHeader.DesMAC, 6);//源MAC为本机MAC
	memcpy(temp->FrameHeader.DesMAC, desmac, 6);//目的MAC为下一跳MAC
	SetCheckSum(temp);//重新设置校验和
	int rtn = pcap_sendpacket(adhandle, (const u_char*)temp, 74);//发送数据报
	if (rtn == 0)
	{
		LT.WritelogIP("转发", temp);
	}
}