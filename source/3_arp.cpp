#include "3_arp.h"

ArpTable AT;

// 向 ARP 表中插入新的 ARP 项
void ArpTable::InsertArp(DWORD ip, BYTE mac[6]) {
	// 调用 ArpRequest 函数，获取 MAC 地址
	ArpRequest(ip, mac);

	// 先检查是否存在相同 IP 的表项
	int existingIndex = FindArp(ip, mac);
	if (existingIndex != 0) {
		// 如果存在，更新 MAC 地址
		memcpy(arpItems[existingIndex].mac, mac, sizeof(arpItems[existingIndex].mac));
		return; // 无需插入新条目
	}
	// 检查是否还有空间插入新的 ARP 项
	if (itemCount < MaxArpItems) {
		arpItems[itemCount].ip = ip;
		memcpy(arpItems[itemCount].mac, mac, sizeof(arpItems[itemCount].mac));
		itemCount++;
	}
}


// 在ARP表中查找指定IP地址的条目
int ArpTable::FindArp(DWORD ip, BYTE mac[6]) {
	for (int i = 0; i < itemCount; ++i) {
		if (arpItems[i].ip == ip) {
			// 找到匹配的IP地址，将对应的MAC地址复制到提供的数组中
			memcpy(mac, arpItems[i].mac, sizeof(arpItems[i].mac));
			return 1; // 找到匹配项，返回true
		}
	}
	return 0; // 未找到匹配项,返回false
}

void ArpTable::PrintArpTable() {
	printf("ARP Table:\n");
	printf("IP Address\tMAC Address\n");
	for (int i = 0; i < itemCount; ++i) {
		printf("%lu\t", arpItems[i].ip);
		for (int j = 0; j < 6; ++j) {
			printf("%02X", arpItems[i].mac[j]);
			if (j < 5) printf(":");
		}
		printf("\n");
	}
}




void ArpRequest(DWORD ip0, BYTE mac[])
{
	memset(mac, 0, sizeof(mac));
	ARP ARPFrame;
	//将APRFrame.FrameHeader.DesMAC设置为广播地址
	for (int i = 0; i < 6; i++)
		ARPFrame.FrameHeader.DesMAC[i] = 0xff;
	//将APRFrame.FrameHeader.SrcMAC设置为本机网卡的MAC地址
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.FrameHeader.SrcMAC[i] = selfmac[i];
		ARPFrame.SendHa[i] = selfmac[i];
	}
	ARPFrame.FrameHeader.FrameType = htons(0x0806);//帧类型为ARP
	ARPFrame.HardwareType = htons(0x0001);//硬件类型为以太网
	ARPFrame.ProtocolType = htons(0x0800);//协议类型为IP
	ARPFrame.HLen = 6;//硬件地址长度为6
	ARPFrame.PLen = 4;//协议地址长为4
	ARPFrame.Operation = htons(0x0001);//操作为ARP请求
	//将ARPFrame.SendIP设置为本机网卡上绑定的IP地址
	ARPFrame.SendIP = inet_addr(ip[0]);
	//将ARPFrame.RecvHa设置为0
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.RecvHa[i] = 0;
	}
	//将ARPFrame.RecvIP设置为请求的IP地址
	ARPFrame.RecvIP = ip0;
	if (adhandle == nullptr)
	{
		printf("网卡接口打开错误\n");
	}
	else
	{
		if (pcap_sendpacket(adhandle, (u_char*)&ARPFrame, sizeof(ARP)) != 0)
		{
			printf("发送错误\n");
			return;
		}
		else
		{
			while (1)
			{
				pcap_pkthdr* pkt_header;
				const u_char* pkt_data;
				int rtn = pcap_next_ex(adhandle, &pkt_header, &pkt_data);
				if (rtn == 1)
				{
					ARP* IPPacket = (ARP*)pkt_data;
					if (ntohs(IPPacket->FrameHeader.FrameType) == 0x0806)
					{   
						if (ntohs(IPPacket->Operation) == 0x0002)//如果帧类型为ARP并且操作为ARP应答
						{
							LT.WritelogARP(IPPacket);
							for (int i = 0; i < 6; i++)
								mac[i] = IPPacket->FrameHeader.SrcMAC[i];
							break;
						}
					}
				}
			}
		}
	}
}