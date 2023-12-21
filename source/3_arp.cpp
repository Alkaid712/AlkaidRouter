#include "3_arp.h"

ArpTable AT;

// �� ARP ���в����µ� ARP ��
void ArpTable::InsertArp(DWORD ip, BYTE mac[6]) {
	// ���� ArpRequest ��������ȡ MAC ��ַ
	ArpRequest(ip, mac);

	// �ȼ���Ƿ������ͬ IP �ı���
	int existingIndex = FindArp(ip, mac);
	if (existingIndex != 0) {
		// ������ڣ����� MAC ��ַ
		memcpy(arpItems[existingIndex].mac, mac, sizeof(arpItems[existingIndex].mac));
		return; // �����������Ŀ
	}
	// ����Ƿ��пռ�����µ� ARP ��
	if (itemCount < MaxArpItems) {
		arpItems[itemCount].ip = ip;
		memcpy(arpItems[itemCount].mac, mac, sizeof(arpItems[itemCount].mac));
		itemCount++;
	}
}


// ��ARP���в���ָ��IP��ַ����Ŀ
int ArpTable::FindArp(DWORD ip, BYTE mac[6]) {
	for (int i = 0; i < itemCount; ++i) {
		if (arpItems[i].ip == ip) {
			// �ҵ�ƥ���IP��ַ������Ӧ��MAC��ַ���Ƶ��ṩ��������
			memcpy(mac, arpItems[i].mac, sizeof(arpItems[i].mac));
			return 1; // �ҵ�ƥ�������true
		}
	}
	return 0; // δ�ҵ�ƥ����,����false
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
	//��APRFrame.FrameHeader.DesMAC����Ϊ�㲥��ַ
	for (int i = 0; i < 6; i++)
		ARPFrame.FrameHeader.DesMAC[i] = 0xff;
	//��APRFrame.FrameHeader.SrcMAC����Ϊ����������MAC��ַ
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.FrameHeader.SrcMAC[i] = selfmac[i];
		ARPFrame.SendHa[i] = selfmac[i];
	}
	ARPFrame.FrameHeader.FrameType = htons(0x0806);//֡����ΪARP
	ARPFrame.HardwareType = htons(0x0001);//Ӳ������Ϊ��̫��
	ARPFrame.ProtocolType = htons(0x0800);//Э������ΪIP
	ARPFrame.HLen = 6;//Ӳ����ַ����Ϊ6
	ARPFrame.PLen = 4;//Э���ַ��Ϊ4
	ARPFrame.Operation = htons(0x0001);//����ΪARP����
	//��ARPFrame.SendIP����Ϊ���������ϰ󶨵�IP��ַ
	ARPFrame.SendIP = inet_addr(ip[0]);
	//��ARPFrame.RecvHa����Ϊ0
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.RecvHa[i] = 0;
	}
	//��ARPFrame.RecvIP����Ϊ�����IP��ַ
	ARPFrame.RecvIP = ip0;
	if (adhandle == nullptr)
	{
		printf("�����ӿڴ򿪴���\n");
	}
	else
	{
		if (pcap_sendpacket(adhandle, (u_char*)&ARPFrame, sizeof(ARP)) != 0)
		{
			printf("���ʹ���\n");
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
						if (ntohs(IPPacket->Operation) == 0x0002)//���֡����ΪARP���Ҳ���ΪARPӦ��
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