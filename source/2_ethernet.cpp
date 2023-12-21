#include "2_ethernet.h"

DWORD WINAPI analyze_ethernet() {
	while (1)
	{
		pcap_pkthdr* pkt_header;
		const u_char* pkt_data;
		while (1)
		{
			int rtn = pcap_next_ex(adhandle, &pkt_header, &pkt_data);
			if (rtn)//���յ���Ϣ
			{
				break;
			}
		}
		Frame_Header* header = (Frame_Header*)pkt_data;
		if (Compare(header->DesMAC, selfmac))//Ŀ��mac���Լ���mac
		{
			if (ntohs(header->FrameType) == 0x0806)//�յ�ARP
			{
				// todo
			}
			else if (ntohs(header->FrameType) == 0x0800)//�յ�IP
			{
				analyze_ip(pkt_data);
			}
		}
	}
}

bool getmyIP() {
	pcap_if_t* alldevs;//ָ���豸�����ײ���ָ��
	pcap_if_t* d;
	char errbuf[PCAP_ERRBUF_SIZE];	//������Ϣ������
	int num = 0;//�ӿ�����

	//��������ȡ˫IP

	//��ñ������豸�б�
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, 	//��ȡ�����Ľӿ��豸
		NULL,			       //������֤
		&alldevs, 		       //ָ���豸�б��ײ�
		errbuf			      //������Ϣ���滺����
	) == -1)
	{
		//������
		printf("��ȡ�����豸����");
		printf("%d\n", errbuf);
		pcap_freealldevs(alldevs);
		return 0;
	}
	int t = 0;
	//��ʾ�ӿ��б�
	for (d = alldevs; d != NULL; d = d->next)
	{
		num++;
		printf("%d:", num);
		printf("%s\n", d->name);
		pcap_addr_t* a; // �����������ĵ�ַ
		for (a = d->addresses; a != NULL; a = a->next)
		{
			switch (a->addr->sa_family)
			{
			case AF_INET://IPV4
				if (a->addr != NULL)
				{
					printf("%s\t%s     ", "IP:", inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
					printf("%s\t%s\n", "MASK:", inet_ntoa(((struct sockaddr_in*)a->netmask)->sin_addr));
					strcpy(ip[t], inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
					strcpy(mask[t], inet_ntoa(((struct sockaddr_in*)a->netmask)->sin_addr));
				}
				break;
			case AF_INET6://IPV6
				break;
			default:
				break;
			}
			t++;
		}
	}
	if (num == 0)
	{
		printf("�޿��ýӿ�\n");
		return 0;
	}
	printf("������Ҫ�򿪵�����ӿں�:");
	int n;
	num = 0;
	scanf("%d", &n);
	for (d = alldevs; num < (n - 1); num++)
	{
		d = d->next;
	}
	adhandle = pcap_open(d->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);
	if (adhandle == NULL)
	{
		printf("���������޷����豸\n");
		pcap_freealldevs(alldevs);
		return 0;
	}
	else
	{
		printf("��ʼ����...\n");
		pcap_freealldevs(alldevs);
	}
	RT.RouterDirect();
	return 1;
}

bool getmyMAC() {
	//α��ARP���Ļ�ȡ����MAC
	memset(selfmac, 0, sizeof(selfmac));
	ARP ARPFrame;
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.FrameHeader.DesMAC[i] = 0xff;
	}
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.FrameHeader.SrcMAC[i] = 0x0f;
	}
	ARPFrame.FrameHeader.FrameType = htons(0x0806);// ֡����ΪARP
	ARPFrame.HardwareType = htons(0x0001);//Ӳ������Ϊ��̫��
	ARPFrame.ProtocolType = htons(0x0800);//Э������ΪIP
	ARPFrame.HLen = 6;//Ӳ����ַ����Ϊ6
	ARPFrame.PLen = 4;//Э���ַ��Ϊ4
	ARPFrame.Operation = htons(0x0001);//����ΪARP����
	//��ARPFrame.SendHa����Ϊ����������MAC��ַ
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.SendHa[i] = 0x0f;
	}
	//��ARPFrame.SendIP����Ϊ���������ϰ󶨵�IP��ַ
	ARPFrame.SendIP = inet_addr("206.1.2.1");
	//��ARPFrame.RecvHa����Ϊ0
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.RecvHa[i] = 0x00;
	}
	//��ARPFrame.RecvIP����Ϊ�����IP��ַ
	ARPFrame.RecvIP = inet_addr(ip[0]);

	if (pcap_sendpacket(adhandle, (u_char*)&ARPFrame, sizeof(ARP)) != 0)
	{
		printf("��ȡ����macʧ��\n");
		return 0;
	}
	ARP* IPPacket;
	while (1)
	{
		pcap_pkthdr* pkt_header;
		const u_char* pkt_data;
		int rtn = pcap_next_ex(adhandle, &pkt_header, &pkt_data);
		if (rtn == 1)
		{
			IPPacket = (ARP*)pkt_data;
			for (int i = 0; i < 6; i++)
			{
				selfmac[i] = IPPacket->FrameHeader.SrcMAC[i];
			}
			if ((ntohs(IPPacket->FrameHeader.FrameType) == 0x0806) && (ntohs(IPPacket->Operation) == 0x0002))//���֡����ΪARP���Ҳ���ΪARPӦ��
			{
				LT.WritelogARP(IPPacket);
				printf("����Mac��ַ��\n");
				printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
					IPPacket->FrameHeader.SrcMAC[0],
					IPPacket->FrameHeader.SrcMAC[1],
					IPPacket->FrameHeader.SrcMAC[2],
					IPPacket->FrameHeader.SrcMAC[3],
					IPPacket->FrameHeader.SrcMAC[4],
					IPPacket->FrameHeader.SrcMAC[5]
				);
				break;
			}
		}
	}
	return 1;
}