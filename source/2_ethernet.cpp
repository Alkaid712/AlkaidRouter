#include "2_ethernet.h"

DWORD WINAPI analyze_ethernet() {
	while (1)
	{
		pcap_pkthdr* pkt_header;
		const u_char* pkt_data;
		while (1)
		{
			int rtn = pcap_next_ex(adhandle, &pkt_header, &pkt_data);
			if (rtn)//接收到消息
			{
				break;
			}
		}
		Frame_Header* header = (Frame_Header*)pkt_data;
		if (Compare(header->DesMAC, selfmac))//目的mac是自己的mac
		{
			if (ntohs(header->FrameType) == 0x0806)//收到ARP
			{
				// todo
			}
			else if (ntohs(header->FrameType) == 0x0800)//收到IP
			{
				analyze_ip(pkt_data);
			}
		}
	}
}

bool getmyIP() {
	pcap_if_t* alldevs;//指向设备链表首部的指针
	pcap_if_t* d;
	char errbuf[PCAP_ERRBUF_SIZE];	//错误信息缓冲区
	int num = 0;//接口数量

	//打开网卡获取双IP

	//获得本机的设备列表
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, 	//获取本机的接口设备
		NULL,			       //无需认证
		&alldevs, 		       //指向设备列表首部
		errbuf			      //出错信息保存缓存区
	) == -1)
	{
		//错误处理
		printf("获取本机设备错误");
		printf("%d\n", errbuf);
		pcap_freealldevs(alldevs);
		return 0;
	}
	int t = 0;
	//显示接口列表
	for (d = alldevs; d != NULL; d = d->next)
	{
		num++;
		printf("%d:", num);
		printf("%s\n", d->name);
		pcap_addr_t* a; // 网络适配器的地址
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
		printf("无可用接口\n");
		return 0;
	}
	printf("请输入要打开的网络接口号:");
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
		printf("产生错误，无法打开设备\n");
		pcap_freealldevs(alldevs);
		return 0;
	}
	else
	{
		printf("开始监听...\n");
		pcap_freealldevs(alldevs);
	}
	RT.RouterDirect();
	return 1;
}

bool getmyMAC() {
	//伪造ARP报文获取本机MAC
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
	ARPFrame.FrameHeader.FrameType = htons(0x0806);// 帧类型为ARP
	ARPFrame.HardwareType = htons(0x0001);//硬件类型为以太网
	ARPFrame.ProtocolType = htons(0x0800);//协议类型为IP
	ARPFrame.HLen = 6;//硬件地址长度为6
	ARPFrame.PLen = 4;//协议地址长为4
	ARPFrame.Operation = htons(0x0001);//操作为ARP请求
	//将ARPFrame.SendHa设置为本机网卡的MAC地址
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.SendHa[i] = 0x0f;
	}
	//将ARPFrame.SendIP设置为本机网卡上绑定的IP地址
	ARPFrame.SendIP = inet_addr("206.1.2.1");
	//将ARPFrame.RecvHa设置为0
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.RecvHa[i] = 0x00;
	}
	//将ARPFrame.RecvIP设置为请求的IP地址
	ARPFrame.RecvIP = inet_addr(ip[0]);

	if (pcap_sendpacket(adhandle, (u_char*)&ARPFrame, sizeof(ARP)) != 0)
	{
		printf("获取本机mac失败\n");
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
			if ((ntohs(IPPacket->FrameHeader.FrameType) == 0x0806) && (ntohs(IPPacket->Operation) == 0x0002))//如果帧类型为ARP并且操作为ARP应答
			{
				LT.WritelogARP(IPPacket);
				printf("本机Mac地址：\n");
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