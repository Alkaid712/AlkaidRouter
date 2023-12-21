#include "shell.h"

void shell() {
	int op;
	while (1)
	{
		printf("请输入操作：");
		printf("0：结束路由程序；1：打印路由表；2：添加路由表；3：删除路由表；4：打印arp表；5：打印日志；\n");
		scanf("%d", &op);
		if (op == 1)
		{
			RT.print();
		}
		else if (op == 2)
		{
			RouterItem ri;
			char temp[30];
			printf("请输入目的网络：");
			scanf("%s", &temp);
			ri.net = inet_addr(temp);
			printf("请输入掩码：");
			scanf("%s", &temp);
			ri.mask = inet_addr(temp);
			printf("请输入下一跳地址：");
			scanf("%s", &temp);
			ri.nextip = inet_addr(temp);
			ri.type = 1;
			RT.RouterAdd(&ri);
		}
		else if (op == 3)
		{
			printf("请输入删除表项编号：");
			int index;
			scanf("%d", &index);
			RT.RouterRemove(index);
		}
		else if (op == 4)
		{
			AT.PrintArpTable();
		}
		else if (op == 0)
		{
			break;
		}
		else
		{
			break;
		}
	}

	pcap_close(adhandle);
}