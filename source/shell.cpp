#include "shell.h"

void shell() {
	int op;
	while (1)
	{
		printf("�����������");
		printf("0������·�ɳ���1����ӡ·�ɱ�2�����·�ɱ�3��ɾ��·�ɱ�4����ӡarp��5����ӡ��־��\n");
		scanf("%d", &op);
		if (op == 1)
		{
			RT.print();
		}
		else if (op == 2)
		{
			RouterItem ri;
			char temp[30];
			printf("������Ŀ�����磺");
			scanf("%s", &temp);
			ri.net = inet_addr(temp);
			printf("���������룺");
			scanf("%s", &temp);
			ri.mask = inet_addr(temp);
			printf("��������һ����ַ��");
			scanf("%s", &temp);
			ri.nextip = inet_addr(temp);
			ri.type = 1;
			RT.RouterAdd(&ri);
		}
		else if (op == 3)
		{
			printf("������ɾ�������ţ�");
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