#include "3_routerstatic.h"

RouterTable RT;

RouterItem::RouterItem()
{
	memset(this, 0, sizeof(*this));//ȫ����ʼ��Ϊ0
}

void RouterItem::PrintItem()//��ӡ�������ݣ����롢Ŀ�����硢��һ��IP������
{
	in_addr addr;
	printf("%d ", index);
	addr.s_addr = mask;
	char* temp = inet_ntoa(addr);
	printf("%s\t", temp);
	addr.s_addr = net;
	temp = inet_ntoa(addr);
	printf("%s\t", temp);
	addr.s_addr = nextip;
	temp = inet_ntoa(addr);
	printf("��һ����%s\t", temp);
	printf("%d\n", type);
}

RouterTable::RouterTable()
{
	head = new RouterItem;
	tail = new RouterItem;
	head->nextitem = tail;
	num = 0;
}

void RouterTable::RouterDirect() {        // ���ֱ��Ͷ��
	for (int i = 0; i < 2; i++)
	{
		RouterItem* temp = new RouterItem;
		temp->net = (inet_addr(ip[i])) & (inet_addr(mask[i]));//����������ip��������а�λ�뼴Ϊ��������
		temp->nextip = 0;
		temp->mask = inet_addr(mask[i]);
		temp->type = 0;
		this->RouterAdd(temp);
	}
}

void RouterTable::RouterAdd(RouterItem* a) //��Ӿ�̬·��
{
	RouterItem* pointer;
	if (!a->type)
	{
		a->nextitem = head->nextitem;
		head->nextitem = a;
		a->type = 0;
	}
	else // ���������ɴ�С����
	{
		for (pointer = head->nextitem; pointer != tail && pointer->nextitem != tail; pointer = pointer->nextitem)
		{
			if (a->mask < pointer->mask && a->mask >= pointer->nextitem->mask || pointer->nextitem == tail)
			{
				break;
			}
		}
		a->nextitem = pointer->nextitem;
		pointer->nextitem = a;
	}
	RouterItem* p = head->nextitem;
	for (int i = 0; p != tail; p = p->nextitem, i++)
	{
		p->index = i;
	}
	num++;
}

void RouterTable::RouterRemove(int index)//·�ɱ��ɾ��
{
	for (RouterItem* t = head; t->nextitem != tail; t = t->nextitem)
	{
		if (t->nextitem->index == index)
		{
			if (t->nextitem->type == 0)
			{
				printf("�����ɾ��\n");
				return;
			}
			else
			{
				t->nextitem = t->nextitem->nextitem;
				return;
			}
		}
	}
	printf("�޸ñ���\n");
}
void RouterTable::print()
{
	for (RouterItem* p = head->nextitem; p != tail; p = p->nextitem)
	{
		p->PrintItem();
	}
}
DWORD RouterTable::RouterFind(DWORD ip)// �����ƥ��
{
	for (RouterItem* t = head->nextitem; t != tail; t = t->nextitem)
	{
		if ((t->mask & ip) == t->net)
		{
			return t->nextip;
		}
	}
	return -1;
}