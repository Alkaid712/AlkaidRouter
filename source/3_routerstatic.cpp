#include "3_routerstatic.h"

RouterTable RT;

RouterItem::RouterItem()
{
	memset(this, 0, sizeof(*this));//全部初始化为0
}

void RouterItem::PrintItem()//打印表项内容：掩码、目的网络、下一跳IP、类型
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
	printf("下一跳：%s\t", temp);
	printf("%d\n", type);
}

RouterTable::RouterTable()
{
	head = new RouterItem;
	tail = new RouterItem;
	head->nextitem = tail;
	num = 0;
}

void RouterTable::RouterDirect() {        // 添加直接投递
	for (int i = 0; i < 2; i++)
	{
		RouterItem* temp = new RouterItem;
		temp->net = (inet_addr(ip[i])) & (inet_addr(mask[i]));//本机网卡的ip和掩码进行按位与即为所在网络
		temp->nextip = 0;
		temp->mask = inet_addr(mask[i]);
		temp->type = 0;
		this->RouterAdd(temp);
	}
}

void RouterTable::RouterAdd(RouterItem* a) //添加静态路由
{
	RouterItem* pointer;
	if (!a->type)
	{
		a->nextitem = head->nextitem;
		head->nextitem = a;
		a->type = 0;
	}
	else // 按照掩码由大到小排列
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

void RouterTable::RouterRemove(int index)//路由表的删除
{
	for (RouterItem* t = head; t->nextitem != tail; t = t->nextitem)
	{
		if (t->nextitem->index == index)
		{
			if (t->nextitem->type == 0)
			{
				printf("该项不可删除\n");
				return;
			}
			else
			{
				t->nextitem = t->nextitem->nextitem;
				return;
			}
		}
	}
	printf("无该表项\n");
}
void RouterTable::print()
{
	for (RouterItem* p = head->nextitem; p != tail; p = p->nextitem)
	{
		p->PrintItem();
	}
}
DWORD RouterTable::RouterFind(DWORD ip)// 查找最长匹配
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