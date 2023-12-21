#pragma once

#include "log.h"

class RouterItem//路由表表项
{
public:
	DWORD mask;          //掩码
	DWORD net;           //目的网络
	DWORD nextip;        //下一跳
	BYTE nextmac[6];
	int index;
	int type;            //0为直接投递，1为静态表项
	RouterItem* nextitem;//采用链表形式存储
	RouterItem();
	void PrintItem();
};

class RouterTable//路由表
{
private:
	RouterItem* head, * tail;
	int num;
public:
	RouterTable();
	void RouterDirect();
	void RouterAdd(RouterItem* a);
	void RouterRemove(int index);
	DWORD RouterFind(DWORD ip);
	void print();
};

extern RouterTable RT;
