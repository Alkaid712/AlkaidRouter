#pragma once

#include "log.h"

class RouterItem//·�ɱ����
{
public:
	DWORD mask;          //����
	DWORD net;           //Ŀ������
	DWORD nextip;        //��һ��
	BYTE nextmac[6];
	int index;
	int type;            //0Ϊֱ��Ͷ�ݣ�1Ϊ��̬����
	RouterItem* nextitem;//����������ʽ�洢
	RouterItem();
	void PrintItem();
};

class RouterTable//·�ɱ�
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
