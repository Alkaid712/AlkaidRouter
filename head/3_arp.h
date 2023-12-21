#pragma once

#include "log.h"

struct ArpItem {
    DWORD ip;
    BYTE mac[6];
};

class ArpTable {
private:
    // 最多支持100个ARP项
    static const int MaxArpItems = 100;
    ArpItem arpItems[MaxArpItems];
    int itemCount;
public:
    ArpTable() : itemCount(0) {}
	void InsertArp(DWORD ip, BYTE mac[6]);
	int FindArp(DWORD ip, BYTE mac[6]);
    void PrintArpTable();
};

extern ArpTable AT;

void ArpRequest(DWORD ip0, BYTE mac[]);
