#pragma once

#include "log.h"
#include "3_routerstatic.h"
#include "3_arp.h"

void SetCheckSum(IP* temp);
void SetCheckSum(ICMP* data); // ���� IP ͷ���� ICMP ͷ����У���
bool CheckSum(IP* temp);

void analyze_ip(const u_char* pkt_data);

void resend(ICMP data, BYTE desmac[]);