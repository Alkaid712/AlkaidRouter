#pragma once

#include "log.h"
#include "3_routerstatic.h"
#include "3_arp.h"

void SetCheckSum(IP* temp);
void SetCheckSum(ICMP* data); // 设置 IP 头部和 ICMP 头部的校验和
bool CheckSum(IP* temp);

void analyze_ip(const u_char* pkt_data);

void resend(ICMP data, BYTE desmac[]);