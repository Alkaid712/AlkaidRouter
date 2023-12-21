#pragma once

#include "log.h"
#include "3_ip.h"
#include "3_arp.h"

bool getmyIP();
bool getmyMAC();

DWORD WINAPI analyze_ethernet();
