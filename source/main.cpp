#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <Winsock2.h>
#include "pcap.h"
#include "stdio.h"

#include "log.h"
#include "shell.h"
#include "2_ethernet.h"
#include "3_routerstatic.h"
#include "3_arp.h"
#include "3_ip.h"

#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib, "packet.lib")
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"wsock32.lib")
#pragma warning(disable : 4996)

int main()
{
	if (!getmyIP()) return 0;
	if (!getmyMAC()) return 0;

	DWORD dwThreadId;
	HANDLE backend = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)analyze_ethernet, NULL, 0, &dwThreadId);
	HANDLE frontend = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)shell, NULL, 0, &dwThreadId);
	WaitForSingleObject(frontend, INFINITE);

	return 0;
}