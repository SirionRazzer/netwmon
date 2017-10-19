// ConsoleApplication1.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#define WIN32_LEAN_AND_MEAN
#define UNICODE
#define _UNICODE

#include <Windows.h>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <IPHlpApi.h>
#include <tcpestats.h>
#include <tcpmib.h>
#include <mstcpip.h>
#include <stdlib.h>
#include <stdio.h>
#include <iostream>



#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

PCWSTR

StringFromState(MIB_TCP_STATE State)
{
	switch (State)
	{
	case MIB_TCP_STATE_CLOSED:
		return L"CLOSED";
	case MIB_TCP_STATE_LISTEN:
		return L"LISTEN";
	case MIB_TCP_STATE_SYN_SENT:
		return L"SYN_SENT";
	case MIB_TCP_STATE_SYN_RCVD:
		return L"SYN_RCVD";
	case MIB_TCP_STATE_ESTAB:
		return L"ESTAB";
	case MIB_TCP_STATE_FIN_WAIT1:
		return L"FIN_WAIT1";
	case MIB_TCP_STATE_FIN_WAIT2:
		return L"FIN_WAIT2";
	case MIB_TCP_STATE_CLOSE_WAIT:
		return L"CLOSE_WAIT";
	case MIB_TCP_STATE_CLOSING:
		return L"CLOSING";
	case MIB_TCP_STATE_TIME_WAIT:
		return L"TIME_WAIT";
	case MIB_TCP_STATE_DELETE_TCB:
		return L"DELETE_TCB";
	default:
		return L"[Unknown]";
	}
}

LPWSTR(NTAPI *pRtlIpv6AddressToStringW) (const IN6_ADDR *, LPWSTR);

int __cdecl main()
{
	ULONG r;

	HMODULE ntdll = LoadLibrary(L"ntdll");
	pRtlIpv6AddressToStringW = (decltype(pRtlIpv6AddressToStringW))GetProcAddress(ntdll, "RtlIpv6AddressToStringW");

	ULONG cbTable = 100; //guessing table size 100
	MIB_TCP6TABLE2 *table = nullptr;
	
	while (true)
	{
		table = (MIB_TCP6TABLE2*)malloc(cbTable);
		if (!table)
			return 1;
		r = GetTcp6Table2(table, &cbTable, FALSE);

		if (ERROR_INSUFFICIENT_BUFFER == r)
		{
			free(table);
			continue;
		}
		else if (ERROR_SUCCESS == r)
		{
			break;
		}
		else
		{
			free(table);
			wprintf(L"GetTcp6Table2 = %u\n", r);
			return 1;
		}
	}

	wprintf(L"%56s %56s %10s %6s\n", L"Local endpoint", L"Remote endpoint", L"State", L"PID");
	
	for (ULONG i = 0; i < table->dwNumEntries; i++)
	{
		MIB_TCP6ROW2 const &entry = table->table[i];

		WCHAR localAddr[46];
		WCHAR remoteAddr[46];
		pRtlIpv6AddressToStringW(&entry.LocalAddr, localAddr);
		pRtlIpv6AddressToStringW(&entry.RemoteAddr, remoteAddr);

		WCHAR localEndpoint[56];
		WCHAR remoteEndpoint[56];
		swprintf_s(localEndpoint, L"[%s]:%-5u", localAddr, ntohs(entry.dwLocalPort));
		swprintf_s(remoteEndpoint, L"[%s]:%-5u", remoteAddr, ntohs(entry.dwRemotePort));

		wprintf(L"%56s %56s %10s %6u\n", localEndpoint, remoteEndpoint, StringFromState(entry.State), entry.dwOwningPid);
	}

	free(table);

	std::cin.get();

    return 0;
}

