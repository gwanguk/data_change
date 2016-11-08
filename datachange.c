#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "windivert.h"

#define MAXBUF  0xFFFF


/*
* Pre-fabricated packets.
*/
typedef struct
{
	WINDIVERT_IPHDR ip;
	WINDIVERT_TCPHDR tcp;
} TCPPACKET, *PTCPPACKET;

/*
* Prototypes.
*/
static void PacketIpInit(PWINDIVERT_IPHDR packet);
static void PacketIpTcpInit(PTCPPACKET packet);
static BOOL changeData(unsigned char * ppacket, int packet_size, const char * origin, int string_size, const char * changed, int changed_size);

/*
* Entry.
*/


int main()
{
	HANDLE handle, console;
	UINT i;
	INT16 priority = 0;
	unsigned char packet[MAXBUF];
	UINT packet_len;
	WINDIVERT_ADDRESS recv_addr, send_addr;
	PWINDIVERT_IPHDR ip_header;
	PWINDIVERT_IPV6HDR ipv6_header;
	PWINDIVERT_ICMPHDR icmp_header;
	PWINDIVERT_ICMPV6HDR icmpv6_header;
	PWINDIVERT_TCPHDR tcp_header;
	PWINDIVERT_UDPHDR udp_header;
	UINT payload_len;

	// Initialize all packets.

								// Get console for pretty colors.
	console = GetStdHandle(STD_OUTPUT_HANDLE);

	// Divert traffic matching the filter:
	handle = WinDivertOpen("tcp", WINDIVERT_LAYER_NETWORK, priority, 0);
	if (handle == INVALID_HANDLE_VALUE)
	{
		if (GetLastError() == ERROR_INVALID_PARAMETER)
		{
			fprintf(stderr, "error: filter syntax error\n");
			exit(EXIT_FAILURE);
		}
		fprintf(stderr, "error: failed to open the WinDivert device (%d)\n",
			GetLastError());
		exit(EXIT_FAILURE);
	}

	// Main loop:
	int packet_num=0;
	while (1)
	{
		// Read a matching packet.
		//IP HEADER FIRST
		if (!WinDivertRecv(handle, packet, sizeof(packet), &recv_addr,
			&packet_len))
		{
			fprintf(stderr, "warning: failed to read packet\n");
			continue;
		}

		// Print info about the matching packet.
		WinDivertHelperParsePacket(packet, packet_len, &ip_header,
			&ipv6_header, &icmp_header, &icmpv6_header, &tcp_header,
			&udp_header, NULL, &payload_len);
		if (ip_header == NULL)
		{
			continue;
		}
		// Dump packet info: 
		SetConsoleTextAttribute(console, FOREGROUND_RED);
		fputs("BLOCK ", stdout);
		SetConsoleTextAttribute(console,
		FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
		if (ip_header != NULL)
		{
			UINT8 *src_addr = (UINT8 *)&ip_header->SrcAddr;
			UINT8 *dst_addr = (UINT8 *)&ip_header->DstAddr;
			printf("ip.SrcAddr=%u.%u.%u.%u ip.DstAddr=%u.%u.%u.%u ",
				src_addr[0], src_addr[1], src_addr[2], src_addr[3],
				dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3]);
		}

		if (ip_header != NULL)
		{
			unsigned char * ppacket;
			ppacket = packet;

			send_addr.Direction = recv_addr.Direction;

			if(!send_addr.Direction) // outbound
				changeData(ppacket, packet_len, "gzip", sizeof("gzip")-1, "    ", sizeof("    ")-1);
			if(send_addr.Direction) // inbound
				changeData(ppacket, packet_len, "Michael", sizeof("Michael")-1,"GILBERT",sizeof("GILBERT")-1);

			WinDivertHelperCalcChecksums((PVOID)ppacket, packet_len, 0);
			
			memcpy(&send_addr, &recv_addr, sizeof(send_addr));
			if (!WinDivertSend(handle, (PVOID)packet, packet_len, &send_addr, NULL))
			{
				fprintf(stderr, "warning: failed (%d)\n",
					GetLastError());
			}
			else
			{
				SetConsoleTextAttribute(console, FOREGROUND_BLUE|FOREGROUND_GREEN);
				fputs("RELAY ", stdout);
			}
		}
		putchar('\n');

	}
}

/*change Packet data*/
static BOOL changeData(unsigned char * ppacket,int packet_size, const char * original, int original_size, const char * changed, int changed_size)
{
	int offset = 0;
	int find_index = 0;

	while (offset+ original_size<packet_size)
	{
		for (int j = 0; j < original_size; j++)
		{
			if (*(ppacket + offset + j) == original[j])
			{
				if (j == original_size - 1)
				{
					for (int k = 0; k < changed_size; k++)
					{
						*(ppacket + offset + k) = changed[k];
					}
					return TRUE;
				}
			}
			else
				break;
		}
		offset++;
	}
	return FALSE;
}


/*
* Initialize a PACKET.
*/
static void PacketIpInit(PWINDIVERT_IPHDR packet)
{
	memset(packet, 0, sizeof(WINDIVERT_IPHDR));
	packet->Version = 4;
	packet->HdrLength = sizeof(WINDIVERT_IPHDR) / sizeof(UINT32);
	packet->Id = ntohs(0xDEAD);
	packet->TTL = 64;
}

/*
* Initialize a TCPPACKET.
*/
static void PacketIpTcpInit(PTCPPACKET packet)
{
	memset(packet, 0, sizeof(TCPPACKET));
	PacketIpInit(&packet->ip);
	packet->ip.Length = htons(sizeof(TCPPACKET));
	packet->ip.Protocol = IPPROTO_TCP;
	packet->tcp.HdrLength = sizeof(WINDIVERT_TCPHDR) / sizeof(UINT32);
}
