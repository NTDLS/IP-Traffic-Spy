#ifndef _ROUTINES_H
#define _ROUTINES_H
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include "../../NSWFL/ANSI/NSWFL.H"

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

using namespace NSWFL::String;
using namespace NSWFL::Collections;

#define MAX_ADDR_LEN 16		//Zero-padded IPv4 mask form ("000.000.000.000").
#define MAX_IP_TEXT 64			//Room for any IPv4/IPv6 address as text.
#define INITEDITPROC (WM_USER + 1000)

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

typedef struct TAG_IP_HDR
{
	unsigned char h_lenver;
	unsigned char tos;
	unsigned short total_len;
	unsigned short ident;
	unsigned short frag_and_flags;
	unsigned char ttl;
	unsigned char proto;
	unsigned short checksum;
	unsigned int sourceIP;
	unsigned int destIP;
}IP_HDR;

typedef struct TAG_IP6_HDR
{
	unsigned int vtc_flow;			//Version, traffic class and flow label.
	unsigned short payload_len;
	unsigned char next_header;
	unsigned char hop_limit;
	unsigned char sourceIP[16];
	unsigned char destIP[16];
} IP6_HDR;

typedef struct TAG_TCP_HDR {
	 unsigned short int sport;
	 unsigned short int dport;
	 unsigned int th_seq;
	 unsigned int th_ack;
	 unsigned char th_x2:4;
	 unsigned char th_off:4;
	 unsigned char Flags;
	 unsigned short int th_win;
	 unsigned short int th_sum;
	 unsigned short int th_urp;
}TCP_HDR;

typedef struct TAG_UDP_HDR
{
	unsigned short sport;       // Source port no.
	unsigned short dport;       // Dest. port no.
	unsigned short udp_length;       // Udp packet length
	unsigned short udp_checksum;     // Udp checksum (optional)
} UDP_HDR, *PUDP_HDR;

typedef struct _TAG_PORTFILTER{
	int *iPort;
	int iCount;
} PORTFILTER, *LPPORTFILTER;

typedef struct _TAG_IPFILTER{
	char **sIP;
	int iCount;
} IPFILTER, *LPIPFILTER;

typedef struct _TAG_BINARY_DATA {
	char *sText;
	int iLength;
	int iProtocol;
} BINARY_DATA, *LPBINARY_DATA;

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

extern HANDLE hListenThread;
//extern HANDLE hResolverThread;

extern StringBuilderArray gIncludeSourceIPFilter;
extern StringBuilderArray gIncludeTargetIPFilter;
extern StringBuilderArray gIncludeSourcePortFilter;
extern StringBuilderArray gIncludeTargetPortFilter;

extern StringBuilderArray gExcludeSourceIPFilter;
extern StringBuilderArray gExcludeTargetIPFilter;
extern StringBuilderArray gExcludeSourcePortFilter;
extern StringBuilderArray gExcludeTargetPortFilter;

volatile extern bool gbShutDownThread;
volatile extern bool gbShutDownResolvers;
volatile extern bool bFilterIncludeTPC;
volatile extern bool bFilterIncludeUDP;
volatile extern bool bFilterIncludeOtherProtocols;
volatile extern bool bFilterIncludeInbpoundPackets;
volatile extern bool bFilterIncludeOutboundPackets;
volatile extern bool bFilterHideOwnDns;
volatile extern bool bAutoScroll;
volatile extern bool bDnsLookups;
volatile extern bool bFilterIncludeBroadcastPackets;

extern CRITICAL_SECTION gCS;
extern volatile LONG gUiWaiting;

#define RESOLVER_THREAD_COUNT 10
extern HANDLE ghResolverThreads[RESOLVER_THREAD_COUNT];

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

DWORD WINAPI ListenThread(LPVOID lpVoid);
DWORD WINAPI ResolverThread(LPVOID lpVoid);
//void FreeExcludeFilters(void);
//void FreeIncludeFilters(void);
void PopListBoxFromArray(HWND hWnd, StringBuilderArray *arr);
void PopListBoxFromArray(HWND hWnd, VectorT<int> *arr);
void PopArrayFromListBox(HWND hWnd, StringBuilderArray *arr);
void PopArrayFromListBox(HWND hWnd, VectorT<int> *arr);
char *MakeIPMask(const char *sInIP, char *sOutIP, int iMaxSz);
bool IsValidIPAddress(const char *sIP);
bool IsValidPort(const char *sPort);
bool CompareIPs(const char *sSIP, const char *sDIP);
int GetPayloadOffset(const char *sPacket, int iSize, int iProtocol);

//Walks the IPv4 header, or the IPv6 header and its extension headers. Returns false if this is not a usable IP packet.
//	piProtocol receives the upper layer protocol, piTransportOffset the offset of the data following the IP headers and
//	pbHasTransport is false when that data does not start with a transport header (non-first fragments).
bool WalkIPHeaders(const char *sPacket, int iSize, int *piProtocol, int *piTransportOffset, bool *pbHasTransport, bool *pbIsV6,
	bool *pbIsFragment = NULL);
void LockListener(void);
void UnlockListener(void);
void ClearGrid(HWND hGrid);
int ApplyFiltersToGrid(HWND hGrid);
void CleanText(const char *sBuf, const int iBufSz, char *sOutBuf, int iOutBufSz);
void CleanRaw(const char *sBuf, const int iBufSz, char *sOutBuf, int iOutBufSz);
void CleanHex(const char *sBuf, const int iBufSz, char *sOutBuf, int iOutBufSz);

//Attaches the advanced rule syntax documentation as a tooltip.
void AttachRuleHelp(HWND hDialog, HWND hEdit, HWND hList, HWND hAddButton);

void AddEditHandler(HWND hOwner, HWND hWnd);
void AddListHandler(HWND hOwner, HWND hWnd);
void AddListViewHandler(HWND hOwner, HWND hWnd);
LRESULT CALLBACK ListControlProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK EditControlProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam);

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#endif
