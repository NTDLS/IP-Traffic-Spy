#ifndef _ROUTINES_H
#define _ROUTINES_H
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include "../../NSWFL/NSWFL.H"

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

using namespace NSWFL::String;
using namespace NSWFL::Collections;

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

extern StringBuilderArray gIncludeSourceIPFilter;
extern StringBuilderArray gIncludeTargetIPFilter;
extern VectorT<int> gIncludeSourcePortFilter;
extern VectorT<int> gIncludeTargetPortFilter;

extern StringBuilderArray gExcludeSourceIPFilter;
extern StringBuilderArray gExcludeTargetIPFilter;
extern VectorT<int> gExcludeSourcePortFilter;
extern VectorT<int> gExcludeTargetPortFilter;

volatile extern bool gbShutDownThread;
volatile extern bool gbSuspendThread;
volatile extern bool bFilterIncludeTPC;
volatile extern bool bFilterIncludeUDP;
volatile extern bool bFilterIncludeOtherProtocols;
volatile extern bool bFilterIncludeInbpoundPackets;
volatile extern bool bFilterIncludeOutboundPackets;
volatile extern bool bFilterIncludeBroadcastPackets;

extern CRITICAL_SECTION gCS;

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

DWORD WINAPI ListenThread(LPVOID lpVoid);
//void FreeExcludeFilters(void);
//void FreeIncludeFilters(void);
void PopListBoxFromArray(HWND hWnd, StringBuilderArray *arr);
void PopListBoxFromArray(HWND hWnd, VectorT<int> *arr);
void PopArrayFromListBox(HWND hWnd, StringBuilderArray *arr);
void PopArrayFromListBox(HWND hWnd, VectorT<int> *arr);
char *MakeIPMask(const char *sInIP, char *sOutIP, int iMaxSz);
bool IsValidIPAddress(const char *sIP);
void ClearGrid(HWND hGrid);
void CleanText(const char *sBuf, const int iBufSz, char *sOutBuf, int iOutBufSz);
void CleanRaw(const char *sBuf, const int iBufSz, char *sOutBuf, int iOutBufSz);
void CleanHex(const char *sBuf, const int iBufSz, char *sOutBuf, int iOutBufSz);

void AddEditHandler(HWND hOwner, HWND hWnd);
void AddListHandler(HWND hOwner, HWND hWnd);
void AddListViewHandler(HWND hOwner, HWND hWnd);
LRESULT CALLBACK ListControlProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK EditControlProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam);

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#endif
