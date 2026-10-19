#ifndef _ROUTINES_CPP
#define _ROUTINES_CPP
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include <WinSock2.h>
#include <Windows.H>
#include <WS2TcpIP.h>
#include <Stdio.H>
#include <Stdlib.H>
#include <CommCtrl.h>
#include <Mstcpip.h>
#include <mswsock.h>
#include <vector>
#include <set>
#include <string>

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include "Entry.H"

#include "Filters.H"

#include "../Dialogs/MainDlg.H"

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

using namespace NSWFL::String;
using namespace NSWFL::DateTime;
using namespace NSWFL::Conversion;
using namespace NSWFL::Windows;
using namespace NSWFL::File;
using namespace NSWFL::ListBox;
using namespace NSWFL::Memory;
using namespace NSWFL::Collections;
using namespace NSWFL::Network;

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#define MAX_HOST_NAME_SZ 255

typedef struct _tag_HostResolverTask
{
	int GridRow;
	int GridColumn;
	char *IPAddress;
	int Sequence;
	LONG Generation;	//gGridGeneration when queued, rows are meaningless once the grid has been cleared/filtered.
	LONG TrimBase;		//gRowsTrimmed when queued, rows move up as old rows are trimmed from the top.
} HOSTRESOLVERTASK, *LPHOSTRESOLVERTASK;

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

StringBuilderArray gIncludeSourceIPFilter;
StringBuilderArray gIncludeTargetIPFilter;
StringBuilderArray gIncludeSourcePortFilter;
StringBuilderArray gIncludeTargetPortFilter;

StringBuilderArray gExcludeSourceIPFilter;
StringBuilderArray gExcludeTargetIPFilter;
StringBuilderArray gExcludeSourcePortFilter;
StringBuilderArray gExcludeTargetPortFilter;

VectorT<HOSTRESOLVERTASK> gHostResolverQueue;
DictionaryString gHostResolverCache;

HANDLE hListenThread = NULL;

__int64 i64MatchPackets = 0;
__int64 i64MatchPakSize = 0;

volatile bool gbShutDownThread = false;
volatile bool gbShutDownResolvers = false;
volatile bool bFilterIncludeTPC = true;
volatile bool bFilterIncludeUDP = true;
volatile bool bFilterIncludeOtherProtocols = true;
volatile bool bFilterIncludeInbpoundPackets = true;
volatile bool bFilterIncludeOutboundPackets = true;
volatile bool bFilterHideOwnDns = true;
volatile bool bAutoScroll = true;	//Keep the newest packet in view.
volatile bool bDnsLookups = true;	//Look up host names (when off, only names already known are used).
volatile bool bFilterIncludeBroadcastPackets = true;

CRITICAL_SECTION gCS;

volatile LONG gGridGeneration = 0;
volatile LONG gRowsTrimmed = 0;
static __int64 gi64StoredBytes = 0; //Bytes of packet data held by the rows of the grid.
#define MAX_STORED_BYTES (512LL * 1024 * 1024)
#define MAX_GRID_ROWS 100000
volatile LONG gUiWaiting = 0; //Non-zero while the UI thread is waiting to acquire gCS.
HANDLE ghResolverThreads[RESOLVER_THREAD_COUNT];

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void PopListBoxFromArray(HWND hWnd, VectorT<int> *arr)
{
	arr->SortAscending();

	char sBuff[128];
	for (int i = 0; i < arr->Count(); i++)
	{
		sprintf_s(sBuff, sizeof(sBuff), "%d", arr->GetValueAtIndex(i));
		InsertListBoxItem(hWnd, sBuff);
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void PopListBoxFromArray(HWND hWnd, StringBuilderArray *arr)
{
	arr->SortAscending();

	for (int i = 0; i < arr->Count(); i++)
	{
		InsertListBoxItem(hWnd, arr->at(i)->Buffer);
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void PopArrayFromListBox(HWND hWnd, VectorT<int> *arr)
{
	int iItemCount = CountListBoxItems(hWnd);
	int iLength = 0;

	arr->Clear();

	for(int i = 0; i < iItemCount; i++)
	{
		if ((iLength = GetListBoxItemLength(hWnd, i)) > 0)
		{
			char *sText = (char *)calloc(sizeof(char), iLength + 1);

			if (GetListBoxItemText(sText, iLength + 1, hWnd, i) > 0)
			{
				arr->Add(atoi(sText));
			}

			free(sText);
		}			
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void PopArrayFromListBox(HWND hWnd, StringBuilderArray *arr)
{
	int iItemCount = CountListBoxItems(hWnd);
	int iLength = 0;

	arr->Clear();

	for (int i = 0; i < iItemCount; i++)
	{
		if ((iLength = GetListBoxItemLength(hWnd, i)) > 0)
		{
			char *sText = (char *)calloc(sizeof(char), iLength + 1);

			if (GetListBoxItemText(sText, iLength + 1, hWnd, i) > 0)
			{
				arr->Add(sText);
			}

			free(sText);
		}
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

LRESULT CALLBACK EditControlProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	static WNDPROC lpOldProc;
	static HWND hOwner;

	if(uMsg == WM_GETDLGCODE)
	{
		return (DLGC_WANTALLKEYS | CallWindowProc(lpOldProc, hWnd, uMsg, wParam, lParam));
	}
	else if(uMsg == INITEDITPROC)
	{
		memcpy(&lpOldProc, (WNDPROC *)lParam, sizeof(WNDPROC));
		memcpy(&hOwner, (WNDPROC *)wParam, sizeof(HWND));
	}
	else if(uMsg == WM_CHAR)
	{
		if(wParam == VK_RETURN)
		{
			return 0;
		}
		else if(wParam == VK_TAB)
		{
			return 0;
		}
		else if(wParam == VK_ESCAPE)
		{
			return 0;
		}
	}
	else if(uMsg == WM_KEYDOWN)
	{
		if(wParam == VK_TAB)
		{
			PostMessage(hOwner, WM_NEXTDLGCTL, 0, 0L);
			return 0;
		}
		else if(wParam == VK_RETURN)
		{
			int iControls[] = {
				IDC_EDIT_SIP,
				IDC_EDIT_DIP,
				IDC_EDIT_SPORT,
				IDC_EDIT_DPORT,
				IDC_EDIT_RULE,
				NULL
			};

			int iMessages[] = {
				IDC_BUTTON_SIP,
				IDC_BUTTON_DIP,
				IDC_BUTTON_SPORT,
				IDC_BUTTON_DPORT,
				IDC_BUTTON_RULE,
				NULL
			};

			for(int iControl = 0; iControls[iControl] != NULL; iControl++)
			{
				if(hWnd == GetDlgItem(hOwner, iControls[iControl]))
				{
					SendMessage(hOwner, WM_COMMAND, iMessages[iControl], 0);
					break;
				}
			}
		}
	}

	if(lpOldProc)
	{
		return CallWindowProc(lpOldProc, hWnd, uMsg, wParam, lParam);
	}
	else{
		return 0;
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

LRESULT CALLBACK ListControlProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	static WNDPROC lpOldProc;
	static HWND hOwner;

	if(uMsg == WM_GETDLGCODE)
	{
		return (DLGC_WANTALLKEYS | CallWindowProc(lpOldProc, hWnd, uMsg, wParam, lParam));
	}
	else if(uMsg == INITEDITPROC)
	{
		memcpy(&lpOldProc, (WNDPROC *)lParam, sizeof(WNDPROC));
		memcpy(&hOwner, (WNDPROC *)wParam, sizeof(HWND));
	}
	else if(uMsg == WM_CHAR)
	{
		if(wParam == VK_RETURN)
		{
			return 0;
		}
		else if(wParam == VK_TAB)
		{
			return 0;
		}
		else if(wParam == VK_ESCAPE)
		{
			return 0;
		}
	}
	else if(uMsg == WM_KEYDOWN)
	{
		if(wParam == VK_TAB)
		{
			PostMessage(hOwner, WM_NEXTDLGCTL, 0, 0L);
			return 0;
		}
		else if(wParam == VK_DELETE)
		{
			int iControls[] = {
				IDC_LIST_SIP,
				IDC_LIST_DIP,
				IDC_LIST_SPORT,
				IDC_LIST_DPORT,
				IDC_LIST_RULE,
				NULL
			};

			int iMessages[] = {
				IDC_BUTTON_SIP_DEL,
				IDC_BUTTON_DIP_DEL,
				IDC_BUTTON_SPORT_DEL,
				IDC_BUTTON_DPORT_DEL,
				IDC_BUTTON_RULE_DEL,
				NULL
			};

			for(int iControl = 0; iControls[iControl] != NULL; iControl++)
			{
				if(hWnd == GetDlgItem(hOwner, iControls[iControl]))
				{
					SendMessage(hOwner, WM_COMMAND, iMessages[iControl], 0);
					break;
				}
			}
		}
	}

	if(lpOldProc)
	{
		return CallWindowProc(lpOldProc, hWnd, uMsg, wParam, lParam);
	}
	else{
		return 0;
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

LRESULT CALLBACK ListViewControlProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	static WNDPROC lpOldProc;
	static HWND hOwner;

	if(uMsg == WM_GETDLGCODE)
	{
		return (DLGC_WANTALLKEYS | CallWindowProc(lpOldProc, hWnd, uMsg, wParam, lParam));
	}
	else if(uMsg == INITEDITPROC)
	{
		memcpy(&lpOldProc, (WNDPROC *)lParam, sizeof(WNDPROC));
		memcpy(&hOwner, (WNDPROC *)wParam, sizeof(HWND));
	}
	else if(uMsg == WM_CHAR)
	{
		return 0;
	}
	else if(uMsg == WM_KEYDOWN || uMsg == WM_KEYUP)
	{
		return 0;
	}

	if(lpOldProc)
	{
		return CallWindowProc(lpOldProc, hWnd, uMsg, wParam, lParam);
	}
	else{
		return 0;
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static const char *gsRuleHelp =
	"ADVANCED RULES\n"
	"\n"
	"A rule is one or more terms. A packet matches a rule only when ALL of its terms match (the word \"and\" between\n"
	"terms is optional). Every rule in the list is an alternative: any one rule matching is enough.\n"
	"Terms are written as a keyword followed by a value, for example:  src 10.0.0.0/8 and dport 443 and proto tcp\n"
	"\n"
	"IP ADDRESSES\n"
	"  src <ip>     the source address\n"
	"  dst <ip>     the destination address\n"
	"  ip <ip>      either address (useful for following a conversation in both directions)\n"
	"  <ip> can be:  192.168.1.5   |   10.0.?.?  (? matches one digit, IPv4 only)   |   10.0.0.0/8  (CIDR block)\n"
	"                2001:db8::1   |   fe80::/10   (IPv6 address or CIDR block)\n"
	"\n"
	"PORTS (TCP and UDP only, and only on packets which carry the transport header)\n"
	"  sport <port>   source port        dport <port>   destination port        port <port>   either port\n"
	"  <port> can be:  443   |   1024-65535  (inclusive range)\n"
	"\n"
	"PROTOCOL\n"
	"  proto <name or number>\n"
	"  names:  tcp  udp  icmp  icmpv6  igmp  gre  esp  ah  sctp      numbers: 0 - 255\n"
	"\n"
	"TCP FLAGS\n"
	"  flags <list>   comma separated, every listed flag must be set; prefix a flag with ! to require it to be clear\n"
	"  flags:  fin  syn  rst  psh  ack  urg  ece  cwr\n"
	"  e.g.  flags syn,!ack  (new connection attempts)      flags rst  (connection resets)\n"
	"\n"
	"HOST NAMES\n"
	"  shost <name>   source host        dhost <name>   destination host        host <name>   either\n"
	"  A plain name such as example.com is looked up for you and matches that site's IP addresses (re-checked every\n"
	"  few minutes), and also any reverse DNS name containing the text.\n"
	"  A name with wildcards (* = anything, ? = one character) such as *.example.com is matched against the reverse DNS\n"
	"  name only. Reverse DNS names are filled in as each address is resolved, so the first packets of a brand new\n"
	"  address can be missed by wildcard patterns.\n"
	"\n"
	"PAYLOAD\n"
	"  contains <text>   case-insensitive search of the packet data after the headers\n"
	"  put the text in double quotes if it contains spaces:   contains \"user-agent: curl\"\n"
	"\n"
	"EXAMPLES\n"
	"  port 53                                      DNS traffic, either direction\n"
	"  ip 10.1.2.3 and ip 10.1.2.9                  everything between two machines\n"
	"  src 192.168.0.0/16 and dport 1024-65535      from the LAN to high ports\n"
	"  proto tcp and flags syn,!ack and dport 22    incoming SSH connection attempts\n"
	"  host *.microsoft.com                         anything involving a Microsoft host\n"
	"  proto udp and contains \"dns\"                 UDP packets mentioning dns\n"
	"\n"
	"HOW RULES ARE USED\n"
	"  Include dialog: only packets matching any include rule (or other include entry) are shown. Tick the\n"
	"  \"require every group\" box to demand a match in every group which has entries.\n"
	"  Exclude dialog: packets matching any exclude rule (or other exclude entry) are hidden.";

static WNDPROC gpOldTipProc = NULL;

static LRESULT CALLBACK RuleHelpTipProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	if(uMsg == WM_NCHITTEST)
	{
		return HTTRANSPARENT;
	}
	return CallWindowProc(gpOldTipProc, hWnd, uMsg, wParam, lParam);
}

void AttachRuleHelp(HWND hDialog, HWND hEdit, HWND hList, HWND hAddButton)
{
	INITCOMMONCONTROLSEX icc;
	icc.dwSize = sizeof(icc);
	icc.dwICC = ICC_WIN95_CLASSES;
	InitCommonControlsEx(&icc);

	HWND hTip = CreateWindowEx(WS_EX_TOPMOST, TOOLTIPS_CLASS, NULL, WS_POPUP | TTS_NOPREFIX | TTS_ALWAYSTIP,
		CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, hDialog, NULL, ghAppInstance, NULL);

	if(hTip == NULL)
	{
		return;
	}

	//Without the v6 common controls the tip window would receive the mouse once it appears under the cursor, which makes
	//	the control think the mouse left and hide the tip again (it flickers). Make the tip window click-through.
	gpOldTipProc = (WNDPROC)SetWindowLongPtr(hTip, GWLP_WNDPROC, (LONG_PTR)&RuleHelpTipProc);

	SendMessage(hTip, TTM_SETMAXTIPWIDTH, 0, 640);
	SendMessage(hTip, TTM_SETDELAYTIME, TTDT_INITIAL, 250);
	SendMessage(hTip, TTM_SETDELAYTIME, TTDT_AUTOPOP, 32000);

	HWND hControls[] = { hEdit, hList, hAddButton };

	for(int i = 0; i < 3; i++)
	{
		//Attach to the control itself so its own mouse messages drive the tip.
		TOOLINFO ti;
		memset(&ti, 0, sizeof(ti));
		ti.cbSize = TTTOOLINFO_V1_SIZE;
		ti.uFlags = TTF_SUBCLASS;
		ti.hwnd = hControls[i];
		ti.uId = 1;
		GetClientRect(hControls[i], &ti.rect);
		ti.lpszText = (LPSTR)gsRuleHelp;
		SendMessage(hTip, TTM_ADDTOOL, 0, (LPARAM)&ti);
	}

	//The header text above the edit box (a static control does not receive mouse messages, so use its area).
	RECT rcEdit;
	GetWindowRect(hEdit, &rcEdit);
	POINT pt1 = { rcEdit.left, rcEdit.top - 16 };
	POINT pt2 = { rcEdit.right, rcEdit.top };
	ScreenToClient(hDialog, &pt1);
	ScreenToClient(hDialog, &pt2);

	TOOLINFO tiHeader;
	memset(&tiHeader, 0, sizeof(tiHeader));
	tiHeader.cbSize = TTTOOLINFO_V1_SIZE;
	tiHeader.uFlags = TTF_SUBCLASS;
	tiHeader.hwnd = hDialog;
	tiHeader.uId = 1;
	tiHeader.rect.left = pt1.x;
	tiHeader.rect.top = pt1.y;
	tiHeader.rect.right = pt2.x;
	tiHeader.rect.bottom = pt2.y;
	tiHeader.lpszText = (LPSTR)gsRuleHelp;
	SendMessage(hTip, TTM_ADDTOOL, 0, (LPARAM)&tiHeader);
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void AddEditHandler(HWND hOwner, HWND hWnd)
{
	WNDPROC gpOldProc = (WNDPROC) SetWindowLongPtr(hWnd, GWLP_WNDPROC, (LONG_PTR) &EditControlProc);
	SendMessage(hWnd, INITEDITPROC, (WPARAM)&hOwner, (LPARAM) &gpOldProc);
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void AddListHandler(HWND hOwner, HWND hWnd)
{
	WNDPROC gpOldProc = (WNDPROC) SetWindowLongPtr(hWnd, GWLP_WNDPROC, (LONG_PTR) &ListControlProc);
	SendMessage(hWnd, INITEDITPROC, (WPARAM)&hOwner, (LPARAM) &gpOldProc);
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void AddListViewHandler(HWND hOwner, HWND hWnd)
{
	WNDPROC gpOldProc = (WNDPROC) SetWindowLongPtr(hWnd, GWLP_WNDPROC, (LONG_PTR) &ListViewControlProc);
	SendMessage(hWnd, INITEDITPROC, (WPARAM)&hOwner, (LPARAM) &gpOldProc);
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void CleanHex(const char *sBuf, const int iBufSz, char *sOutBuf, int iOutBufSz)
{
	Bin2HexFriendly(sOutBuf, iOutBufSz, sBuf, iBufSz, 2, 30);
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void CleanText(const char *sBuf, const int iBufSz, char *sOutBuf, int iOutBufSz)
{
	int iWPos = 0;

	memset(sOutBuf, 0, iOutBufSz);

	for(int iRPos = 0; iRPos < iBufSz && iWPos < iOutBufSz - 1; iRPos++)
	{
		if((sBuf[iRPos] >= 32 && sBuf[iRPos] <= 126)
			|| sBuf[iRPos] == '\r' || sBuf[iRPos] == '\n' || sBuf[iRPos] == '\t')
		{
			sOutBuf[iWPos++] = sBuf[iRPos];
		}
	}
	sOutBuf[iWPos] = '\0';
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void CleanRaw(const char *sBuf, const int iBufSz, char *sOutBuf, int iOutBufSz)
{
	int iWPos = 0;

	memset(sOutBuf, 0, iOutBufSz);

	for (int iRPos = 0; iRPos < iBufSz && iWPos < iOutBufSz - 1; iRPos++)
	{
		if (sBuf[iRPos] == '\0')
		{
			sOutBuf[iWPos++] = ' ';
		}
		else
		{
			sOutBuf[iWPos++] = sBuf[iRPos];
		}
	}

	sOutBuf[iWPos] = '\0';
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void ClearGrid(HWND hGrid)
{
	//The listen thread owns gCS while it touches the list-view, so wait for it to be idle.
	LockListener();

	int iItems = ListView_GetItemCount(hGrid);

	for(int iItem = 0; iItem < iItems; iItem++)
	{
		LV_ITEM lvDelItem;
		memset(&lvDelItem, 0, sizeof(lvDelItem));
		lvDelItem.mask = LVIF_PARAM;
		lvDelItem.iItem = iItem;

		if(ListView_GetItem(hGrid, &lvDelItem))
		{
			BINARY_DATA *delBinData = (BINARY_DATA *)lvDelItem.lParam;
			if(delBinData)
			{
				free(delBinData->sText);
				free(delBinData);
			}
		}
	}

	ListView_DeleteAllItems(hGrid);

	i64MatchPackets = 0;
	i64MatchPakSize = 0;
	gi64StoredBytes = 0;
	InterlockedIncrement(&gGridGeneration);

	UnlockListener();
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//Deletes every row which would not be displayed under the current filters. Returns the number of rows removed.
int ApplyFiltersToGrid(HWND hGrid)
{
	int iRemoved = 0;

	LockListener();

	SendMessage(hGrid, WM_SETREDRAW, FALSE, 0);

	for(int iItem = ListView_GetItemCount(hGrid) - 1; iItem >= 0; iItem--)
	{
		LV_ITEM lvItem;
		memset(&lvItem, 0, sizeof(lvItem));
		lvItem.mask = LVIF_PARAM;
		lvItem.iItem = iItem;

		if(!ListView_GetItem(hGrid, &lvItem))
		{
			continue;
		}

		BINARY_DATA *binData = (BINARY_DATA *)lvItem.lParam;
		PACKET_INFO packet;

		if(binData == NULL || !ParsePacket(binData->sText, binData->iLength, &packet))
		{
			continue;
		}

		char sSourceHost[MAX_HOST_NAME_SZ + 1];
		char sDestHost[MAX_HOST_NAME_SZ + 1];
		ListView_GetItemText(hGrid, iItem, COL_S_HOST_POS, sSourceHost, sizeof(sSourceHost));
		ListView_GetItemText(hGrid, iItem, COL_D_HOST_POS, sDestHost, sizeof(sDestHost));

		int iImage = 0;
		if(EvaluatePacket(&packet, sSourceHost, sDestHost, &iImage) != FILTER_SHOW)
		{
			gi64StoredBytes -= binData->iLength;
			free(binData->sText);
			free(binData);
			ListView_DeleteItem(hGrid, iItem);
			iRemoved++;
		}
	}

	//Recount the statistics for the rows which remain.
	i64MatchPackets = 0;
	i64MatchPakSize = 0;

	for(int iItem = 0; iItem < ListView_GetItemCount(hGrid); iItem++)
	{
		LV_ITEM lvItem;
		memset(&lvItem, 0, sizeof(lvItem));
		lvItem.mask = LVIF_PARAM;
		lvItem.iItem = iItem;

		if(ListView_GetItem(hGrid, &lvItem) && lvItem.lParam)
		{
			i64MatchPackets++;
			i64MatchPakSize += ((BINARY_DATA *)lvItem.lParam)->iLength;
		}
	}

	InterlockedIncrement(&gGridGeneration);

	SendMessage(hGrid, WM_SETREDRAW, TRUE, 0);
	InvalidateRect(hGrid, NULL, TRUE);

	UnlockListener();

	return iRemoved;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//Acquires gCS from the UI thread. The listen thread may be sending messages to the UI thread
//	while it owns the lock, so we must keep pumping messages while we wait.
void LockListener(void)
{
	//Tell the listener we are waiting, it holds the lock for nearly every instant on a busy network and would starve us.
	InterlockedIncrement(&gUiWaiting);

	while(!TryEnterCriticalSection(&gCS))
	{
		PumpMessages();
		Sleep(1);
	}

	InterlockedDecrement(&gUiWaiting);
}

void UnlockListener(void)
{
	LeaveCriticalSection(&gCS);
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

bool WalkIPHeaders(const char *sPacket, int iSize, int *piProtocol, int *piTransportOffset, bool *pbHasTransport, bool *pbIsV6,
	bool *pbIsFragment)
{
	if(iSize < 1)
	{
		return false;
	}

	int iVersion = ((unsigned char)sPacket[0]) >> 4;

	if(pbIsFragment)
	{
		*pbIsFragment = false;
	}

	if(iVersion == 4)
	{
		if(iSize < (int)sizeof(IP_HDR))
		{
			return false;
		}

		const IP_HDR *pIP = (const IP_HDR *)sPacket;

		int iOffset = (pIP->h_lenver & 0x0F) * 4;
		if(iOffset < (int)sizeof(IP_HDR) || iOffset > iSize)
		{
			iOffset = (int)sizeof(IP_HDR);
		}

		*piProtocol = pIP->proto;
		*piTransportOffset = iOffset;
		*pbHasTransport = (ntohs(pIP->frag_and_flags) & 0x1FFF) == 0; //Non-first fragments do not carry a transport header.
		*pbIsV6 = false;
		if(pbIsFragment)
		{
			*pbIsFragment = (ntohs(pIP->frag_and_flags) & 0x3FFF) != 0; //More-fragments flag or a fragment offset.
		}
		return true;
	}

	if(iVersion == 6)
	{
		if(iSize < (int)sizeof(IP6_HDR))
		{
			return false;
		}

		const unsigned char *pData = (const unsigned char *)sPacket;
		int iProtocol = ((const IP6_HDR *)sPacket)->next_header;
		int iOffset = (int)sizeof(IP6_HDR);
		bool bHasTransport = true;

		//Walk the extension header chain to find the upper layer protocol.
		for(int iHeader = 0; iHeader < 16; iHeader++)
		{
			if(iProtocol == 0 || iProtocol == 43 || iProtocol == 60) //Hop-by-hop, routing, destination options.
			{
				if(iOffset + 8 > iSize) { bHasTransport = false; break; }
				iProtocol = pData[iOffset];
				iOffset += (pData[iOffset + 1] + 1) * 8;
			}
			else if(iProtocol == 44) //Fragment.
			{
				if(iOffset + 8 > iSize) { bHasTransport = false; break; }
				int iFragmentOffset = ((pData[iOffset + 2] << 8) | pData[iOffset + 3]) >> 3;
				if(pbIsFragment)
				{
					*pbIsFragment = true;
				}
				iProtocol = pData[iOffset];
				iOffset += 8;
				if(iFragmentOffset != 0)
				{
					bHasTransport = false;
					break;
				}
			}
			else if(iProtocol == 51) //Authentication header.
			{
				if(iOffset + 8 > iSize) { bHasTransport = false; break; }
				iProtocol = pData[iOffset];
				iOffset += (pData[iOffset + 1] + 2) * 4;
			}
			else
			{
				break;
			}
		}

		if(iOffset > iSize)
		{
			iOffset = iSize;
			bHasTransport = false;
		}

		*piProtocol = iProtocol;
		*piTransportOffset = iOffset;
		*pbHasTransport = bHasTransport;
		*pbIsV6 = true;
		return true;
	}

	return false;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//Returns the offset of the payload (past the IP and TCP/UDP headers), honoring the actual header lengths.
int GetPayloadOffset(const char *sPacket, int iSize, int iProtocol)
{
	int iWalkedProtocol = 0;
	int iOffset = 0;
	bool bHasTransport = false;
	bool bIsV6 = false;

	if(!WalkIPHeaders(sPacket, iSize, &iWalkedProtocol, &iOffset, &bHasTransport, &bIsV6))
	{
		return 0;
	}

	if(!bHasTransport)
	{
		return iOffset;
	}

	if(iWalkedProtocol == IPPROTO_TCP && iSize - iOffset >= (int)sizeof(TCP_HDR))
	{
		const TCP_HDR *pTCP = (const TCP_HDR *)(sPacket + iOffset);
		int iTcpLen = pTCP->th_off * 4;
		if(iTcpLen < (int)sizeof(TCP_HDR) || iTcpLen > iSize - iOffset)
		{
			iTcpLen = (int)sizeof(TCP_HDR);
		}
		iOffset += iTcpLen;
	}
	else if(iWalkedProtocol == IPPROTO_UDP && iSize - iOffset >= (int)sizeof(UDP_HDR))
	{
		iOffset += (int)sizeof(UDP_HDR);
	}

	return iOffset;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

bool IsValidPort(const char *sPort)
{
	int iLength = (int)strlen(sPort);

	if(iLength < 1 || iLength > 5)
	{
		return false;
	}

	for(int iPos = 0; iPos < iLength; iPos++)
	{
		if(!IsNumeric(sPort[iPos]))
		{
			return false;
		}
	}

	return atol(sPort) <= 65535;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

int AddListBoxItem(const char *sSourceIP, char *sSourceHost, const char *sDestIP, char *sDestHost, const int iSourcePort, const int iDestPort,
					const char *sText, const int iSize, int iProtocol, const int iImage, int iSequence, const char *sMatchedBy)
{
	char sTemp[1024];

	LV_ITEM lvItem;
	memset(&lvItem, 0, sizeof(lvItem));
	int iItems = ListView_GetItemCount(hItemList);

	//Keep both the number of rows and the memory held by their packets bounded. Removing a row from the top of a list-view
	//	makes it redraw and re-anchor its scroll position, which flickers badly if it happens for every packet. So when a limit
	//	is hit, remove a whole batch at once with redrawing suspended, and then not again until the batch has been used up.
	if(iItems > MAX_GRID_ROWS || gi64StoredBytes > MAX_STORED_BYTES)
	{
		const int iTargetRows = MAX_GRID_ROWS - (MAX_GRID_ROWS / 100);
		const __int64 i64TargetBytes = MAX_STORED_BYTES - (MAX_STORED_BYTES / 100);

		SendMessage(hItemList, WM_SETREDRAW, FALSE, 0);

		int iTopIndex = ListView_GetTopIndex(hItemList);
		int iRemoved = 0;

		while(iItems > 0 && iRemoved < 20000 && (iItems > iTargetRows || gi64StoredBytes > i64TargetBytes))
		{
			LV_ITEM lvDelItem;
			memset(&lvDelItem, 0, sizeof(lvDelItem));
			lvDelItem.mask = LVIF_PARAM;
			lvDelItem.iItem = 0;

			if(ListView_GetItem(hItemList, &lvDelItem))
			{
				BINARY_DATA *delBinData = (BINARY_DATA *)lvDelItem.lParam;
				if(delBinData)
				{
					gi64StoredBytes -= delBinData->iLength;
					free(delBinData->sText);
					free(delBinData);
				}
			}

			ListView_DeleteItem(hItemList, 0);
			InterlockedIncrement(&gRowsTrimmed);
			iItems--;
			iRemoved++;
		}

		//The rows moved up. Unless we are about to scroll to the bottom anyway, keep showing the same rows.
		if(!bAutoScroll && iRemoved > 0)
		{
			ListView_EnsureVisible(hItemList, iTopIndex > iRemoved ? iTopIndex - iRemoved : 0, FALSE);
		}

		SendMessage(hItemList, WM_SETREDRAW, TRUE, 0);
		InvalidateRect(hItemList, NULL, FALSE);
	}

	BINARY_DATA *binData = (BINARY_DATA *) calloc(1, sizeof(BINARY_DATA));
	binData->sText = (char *)calloc(iSize, sizeof(char));
	binData->iProtocol = iProtocol;
	memcpy(binData->sText, sText, iSize);
	binData->iLength = iSize;
	gi64StoredBytes += iSize;

	Get_ShortDate(sTemp, sizeof(sTemp));
	lvItem.pszText = sTemp;
	lvItem.mask = LVIF_TEXT|LVIF_IMAGE|LVIF_PARAM;
	lvItem.iSubItem = COL_DATE_POS;
	lvItem.lParam = (LPARAM)binData;
	lvItem.iItem = iItems;
	lvItem.iImage = iImage;
	int iItem = ListView_InsertItem(hItemList, &lvItem);

	Get_Time(sTemp, sizeof(sTemp), 0);
	lvItem.pszText = sTemp;
	lvItem.mask = LVIF_TEXT;
	lvItem.iSubItem = COL_TIME_POS;
	lvItem.iItem = iItem;
	ListView_SetItem(hItemList, &lvItem);

	char *sProto = "Other";
	if(iProtocol == IPPROTO_TCP)
	{
		sProto = "TCP";
	}
	else if (iProtocol == IPPROTO_UDP)
	{
		sProto = "UDP";
	}
	else if (iProtocol == IPPROTO_ICMP)
	{
		sProto = "ICMP";
	}
	else if (iProtocol == IPPROTO_ICMPV6)
	{
		sProto = "ICMPv6";
	}
	else if (iProtocol == IPPROTO_IGMP)
	{
		sProto = "IGMP";
	}
	else if (iProtocol == IPPROTO_GGP)
	{
		sProto = "GGP";
	}
	else if (iProtocol == IPPROTO_ST)
	{
		sProto = "ST";
	}
	else if (iProtocol == IPPROTO_CBT)
	{
		sProto = "CBT";
	}
	else if (iProtocol == IPPROTO_EGP)
	{
		sProto = "EGP";
	}
	else if (iProtocol == IPPROTO_IGP)
	{
		sProto = "IGP";
	}
	else if (iProtocol == IPPROTO_PUP)
	{
		sProto = "PUP";
	}
	else if (iProtocol == IPPROTO_IDP)
	{
		sProto = "IDP";
	}
	else if (iProtocol == IPPROTO_RDP)
	{
		sProto = "RDP";
	}

	lvItem.pszText = (char *)sProto;
	lvItem.mask = LVIF_TEXT;
	lvItem.iSubItem = COL_PROTO;
	lvItem.iItem = iItem;
	ListView_SetItem(hItemList, &lvItem);

	lvItem.pszText = (char *)sSourceIP;
	lvItem.mask = LVIF_TEXT;
	lvItem.iSubItem = COL_S_IP_POS;
	lvItem.iItem = iItem;
	ListView_SetItem(hItemList, &lvItem);

	lvItem.pszText = (char *)sDestIP;
	lvItem.mask = LVIF_TEXT;
	lvItem.iSubItem = COL_D_IP_POS;
	lvItem.iItem = iItem;
	ListView_SetItem(hItemList, &lvItem);

	lvItem.pszText = (char *)sSourceHost;
	lvItem.mask = LVIF_TEXT;
	lvItem.iSubItem = COL_S_HOST_POS;
	lvItem.iItem = iItem;
	ListView_SetItem(hItemList, &lvItem);

	lvItem.pszText = (char *)sDestHost;
	lvItem.mask = LVIF_TEXT;
	lvItem.iSubItem = COL_D_HOST_POS;
	lvItem.iItem = iItem;
	ListView_SetItem(hItemList, &lvItem);

	sprintf_s(sTemp, sizeof(sTemp), "%d", iDestPort);
	lvItem.pszText = sTemp;
	lvItem.mask = LVIF_TEXT;
	lvItem.iSubItem = COL_DPORT_POS;
	lvItem.iItem = iItem;
	ListView_SetItem(hItemList, &lvItem);

	sprintf_s(sTemp, sizeof(sTemp), "%d", iSourcePort);
	lvItem.pszText = sTemp;
	lvItem.mask = LVIF_TEXT;
	lvItem.iSubItem = COL_SPORT_POS;
	lvItem.iItem = iItem;
	ListView_SetItem(hItemList, &lvItem);

	sprintf_s(sTemp, sizeof(sTemp), "%d", iSequence);
	lvItem.pszText = sTemp;
	lvItem.mask = LVIF_TEXT;
	lvItem.iSubItem = COL_RESOLVER_SEQ_POS;
	lvItem.iItem = iItem;
	ListView_SetItem(hItemList, &lvItem);	

	char *sDisplayTextPtr = StrnDup(sText, iSize);
	char *sDisplayText = sDisplayTextPtr;
	int iPayloadOffset = GetPayloadOffset(sText, iSize, iProtocol);
	sDisplayText += iPayloadOffset;
	int iDisplaySize = iSize - iPayloadOffset;

	CleanText(sDisplayText, iDisplaySize, sPackText, MAX_PACK_TEXT - 1);

	//Recognized protocols (DNS, HTTP, TLS SNI) get a readable description instead of the raw payload text.
	PACKET_INFO info;
	bool bParsed = ParsePacket(sText, iSize, &info);

	char sDescription[1024];
	const char *sColumnText = sPackText;
	if(bParsed && DescribePayload(&info, sDescription, sizeof(sDescription)))
	{
		sColumnText = sDescription;
	}

	lvItem.pszText = (char *)sColumnText;
	lvItem.mask = LVIF_TEXT;
	lvItem.iSubItem = COL_TEXT_POS;
	lvItem.iItem = iItem;
	ListView_SetItem(hItemList, &lvItem);

	sprintf_s(sTemp, sizeof(sTemp), "%d", iSize);
	lvItem.pszText = sTemp;
	lvItem.mask = LVIF_TEXT;
	lvItem.iSubItem = COL_SIZE_POS;
	lvItem.iItem = iItem;
	ListView_SetItem(hItemList, &lvItem);

	//Direction, TCP flags, TTL, IP version and fragmentation.
	char sFlags[64] = "";
	if(bParsed && info.TcpFlags >= 0)
	{
		static const struct { int Bit; const char *Name; } flagNames[] = {
			{0x02, "SYN"}, {0x10, "ACK"}, {0x01, "FIN"}, {0x04, "RST"}, {0x08, "PSH"}, {0x20, "URG"}, {0x40, "ECE"}, {0x80, "CWR"}
		};

		for(int iFlag = 0; iFlag < (int)(sizeof(flagNames) / sizeof(flagNames[0])); iFlag++)
		{
			if(info.TcpFlags & flagNames[iFlag].Bit)
			{
				if(sFlags[0])
				{
					strcat_s(sFlags, sizeof(sFlags), " ");
				}
				strcat_s(sFlags, sizeof(sFlags), flagNames[iFlag].Name);
			}
		}
	}

	char sTtl[16] = "";
	if(bParsed && info.Ttl > 0)
	{
		sprintf_s(sTtl, sizeof(sTtl), "%d", info.Ttl);
	}

	struct { int Column; const char *Text; } extraColumns[] = {
		{ COL_DIR_POS, iImage == 1 ? "Outbound" : (iImage == 2 ? "Inbound" : "Other") },
		{ COL_FLAGS_POS, sFlags },
		{ COL_TTL_POS, sTtl },
		{ COL_IPVER_POS, bParsed ? (info.IsIPv6 ? "6" : "4") : "" },
		{ COL_FRAG_POS, (bParsed && info.IsFragment) ? "Yes" : "" },
		{ COL_MATCH_POS, sMatchedBy ? sMatchedBy : "" }
	};

	for(int iColumn = 0; iColumn < (int)(sizeof(extraColumns) / sizeof(extraColumns[0])); iColumn++)
	{
		lvItem.pszText = (char *)extraColumns[iColumn].Text;
		lvItem.mask = LVIF_TEXT;
		lvItem.iSubItem = extraColumns[iColumn].Column;
		lvItem.iItem = iItem;
		ListView_SetItem(hItemList, &lvItem);
	}

	free(sDisplayTextPtr);

	if(bAutoScroll)
	{
		ListView_EnsureVisible(hItemList, iItem, FALSE);
	}

	return iItem;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

bool IsValidIPAddress(const char *sIP)
{
	char **sIPs = Split(sIP, ".");

	if(UBound(sIPs) != 4)
	{
		FreeArray(sIPs);
		return false;
	}

	int iOctLen = 0;

	char sOct[4];

	for(unsigned short iOct = 0; iOct < 4; iOct++)
	{
		sOct[0] = '\0';

		iOctLen = (int)strlen(sIPs[iOct]);
		if(iOctLen < 1 || iOctLen > 3)
		{
			FreeArray(sIPs);
			return false;
		}

		for(int iPos = 0; iPos < iOctLen; iPos++)
		{
			if(sIPs[iOct][iPos] == '?')
			{
				sOct[iPos] = '0';
			}
			else{
				if(!IsNumeric(sIPs[iOct][iPos])) //No letters allowed
				{
					FreeArray(sIPs);
					return false;
				}
				sOct[iPos] = sIPs[iOct][iPos];
			}

			sOct[iPos+1] = '\0';
		}

		if(atol(sOct) > 255)
		{
			FreeArray(sIPs);
			return false;
		}
	}

	FreeArray(sIPs);

	return true;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

char *MakeIPMask(const char *sInIP, char *sOutIP, int iMaxSz)
{
	char **sIPs = Split(sInIP, ".");
	char sIP[4];
	int iOctLen = 0;
	int iOffset = 0;

	memset(sOutIP, 0, iMaxSz);

	for(unsigned short iOct = 0; iOct < 4; iOct++)
	{
		iOctLen = (int)strlen(sIPs[iOct]);
		iOffset = 3 - iOctLen;

		memset(sIP, '0', sizeof(sIP));

		strcpy_s(sIP + iOffset, sizeof(sIP) - iOffset, sIPs[iOct]);
		strcat_s(sOutIP, iMaxSz, sIP);
		if(iOct < 3)
		{
			strcat_s(sOutIP, iMaxSz, ".");
		}
	}

	FreeArray(sIPs);
	return sOutIP;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

bool CompareIPs(const char *sSIP, const char *sDIP)
{
	for(unsigned short iOct = 0; iOct < (MAX_ADDR_LEN - 1); iOct++)
	{
		if(!(sSIP[iOct] == sDIP[iOct] || sSIP[iOct] == '?' || sDIP[iOct] == '?'))
		{
			return false;
		}
	}
	return true;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

bool ResolveIP(char *sIPAddress, char *sOutHost, int iOutHostSz)
{
	bool result = false;
	struct addrinfo    hints;
	struct addrinfo   *res = 0;
	int status;

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;

	if ((status = getaddrinfo(sIPAddress, 0, &hints, &res)) == 0)
	{
		if ((status = getnameinfo(res->ai_addr, (socklen_t)res->ai_addrlen, sOutHost, iOutHostSz, 0, 0, 0)) == 0)
		{
			result = true;
		}
	}
	if (res)
	{
		freeaddrinfo(res);
	}

	return result;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//IPs which a resolver thread is working on right now, so the same slow lookup is not repeated by every queued task.
static std::set<std::string> gInFlightResolves;

//The reverse DNS name which a lookup of the address asks for (d.c.b.a.in-addr.arpa or the ip6.arpa nibble form).
static std::string ReverseDnsName(const char *sIPAddress)
{
	unsigned char addr[16];
	bool bIsV6 = false;
	char sBuf[160];

	if (!ParseIPAddress(sIPAddress, addr, &bIsV6, NULL))
	{
		return "";
	}

	if (!bIsV6)
	{
		sprintf_s(sBuf, sizeof(sBuf), "%d.%d.%d.%d.in-addr.arpa", addr[15], addr[14], addr[13], addr[12]);
		return sBuf;
	}

	std::string s;
	for (int i = 15; i >= 0; i--)
	{
		sprintf_s(sBuf, sizeof(sBuf), "%x.%x.", addr[i] & 0x0F, addr[i] >> 4);
		s += sBuf;
	}
	return s + "ip6.arpa";
}

//IPs which have been queued for reverse resolution without a grid row (packets which were hidden by a host filter).
static std::set<std::string> gPendingRowlessResolves;

//Queues a reverse lookup purely to fill the cache. Call with the listener holding gCS (it only takes the cache lock).
static void QueueRowlessResolve(const char *sIPAddress)
{
	if (!bDnsLookups)
	{
		return;
	}

	EnterCriticalSection(&gcsHostResolverCache);

	//Already known, or already queued, then there is nothing to do.
	//(The backlog is capped so a flood of distinct addresses, e.g. a scan, cannot queue unbounded DNS work.)
	if (gHostResolverQueue.Count() < 5000 && gHostResolverCache.GetByKey((char *)sIPAddress) == NULL
		&& gPendingRowlessResolves.insert(sIPAddress).second)
	{
		HOSTRESOLVERTASK task;
		task.GridRow = -1;
		task.GridColumn = 0;
		task.Sequence = 0;
		task.Generation = 0;
		task.TrimBase = 0;
		task.IPAddress = _strdup(sIPAddress);
		gHostResolverQueue.Add(task);
	}

	LeaveCriticalSection(&gcsHostResolverCache);
}

//Resolves a host name to its IPv4/IPv6 addresses.
static bool ResolveForward(const char *sName, std::vector<LOCAL_ADDRESS> *pAddresses)
{
	struct addrinfo hints;
	struct addrinfo *res = NULL;

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if (getaddrinfo(sName, NULL, &hints, &res) != 0)
	{
		return false;
	}

	for (struct addrinfo *p = res; p != NULL; p = p->ai_next)
	{
		LOCAL_ADDRESS addr;
		memset(&addr, 0, sizeof(addr));

		if (p->ai_family == AF_INET)
		{
			addr.Family = AF_INET;
			addr.Addr[10] = addr.Addr[11] = 0xFF;
			memcpy(addr.Addr + 12, &((SOCKADDR_IN *)p->ai_addr)->sin_addr, 4);
		}
		else if (p->ai_family == AF_INET6)
		{
			addr.Family = AF_INET6;
			memcpy(addr.Addr, &((SOCKADDR_IN6 *)p->ai_addr)->sin6_addr, 16);
		}
		else
		{
			continue;
		}

		pAddresses->push_back(addr);
	}

	freeaddrinfo(res);
	return !pAddresses->empty();
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

DWORD WINAPI ResolverThread(LPVOID lpVoid)
{
	while (!gbShutDownResolvers)
	{
		bool bGotItem = false;
		HOSTRESOLVERTASK task;

		EnterCriticalSection(&gcsHostResolverCache);
		{
			auto originalTask = gHostResolverQueue.FirstPointer();
			if (originalTask != NULL)
			{
				bGotItem = true;
				memcpy_s(&task, sizeof(task), originalTask, sizeof(task));
				gHostResolverQueue.DeleteAtIndex(0);
			}
		}
		LeaveCriticalSection(&gcsHostResolverCache);

		if (bGotItem && !bDnsLookups)
		{
			//Lookups were switched off while this was queued.
			if (task.GridRow < 0)
			{
				EnterCriticalSection(&gcsHostResolverCache);
				gPendingRowlessResolves.erase(task.IPAddress);
				LeaveCriticalSection(&gcsHostResolverCache);
			}
			free(task.IPAddress);
		}
		else if (bGotItem)
		{
			char sHostName[255];
			strcpy_s(sHostName, sizeof(sHostName), "");
			//Copy the value while holding the lock, the cache can reallocate or free it when another thread upserts.
			bool bCached = false;
			EnterCriticalSection(&gcsHostResolverCache);
			auto cachedHost = gHostResolverCache.GetByKey(task.IPAddress);
			if (cachedHost != NULL)
			{
				strcpy_s(sHostName, sizeof(sHostName), cachedHost->Value);
				bCached = true;
			}
			LeaveCriticalSection(&gcsHostResolverCache);

			if (!bCached)
			{
				//If another thread is already resolving this address, wait for it instead of repeating the (slow) lookup.
				//	Without this every queued task for an address does its own lookup, and each lookup produces DNS packets
				//	which queue yet more tasks.
				EnterCriticalSection(&gcsHostResolverCache);
				bool bBusy = !gInFlightResolves.insert(task.IPAddress).second;
				if (bBusy)
				{
					gHostResolverQueue.Add(task);
				}
				LeaveCriticalSection(&gcsHostResolverCache);

				if (bBusy)
				{
					Sleep(10);
					continue;
				}

				NoteOwnLookup(ReverseDnsName(task.IPAddress).c_str());

				if (ResolveIP(task.IPAddress, sHostName, sizeof(sHostName)) == false)
				{
					strcpy_s(sHostName, sizeof(sHostName), "");
				}
				if (strcmp(task.IPAddress, sHostName) == 0)
				{
					strcpy_s(sHostName, sizeof(sHostName), "");
				}

				EnterCriticalSection(&gcsHostResolverCache);
				gHostResolverCache.Upsert(task.IPAddress, sHostName);
				gInFlightResolves.erase(task.IPAddress);
				LeaveCriticalSection(&gcsHostResolverCache);
			}

				if (task.GridRow >= 0)
				{
					//Old rows are trimmed from the top once the grid is full, which moves every row up. Account for that,
					//	and give up if the grid was cleared or filtered since the task was queued.
					int iRow = task.GridRow - (int)(gRowsTrimmed - task.TrimBase);

					if (task.Generation == gGridGeneration && iRow >= 0)
					{
						char sResolverSequence[255];
						ListView_GetItemText(hItemList, iRow, COL_RESOLVER_SEQ_POS, sResolverSequence, sizeof(sResolverSequence));
						if (atoi(sResolverSequence) == task.Sequence)
						{
							ListView_SetItemText(hItemList, iRow, task.GridColumn, sHostName);
						}
					}
				}
				else
				{
					EnterCriticalSection(&gcsHostResolverCache);
					gPendingRowlessResolves.erase(task.IPAddress);
					LeaveCriticalSection(&gcsHostResolverCache);
				}

			free(task.IPAddress);
		}
		else
		{
			//Nothing queued, so do any forward lookups the host filters are waiting on.
			char sForwardName[256];
			if (bDnsLookups && GetNextForwardLookup(sForwardName, sizeof(sForwardName)))
			{
				std::vector<LOCAL_ADDRESS> addresses;
				NoteOwnLookup(sForwardName);
				bool bResolved = ResolveForward(sForwardName, &addresses);
				SetForwardAddresses(sForwardName, addresses, bResolved);
			}
			else
			{
				Sleep(25);
			}
		}
	}
	return 0;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#ifndef IPV6_PKTINFO
#define IPV6_PKTINFO 19
#endif

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//Creates a raw socket bound to the given local address which receives all packets of that family on the interface.
static SOCKET OpenRawSocket(int iFamily, const SOCKADDR *pBind, int iBindLen, char *sError, int iErrorSz)
{
	const char *sFamily = (iFamily == AF_INET6) ? "IPv6" : "IPv4";

	SOCKET sck = socket(iFamily, SOCK_RAW, IPPROTO_IP);
	if (sck == INVALID_SOCKET && iFamily == AF_INET6)
	{
		sck = socket(iFamily, SOCK_RAW, IPPROTO_IPV6);
	}

	if (sck == INVALID_SOCKET)
	{
		sprintf_s(sError, iErrorSz, "Failed to create the %s socket. Error %d", sFamily, WSAGetLastError());
		return INVALID_SOCKET;
	}

	if (bind(sck, pBind, iBindLen) != 0)
	{
		sprintf_s(sError, iErrorSz, "Failed to bind the %s socket to the local machine. Error %d", sFamily, WSAGetLastError());
		closesocket(sck);
		return INVALID_SOCKET;
	}

	if (iFamily == AF_INET6)
	{
		//Lets us learn the destination address if Windows does not hand us the IPv6 header.
		DWORD dwOn = 1;
		setsockopt(sck, IPPROTO_IPV6, IPV6_PKTINFO, (const char *)&dwOn, sizeof(dwOn));
	}

	unsigned int iOptions = RCVALL_ON;
	DWORD dwBytesRead = 0;
	if (WSAIoctl(sck, SIO_RCVALL, &iOptions, sizeof(iOptions), NULL, 0, &dwBytesRead, NULL, NULL) != 0)
	{
		sprintf_s(sError, iErrorSz, "Failed to set I/O control on the %s socket! Error %d", sFamily, WSAGetLastError());
		closesocket(sck);
		return INVALID_SOCKET;
	}

	return sck;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static LPFN_WSARECVMSG GetRecvMsgFunction(SOCKET sck)
{
	GUID guid = WSAID_WSARECVMSG;
	LPFN_WSARECVMSG pfn = NULL;
	DWORD dwBytes = 0;

	if (WSAIoctl(sck, SIO_GET_EXTENSION_FUNCTION_POINTER, &guid, sizeof(guid), &pfn, sizeof(pfn), &dwBytes, NULL, NULL) != 0)
	{
		return NULL;
	}
	return pfn;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//Receives an IPv6 packet into sPackBuff. Windows may or may not include the IPv6 header on raw sockets, so this detects
//	which it is and, when the header is missing, builds one from the sender/destination address (the protocol is unknown).
static int ReceiveIPv6(SOCKET sck, LPFN_WSARECVMSG pfnRecvMsg, const unsigned char *pLocalAddr, bool *pbSynthesized)
{
	const int iHeaderSize = (int)sizeof(IP6_HDR);

	*pbSynthesized = false;

	//Without WSARecvMsg we still have to drain the socket, we just will not know who it was from.
	if (pfnRecvMsg == NULL)
	{
		int iPlain = recv(sck, sPackBuff + iHeaderSize, MAX_PACK_BUFF, 0);
		if (iPlain <= 0)
		{
			return -1;
		}

		const unsigned char *pPlain = (const unsigned char *)sPackBuff + iHeaderSize;
		if (iPlain >= iHeaderSize && (pPlain[0] >> 4) == 6 && (((pPlain[4] << 8) | pPlain[5]) + iHeaderSize) == iPlain)
		{
			memmove(sPackBuff, pPlain, iPlain);
			return iPlain;
		}

		IP6_HDR *pPlainHeader = (IP6_HDR *)sPackBuff;
		memset(pPlainHeader, 0, iHeaderSize);
		pPlainHeader->vtc_flow = htonl(0x60000000);
		pPlainHeader->payload_len = htons((unsigned short)iPlain);
		pPlainHeader->next_header = 59;
		memcpy(pPlainHeader->destIP, pLocalAddr, 16);
		*pbSynthesized = true;
		return iPlain + iHeaderSize;
	}

	char sControl[256];
	SOCKADDR_IN6 saFrom;
	memset(&saFrom, 0, sizeof(saFrom));

	WSABUF wsaBuf;
	wsaBuf.buf = sPackBuff + iHeaderSize;
	wsaBuf.len = MAX_PACK_BUFF;

	WSAMSG msg;
	memset(&msg, 0, sizeof(msg));
	msg.name = (LPSOCKADDR)&saFrom;
	msg.namelen = sizeof(saFrom);
	msg.lpBuffers = &wsaBuf;
	msg.dwBufferCount = 1;
	msg.Control.buf = sControl;
	msg.Control.len = sizeof(sControl);

	DWORD dwBytes = 0;
	if (pfnRecvMsg(sck, &msg, &dwBytes, NULL, NULL) != 0)
	{
		return -1;
	}

	int iSize = (int)dwBytes;
	const unsigned char *pData = (const unsigned char *)sPackBuff + iHeaderSize;

	//The header was included: version 6 and a payload length which accounts for the rest of the datagram.
	if (iSize >= iHeaderSize && (pData[0] >> 4) == 6 && (((pData[4] << 8) | pData[5]) + iHeaderSize) == iSize)
	{
		memmove(sPackBuff, pData, iSize);
		return iSize;
	}

	//No header, so build one.
	unsigned char destination[16];
	memcpy(destination, pLocalAddr, 16);

	for (WSACMSGHDR *pCmsg = WSA_CMSG_FIRSTHDR(&msg); pCmsg != NULL; pCmsg = WSA_CMSG_NXTHDR(&msg, pCmsg))
	{
		if (pCmsg->cmsg_level == IPPROTO_IPV6 && pCmsg->cmsg_type == IPV6_PKTINFO)
		{
			memcpy(destination, &((IN6_PKTINFO *)WSA_CMSG_DATA(pCmsg))->ipi6_addr, 16);
		}
	}

	IP6_HDR *pHeader = (IP6_HDR *)sPackBuff;
	memset(pHeader, 0, iHeaderSize);
	pHeader->vtc_flow = htonl(0x60000000);
	pHeader->payload_len = htons((unsigned short)iSize);
	pHeader->next_header = 59; //"No next header", the real protocol is not available.
	pHeader->hop_limit = 0; //Unknown.
	memcpy(pHeader->sourceIP, &saFrom.sin6_addr, 16);
	memcpy(pHeader->destIP, destination, 16);

	*pbSynthesized = true;
	return iSize + iHeaderSize;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

DWORD WINAPI ListenThread(LPVOID lpVoid)
{
	WaitOnWindow(hMainDialog, 1000);

	SOCKET sckSocket4 = INVALID_SOCKET;
	SOCKET sckSocket6 = INVALID_SOCKET;
	char sText[65535 + 1];
	char sError4[1024] = "";
	char sError6[1024] = "";

	SOCKADDR_IN sa4;
	SOCKADDR_IN6 sa6;
	bool bHasV4 = false;
	bool bHasV6 = false;
	std::vector<LOCAL_ADDRESS> localAddresses;

	if (!ResolveBindTargets(gsBindToIpAddress, &sa4, &bHasV4, &sa6, &bHasV6, &localAddresses))
	{
		SendMessage(hStatusBar, (UINT)SB_SETTEXT, (WPARAM)0, (LPARAM)"Invalid IP address to bind to!");
		return 0;
	}

	//Publish the addresses which are "us" (the UI also reads them), without ever blocking a shutdown request.
	while (!TryEnterCriticalSection(&gCS))
	{
		if (gbShutDownThread)
		{
			return 0;
		}
		Sleep(1);
	}
	SetLocalAddresses(localAddresses);
	LeaveCriticalSection(&gCS);

	if (bHasV4)
	{
		sckSocket4 = OpenRawSocket(AF_INET, (SOCKADDR *)&sa4, sizeof(sa4), sError4, sizeof(sError4));
	}
	if (bHasV6)
	{
		sckSocket6 = OpenRawSocket(AF_INET6, (SOCKADDR *)&sa6, sizeof(sa6), sError6, sizeof(sError6));
	}

	if (sckSocket4 == INVALID_SOCKET && sckSocket6 == INVALID_SOCKET)
	{
		SendMessage(hStatusBar, (UINT)SB_SETTEXT, (WPARAM)0, (LPARAM)(sError4[0] ? sError4 : sError6));
		return 0;
	}

	sprintf_s(sText, sizeof(sText), "Connected to %s (%s)", gsBindToIpAddress,
		(sckSocket4 != INVALID_SOCKET && sckSocket6 != INVALID_SOCKET) ? "IPv4 + IPv6" : (sckSocket4 != INVALID_SOCKET ? "IPv4" : "IPv6"));
	SendMessage(hStatusBar, (UINT)SB_SETTEXT, (WPARAM)0, (LPARAM)sText);

	LPFN_WSARECVMSG pfnRecvMsg = (sckSocket6 != INVALID_SOCKET) ? GetRecvMsgFunction(sckSocket6) : NULL;
	bool bWarnedAboutHeaders = false;

	__int64 i64Packets = 0;
	__int64 i64PakSize = 0;
	char sPackets[128];
	char sPakSize[128];

	fd_set ExceptFDS;
	fd_set ReadFDS;

	struct timeval TimeOut;	// The TimeOut structure.
	TimeOut.tv_sec = 1;
	TimeOut.tv_usec = 250;

	//Filters and displays one packet which is in sPackBuff. Returns false when the thread should shut down.
	auto ProcessPacket = [&](int iReceiveSize) -> bool
	{
		PACKET_INFO packet;
		if (!ParsePacket(sPackBuff, iReceiveSize, &packet))
		{
			return true;
		}

		const char *sSourceIP = packet.SourceIPText;
		const char *sDestIP = packet.DestIPText;

		//Let the UI thread in first if it is waiting for the lock.
		while (gUiWaiting > 0 && !gbShutDownThread)
		{
			Sleep(1);
		}

		//The UI thread owns gCS while paused or modifying the grid/filters.
		bool bLocked = false;
		while (!(bLocked = (TryEnterCriticalSection(&gCS) != FALSE)))
		{
			if (gbShutDownThread)
			{
				break;
			}
			Sleep(1);
		}

		if (!bLocked)
		{
			return false;
		}

		//The DNS lookups this program makes itself (to name the addresses it sees) are not interesting, and recording them
		//	would make every new address cause yet more packets to look at.
		if (IsOwnLookup(&packet))
		{
			gi64FilteredOut++;
			LeaveCriticalSection(&gCS);
			return true;
		}

		//Copy the values while holding the lock, the cache can reallocate or free them when the resolvers upsert.
		char sSourceHostBuf[MAX_HOST_NAME_SZ + 1];
		char sDestHostBuf[MAX_HOST_NAME_SZ + 1];
		bool bSourceResolved = false;
		bool bDestResolved = false;
		bool bHostsLookedUp = false;

		auto LookupHosts = [&]()
		{
			EnterCriticalSection(&gcsHostResolverCache);
			auto sSourceHost = gHostResolverCache.GetByKey((char *)sSourceIP);
			if (sSourceHost != NULL)
			{
				strcpy_s(sSourceHostBuf, sizeof(sSourceHostBuf), sSourceHost->Value);
				bSourceResolved = true;
			}
			auto sDestHost = gHostResolverCache.GetByKey((char *)sDestIP);
			if (sDestHost != NULL)
			{
				strcpy_s(sDestHostBuf, sizeof(sDestHostBuf), sDestHost->Value);
				bDestResolved = true;
			}
			LeaveCriticalSection(&gcsHostResolverCache);
			bHostsLookedUp = true;
		};

		//Host name filters need the names up front, otherwise we only look them up for packets we display.
		if (FiltersNeedHostNames())
		{
			LookupHosts();
		}

		int iImage = 0;
		FILTER_RESULT eResult = EvaluatePacket(&packet, bSourceResolved ? sSourceHostBuf : "",
			bDestResolved ? sDestHostBuf : "", &iImage);

		if (eResult == FILTER_HIDDEN_BY_RULES)
		{
			gi64FilteredOut++;
		}

		//Resolve the host names of every IP we see, even for packets which are hidden. Displayed packets queue their own
		//	lookup (so the grid gets updated), hidden ones just fill the cache, which also lets host filters see them.
		if (eResult != FILTER_SHOW)
		{
			QueueRowlessResolve(sSourceIP);
			QueueRowlessResolve(sDestIP);
		}

		bool itemAdded = false;

		if (eResult == FILTER_SHOW)
		{
			if (!bHostsLookedUp)
			{
				LookupHosts();
			}

			//"..." means a lookup is pending, with lookups off nothing is pending so leave it blank.
			char *sSourceHostName = bSourceResolved ? sSourceHostBuf : (bDnsLookups ? "..." : "");
			char *sDestHostName = bDestResolved ? sDestHostBuf : (bDnsLookups ? "..." : "");

			char sMatchedBy[256];
			DescribeIncludeMatches(&packet, bSourceResolved ? sSourceHostBuf : "", bDestResolved ? sDestHostBuf : "",
				sMatchedBy, sizeof(sMatchedBy));

			int iGridRow = AddListBoxItem(sSourceIP, sSourceHostName, sDestIP, sDestHostName,
				packet.SourcePort < 0 ? 0 : packet.SourcePort, packet.DestPort < 0 ? 0 : packet.DestPort,
				sPackBuff, iReceiveSize, packet.Protocol, iImage, (int)i64Packets, sMatchedBy);
			itemAdded = true;

			if (iGridRow >= 0 && bDnsLookups)
			{
				if (!bSourceResolved)
				{
					EnterCriticalSection(&gcsHostResolverCache);
					HOSTRESOLVERTASK task;
					task.GridRow = iGridRow;
					task.GridColumn = COL_S_HOST_POS;
					task.Sequence = (int)i64Packets;
					task.Generation = gGridGeneration;
					task.TrimBase = gRowsTrimmed;
					task.IPAddress = _strdup(sSourceIP);
					gHostResolverQueue.Add(task);
					LeaveCriticalSection(&gcsHostResolverCache);
				}

				if (!bDestResolved)
				{
					EnterCriticalSection(&gcsHostResolverCache);
					HOSTRESOLVERTASK task;
					task.GridRow = iGridRow;
					task.GridColumn = COL_D_HOST_POS;
					task.Sequence = (int)i64Packets;
					task.Generation = gGridGeneration;
					task.TrimBase = gRowsTrimmed;
					task.IPAddress = _strdup(sDestIP);
					gHostResolverQueue.Add(task);
					LeaveCriticalSection(&gcsHostResolverCache);
				}
			}
		}

		if (itemAdded)
		{
			i64MatchPackets++;
			i64MatchPakSize += iReceiveSize;
		}

		i64Packets++;
		i64PakSize += iReceiveSize;

		I64FormatInteger(sPackets, sizeof(sPackets), i64Packets);
		FileSizeFriendly(i64PakSize, sPakSize, sizeof(sPakSize));

		sprintf_s(sText, sizeof(sText), "Packets: %s (%s)",
			I64FormatInteger(sPackets, sizeof(sPackets), i64Packets),
			FileSizeFriendly(i64PakSize, sPakSize, sizeof(sPakSize)));
		SendMessage(hStatusBar, (UINT)SB_SETTEXT, (WPARAM)1, (LPARAM)sText);

		sprintf_s(sText, sizeof(sText), "Matchs: %s (%s)",
			I64FormatInteger(sPackets, sizeof(sPackets), i64MatchPackets),
			FileSizeFriendly(i64MatchPakSize, sPakSize, sizeof(sPakSize)));
		SendMessage(hStatusBar, (UINT)SB_SETTEXT, (WPARAM)2, (LPARAM)sText);

		char sCache[64];
		char sQueue[64];

		EnterCriticalSection(&gcsHostResolverCache);
		I64FormatInteger(sCache, sizeof(sCache), gHostResolverCache.Count());
		I64FormatInteger(sQueue, sizeof(sQueue), gHostResolverQueue.Count());
		LeaveCriticalSection(&gcsHostResolverCache);

		sprintf_s(sText, sizeof(sText), "DNS Cache %s, Backlog: %s", sCache, sQueue);
		SendMessage(hStatusBar, (UINT)SB_SETTEXT, (WPARAM)3, (LPARAM)sText);

		GetFilterSummary(sText, sizeof(sText));
		SendMessage(hStatusBar, (UINT)SB_SETTEXT, (WPARAM)4, (LPARAM)sText);

		LeaveCriticalSection(&gCS);
		return true;
	};

	while (!gbShutDownThread)
	{
		FD_ZERO(&ReadFDS);
		FD_ZERO(&ExceptFDS);

		SOCKET sockets[2] = { sckSocket4, sckSocket6 };

		for (int iSocket = 0; iSocket < 2; iSocket++)
		{
			if (sockets[iSocket] != INVALID_SOCKET)
			{
				FD_SET(sockets[iSocket], &ReadFDS);
				FD_SET(sockets[iSocket], &ExceptFDS);
			}
		}

		// Socket Select...
		if (select(-1, &ReadFDS, NULL, &ExceptFDS, &TimeOut) == SOCKET_ERROR)
		{
			sprintf_s(sText, sizeof(sText), "Socket select error.");
			SendMessage(hStatusBar, (UINT)SB_SETTEXT, (WPARAM)1, (LPARAM)sText);
			break;
		}

		bool bStop = false;

		for (int iSocket = 0; iSocket < 2 && !bStop; iSocket++)
		{
			SOCKET sck = sockets[iSocket];
			if (sck == INVALID_SOCKET)
			{
				continue;
			}

			if (FD_ISSET(sck, &ExceptFDS))
			{
				sprintf_s(sText, sizeof(sText), "Socket FD exception.");
				SendMessage(hStatusBar, (UINT)SB_SETTEXT, (WPARAM)1, (LPARAM)sText);
				bStop = true;
				break;
			}

			if (!FD_ISSET(sck, &ReadFDS))
			{
				continue;
			}

			int iReceiveSize = 0;

			if (sck == sckSocket4)
			{
				iReceiveSize = recv(sck, sPackBuff, MAX_PACK_BUFF, 0);
			}
			else
			{
				bool bSynthesized = false;
				iReceiveSize = ReceiveIPv6(sck, pfnRecvMsg, sa6.sin6_addr.u.Byte, &bSynthesized);

				if (bSynthesized && !bWarnedAboutHeaders)
				{
					bWarnedAboutHeaders = true;
					sprintf_s(sText, sizeof(sText), "Connected to %s (IPv6 protocol/ports unavailable: no IPv6 headers from Windows)", gsBindToIpAddress);
					SendMessage(hStatusBar, (UINT)SB_SETTEXT, (WPARAM)0, (LPARAM)sText);
				}
			}

			if (iReceiveSize > 0 && !ProcessPacket(iReceiveSize))
			{
				bStop = true;
			}
			else if (iReceiveSize <= 0)
			{
				Sleep(1); //Do not spin if the socket is reporting errors.
			}
		}

		if (bStop)
		{
			break;
		}
	}

	if (sckSocket4 != INVALID_SOCKET)
	{
		closesocket(sckSocket4);
	}
	if (sckSocket6 != INVALID_SOCKET)
	{
		closesocket(sckSocket6);
	}

	SendMessage(hStatusBar, (UINT)SB_SETTEXT, (WPARAM)0, (LPARAM)"(Not Connected)");
	SendMessage(hStatusBar, (UINT)SB_SETTEXT, (WPARAM)1, (LPARAM)"");
	SendMessage(hStatusBar, (UINT)SB_SETTEXT, (WPARAM)2, (LPARAM)"");

	return 0;
}

///////
#endif
