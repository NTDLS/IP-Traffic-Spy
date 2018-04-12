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

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include "Entry.H"

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

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#define MAX_ADDR_LEN 16
#define MAX_HOST_NAME_SZ 255

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

StringBuilderArray gIncludeSourceIPFilter;
StringBuilderArray gIncludeTargetIPFilter;
VectorT<int> gIncludeSourcePortFilter;
VectorT<int> gIncludeTargetPortFilter;

StringBuilderArray gExcludeSourceIPFilter;
StringBuilderArray gExcludeTargetIPFilter;
VectorT<int> gExcludeSourcePortFilter;
VectorT<int> gExcludeTargetPortFilter;

HANDLE hListenThread = NULL;

__int64 i64MatchPackets = 0;
__int64 i64MatchPakSize = 0;

volatile bool gbShutDownThread = false;
volatile bool gbSuspendThread = false;
volatile bool bFilterIncludeTPC = true;
volatile bool bFilterIncludeUDP = true;
volatile bool bFilterIncludeOtherProtocols = true;
volatile bool bFilterIncludeInbpoundPackets = true;
volatile bool bFilterIncludeOutboundPackets = true;
volatile bool bFilterIncludeBroadcastPackets = true;

CRITICAL_SECTION gCS;

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void PopListBoxFromArray(HWND hWnd, VectorT<int> *arr)
{
	arr->SortAscending();

	char sBuff[128];
	for (int i = 0; i < arr->Count(); i++)
	{
		sprintf_s(sBuff, sizeof(sBuff), "%d", arr->at(i));
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
				NULL
			};

			int iMessages[] = {
				IDC_BUTTON_SIP,
				IDC_BUTTON_DIP,
				IDC_BUTTON_SPORT,
				IDC_BUTTON_DPORT,
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
				NULL
			};

			int iMessages[] = {
				IDC_BUTTON_SIP_DEL,
				IDC_BUTTON_DIP_DEL,
				IDC_BUTTON_SPORT_DEL,
				IDC_BUTTON_DPORT_DEL,
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

	for(int iRPos = 0; iRPos < iBufSz && iWPos <= iOutBufSz; iRPos++)
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

	for (int iRPos = 0; iRPos < iBufSz && iWPos <= iOutBufSz; iRPos++)
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
	SuspendThread(hListenThread);

	/*
	gbSuspendThread = true;
	while(gbSuspendThread)
	{
		DoEvents();
		//Accessing the list-view in a multi-threaded env is tricky. Just tell the listen thread to lock when it's ready.
		Sleep(1);
	}
	*/

	int iItems = ListView_GetItemCount(hItemList);

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

	ResumeThread(hListenThread);
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

bool AddListBoxItem(const char *sSourceIP, const char *sDestIP, const int iSourcePort, const int iDestPort, 
					const char *sText, const int iSize, int iProtocol, const int iImage)
{
	char sTemp[1024];

	LV_ITEM lvItem;
	memset(&lvItem, 0, sizeof(lvItem));
	int iItems = ListView_GetItemCount(hItemList);

	if(iItems > 100000)
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
				free(delBinData->sText);
				free(delBinData);
			}
		}

		ListView_DeleteItem(hItemList, 0);
	}

	BINARY_DATA *binData = (BINARY_DATA *) calloc(1, sizeof(BINARY_DATA));
	binData->sText = (char *)calloc(iSize, sizeof(char));
	binData->iProtocol = iProtocol;
	memcpy(binData->sText, sText, iSize);
	binData->iLength = iSize;

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

	char *sDisplayTextPtr = StrnDup(sText, iSize);
	char *sDisplayText = sDisplayTextPtr;
	int iDisplaySize = iSize;

	if (iDisplaySize >= sizeof(IP_HDR))
	{
		sDisplayText += sizeof(IP_HDR);
		iDisplaySize -= sizeof(IP_HDR);

		if (iProtocol == IPPROTO_TCP && iDisplaySize > sizeof(TCP_HDR))
		{
			sDisplayText += sizeof(TCP_HDR);
			iDisplaySize -= sizeof(TCP_HDR);
		}
		else if (iProtocol == IPPROTO_UDP && iDisplaySize > sizeof(UDP_HDR))
		{
			sDisplayText += sizeof(UDP_HDR);
			iDisplaySize -= sizeof(UDP_HDR);
		}
	}

	CleanText(sDisplayText, iDisplaySize, sPackText, MAX_PACK_TEXT - 1);

	lvItem.pszText = (char *)sPackText;
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

	free(sDisplayTextPtr);

	ListView_EnsureVisible(hItemList, iItem, FALSE);

	return(iItems == 0);
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
		if((iOctLen = (int)strlen(sIPs[iOct])) > 3)
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

DWORD WINAPI ListenThread(LPVOID lpVoid)
{
	WaitOnWindow(hMainDialog, 1000);

	SOCKET sckSocket;
	char sText[65535 + 1];
	DWORD dwBytesRead = 0;
	char sHostName[MAX_HOST_NAME_SZ];
	char sLocalIPMask[MAX_ADDR_LEN];

	if ((sckSocket = socket(AF_INET, SOCK_RAW, IPPROTO_IP)) == INVALID_SOCKET) //FIXFIX: Implement IPPROTO_IPV6.
	{
		int iLastError = WSAGetLastError();
		char sError[1024];
		sprintf_s(sError, sizeof(sError), "Failed to create local socket. Error %d", iLastError);
		SendMessage(hStatusBar, (UINT)SB_SETTEXT, (WPARAM)0, (LPARAM)sError);
		return 0;
	}

	gethostname(sHostName, sizeof(sHostName));

	sprintf_s(sText, sizeof(sText), "Connected to %s (%s)", sHostName, gsBindToIpAddress);
	SendMessage(hStatusBar, (UINT)SB_SETTEXT, (WPARAM)0, (LPARAM)sText);

	MakeIPMask(gsBindToIpAddress, sLocalIPMask, sizeof(sLocalIPMask));

	SOCKADDR_IN sa;
	sa.sin_family = AF_INET;
	sa.sin_port = htons(0);
	InetPton(AF_INET, gsBindToIpAddress, &sa.sin_addr.s_addr);

	if (bind(sckSocket, (SOCKADDR *)&sa, sizeof(sa)) != 0)
	{
		int iLastError = WSAGetLastError();
		char sError[1024];
		sprintf_s(sError, sizeof(sError), "Failed to bind to the local machine. Error %d", iLastError);
		SendMessage(hStatusBar, (UINT)SB_SETTEXT, (WPARAM)0, (LPARAM)sError);
		return 0;
	}

	unsigned int iOptions = RCVALL_ON;
	if (WSAIoctl(sckSocket, SIO_RCVALL, &iOptions, sizeof(iOptions), NULL, 0, &dwBytesRead, NULL, NULL) != 0)
	{
		SendMessage(hStatusBar, (UINT)SB_SETTEXT, (WPARAM)0, (LPARAM)"Failed to set I/O control!");
		return 0;
	}

	int iReceiveSize = 0;
	__int64 i64Packets = 0;
	__int64 i64PakSize = 0;
	char sPackets[128];
	char sPakSize[128];

	IP_HDR *pIPHeader;
	TCP_HDR *pTCPHeader;
	UDP_HDR *pUDPHeader;

	char sSourceIP[MAX_ADDR_LEN];
	char sDestIP[MAX_ADDR_LEN];

	char sSourceIPMask[MAX_ADDR_LEN];
	char sDestIPMask[MAX_ADDR_LEN];
	char sTempIP[255];

	fd_set ExceptFDS;
	fd_set ReadFDS;

	struct timeval TimeOut;	// The TimeOut structure.
	TimeOut.tv_sec = 1;
	TimeOut.tv_usec = 250;

	while (!gbShutDownThread)
	{
		if (gbSuspendThread)
		{
			gbSuspendThread = false;
			SuspendThread(hListenThread);
		}

		sockaddr addrFrom;
		int iAddrFromSz = sizeof(addrFrom);
		memset(&addrFrom, 0, iAddrFromSz);

		// Zero the Read, Write and Except
		FD_ZERO(&ReadFDS);
		FD_ZERO(&ExceptFDS);

		FD_SET(sckSocket, &ReadFDS);
		FD_SET(sckSocket, &ExceptFDS);

		// Socket Select...
		if (select(-1, &ReadFDS, NULL, &ExceptFDS, &TimeOut) == SOCKET_ERROR)
		{
			sprintf_s(sText, sizeof(sText), "Socket select error.");
			SendMessage(hStatusBar, (UINT)SB_SETTEXT, (WPARAM)1, (LPARAM)sText);
			break;
		}

		if (FD_ISSET(sckSocket, &ExceptFDS))
		{
			sprintf_s(sText, sizeof(sText), "Socket FD exception.");
			SendMessage(hStatusBar, (UINT)SB_SETTEXT, (WPARAM)1, (LPARAM)sText);
			break;
		}

		if (FD_ISSET(sckSocket, &ReadFDS))
		{
			//if((iReceiveSize = recvfrom(sckSocket, sPackBuff, MAX_PACK_BUFF, 0, &addrFrom, &iAddrFromSz)) > 0)
			if ((iReceiveSize = recv(sckSocket, sPackBuff, MAX_PACK_BUFF, 0)) > 0)
			{
				pIPHeader = (IP_HDR *)sPackBuff;
				pTCPHeader = NULL;
				pUDPHeader = NULL;

				if (pIPHeader->proto == IPPROTO_TCP)
				{
					pTCPHeader = (TCP_HDR *)(sPackBuff + sizeof(IP_HDR));
				}
				else if (pIPHeader->proto == IPPROTO_UDP)
				{
					pUDPHeader = (UDP_HDR *)(sPackBuff + sizeof(IP_HDR));
				}

				SOCKADDR_IN saSource;
				SOCKADDR_IN saDest;

				//Check Source IP
				saSource.sin_addr.s_addr = pIPHeader->sourceIP;
				saDest.sin_addr.s_addr = pIPHeader->destIP;

				if (InetNtop(AF_INET, &saSource.sin_addr, sTempIP, sizeof(sTempIP)) != NULL)
				{
					MakeIPMask(sTempIP, sSourceIPMask, sizeof(sSourceIPMask));
					strcpy_s(sSourceIP, sizeof(sSourceIP), sTempIP);
				}
				else {
					strcpy_s(sSourceIPMask, sizeof(sSourceIPMask), "0.0.0.0");
					strcpy_s(sSourceIP, sizeof(sSourceIP), sSourceIPMask);
				}

				if (InetNtop(AF_INET, &saDest.sin_addr, sTempIP, sizeof(sTempIP)))
				{
					MakeIPMask(sTempIP, sDestIPMask, sizeof(sDestIPMask));
					strcpy_s(sDestIP, sizeof(sDestIP), sTempIP);
				}
				else {
					strcpy_s(sDestIPMask, sizeof(sDestIPMask), "0.0.0.0");
					strcpy_s(sDestIP, sizeof(sDestIP), sDestIPMask);
				}

				int iFItem = 0;
				int iImage = 0;

				bool bShowItem = true;

				while (!TryEnterCriticalSection(&gCS))
				{
					if (gbShutDownThread)
					{
						break;
					}
					Sleep(1);
				}

				if (gbShutDownThread)
				{
					break;
				}

				if (CompareIPs(sSourceIPMask, sLocalIPMask))
				{
					iImage = 1; //Outbound
					bShowItem = bFilterIncludeOutboundPackets;
				}
				else if (CompareIPs(sDestIPMask, sLocalIPMask))
				{
					iImage = 2; //Inbound
					bShowItem = bFilterIncludeInbpoundPackets;
				}
				else
				{
					iImage = 0; //Broadcast.
					bShowItem = bFilterIncludeBroadcastPackets;
				}

				if (bShowItem)
				{
					//Check Include Filters.
					if (gIncludeSourceIPFilter.Count() != 0 || gIncludeTargetIPFilter.Count() != 0 ||
						gIncludeSourcePortFilter.Count() != 0 || gIncludeTargetPortFilter.Count() != 0)
					{
						bShowItem = false;

						for (iFItem = 0; !bShowItem && iFItem < gIncludeSourceIPFilter.Count(); iFItem++)
						{
							if (CompareIPs(gIncludeSourceIPFilter.at(iFItem)->Buffer, sSourceIPMask))
							{
								bShowItem = true;
								break;
							}
						}

						for (iFItem = 0; !bShowItem && iFItem < gIncludeTargetIPFilter.Count(); iFItem++)
						{
							if (CompareIPs(gIncludeTargetIPFilter.at(iFItem)->Buffer, sDestIPMask))
							{
								bShowItem = true;
								break;
							}
						}

						for (iFItem = 0; !bShowItem && iFItem < gIncludeSourcePortFilter.Count(); iFItem++)
						{
							if (pIPHeader->proto == IPPROTO_TCP)
							{
								if (gIncludeSourcePortFilter.at(iFItem) == ntohs(pTCPHeader->sport))
								{
									bShowItem = true;
									break;
								}
							}
							else if (pIPHeader->proto == IPPROTO_UDP)
							{
								if (gIncludeSourcePortFilter.at(iFItem) == ntohs(pUDPHeader->sport))
								{
									bShowItem = true;
									break;
								}
							}
						}

						for (iFItem = 0; !bShowItem && iFItem < gIncludeTargetPortFilter.Count(); iFItem++)
						{
							if (pIPHeader->proto == IPPROTO_TCP)
							{
								if (gIncludeTargetPortFilter.at(iFItem) == ntohs(pTCPHeader->dport))
								{
									bShowItem = true;
									break;
								}
							}
							else if (pIPHeader->proto == IPPROTO_UDP)
							{
								if (gIncludeTargetPortFilter.at(iFItem) == ntohs(pUDPHeader->dport))
								{
									bShowItem = true;
									break;
								}
							}
						}
					}

					//Check Exclude Filters.
					if (gExcludeSourceIPFilter.Count() != 0 || gExcludeTargetIPFilter.Count() != 0 ||
						gExcludeSourcePortFilter.Count() != 0 || gExcludeTargetPortFilter.Count() != 0)
					{
						for (iFItem = 0; bShowItem && iFItem < gExcludeSourceIPFilter.Count(); iFItem++)
						{
							if (CompareIPs(gExcludeSourceIPFilter.at(iFItem)->Buffer, sSourceIPMask))
							{
								bShowItem = false;
								break;
							}
						}

						for (iFItem = 0; bShowItem && iFItem < gExcludeTargetIPFilter.Count(); iFItem++)
						{
							if (CompareIPs(gExcludeTargetIPFilter.at(iFItem)->Buffer, sDestIPMask))
							{
								bShowItem = false;
								break;
							}
						}

						for (iFItem = 0; bShowItem && iFItem < gExcludeSourcePortFilter.Count(); iFItem++)
						{
							if (pIPHeader->proto == IPPROTO_TCP)
							{
								if (gExcludeSourcePortFilter.at(iFItem) == ntohs(pTCPHeader->sport))
								{
									bShowItem = false;
									break;
								}
							}
							else if (pIPHeader->proto == IPPROTO_UDP)
							{
								if (gExcludeSourcePortFilter.at(iFItem) == ntohs(pUDPHeader->sport))
								{
									bShowItem = false;
									break;
								}
							}
						}

						for (iFItem = 0; bShowItem && iFItem < gExcludeTargetPortFilter.Count(); iFItem++)
						{
							if (pIPHeader->proto == IPPROTO_TCP)
							{
								if (gExcludeTargetPortFilter.at(iFItem) == ntohs(pTCPHeader->dport))
								{
									bShowItem = false;
									break;
								}
							}
							else if (pIPHeader->proto == IPPROTO_UDP)
							{
								if (gExcludeTargetPortFilter.at(iFItem) == ntohs(pUDPHeader->dport))
								{
									bShowItem = false;
									break;
								}
							}
						}
					}
				}

				bool itemAdded = false;

				if (bShowItem)
				{
					if (pIPHeader->proto == IPPROTO_TCP)
					{
						if (bFilterIncludeTPC)
						{
							AddListBoxItem(sSourceIP, sDestIP, ntohs(pTCPHeader->sport),
								ntohs(pTCPHeader->dport), sPackBuff, iReceiveSize, pIPHeader->proto, iImage);
							itemAdded = true;
						}
					}
					else if (pIPHeader->proto == IPPROTO_UDP)
					{
						if (bFilterIncludeUDP)
						{
							AddListBoxItem(sSourceIP, sDestIP, ntohs(pUDPHeader->sport),
								ntohs(pUDPHeader->dport), sPackBuff, iReceiveSize, pIPHeader->proto, iImage);
							itemAdded = true;

						}
					}
					else
					{
						if (bFilterIncludeOtherProtocols)
						{
							AddListBoxItem(sSourceIP, sDestIP, 0, 0, sPackBuff, iReceiveSize, pIPHeader->proto, iImage);
							itemAdded = true;
						}
					}

					if (itemAdded)
					{
						i64MatchPackets++;
						i64MatchPakSize += iReceiveSize;
					}
				}

				i64Packets++;
				i64PakSize += iReceiveSize;

				I64FormatInteger(sPackets, sizeof(sPackets), i64Packets);
				FileSizeFriendly(i64PakSize, sPakSize, sizeof(sPakSize));

				sprintf_s(sText, sizeof(sText), "All Packets: %s (%s)",
					I64FormatInteger(sPackets, sizeof(sPackets), i64Packets),
					FileSizeFriendly(i64PakSize, sPakSize, sizeof(sPakSize)));
				SendMessage(hStatusBar, (UINT)SB_SETTEXT, (WPARAM)1, (LPARAM)sText);

				sprintf_s(sText, sizeof(sText), "Match Packets: %s (%s)",
					I64FormatInteger(sPackets, sizeof(sPackets), i64MatchPackets),
					FileSizeFriendly(i64MatchPakSize, sPakSize, sizeof(sPakSize)));
				SendMessage(hStatusBar, (UINT)SB_SETTEXT, (WPARAM)2, (LPARAM)sText);

				LeaveCriticalSection(&gCS);
			}
		}
	}

	closesocket(sckSocket);

	SendMessage(hStatusBar, (UINT)SB_SETTEXT, (WPARAM)0, (LPARAM)"(Not Connected)");
	SendMessage(hStatusBar, (UINT)SB_SETTEXT, (WPARAM)1, (LPARAM)"");
	SendMessage(hStatusBar, (UINT)SB_SETTEXT, (WPARAM)2, (LPARAM)"");

	return 0;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#endif
