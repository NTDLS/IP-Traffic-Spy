#ifndef _MAINDLG_CPP
#define _MAINDLG_CPP
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include <Windows.H>
#include <Stdio.H>
#include <Stdlib.H>
#include <CommCtrl.h>

#include "../Source/Entry.H"

#include "../Dialogs/MainDlg.H"
#include "../Dialogs/NetLogoDlg.H"
#include "../Dialogs/ViewTextDlg.H"
#include "../Dialogs/ExcludeFiltersDlg.H"
#include "../Dialogs/IncludeFiltersDlg.H"
#include "../Dialogs/BindToDlg.H"

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

using namespace NSWFL::Windows;
using namespace NSWFL::File;
using namespace NSWFL::String;
using namespace NSWFL::DateTime;
using namespace NSWFL::Registry;
using namespace NSWFL::ListView;
using namespace NSWFL::Menu;
using namespace NSWFL::Collections;

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//---------------------(Variable Declarations)
HWND hMainDialog = NULL;
HWND hItemList = NULL;
HWND hStatusBar = NULL;
WNDPROC gpOldItemListProc;

HIMAGELIST hImageList = NULL;

BINARY_DATA *BinDataPointer = NULL;

static bool gbFilterDialogBusy = false; //True while an include/exclude filter dialog is open or opening.
static bool gbPaused = false; //True while the UI thread owns gCS on behalf of Pause().

//Shows the filter summary (or a short-lived message) in the status bar.
void UpdateFilterStatus(void)
{
	char sText[256];
	GetFilterSummary(sText, sizeof(sText));
	SendMessage(hStatusBar, (UINT)SB_SETTEXT, (WPARAM)4, (LPARAM)sText);
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

bool IsPaused(void)
{
	MENUITEMINFO MyMII;
	memset(&MyMII, 0, sizeof(MyMII));

	MyMII.cbSize = sizeof(MyMII);
	MyMII.fMask = MIIM_STATE;

	GetMenuItemInfo(GetMenu(hMainDialog), ID_OPTIONS_PAUSE, FALSE, &MyMII);

	if(MyMII.fState & MFS_CHECKED)
	{
		return true;
	}
	else return false;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void Pause(void)
{
	CheckMenuItem(GetMenu(hMainDialog), ID_OPTIONS_PAUSE, MF_BYCOMMAND|MF_CHECKED);

	char sCaption[255];
	sprintf_s(sCaption, sizeof(sCaption), "%s (Paused)", gsTitleCaption);
	SendMessage(hMainDialog, (UINT)WM_SETTEXT, (WPARAM)0, (LPARAM)sCaption);

	//The listen thread holds gCS while it processes a packet, so owning it here
	//	guarantees the thread is idle (and that the filters/grid are safe to modify).
	if(!gbPaused)
	{
		LockListener();
		gbPaused = true;
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void Resume(void)
{
	SendMessage(hMainDialog, (UINT)WM_SETTEXT, (WPARAM)0, (LPARAM)gsTitleCaption);
	CheckMenuItem(GetMenu(hMainDialog), ID_OPTIONS_PAUSE, MF_BYCOMMAND|MF_UNCHECKED);

	if(gbPaused)
	{
		//Anything that modified the filters did so while paused, make sure the listener sees it.
		RebuildFilters();
		UpdateFilterStatus();

		gbPaused = false;
		UnlockListener();
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void Stop(void)
{
	LockListener();

	if(hListenThread)
	{
		gbShutDownThread = true;

		//The thread may be sending messages to this thread, so we have to keep pumping.
		while(WaitForSingleObject(hListenThread, 0) == WAIT_TIMEOUT)
		{
			PumpMessages();
			Sleep(1);
		}

		CloseHandle(hListenThread);
	}
	hListenThread = NULL;

	UnlockListener();
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void Start(void)
{
	if(hListenThread)
	{
		Stop();
	}

	gbShutDownThread = false;

	hListenThread = CreateThread(NULL, 0, ListenThread, (LPVOID)0, 0, NULL);
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#define MENU_SEPERATOR			 WM_USER + 1
#define MENU_CLEAR				 WM_USER + 100
#define MENU_DETAILS			 WM_USER + 101
#define MENU_SELECT_ALL			 WM_USER + 102

#define MENU_EXCLUDE_SOURCE_IP	 WM_USER + 103
#define MENU_EXCLUDE_SOURCE_PORT WM_USER + 104
#define MENU_EXCLUDE_TARGET_IP	 WM_USER + 105
#define MENU_EXCLUDE_TARGET_PORT WM_USER + 106
#define MENU_INCLUDE_SOURCE_IP	 WM_USER + 107
#define MENU_INCLUDE_SOURCE_PORT WM_USER + 108
#define MENU_INCLUDE_TARGET_IP	 WM_USER + 109
#define MENU_INCLUDE_TARGET_PORT WM_USER + 110
#define MENU_COPY_SOURCE_IP		 WM_USER + 111
#define MENU_COPY_SOURCE_PORT	 WM_USER + 112
#define MENU_COPY_TARGET_IP		 WM_USER + 113
#define MENU_COPY_TARGET_PORT	 WM_USER + 114
#define MENU_COPY_TEXT			 WM_USER + 115
#define MENU_COPY_SOURCE_HOST	 WM_USER + 116
#define MENU_COPY_TARGET_HOST	 WM_USER + 117

#define MENU_EXCLUDE_CONVERSATION WM_USER + 118
#define MENU_EXCLUDE_REMOTE_IP	 WM_USER + 119
#define MENU_EXCLUDE_REMOTE_PORT WM_USER + 120
#define MENU_EXCLUDE_REMOTE_HOST WM_USER + 121
#define MENU_EXCLUDE_PROTOCOL	 WM_USER + 122
#define MENU_INCLUDE_CONVERSATION WM_USER + 123
#define MENU_INCLUDE_REMOTE_IP	 WM_USER + 124
#define MENU_INCLUDE_REMOTE_PORT WM_USER + 125
#define MENU_INCLUDE_REMOTE_HOST WM_USER + 126
#define MENU_INCLUDE_PROTOCOL	 WM_USER + 127
#define MENU_REMOVE_FILTERS		 WM_USER + 128

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

enum { KIND_SRC_IP, KIND_DST_IP, KIND_SRC_PORT, KIND_DST_PORT, KIND_CONVERSATION,
	KIND_REMOTE_IP, KIND_REMOTE_PORT, KIND_REMOTE_HOST, KIND_PROTOCOL };

static bool DecodeFilterAction(WPARAM wCommand, bool *pbInclude, int *piKind)
{
	switch(wCommand)
	{
	case MENU_EXCLUDE_SOURCE_IP:		*pbInclude = false;	*piKind = KIND_SRC_IP;			return true;
	case MENU_EXCLUDE_SOURCE_PORT:		*pbInclude = false;	*piKind = KIND_SRC_PORT;		return true;
	case MENU_EXCLUDE_TARGET_IP:		*pbInclude = false;	*piKind = KIND_DST_IP;			return true;
	case MENU_EXCLUDE_TARGET_PORT:		*pbInclude = false;	*piKind = KIND_DST_PORT;		return true;
	case MENU_EXCLUDE_CONVERSATION:		*pbInclude = false;	*piKind = KIND_CONVERSATION;	return true;
	case MENU_EXCLUDE_REMOTE_IP:		*pbInclude = false;	*piKind = KIND_REMOTE_IP;		return true;
	case MENU_EXCLUDE_REMOTE_PORT:		*pbInclude = false;	*piKind = KIND_REMOTE_PORT;		return true;
	case MENU_EXCLUDE_REMOTE_HOST:		*pbInclude = false;	*piKind = KIND_REMOTE_HOST;		return true;
	case MENU_EXCLUDE_PROTOCOL:			*pbInclude = false;	*piKind = KIND_PROTOCOL;		return true;
	case MENU_INCLUDE_SOURCE_IP:		*pbInclude = true;	*piKind = KIND_SRC_IP;			return true;
	case MENU_INCLUDE_SOURCE_PORT:		*pbInclude = true;	*piKind = KIND_SRC_PORT;		return true;
	case MENU_INCLUDE_TARGET_IP:		*pbInclude = true;	*piKind = KIND_DST_IP;			return true;
	case MENU_INCLUDE_TARGET_PORT:		*pbInclude = true;	*piKind = KIND_DST_PORT;		return true;
	case MENU_INCLUDE_CONVERSATION:		*pbInclude = true;	*piKind = KIND_CONVERSATION;	return true;
	case MENU_INCLUDE_REMOTE_IP:		*pbInclude = true;	*piKind = KIND_REMOTE_IP;		return true;
	case MENU_INCLUDE_REMOTE_PORT:		*pbInclude = true;	*piKind = KIND_REMOTE_PORT;		return true;
	case MENU_INCLUDE_REMOTE_HOST:		*pbInclude = true;	*piKind = KIND_REMOTE_HOST;		return true;
	case MENU_INCLUDE_PROTOCOL:			*pbInclude = true;	*piKind = KIND_PROTOCOL;		return true;
	}
	return false;
}

//Parses the packet which backs a row in the grid.
static bool GetRowPacket(int iRow, PACKET_INFO *pPacket)
{
	LV_ITEM lvItem;
	memset(&lvItem, 0, sizeof(lvItem));
	lvItem.mask = LVIF_PARAM;
	lvItem.iItem = iRow;

	if(!ListView_GetItem(hItemList, &lvItem))
	{
		return false;
	}

	BINARY_DATA *binData = (BINARY_DATA *)lvItem.lParam;
	return binData != NULL && ParsePacket(binData->sText, binData->iLength, pPacket);
}

static void GetRowHost(int iRow, int iColumn, char *sOut, int iOutSz)
{
	ListView_GetItemText(hItemList, iRow, iColumn, sOut, iOutSz);
	if(strcmp(sOut, "...") == 0)
	{
		sOut[0] = '\0';
	}
}

//Builds the filter entry (and chooses the list it belongs in) for the given row and kind of filter.
static bool BuildSelectionEntry(int iRow, bool bInclude, int iKind, StringBuilderArray **ppList, char *sEntry, int iEntrySz)
{
	char sText[1024];

	if(iKind == KIND_SRC_IP || iKind == KIND_DST_IP)
	{
		ListView_GetItemText(hItemList, iRow, iKind == KIND_SRC_IP ? COL_S_IP_POS : COL_D_IP_POS, sText, sizeof(sText));
		if(!NormalizeIPFilter(sText, sEntry, iEntrySz))
		{
			return false;
		}

		if(iKind == KIND_SRC_IP)
		{
			*ppList = bInclude ? &gIncludeSourceIPFilter : &gExcludeSourceIPFilter;
		}
		else {
			*ppList = bInclude ? &gIncludeTargetIPFilter : &gExcludeTargetIPFilter;
		}
		return true;
	}

	if(iKind == KIND_SRC_PORT || iKind == KIND_DST_PORT)
	{
		ListView_GetItemText(hItemList, iRow, iKind == KIND_SRC_PORT ? COL_SPORT_POS : COL_DPORT_POS, sText, sizeof(sText));
		if(!NormalizePortFilter(sText, sEntry, iEntrySz))
		{
			return false;
		}

		if(iKind == KIND_SRC_PORT)
		{
			*ppList = bInclude ? &gIncludeSourcePortFilter : &gExcludeSourcePortFilter;
		}
		else {
			*ppList = bInclude ? &gIncludeTargetPortFilter : &gExcludeTargetPortFilter;
		}
		return true;
	}

	//Everything else is expressed as an advanced rule.
	PACKET_INFO packet;
	if(!GetRowPacket(iRow, &packet))
	{
		return false;
	}

	*ppList = bInclude ? &gIncludeRules : &gExcludeRules;

	//The "remote" end is whichever end is not this machine.
	bool bSourceIsLocal = IsLocalAddress(packet.SourceAddr);

	if(iKind == KIND_CONVERSATION)
	{
		sprintf_s(sEntry, iEntrySz, "ip %s and ip %s", packet.SourceIPText, packet.DestIPText);
		return true;
	}
	else if(iKind == KIND_REMOTE_IP)
	{
		sprintf_s(sEntry, iEntrySz, "ip %s", bSourceIsLocal ? packet.DestIPText : packet.SourceIPText);
		return true;
	}
	else if(iKind == KIND_REMOTE_PORT)
	{
		int iPort = bSourceIsLocal ? packet.DestPort : packet.SourcePort;
		if(iPort < 0)
		{
			return false;
		}
		sprintf_s(sEntry, iEntrySz, "port %d", iPort);
		return true;
	}
	else if(iKind == KIND_REMOTE_HOST)
	{
		GetRowHost(iRow, bSourceIsLocal ? COL_D_HOST_POS : COL_S_HOST_POS, sText, sizeof(sText));
		if(sText[0] == '\0' || strchr(sText, ' ') != NULL)
		{
			return false;
		}
		sprintf_s(sEntry, iEntrySz, "host %s", sText);
		return true;
	}
	else if(iKind == KIND_PROTOCOL)
	{
		const char *sName = NULL;
		switch(packet.Protocol)
		{
		case IPPROTO_TCP:	sName = "tcp";	break;
		case IPPROTO_UDP:	sName = "udp";	break;
		case IPPROTO_ICMP:	sName = "icmp";	break;
		case IPPROTO_IGMP:	sName = "igmp";	break;
		}

		if(sName)
		{
			sprintf_s(sEntry, iEntrySz, "proto %s", sName);
		}
		else {
			sprintf_s(sEntry, iEntrySz, "proto %d", packet.Protocol);
		}
		return true;
	}

	return false;
}

//Adds a filter built from each of the selected rows.
static void ApplySelectionFilter(bool bInclude, int iKind)
{
	bool bWasPaused = IsPaused();
	if(bWasPaused == false)
	{
		Pause();
	}

	int iAdded = 0;
	int iExisting = 0;
	int iItem = -1;

	while((iItem = ListView_GetNextItem(hItemList, iItem, LVNI_SELECTED)) != -1)
	{
		char sEntry[512];
		StringBuilderArray *pList = NULL;

		if(BuildSelectionEntry(iItem, bInclude, iKind, &pList, sEntry, sizeof(sEntry)))
		{
			if(AddFilterEntry(pList, sEntry))
			{
				iAdded++;
			}
			else {
				iExisting++;
			}
		}
	}

	RebuildFilters();

	char sMessage[128];
	if(iAdded == 0 && iExisting > 0)
	{
		sprintf_s(sMessage, sizeof(sMessage), "That filter already exists.");
	}
	else if(iAdded == 0)
	{
		sprintf_s(sMessage, sizeof(sMessage), "Nothing to add for the selection.");
	}
	else {
		sprintf_s(sMessage, sizeof(sMessage), "Added %d %s filter%s%s.", iAdded, bInclude ? "include" : "exclude",
			iAdded == 1 ? "" : "s", iExisting > 0 ? " (some already existed)" : "");
	}
	SetFilterMessage(sMessage);
	UpdateFilterStatus();

	if(bWasPaused == false)
	{
		Resume();
	}
}

//Removes any existing filters which match each of the selected rows.
static void RemoveSelectionFilters(void)
{
	bool bWasPaused = IsPaused();
	if(bWasPaused == false)
	{
		Pause();
	}

	int iRemoved = 0;
	int iItem = -1;

	while((iItem = ListView_GetNextItem(hItemList, iItem, LVNI_SELECTED)) != -1)
	{
		PACKET_INFO packet;
		if(GetRowPacket(iItem, &packet))
		{
			char sSourceHost[MAX_PATH];
			char sDestHost[MAX_PATH];
			GetRowHost(iItem, COL_S_HOST_POS, sSourceHost, sizeof(sSourceHost));
			GetRowHost(iItem, COL_D_HOST_POS, sDestHost, sizeof(sDestHost));

			iRemoved += RemoveFiltersMatching(&packet, sSourceHost, sDestHost);
		}
	}

	char sMessage[128];
	sprintf_s(sMessage, sizeof(sMessage), "Removed %d filter%s.", iRemoved, iRemoved == 1 ? "" : "s");
	SetFilterMessage(sMessage);
	UpdateFilterStatus();

	if(bWasPaused == false)
	{
		Resume();
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

LRESULT CALLBACK ItemListProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	LRESULT lResult = CallWindowProc(gpOldItemListProc, hWnd, uMsg, wParam, lParam);

	if (uMsg == WM_RBUTTONDOWN)
	{
		HMENU hParent = CreateMenu();
		HMENU hChild = CreateMenu();

		int iSelectedCount = ListView_GetSelectedCount(hWnd);

		if (iSelectedCount > 0)
		{
				HMENU hFilterMenu = CreateMenu();

				HMENU hExcludeMenu = CreateMenu();
				AppendMenu(hExcludeMenu, MF_STRING, MENU_EXCLUDE_SOURCE_IP, "Source IP");
				AppendMenu(hExcludeMenu, MF_STRING, MENU_EXCLUDE_SOURCE_PORT, "Source Port");
				AppendMenu(hExcludeMenu, MF_STRING, MENU_EXCLUDE_TARGET_IP, "Destination IP");
				AppendMenu(hExcludeMenu, MF_STRING, MENU_EXCLUDE_TARGET_PORT, "Destination Port");
				AppendMenu(hExcludeMenu, MF_SEPARATOR, MENU_SEPERATOR, "");
				AppendMenu(hExcludeMenu, MF_STRING, MENU_EXCLUDE_CONVERSATION, "Conversation (Both Directions)");
				AppendMenu(hExcludeMenu, MF_STRING, MENU_EXCLUDE_REMOTE_IP, "Remote IP (Either Direction)");
				AppendMenu(hExcludeMenu, MF_STRING, MENU_EXCLUDE_REMOTE_PORT, "Remote Port (Either Direction)");
				AppendMenu(hExcludeMenu, MF_STRING, MENU_EXCLUDE_REMOTE_HOST, "Remote Host (Either Direction)");
				AppendMenu(hExcludeMenu, MF_STRING, MENU_EXCLUDE_PROTOCOL, "Protocol");
				AppendMenu(hFilterMenu, MF_POPUP, (UINT_PTR)hExcludeMenu, "Exclude");

				HMENU hIncludeMenu = CreateMenu();
				AppendMenu(hIncludeMenu, MF_STRING, MENU_INCLUDE_SOURCE_IP, "Source IP");
				AppendMenu(hIncludeMenu, MF_STRING, MENU_INCLUDE_SOURCE_PORT, "Source Port");
				AppendMenu(hIncludeMenu, MF_STRING, MENU_INCLUDE_TARGET_IP, "Destination IP");
				AppendMenu(hIncludeMenu, MF_STRING, MENU_INCLUDE_TARGET_PORT, "Destination Port");
				AppendMenu(hIncludeMenu, MF_SEPARATOR, MENU_SEPERATOR, "");
				AppendMenu(hIncludeMenu, MF_STRING, MENU_INCLUDE_CONVERSATION, "Conversation (Both Directions)");
				AppendMenu(hIncludeMenu, MF_STRING, MENU_INCLUDE_REMOTE_IP, "Remote IP (Either Direction)");
				AppendMenu(hIncludeMenu, MF_STRING, MENU_INCLUDE_REMOTE_PORT, "Remote Port (Either Direction)");
				AppendMenu(hIncludeMenu, MF_STRING, MENU_INCLUDE_REMOTE_HOST, "Remote Host (Either Direction)");
				AppendMenu(hIncludeMenu, MF_STRING, MENU_INCLUDE_PROTOCOL, "Protocol");
				AppendMenu(hFilterMenu, MF_POPUP, (UINT_PTR)hIncludeMenu, "Include");

				AppendMenu(hFilterMenu, MF_SEPARATOR, MENU_SEPERATOR, "");
				AppendMenu(hFilterMenu, MF_STRING, MENU_REMOVE_FILTERS, "Remove Filters Matching This Packet");
				InsertMenu(hChild, 0, MF_POPUP | MF_BYPOSITION, (UINT_PTR)hFilterMenu, "Filters");

			HMENU hClipboardMenu = CreateMenu();
			AppendMenu(hClipboardMenu, MF_STRING, MENU_COPY_TEXT, "Copy Text");
			AppendMenu(hClipboardMenu, MF_SEPARATOR, MENU_SEPERATOR, "");
			AppendMenu(hClipboardMenu, MF_STRING, MENU_COPY_SOURCE_IP, "Copy Source IP");
			AppendMenu(hClipboardMenu, MF_STRING, MENU_COPY_SOURCE_HOST, "Copy Source Host");
			AppendMenu(hClipboardMenu, MF_STRING, MENU_COPY_SOURCE_PORT, "Copy Source Port");
			AppendMenu(hClipboardMenu, MF_STRING, MENU_COPY_TARGET_IP, "Copy Destination IP");
			AppendMenu(hClipboardMenu, MF_STRING, MENU_COPY_TARGET_HOST, "Copy Destination Host");
			AppendMenu(hClipboardMenu, MF_STRING, MENU_COPY_TARGET_PORT, "Copy Destination Port");
			InsertMenu(hChild, 0, MF_POPUP | MF_BYPOSITION, (UINT_PTR)hClipboardMenu, "Clipboard");
			
			if (iSelectedCount == 1)
			{
				AppendMenu(hChild, MF_SEPARATOR, MENU_SEPERATOR, "");
				AppendMenu(hChild, MF_STRING, MENU_DETAILS, "Details");
			}
		}

		AppendMenu(hChild, MF_STRING, MENU_SELECT_ALL, "Select All");
		AppendMenu(hChild, MF_STRING, MENU_CLEAR, "Clear");

		InsertMenu(hParent, 0, MF_POPUP | MF_BYPOSITION, (UINT_PTR)hChild, "TCP IP Spy");

		POINT xy;
		GetCursorPos(&xy);
		TrackPopupMenuEx(hChild, TPM_LEFTALIGN | TPM_RIGHTBUTTON, (xy.x) + 1, xy.y, hWnd, NULL);
		DestroyMenu(hChild);
		DestroyMenu(hParent);
	}
	else if (uMsg == WM_COMMAND)
	{
		if (wParam == MENU_CLEAR)
		{
			ClearGrid(hItemList);
		}
		else if (wParam == MENU_DETAILS)
		{
			if (ListView_GetSelectedCount(hItemList) == 1)
			{
				int iIndex = -1;

				if ((iIndex = ListView_GetNextItem(hItemList, iIndex, LVNI_SELECTED)) >= 0)
				{
					LV_ITEM lvItem;
					memset(&lvItem, 0, sizeof(lvItem));
					lvItem.mask = LVIF_PARAM;
					lvItem.iItem = iIndex;

					if (ListView_GetItem(hItemList, &lvItem))
					{
						if ((BinDataPointer = (BINARY_DATA *)lvItem.lParam))
						{
							bool bPauseStatus = IsPaused();

							if (bPauseStatus == false)
							{
								Pause();
							}

							giViewRow = iIndex;
							DialogBox(ghAppInstance, MAKEINTRESOURCE(IDD_VIEWTEXT), hWnd, ViewTextDialog);

							if (bPauseStatus == false)
							{
								Resume();
							}
						}
					}
				}
			}
		}
		else if (wParam == MENU_SELECT_ALL)
		{
			LVSelectAllRows(hItemList);
		}

#pragma region Clipboard.
		else if (wParam == MENU_COPY_TEXT)
		{
			bool isPaused = IsPaused();

			if (isPaused == false)
			{
				Pause();
			}

			int iItemPos = -1;
			char sText[65535];

			StringBuilderArray list;

			while ((iItemPos = ListView_GetNextItem(hItemList, iItemPos, LVNI_SELECTED)) != -1)
			{
				ListView_GetItemText(hItemList, iItemPos, COL_TEXT_POS, sText, sizeof(sText));
				list.Add(sText);
			}

			StringBuilder stringBuf;
			for (int i = 0; i < list.Count(); i++)
			{
				stringBuf.AppendF("%s\r\n", list.at(i)->Buffer);
			}

			CopyToClipboard(stringBuf.Buffer);

			if (isPaused == false)
			{
				Resume();
			}
		}
		else if (wParam == MENU_COPY_TARGET_HOST)
		{
			bool isPaused = IsPaused();

			if (isPaused == false)
			{
				Pause();
			}

			int iItemPos = -1;
			char sText[1024];

			StringBuilderArray list;

			while ((iItemPos = ListView_GetNextItem(hItemList, iItemPos, LVNI_SELECTED)) != -1)
			{
				ListView_GetItemText(hItemList, iItemPos, COL_D_HOST_POS, sText, sizeof(sText));
				if (list.Contiains(sText) == false)
				{
					list.Add(sText);
				}
			}

			list.SortAscending();

			StringBuilder stringBuf;
			for (int i = 0; i < list.Count(); i++)
			{
				stringBuf.AppendF("%s\r\n", list.at(i)->Buffer);
			}

			CopyToClipboard(stringBuf.Buffer);

			if (isPaused == false)
			{
				Resume();
			}
		}
		else if (wParam == MENU_COPY_SOURCE_HOST)
		{
			bool isPaused = IsPaused();

			if (isPaused == false)
			{
				Pause();
			}

			int iItemPos = -1;
			char sText[1024];

			StringBuilderArray list;

			while ((iItemPos = ListView_GetNextItem(hItemList, iItemPos, LVNI_SELECTED)) != -1)
			{
				ListView_GetItemText(hItemList, iItemPos, COL_S_HOST_POS, sText, sizeof(sText));
				if (list.Contiains(sText) == false)
				{
					list.Add(sText);
				}
			}

			list.SortAscending();

			StringBuilder stringBuf;
			for (int i = 0; i < list.Count(); i++)
			{
				stringBuf.AppendF("%s\r\n", list.at(i)->Buffer);
			}

			CopyToClipboard(stringBuf.Buffer);

			if (isPaused == false)
			{
				Resume();
			}
		}
		else if (wParam == MENU_COPY_SOURCE_IP)
		{
			bool isPaused = IsPaused();

			if (isPaused == false)
			{
				Pause();
			}

			int iItemPos = -1;
			char sText[1024];

			StringBuilderArray list;

			while ((iItemPos = ListView_GetNextItem(hItemList, iItemPos, LVNI_SELECTED)) != -1)
			{
				ListView_GetItemText(hItemList, iItemPos, COL_S_IP_POS, sText, sizeof(sText));
				if (list.Contiains(sText) == false)
				{
					list.Add(sText);
				}
			}

			list.SortAscending();

			StringBuilder stringBuf;
			for (int i = 0; i < list.Count(); i++)
			{
				stringBuf.AppendF("%s\r\n", list.at(i)->Buffer);
			}

			CopyToClipboard(stringBuf.Buffer);

			if (isPaused == false)
			{
				Resume();
			}
		}
		else if (wParam == MENU_COPY_SOURCE_PORT)
		{
			bool isPaused = IsPaused();

			if (isPaused == false)
			{
				Pause();
			}

			int iItemPos = -1;
			char sText[1024];

			StringBuilderArray list;

			while ((iItemPos = ListView_GetNextItem(hItemList, iItemPos, LVNI_SELECTED)) != -1)
			{
				ListView_GetItemText(hItemList, iItemPos, COL_SPORT_POS, sText, sizeof(sText));
				if (list.Contiains(sText) == false)
				{
					list.Add(sText);
				}
			}

			list.SortAscending();

			StringBuilder stringBuf;
			for (int i = 0; i < list.Count(); i++)
			{
				stringBuf.AppendF("%s\r\n", list.at(i)->Buffer);
			}

			CopyToClipboard(stringBuf.Buffer);

			if (isPaused == false)
			{
				Resume();
			}
		}
		else if (wParam == MENU_COPY_TARGET_IP)
		{
			bool isPaused = IsPaused();

			if (isPaused == false)
			{
				Pause();
			}

			int iItemPos = -1;
			char sText[1024];

			StringBuilderArray list;

			while ((iItemPos = ListView_GetNextItem(hItemList, iItemPos, LVNI_SELECTED)) != -1)
			{
				ListView_GetItemText(hItemList, iItemPos, COL_D_IP_POS, sText, sizeof(sText));
				if (list.Contiains(sText) == false)
				{
					list.Add(sText);
				}
			}

			list.SortAscending();

			StringBuilder stringBuf;
			for (int i = 0; i < list.Count(); i++)
			{
				stringBuf.AppendF("%s\r\n", list.at(i)->Buffer);
			}

			CopyToClipboard(stringBuf.Buffer);

			if (isPaused == false)
			{
				Resume();
			}
		}
		else if (wParam == MENU_COPY_TARGET_PORT)
		{
			bool isPaused = IsPaused();

			if (isPaused == false)
			{
				Pause();
			}

			int iItemPos = -1;
			char sText[1024];

			StringBuilderArray list;

			while ((iItemPos = ListView_GetNextItem(hItemList, iItemPos, LVNI_SELECTED)) != -1)
			{
				ListView_GetItemText(hItemList, iItemPos, COL_DPORT_POS, sText, sizeof(sText));
				if (list.Contiains(sText) == false)
				{
					list.Add(sText);
				}
			}

			list.SortAscending();

			StringBuilder stringBuf;
			for (int i = 0; i < list.Count(); i++)
			{
				stringBuf.AppendF("%s\r\n", list.at(i)->Buffer);
			}

			CopyToClipboard(stringBuf.Buffer);

			if (isPaused == false)
			{
				Resume();
			}
		}
#pragma endregion
else if (wParam == MENU_REMOVE_FILTERS)
		{
			RemoveSelectionFilters();
		}
		else
		{
			bool bInclude = false;
			int iKind = 0;

			if (DecodeFilterAction(wParam, &bInclude, &iKind))
			{
				ApplySelectionFilter(bInclude, iKind);
			}
		}

	}

	return lResult;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

INT_PTR CALLBACK MainDialog(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	static bool bFirstPaint = true;
	static HMENU hMainMenu = NULL;

	//--------------------------------------------------------------------------

	if(uMsg == WM_INITDIALOG) // Received A Initilize Dialog Message
	{
		HMENU hMenu = GetSystemMenu(hWnd, FALSE);
		AppendMenu(hMenu, MF_SEPARATOR, 0, 0);
		AppendMenu(hMenu, MF_STRING, MAINDIALOG_MENU_ABOUT, "About");

		hMainMenu = GetMenu(hWnd);

		SendMessage(hWnd, (UINT)WM_SETTEXT, (WPARAM)0, (LPARAM)gsTitleCaption);
		SendMessage(hWnd, WM_SETICON, TRUE, (LPARAM) LoadIcon(ghAppInstance, MAKEINTRESOURCE(IDI_MAIN)));

		LV_COLUMN lvColumn;
		memset(&lvColumn, 0, sizeof(lvColumn));

		hItemList = GetDlgItem(hWnd, IDC_ITEMS);

		//DEBUG//AddListViewHandler(hWnd, hItemList);

		HICON hIcon = NULL;

		hImageList = ImageList_Create( GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON), ILC_MASK|ILC_COLOR32, 1, 1);
		ListView_SetImageList(hItemList, hImageList, LVSIL_SMALL);

		hIcon = LoadIcon(ghAppInstance, MAKEINTRESOURCE(IDI_FOREIGN));
		ImageList_AddIcon(hImageList, hIcon);
		DestroyIcon(hIcon);
		DeleteObject(hIcon);

		hIcon = LoadIcon(ghAppInstance, MAKEINTRESOURCE(IDI_UP));
		ImageList_AddIcon(hImageList, hIcon);
		DestroyIcon(hIcon);
		DeleteObject(hIcon);

		hIcon = LoadIcon(ghAppInstance, MAKEINTRESOURCE(IDI_DOWN));
		ImageList_AddIcon(hImageList, hIcon);
		DestroyIcon(hIcon);
		DeleteObject(hIcon);

		hStatusBar = CreateStatusWindow(WS_CHILD|WS_VISIBLE, "(Not Connected)", hWnd, 1);
		int Widths[] = {260, 430, 600, 780, -1};
		SendMessage(hStatusBar, (UINT)SB_SETPARTS, (WPARAM)5, (LPARAM)&Widths);

		int iLVStyle = LVS_EX_GRIDLINES | LVS_EX_FULLROWSELECT | LVS_EX_HEADERDRAGDROP;
		SendMessage(hItemList, (UINT)LVM_SETEXTENDEDLISTVIEWSTYLE, (WPARAM)0, (LPARAM)iLVStyle);

		// Create Listview columns
		lvColumn.cx        = 91;
		lvColumn.pszText   = "Date";
		lvColumn.iSubItem  = COL_DATE_POS;
		lvColumn.mask      = LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
		lvColumn.fmt       = LVCFMT_LEFT;
		ListView_InsertColumn(hItemList, lvColumn.iSubItem, &lvColumn);

		lvColumn.cx        = 75;
		lvColumn.pszText   = "Time";
		lvColumn.iSubItem  = COL_TIME_POS;
		lvColumn.mask      = LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
		lvColumn.fmt       = LVCFMT_LEFT;
		ListView_InsertColumn(hItemList, lvColumn.iSubItem, &lvColumn);

		lvColumn.cx        = 60;
		lvColumn.pszText   = "Protocol";
		lvColumn.iSubItem  = COL_PROTO;
		lvColumn.mask      = LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
		lvColumn.fmt       = LVCFMT_LEFT;
		ListView_InsertColumn(hItemList, lvColumn.iSubItem, &lvColumn);

		lvColumn.cx        = 140;
		lvColumn.pszText   = "S-IP";
		lvColumn.iSubItem  = COL_S_IP_POS;
		lvColumn.mask      = LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
		lvColumn.fmt       = LVCFMT_LEFT;
		ListView_InsertColumn(hItemList, lvColumn.iSubItem, &lvColumn);

		lvColumn.cx = 100;
		lvColumn.pszText = "S-Host";
		lvColumn.iSubItem = COL_S_HOST_POS;
		lvColumn.mask = LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
		lvColumn.fmt = LVCFMT_LEFT;
		ListView_InsertColumn(hItemList, lvColumn.iSubItem, &lvColumn);

		lvColumn.cx        = 140;
		lvColumn.pszText   = "D-IP";
		lvColumn.iSubItem  = COL_D_IP_POS;
		lvColumn.mask      = LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
		lvColumn.fmt       = LVCFMT_LEFT;
		ListView_InsertColumn(hItemList, lvColumn.iSubItem, &lvColumn);

		lvColumn.cx = 100;
		lvColumn.pszText = "D-Host";
		lvColumn.iSubItem = COL_D_HOST_POS;
		lvColumn.mask = LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
		lvColumn.fmt = LVCFMT_LEFT;
		ListView_InsertColumn(hItemList, lvColumn.iSubItem, &lvColumn);

		lvColumn.cx        = 50;
		lvColumn.pszText   = "S-Port";
		lvColumn.iSubItem  = COL_SPORT_POS;
		lvColumn.mask      = LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
		lvColumn.fmt       = LVCFMT_LEFT;
		ListView_InsertColumn(hItemList, lvColumn.iSubItem, &lvColumn);

		lvColumn.cx        = 50;
		lvColumn.pszText   = "D-Port";
		lvColumn.iSubItem  = COL_DPORT_POS;
		lvColumn.mask      = LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
		lvColumn.fmt       = LVCFMT_LEFT;
		ListView_InsertColumn(hItemList, lvColumn.iSubItem, &lvColumn);

		lvColumn.cx        = 400;
		lvColumn.pszText   = "Text";
		lvColumn.iSubItem  = COL_TEXT_POS;
		lvColumn.mask      = LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
		lvColumn.fmt       = LVCFMT_LEFT;
		ListView_InsertColumn(hItemList, lvColumn.iSubItem, &lvColumn);

		lvColumn.cx        = 50;
		lvColumn.pszText   = "Size";
		lvColumn.iSubItem  = COL_SIZE_POS;
		lvColumn.mask      = LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
		lvColumn.fmt       = LVCFMT_LEFT;
		ListView_InsertColumn(hItemList, lvColumn.iSubItem, &lvColumn);

		lvColumn.cx        = 65;
		lvColumn.pszText   = "Direction";
		lvColumn.iSubItem  = COL_DIR_POS;
		lvColumn.mask      = LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
		lvColumn.fmt       = LVCFMT_LEFT;
		ListView_InsertColumn(hItemList, lvColumn.iSubItem, &lvColumn);

		lvColumn.cx        = 110;
		lvColumn.pszText   = "Flags";
		lvColumn.iSubItem  = COL_FLAGS_POS;
		lvColumn.mask      = LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
		lvColumn.fmt       = LVCFMT_LEFT;
		ListView_InsertColumn(hItemList, lvColumn.iSubItem, &lvColumn);

		lvColumn.cx        = 40;
		lvColumn.pszText   = "TTL";
		lvColumn.iSubItem  = COL_TTL_POS;
		lvColumn.mask      = LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
		lvColumn.fmt       = LVCFMT_LEFT;
		ListView_InsertColumn(hItemList, lvColumn.iSubItem, &lvColumn);

		lvColumn.cx        = 30;
		lvColumn.pszText   = "IP";
		lvColumn.iSubItem  = COL_IPVER_POS;
		lvColumn.mask      = LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
		lvColumn.fmt       = LVCFMT_LEFT;
		ListView_InsertColumn(hItemList, lvColumn.iSubItem, &lvColumn);

		lvColumn.cx        = 40;
		lvColumn.pszText   = "Frag";
		lvColumn.iSubItem  = COL_FRAG_POS;
		lvColumn.mask      = LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
		lvColumn.fmt       = LVCFMT_LEFT;
		ListView_InsertColumn(hItemList, lvColumn.iSubItem, &lvColumn);

		lvColumn.cx        = 170;
		lvColumn.pszText   = "Matched By";
		lvColumn.iSubItem  = COL_MATCH_POS;
		lvColumn.mask      = LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
		lvColumn.fmt       = LVCFMT_LEFT;
		ListView_InsertColumn(hItemList, lvColumn.iSubItem, &lvColumn);

		lvColumn.cx = 0;
		lvColumn.pszText = "Resolver Context";
		lvColumn.iSubItem = COL_RESOLVER_SEQ_POS;
		lvColumn.mask = LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
		lvColumn.fmt = LVCFMT_LEFT;
		ListView_InsertColumn(hItemList, lvColumn.iSubItem, &lvColumn);

		UpdateFilterStatus();

		CenterWindow(hWnd);

		RECT recDimensions;
		memset(&recDimensions, 0, sizeof(recDimensions));
		GetClientRect(hWnd, &recDimensions);

		SendMessage(hWnd, WM_SIZE, 0, MAKELONG(recDimensions.right, recDimensions.bottom));

		gpOldItemListProc = (WNDPROC)SetWindowLongPtr(hItemList, GWLP_WNDPROC, (LRESULT)&ItemListProc);

		return FALSE; // Return TRUE to set the keyboard focus, Otherwise return FALSE.
	}
	//--------------------------------------------------------------------------
	else if(uMsg == WM_KEYUP)
	{
		if(wParam == VK_SPACE)
		{
			SendMessage(hWnd, WM_COMMAND, ID_OPTIONS_PAUSE, 0);
		}
		else if (wParam == 'I')
		{
			SendMessage(hWnd, WM_COMMAND, ID_FILTERS_INCLUDEFILTERS, 0);
		}
		else if (wParam == 'E')
		{
			SendMessage(hWnd, WM_COMMAND, ID_FILTERS_EXCLUDEFILTERS, 0); 
		}
		else if (wParam == VK_DELETE)
		{
			SendMessage(hWnd, WM_COMMAND, ID_OPTIONS_CLEARGRID, 0); 
		}
		else if (wParam == VK_F1)
		{
			SendMessage(hWnd, WM_COMMAND, ID_HELP_CONTENTS, 0); 
		}

		return FALSE;
	}
	//--------------------------------------------------------------------------
	else if(uMsg == WM_NOTIFY)
	{
		LPNMHDR lpnmhdr = (LPNMHDR)lParam;
		if(lpnmhdr->hwndFrom == hItemList)
		{
			if(lpnmhdr->code == NM_DBLCLK)
			{
				if(ListView_GetSelectedCount(hItemList) == 1)
				{
					int iIndex = -1;

					if((iIndex = ListView_GetNextItem(hItemList, iIndex, LVNI_SELECTED)) >= 0)
					{
						LV_ITEM lvItem;
						memset(&lvItem, 0, sizeof(lvItem));
						lvItem.mask = LVIF_PARAM;
						lvItem.iItem = iIndex;

						if(ListView_GetItem(hItemList, &lvItem))
						{
							if((BinDataPointer = (BINARY_DATA *)lvItem.lParam))
							{
								bool bPauseStatus = IsPaused();

								if(bPauseStatus == false)
								{
									Pause();
								}

								giViewRow = iIndex;
								DialogBox(ghAppInstance, MAKEINTRESOURCE(IDD_VIEWTEXT), hWnd, ViewTextDialog);

								if(bPauseStatus == false)
								{
									Resume();
								}
							}
						}
					}
				}
			}
		}
		return TRUE;
	}
	//--------------------------------------------------------------------------
	else if(uMsg == WM_SIZE)
	{
		int nWidth = LOWORD(lParam);
		int nHeight = HIWORD(lParam);

		MoveWindow(hItemList, 1, 1, nWidth - 2, nHeight - 25, TRUE);
		MoveWindow(hStatusBar, nWidth-0, nHeight-0, nWidth, nHeight, TRUE);

		return FALSE; //Return false if we process WM_SIZE.
	}
	//--------------------------------------------------------------------------
	else if(uMsg == WM_COMMAND)
	{
		if (wParam == ID_FILTERS_TCP)
		{
			CheckMenuItem(hMainMenu, ID_FILTERS_TCP, bFilterIncludeTPC ? MF_UNCHECKED : MF_CHECKED);
			bFilterIncludeTPC = IsMenuItemChecked(hMainMenu, ID_FILTERS_TCP) != 0;
		}
		else if (wParam == ID_FILTERS_UPD)
		{
			CheckMenuItem(hMainMenu, ID_FILTERS_UPD, bFilterIncludeUDP ? MF_UNCHECKED : MF_CHECKED);
			bFilterIncludeUDP = IsMenuItemChecked(hMainMenu, ID_FILTERS_UPD) != 0;
		}
		else if (wParam == ID_FILTERS_OTHERPROTOCOLS)
		{
			CheckMenuItem(hMainMenu, ID_FILTERS_OTHERPROTOCOLS, bFilterIncludeOtherProtocols ? MF_UNCHECKED : MF_CHECKED);
			bFilterIncludeOtherProtocols = IsMenuItemChecked(hMainMenu, ID_FILTERS_OTHERPROTOCOLS) != 0;
		}

		else if (wParam == ID_FILTERS_INBOUNDPACKETS)
		{
			CheckMenuItem(hMainMenu, ID_FILTERS_INBOUNDPACKETS, bFilterIncludeInbpoundPackets ? MF_UNCHECKED : MF_CHECKED);
			bFilterIncludeInbpoundPackets = IsMenuItemChecked(hMainMenu, ID_FILTERS_INBOUNDPACKETS) != 0;
		}
		else if (wParam == ID_FILTERS_OUTBOUNDPACKETS)
		{
			CheckMenuItem(hMainMenu, ID_FILTERS_OUTBOUNDPACKETS, bFilterIncludeOutboundPackets ? MF_UNCHECKED : MF_CHECKED);
			bFilterIncludeOutboundPackets = IsMenuItemChecked(hMainMenu, ID_FILTERS_OUTBOUNDPACKETS) != 0;
		}
		else if (wParam == ID_OPTIONS_AUTOSCROLL)
		{
			CheckMenuItem(hMainMenu, ID_OPTIONS_AUTOSCROLL, bAutoScroll ? MF_UNCHECKED : MF_CHECKED);
			bAutoScroll = IsMenuItemChecked(hMainMenu, ID_OPTIONS_AUTOSCROLL) != 0;
		}
		else if (wParam == ID_OPTIONS_DNSLOOKUPS)
		{
			CheckMenuItem(hMainMenu, ID_OPTIONS_DNSLOOKUPS, bDnsLookups ? MF_UNCHECKED : MF_CHECKED);
			bDnsLookups = IsMenuItemChecked(hMainMenu, ID_OPTIONS_DNSLOOKUPS) != 0;
		}
		else if (wParam == ID_FILTERS_HIDEOWNDNS)
		{
			CheckMenuItem(hMainMenu, ID_FILTERS_HIDEOWNDNS, bFilterHideOwnDns ? MF_UNCHECKED : MF_CHECKED);
			bFilterHideOwnDns = IsMenuItemChecked(hMainMenu, ID_FILTERS_HIDEOWNDNS) != 0;
		}
		else if (wParam == ID_FILTERS_BROADCASTPACKETS)
		{
			CheckMenuItem(hMainMenu, ID_FILTERS_BROADCASTPACKETS, bFilterIncludeBroadcastPackets ? MF_UNCHECKED : MF_CHECKED);
			bFilterIncludeBroadcastPackets = IsMenuItemChecked(hMainMenu, ID_FILTERS_BROADCASTPACKETS) != 0;
		}
		else if(wParam == ID_OPTIONS_CHANGECONNECTION)
		{
			Pause();
			Stop();

			if(DialogBox(ghAppInstance, MAKEINTRESOURCE(IDD_BINDTOIP), hWnd, BindToDialog) == TRUE)
			{
				Start();
				Resume();
			}
			else {
				DestroyWindow(hWnd);
			}
		}
		else if(wParam == ID_OPTIONS_PAUSE)
		{
			if(IsPaused())
			{
				Resume();
			}
			else{
				Pause();
			}
			return TRUE;
		}
		else if(wParam == ID_OPTIONS_CLEARGRID)
		{
			ClearGrid(hItemList);
			return TRUE;
		}
		else if(wParam == ID_FILTERS_INCLUDEFILTERS)
		{
			//Ignore the request if a filter dialog is already open or being opened.
			if(gbFilterDialogBusy)
			{
				return TRUE;
			}
			gbFilterDialogBusy = true;

			bool bPauseStatus = IsPaused();

			if(bPauseStatus == false)
			{
				Pause();
			}

			DialogBox(ghAppInstance, MAKEINTRESOURCE(IDD_INCLUDEFILTERS), hWnd, IncludeFiltersDialog);
			UpdateFilterStatus();

			if(bPauseStatus == false)
			{
				Resume();
			}

			gbFilterDialogBusy = false;
			return TRUE;
		}
		else if(wParam == ID_FILTERS_EXCLUDEFILTERS)
		{
			//Ignore the request if a filter dialog is already open or being opened.
			if(gbFilterDialogBusy)
			{
				return TRUE;
			}
			gbFilterDialogBusy = true;

			bool bPauseStatus = IsPaused();

			if(bPauseStatus == false)
			{
				Pause();
			}

			DialogBox(ghAppInstance, MAKEINTRESOURCE(IDD_EXCLUDEFILTERS), hWnd, ExcludeFiltersDialog);
			UpdateFilterStatus();

			if(bPauseStatus == false)
			{
				Resume();
			}

			gbFilterDialogBusy = false;
			return TRUE;
		}
		else if(wParam == ID_FILTERS_CLEARALL || wParam == ID_FILTERS_PRESET_NOISE || wParam == ID_FILTERS_PRESET_WEB)
		{
			bool bPauseStatus = IsPaused();

			if(bPauseStatus == false)
			{
				Pause();
			}

			if(wParam == ID_FILTERS_CLEARALL)
			{
				ClearAllFilters();
				SetFilterMessage("All filters cleared.");
			}
			else if(wParam == ID_FILTERS_PRESET_NOISE)
			{
				AddNoiseExclusions();
				SetFilterMessage("Added the network noise exclusions.");
			}
			else {
				AddWebOnlyInclusions();
				SetFilterMessage("Added the web traffic inclusions.");
			}

			UpdateFilterStatus();

			if(bPauseStatus == false)
			{
				Resume();
			}
			return TRUE;
		}
		else if(wParam == ID_FILTERS_APPLYGRID)
		{
			if(MessageBox(hWnd, "This deletes every row in the grid which does not match the current filters. Continue?",
				gsTitleCaption, MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON2) == IDYES)
			{
				int iRemoved = ApplyFiltersToGrid(hItemList);

				char sMessage[128];
				sprintf_s(sMessage, sizeof(sMessage), "Removed %d row%s from the grid.", iRemoved, iRemoved == 1 ? "" : "s");
				SetFilterMessage(sMessage);
				UpdateFilterStatus();
			}
			return TRUE;
		}
		else if(wParam == ID_FILTERS_SAVE || wParam == ID_FILTERS_LOAD)
		{
			char sFile[MAX_PATH];
			char sDefaultDir[MAX_PATH];
			bool bSave = (wParam == ID_FILTERS_SAVE);

			Get_CurrentDirectory(sDefaultDir, sizeof(sDefaultDir));
			strcpy_s(sFile, sizeof(sFile), bSave ? "Filters.ipsf" : "");

			if(OSFileDialog(hWnd, sFile, sizeof(sFile), "ipsf", bSave ? "Save filters to..." : "Load filters from...",
				"IP-Spy-Filter-Files\0*.ipsf\0All-Files\0*.*\0\0", sDefaultDir, bSave ? SFD : OFD, 0))
			{
				if(bSave)
				{
					if(FileAccess(sFile, FExist)
						&& MessageBox(hWnd, "The specified file already exists, overwrite?",
							gsTitleCaption, MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON2) != IDYES)
					{
						return TRUE;
					}

					if(SaveFiltersToFile(sFile))
					{
						SetFilterMessage("Filters saved.");
					}
					else {
						MessageBox(hWnd, "Failed to save the filters.", gsTitleCaption, MB_ICONERROR);
					}
					UpdateFilterStatus();
				}
				else {
					bool bPauseStatus = IsPaused();

					if(bPauseStatus == false)
					{
						Pause();
					}

					if(LoadFiltersFromFile(sFile))
					{
						SetFilterMessage("Filters loaded.");
					}
					else {
						MessageBox(hWnd, "Failed to load the filters, the file could not be read or is not a filter file.",
							gsTitleCaption, MB_ICONERROR);
					}
					UpdateFilterStatus();

					if(bPauseStatus == false)
					{
						Resume();
					}
				}
			}
			return TRUE;
		}
		else if(wParam == ID_FILE_EXIT)
		{
			DestroyWindow(hWnd);
			return TRUE;
		}
		else if(wParam == ID_HELP_ABOUT)
		{
			_AboutDialogInfo ADI;
	
			ADI.DisplayIcon  = LoadIcon(ghAppInstance, MAKEINTRESOURCE(IDI_MAIN));
			ADI.TitleCaption = gsTitleCaption;
			ADI.FileVersion  = gsFileVersion;
			ADI.BuildDate    = __DATE__;
			ADI.BuildTime    = __TIME__;
			ADI.CopyRight    = gsAppCopyRight;
			ADI.OwnerHandle  = hWnd;

			NetLogo(&ADI);
			return TRUE;
		}
		else if(wParam == ID_FILE_SAVEDATA)
		{
			char sFile[MAX_PATH];
			char sDefaultDir[MAX_PATH];
			char sDelimiter[MAX_PATH];

			Get_CurrentDirectory(sDefaultDir, sizeof(sDefaultDir));

			char sDate[64];
			char sTime[64];

			Get_ShortDate(sDate, sizeof(sDate));
			ReplaceCharacter(sDate, '\"', '-');
			ReplaceCharacter(sDate, '/', '-');
			ReplaceCharacter(sDate, ':', '-');

			Get_Time(sTime, sizeof(sTime));
			ReplaceCharacter(sTime, '\"', '-');
			ReplaceCharacter(sTime, '/', '-');
			ReplaceCharacter(sTime, ':', '-');

			sprintf_s(sFile, sizeof(sFile), "%s %s.txt", sDate, sTime);

			if(OSFileDialog(hWnd, sFile, sizeof(sFile), "txt", "Save TCP/IP log data to...",
				"Text-Files\0*.txt\0Comma-Separated-Values\0*.csv\0Tab-Separated-Values\0*.tsv\0All-Files\0*.*\0\0", sDefaultDir, SFD, 0))
			{
				if(FileAccess(sFile, FExist))
				{
					if(MessageBox(hWnd, "The specified file already exists, overwrite?",
						gsTitleCaption, MB_ICONQUESTION | MB_YESNO |MB_DEFBUTTON2) != IDYES)
					{
						return TRUE;
					}
				}

				bool bPauseStatus = IsPaused();

				if(bPauseStatus == false)
				{
					Pause();
				}

				int iIndex = -1;
				FILE *fTarget = NULL;

				_splitpath_s(sFile, NULL, NULL, NULL, NULL, NULL, NULL, sDelimiter, sizeof(sDelimiter));
				if(_strcmpi(sDelimiter, ".CSV") == 0)
				{
					strcpy_s(sDelimiter, sizeof(sDelimiter), ",");
				}
				else{
					strcpy_s(sDelimiter, sizeof(sDelimiter), "\t");
				}

				if(fopen_s(&fTarget, sFile, "wb") != 0)
				{
					MessageBox(hWnd, "Failed to create the specified file.", gsTitleCaption, MB_ICONERROR);

					if(bPauseStatus == false)
					{
						Resume();
					}
					return TRUE;
				}

				fprintf(fTarget,
					"Date%s"
					"Time%s"
					"Protocol%s"
					"Source IP%s"
					"Destination IP%s"
					"Source Port%s"
					"Destination Port%s"
					"Text%s"
					"Size%s"
					"Direction%s"
					"Flags%s"
					"TTL%s"
					"IP Version%s"
					"Fragment%s"
					"Matched By\r\n", sDelimiter, sDelimiter, sDelimiter, sDelimiter, sDelimiter, sDelimiter, sDelimiter,
					sDelimiter, sDelimiter, sDelimiter, sDelimiter, sDelimiter, sDelimiter, sDelimiter);

				while((iIndex = ListView_GetNextItem(hItemList, iIndex, LVNI_ALL)) >= 0)
				{
					char sText[65535 + 1];

					ListView_GetItemText(hItemList, iIndex, COL_DATE_POS, sText, sizeof(sText));
					fprintf(fTarget, "%s%s", sText, sDelimiter);
					ListView_GetItemText(hItemList, iIndex, COL_TIME_POS, sText, sizeof(sText));
					fprintf(fTarget, "%s%s", sText, sDelimiter);
					ListView_GetItemText(hItemList, iIndex, COL_PROTO, sText, sizeof(sText));
					fprintf(fTarget, "%s%s", sText, sDelimiter);
					ListView_GetItemText(hItemList, iIndex, COL_S_IP_POS, sText, sizeof(sText));
					fprintf(fTarget, "%s%s", sText, sDelimiter);
					ListView_GetItemText(hItemList, iIndex, COL_D_IP_POS, sText, sizeof(sText));
					fprintf(fTarget, "%s%s", sText, sDelimiter);
					ListView_GetItemText(hItemList, iIndex, COL_SPORT_POS, sText, sizeof(sText));
					fprintf(fTarget, "%s%s", sText, sDelimiter);
					ListView_GetItemText(hItemList, iIndex, COL_DPORT_POS, sText, sizeof(sText));
					fprintf(fTarget, "%s%s", sText, sDelimiter);
					ListView_GetItemText(hItemList, iIndex, COL_TEXT_POS, sText, sizeof(sText));
					fputc('\"', fTarget);
					for(const char *sChar = sText; *sChar; sChar++)
					{
						if(*sChar == '\"')
						{
							fputc('\"', fTarget); //Escape embedded quotes by doubling them.
						}
						fputc(*sChar, fTarget);
					}
					fprintf(fTarget, "\"%s", sDelimiter);
					ListView_GetItemText(hItemList, iIndex, COL_SIZE_POS, sText, sizeof(sText));
					fprintf(fTarget, "%s%s", sText, sDelimiter);
					ListView_GetItemText(hItemList, iIndex, COL_DIR_POS, sText, sizeof(sText));
					fprintf(fTarget, "%s%s", sText, sDelimiter);
					ListView_GetItemText(hItemList, iIndex, COL_FLAGS_POS, sText, sizeof(sText));
					fprintf(fTarget, "%s%s", sText, sDelimiter);
					ListView_GetItemText(hItemList, iIndex, COL_TTL_POS, sText, sizeof(sText));
					fprintf(fTarget, "%s%s", sText, sDelimiter);
					ListView_GetItemText(hItemList, iIndex, COL_IPVER_POS, sText, sizeof(sText));
					fprintf(fTarget, "%s%s", sText, sDelimiter);
					ListView_GetItemText(hItemList, iIndex, COL_FRAG_POS, sText, sizeof(sText));
					fprintf(fTarget, "%s%s", sText, sDelimiter);
					ListView_GetItemText(hItemList, iIndex, COL_MATCH_POS, sText, sizeof(sText));
					fprintf(fTarget, "%s\r\n", sText);
				}

				fclose(fTarget);

				if(bPauseStatus == false)
				{
					Resume();
				}
			}
			return TRUE;
		}
		else if(wParam == ID_HELP_CONTENTS)
		{
			char sPath[MAX_PATH];
			char sHelpFile[MAX_PATH];
			DWORD dwBufSize = sizeof(sPath);
			if (Get_StringRegistryValue(HKEY_LOCAL_MACHINE, gsRegistryKey, "Path", sPath, dwBufSize))
			{
				sprintf_s(sHelpFile, sizeof(sHelpFile), "%s\\Help.chm", sPath);
				ShellExecute(hWnd, "open", sHelpFile, NULL, sPath, SW_MAXIMIZE);
			}
		}

		return FALSE;
	}
	//--------------------------------------------------------------------------
	else if(uMsg == WM_PAINT)
	{
		if(bFirstPaint)
		{
			bFirstPaint = false;

			if(DialogBox(ghAppInstance, MAKEINTRESOURCE(IDD_BINDTOIP), hWnd, BindToDialog) == TRUE)
			{
				Start();
			}
			else {
				DestroyWindow(hWnd);
			}
		}

		HDC ThisHDC;
		PAINTSTRUCT ThisPS;

		ThisHDC = BeginPaint(hWnd, &ThisPS);

		//- Any painting should be done here.

		EndPaint(hWnd, &ThisPS);
		return TRUE;
	}
	//--------------------------------------------------------------------------
	else if(uMsg == WM_SYSCOMMAND) //- Received a system menu message.
	{
		if(LOWORD(wParam) == MAINDIALOG_MENU_ABOUT) //- About.
		{
			_AboutDialogInfo ADI;
	
			ADI.DisplayIcon  = LoadIcon(ghAppInstance, MAKEINTRESOURCE(IDI_MAIN));
			ADI.TitleCaption = gsTitleCaption;
			ADI.FileVersion  = gsFileVersion;
			ADI.BuildDate    = __DATE__;
			ADI.BuildTime    = __TIME__;
			ADI.CopyRight    = gsAppCopyRight;
			ADI.OwnerHandle  = hWnd;

			NetLogo(&ADI);
			return TRUE;
		}

		return FALSE;
	}
	//--------------------------------------------------------------------------
	else if(uMsg == WM_CLOSE) //- Received close message.
	{
		DestroyWindow(hWnd);
		return FALSE;
	}
	//--------------------------------------------------------------------------

	return FALSE;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#endif

