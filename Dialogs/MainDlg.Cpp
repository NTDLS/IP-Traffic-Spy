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

	gbSuspendThread = true;

	while(!gbSuspendThread)
	{
		DoEvents();
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void Resume(void)
{
	gbSuspendThread = false;

	SendMessage(hMainDialog, (UINT)WM_SETTEXT, (WPARAM)0, (LPARAM)gsTitleCaption);
	CheckMenuItem(GetMenu(hMainDialog), ID_OPTIONS_PAUSE, MF_BYCOMMAND|MF_UNCHECKED);

	ResumeThread(hListenThread);
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void Stop(void)
{
	while(!TryEnterCriticalSection(&gCS))
	{
		DoEvents();
	}

	if(hListenThread)
	{
		gbShutDownThread = true;
		ResumeThread(hListenThread);

		DWORD dwExitCode = 0;
		while(GetExitCodeThread(hListenThread, &dwExitCode) != 0)
		{
			if(dwExitCode != STILL_ACTIVE)
			{
				break;
			}
			DoEvents();
		}
	}
	hListenThread = NULL;

	/*
	if (hResolverThread)
	{
		gbShutDownThread = true;
		ResumeThread(hResolverThread);

		DWORD dwExitCode = 0;
		while (GetExitCodeThread(hResolverThread, &dwExitCode) != 0)
		{
			if (dwExitCode != STILL_ACTIVE)
			{
				break;
			}
			DoEvents();
		}
	}
	hResolverThread = NULL;
	*/

	LeaveCriticalSection(&gCS);
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void Start(void)
{
	gbShutDownThread = false;

	if(hListenThread)
	{
		Stop();
	}

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
			AppendMenu(hFilterMenu, MF_STRING, MENU_EXCLUDE_SOURCE_IP, "Exclude Source IP");
			AppendMenu(hFilterMenu, MF_STRING, MENU_EXCLUDE_SOURCE_PORT, "Exclude Source Port");
			AppendMenu(hFilterMenu, MF_STRING, MENU_EXCLUDE_TARGET_IP, "Exclude Destination IP");
			AppendMenu(hFilterMenu, MF_STRING, MENU_EXCLUDE_TARGET_PORT, "Exclude Destination Port");
			AppendMenu(hFilterMenu, MF_SEPARATOR, MENU_SEPERATOR, "");
			AppendMenu(hFilterMenu, MF_STRING, MENU_INCLUDE_SOURCE_IP, "Include Source IP");
			AppendMenu(hFilterMenu, MF_STRING, MENU_INCLUDE_SOURCE_PORT, "Include Source Port");
			AppendMenu(hFilterMenu, MF_STRING, MENU_INCLUDE_TARGET_IP, "Include Destination IP");
			AppendMenu(hFilterMenu, MF_STRING, MENU_INCLUDE_TARGET_PORT, "Include Destination Port");
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

			int iItemPos = 0;
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

			int iItemPos = 0;
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

			int iItemPos = 0;
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

			int iItemPos = 0;
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

			int iItemPos = 0;
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

			int iItemPos = 0;
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

			int iItemPos = 0;
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
#pragma region Exclude Filters.		
		else if (wParam == MENU_EXCLUDE_SOURCE_IP)
		{
			bool isPaused = IsPaused();

			if(isPaused == false)
			{
				Pause();
			}
	
			int iItemPos = 0;
			char sText[1024];

			while ((iItemPos = ListView_GetNextItem(hItemList, iItemPos, LVNI_SELECTED)) != -1)
			{
				ListView_GetItemText(hItemList, iItemPos, COL_S_IP_POS, sText, sizeof(sText));

				char sIPMask[255];
				MakeIPMask(sText, sIPMask, sizeof(sIPMask));

				if (gExcludeSourceIPFilter.Contiains(sIPMask) == false)
				{
					gExcludeSourceIPFilter.Add(sIPMask);
				}
			}
			
			if (isPaused == false)
			{
				Resume();
			}
		}
		else if (wParam == MENU_EXCLUDE_TARGET_IP)
		{
			bool isPaused = IsPaused();

			if (isPaused == false)
			{
				Pause();
			}

			int iItemPos = 0;
			char sText[1024];

			while ((iItemPos = ListView_GetNextItem(hItemList, iItemPos, LVNI_SELECTED)) != -1)
			{
				ListView_GetItemText(hItemList, iItemPos, COL_D_IP_POS, sText, sizeof(sText));

				char sIPMask[255];
				MakeIPMask(sText, sIPMask, sizeof(sIPMask));

				if (gExcludeTargetIPFilter.Contiains(sIPMask) == false)
				{
					gExcludeTargetIPFilter.Add(sIPMask);
				}
			}

			if (isPaused == false)
			{
				Resume();
			}
		}
		else if (wParam == MENU_EXCLUDE_SOURCE_PORT)
		{
			bool isPaused = IsPaused();

			if (isPaused == false)
			{
				Pause();
			}

			int iItemPos = 0;
			char sText[1024];

			while ((iItemPos = ListView_GetNextItem(hItemList, iItemPos, LVNI_SELECTED)) != -1)
			{
				ListView_GetItemText(hItemList, iItemPos, COL_SPORT_POS, sText, sizeof(sText));

				int iPort = atoi(sText);

				if (gExcludeSourcePortFilter.ContiainsValue(iPort) == false)
				{
					gExcludeSourcePortFilter.Add(iPort);
				}
			}

			if (isPaused == false)
			{
				Resume();
			}
		}
		else if (wParam == MENU_EXCLUDE_TARGET_PORT)
		{
			bool isPaused = IsPaused();

			if (isPaused == false)
			{
				Pause();
			}

			int iItemPos = 0;
			char sText[1024];

			while ((iItemPos = ListView_GetNextItem(hItemList, iItemPos, LVNI_SELECTED)) != -1)
			{
				ListView_GetItemText(hItemList, iItemPos, COL_DPORT_POS, sText, sizeof(sText));

				int iPort = atoi(sText);

				if (gExcludeTargetPortFilter.ContiainsValue(iPort) == false)
				{
					gExcludeTargetPortFilter.Add(iPort);
				}
			}

			if (isPaused == false)
			{
				Resume();
			}
		}
#pragma endregion
#pragma region Include Filters.		
		else if (wParam == MENU_INCLUDE_SOURCE_IP)
		{
			bool isPaused = IsPaused();

			if (isPaused == false)
			{
				Pause();
			}

			int iItemPos = 0;
			char sText[1024];

			while ((iItemPos = ListView_GetNextItem(hItemList, iItemPos, LVNI_SELECTED)) != -1)
			{
				ListView_GetItemText(hItemList, iItemPos, COL_S_IP_POS, sText, sizeof(sText));

				char sIPMask[255];
				MakeIPMask(sText, sIPMask, sizeof(sIPMask));

				if (gIncludeSourceIPFilter.Contiains(sIPMask) == false)
				{
					gIncludeSourceIPFilter.Add(sIPMask);
				}
			}

			if (isPaused == false)
			{
				Resume();
			}
		}
		else if (wParam == MENU_INCLUDE_TARGET_IP)
		{
			bool isPaused = IsPaused();

			if (isPaused == false)
			{
				Pause();
			}

			int iItemPos = 0;
			char sText[1024];

			while ((iItemPos = ListView_GetNextItem(hItemList, iItemPos, LVNI_SELECTED)) != -1)
			{
				ListView_GetItemText(hItemList, iItemPos, COL_D_IP_POS, sText, sizeof(sText));

				char sIPMask[255];
				MakeIPMask(sText, sIPMask, sizeof(sIPMask));

				if (gIncludeTargetIPFilter.Contiains(sIPMask) == false)
				{
					gIncludeTargetIPFilter.Add(sIPMask);
				}
			}

			if (isPaused == false)
			{
				Resume();
			}
		}
		else if (wParam == MENU_INCLUDE_SOURCE_PORT)
		{
			bool isPaused = IsPaused();

			if (isPaused == false)
			{
				Pause();
			}

			int iItemPos = 0;
			char sText[1024];

			while ((iItemPos = ListView_GetNextItem(hItemList, iItemPos, LVNI_SELECTED)) != -1)
			{
				ListView_GetItemText(hItemList, iItemPos, COL_SPORT_POS, sText, sizeof(sText));

				int iPort = atoi(sText);

				if (gIncludeSourcePortFilter.ContiainsValue(iPort) == false)
				{
					gIncludeSourcePortFilter.Add(iPort);
				}
			}

			if (isPaused == false)
			{
				Resume();
			}
		}
		else if (wParam == MENU_INCLUDE_TARGET_PORT)
		{
			bool isPaused = IsPaused();

			if (isPaused == false)
			{
				Pause();
			}

			int iItemPos = 0;
			char sText[1024];

			while ((iItemPos = ListView_GetNextItem(hItemList, iItemPos, LVNI_SELECTED)) != -1)
			{
				ListView_GetItemText(hItemList, iItemPos, COL_DPORT_POS, sText, sizeof(sText));

				int iPort = atoi(sText);

				if (gIncludeTargetPortFilter.ContiainsValue(iPort) == false)
				{
					gIncludeTargetPortFilter.Add(iPort);
				}
			}

			if (isPaused == false)
			{
				Resume();
			}
		}
#pragma endregion

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
		int Widths[] = {180, 350, 520, -1};
		SendMessage(hStatusBar, (UINT)SB_SETPARTS, (WPARAM)4, (LPARAM)&Widths);

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

		lvColumn.cx        = 100;
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

		lvColumn.cx        = 100;
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

		lvColumn.cx = 0;
		lvColumn.pszText = "Resolver Context";
		lvColumn.iSubItem = COL_RESOLVER_SEQ_POS;
		lvColumn.mask = LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
		lvColumn.fmt = LVCFMT_LEFT;
		ListView_InsertColumn(hItemList, lvColumn.iSubItem, &lvColumn);

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
			bool bPauseStatus = IsPaused();

			if(bPauseStatus == false)
			{
				Pause();
			}

			DialogBox(ghAppInstance, MAKEINTRESOURCE(IDD_INCLUDEFILTERS), hWnd, IncludeFiltersDialog);

			if(bPauseStatus == false)
			{
				Resume();
			}

			return TRUE;
		}
		else if(wParam == ID_FILTERS_EXCLUDEFILTERS)
		{
			bool bPauseStatus = IsPaused();

			if(bPauseStatus == false)
			{
				Pause();
			}

			DialogBox(ghAppInstance, MAKEINTRESOURCE(IDD_EXCLUDEFILTERS), hWnd, ExcludeFiltersDialog);

			if(bPauseStatus == false)
			{
				Resume();
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
					strcpy_s(sDelimiter, sizeof(sDelimiter), "\t");
				}
				if(_strcmpi(sDelimiter, ".TSV") == 0)
				{
					strcpy_s(sDelimiter, sizeof(sDelimiter), "\t");
				}
				else{
					strcpy_s(sDelimiter, sizeof(sDelimiter), "\t");
				}

				if(fopen_s(&fTarget, sFile, "wb") != 0)
				{
					MessageBox(hWnd, "Failed to create the specified file.", gsTitleCaption, MB_ICONERROR);
					return TRUE;
				}

				fprintf(fTarget,
					"Date%s"
					"Time%s"
					"Source IP%s"
					"Destination IP%s"
					"Source Port%s"
					"Destination Port%s"
					"Text%s"
					"Size\r\n", sDelimiter, sDelimiter, sDelimiter, sDelimiter, sDelimiter, sDelimiter, sDelimiter);

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
					fprintf(fTarget, "\"%s\"%s", sText, sDelimiter);
					ListView_GetItemText(hItemList, iIndex, COL_SIZE_POS, sText, sizeof(sText));
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

