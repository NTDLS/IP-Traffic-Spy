#ifndef _ViewTextDlg_CPP
#define _ViewTextDlg_CPP
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include <Windows.H>
#include <Stdio.H>
#include <Stdlib.H>
#include <CommCtrl.h>
#include <string>

#include "../Source/Entry.H"
#include "../Source/Decode.H"

#include "../Dialogs/MainDlg.H"
#include "../Dialogs/ViewTextDlg.H"
#include "../Dialogs/NetLogoDlg.H"

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

using namespace NSWFL::Windows;
using namespace NSWFL::File;

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//---------------------(Variable Declarations)
HWND hViewTextDialog = NULL;
int giViewRow = -1; //The grid row being viewed, set by whoever opens the dialog.

static HWND hTextBox = NULL;
static HWND hTextBoxWrap = NULL;
static HWND hDecodeBox = NULL;
static HWND hResizeBar = NULL;
static HWND hOmitTCPHeader = NULL;

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//Lays out the left hand options, the decoded pane (top) and the bytes pane (bottom).
static void LayoutView(HWND hWnd)
{
	RECT rcClient;
	GetClientRect(hWnd, &rcClient);

	RECT rcOption;
	GetClientRect(hOmitTCPHeader, &rcOption);

	int nWidth = rcClient.right;
	int nHeight = rcClient.bottom;

	int iLeft = rcOption.right + 25;
	int iWidth = nWidth - iLeft - 2;
	int iHeight = nHeight - 25;

	if(iWidth < 10 || iHeight < 10)
	{
		return;
	}

	bool bShowDecoded = IsDlgButtonChecked(hWnd, IDC_SHOWDECODE) != 0;

	int iBytesTop = 1;
	int iBytesHeight = iHeight;

	if(bShowDecoded)
	{
		int iDecodeHeight = (iHeight * 45) / 100;
		MoveWindow(hDecodeBox, iLeft, 1, iWidth, iDecodeHeight, TRUE);
		iBytesTop = 1 + iDecodeHeight + 4;
		iBytesHeight = iHeight - iDecodeHeight - 4;
	}
	ShowWindow(hDecodeBox, bShowDecoded ? SW_SHOW : SW_HIDE);

	MoveWindow(hTextBox, iLeft, iBytesTop, iWidth, iBytesHeight, TRUE);
	MoveWindow(hTextBoxWrap, iLeft, iBytesTop, iWidth, iBytesHeight, TRUE);
	MoveWindow(hResizeBar, nWidth - 0, nHeight - 0, nWidth, nHeight, TRUE);
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//Fills the bytes pane according to the view mode / omit header / wrap options.
static void RenderBytes(HWND hWnd)
{
	if(BinDataPointer == NULL)
	{
		return;
	}

	char *sText = BinDataPointer->sText;
	int iSize = BinDataPointer->iLength;

	if (IsDlgButtonChecked(hWnd, IDC_WRAPTEXT))
	{
		ShowWindow(hTextBoxWrap, TRUE);
		ShowWindow(hTextBox, FALSE);
	}
	else
	{
		ShowWindow(hTextBoxWrap, FALSE);
		ShowWindow(hTextBox, TRUE);
	}

	if(IsDlgButtonChecked(hWnd, IDC_OMITTCPHEADER))
	{
		int iPayloadOffset = GetPayloadOffset(sText, iSize, BinDataPointer->iProtocol);
		sText += iPayloadOffset;
		iSize -= iPayloadOffset;
	}

	if(IsDlgButtonChecked(hWnd, IDC_VIEWMODEHEX))
	{
		std::string sDump;
		HexDumpText(sText, iSize, &sDump);
		Set_Text(hTextBox, (char *)sDump.c_str());
		Set_Text(hTextBoxWrap, (char *)sDump.c_str());
	}
	else if(IsDlgButtonChecked(hWnd, IDC_VIEWMODETEXT))
	{
		char *sCleanText = (char *) calloc(iSize + 1, sizeof(char));
		CleanText(sText, iSize, sCleanText, iSize + 1);
		Set_Text(hTextBox, sCleanText);
		Set_Text(hTextBoxWrap, sCleanText);
		free(sCleanText);
	}
	else if(IsDlgButtonChecked(hWnd, IDC_VIEWMODERAW))
	{
		char *sCleanText = (char *) calloc(iSize + 1, sizeof(char));
		CleanRaw(sText, iSize, sCleanText, iSize + 1);
		Set_Text(hTextBox, sCleanText);
		Set_Text(hTextBoxWrap, sCleanText);
		free(sCleanText);
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//Fills the decoded pane: what the grid knows about the row, then the field-by-field decode.
static void RenderDecode(HWND hWnd, int iRow)
{
	if(BinDataPointer == NULL)
	{
		return;
	}

	char sDate[64], sTime[64], sDirection[64], sSize[64], sSourceIP[128], sSourceHost[256], sDestIP[128], sDestHost[256], sMatched[512];

	ListView_GetItemText(hItemList, iRow, COL_DATE_POS, sDate, sizeof(sDate));
	ListView_GetItemText(hItemList, iRow, COL_TIME_POS, sTime, sizeof(sTime));
	ListView_GetItemText(hItemList, iRow, COL_DIR_POS, sDirection, sizeof(sDirection));
	ListView_GetItemText(hItemList, iRow, COL_SIZE_POS, sSize, sizeof(sSize));
	ListView_GetItemText(hItemList, iRow, COL_S_IP_POS, sSourceIP, sizeof(sSourceIP));
	ListView_GetItemText(hItemList, iRow, COL_S_HOST_POS, sSourceHost, sizeof(sSourceHost));
	ListView_GetItemText(hItemList, iRow, COL_D_IP_POS, sDestIP, sizeof(sDestIP));
	ListView_GetItemText(hItemList, iRow, COL_D_HOST_POS, sDestHost, sizeof(sDestHost));
	ListView_GetItemText(hItemList, iRow, COL_MATCH_POS, sMatched, sizeof(sMatched));

	char sLine[1024];
	std::string s;

	sprintf_s(sLine, sizeof(sLine), "Captured %s %s    %s    %s bytes\r\n", sDate, sTime, sDirection, sSize);
	s += sLine;
	sprintf_s(sLine, sizeof(sLine), "From %s%s%s%s\r\n", sSourceIP, sSourceHost[0] && strcmp(sSourceHost, "...") ? " (" : "",
		strcmp(sSourceHost, "...") ? sSourceHost : "", sSourceHost[0] && strcmp(sSourceHost, "...") ? ")" : "");
	s += sLine;
	sprintf_s(sLine, sizeof(sLine), "To   %s%s%s%s\r\n", sDestIP, sDestHost[0] && strcmp(sDestHost, "...") ? " (" : "",
		strcmp(sDestHost, "...") ? sDestHost : "", sDestHost[0] && strcmp(sDestHost, "...") ? ")" : "");
	s += sLine;
	if(sMatched[0])
	{
		sprintf_s(sLine, sizeof(sLine), "Matched by %s\r\n", sMatched);
		s += sLine;
	}
	s += "\r\n";

	std::string sDecoded;
	DecodePacketText(BinDataPointer->sText, BinDataPointer->iLength, &sDecoded);
	s += sDecoded;

	SetWindowText(hDecodeBox, s.c_str());
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//Makes the given grid row the one being viewed. Returns false if there is no such row.
static bool LoadRow(HWND hWnd, int iRow)
{
	int iCount = ListView_GetItemCount(hItemList);

	if(iRow < 0 || iRow >= iCount)
	{
		return false;
	}

	LV_ITEM lvItem;
	memset(&lvItem, 0, sizeof(lvItem));
	lvItem.mask = LVIF_PARAM;
	lvItem.iItem = iRow;

	if(!ListView_GetItem(hItemList, &lvItem) || lvItem.lParam == 0)
	{
		return false;
	}

	BinDataPointer = (BINARY_DATA *)lvItem.lParam;
	giViewRow = iRow;

	//Keep the grid's selection in step so closing the viewer leaves you where you were looking.
	ListView_SetItemState(hItemList, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
	ListView_SetItemState(hItemList, iRow, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
	ListView_EnsureVisible(hItemList, iRow, FALSE);

	char sText[256];
	char sPakSize[256];
	char sTime[64];
	char sDirection[64];

	sprintf_s(sText, sizeof(sText), "Packet Size: %s", FileSizeFriendly(BinDataPointer->iLength, sPakSize, sizeof(sPakSize)));
	SendMessage(hResizeBar, (UINT)SB_SETTEXT, (WPARAM)1, (LPARAM)sText);

	ListView_GetItemText(hItemList, iRow, COL_TIME_POS, sTime, sizeof(sTime));
	ListView_GetItemText(hItemList, iRow, COL_DIR_POS, sDirection, sizeof(sDirection));
	sprintf_s(sText, sizeof(sText), "Row %d of %d  %s  %s", iRow + 1, iCount, sTime, sDirection);
	SendMessage(hResizeBar, (UINT)SB_SETTEXT, (WPARAM)0, (LPARAM)sText);

	sprintf_s(sText, sizeof(sText), "Packet %d of %d", iRow + 1, iCount);
	SetDlgItemText(hWnd, IDC_VIEWPOS, sText);

	sprintf_s(sText, sizeof(sText), "Packet %d of %d", iRow + 1, iCount);
	SendMessage(hWnd, WM_SETTEXT, 0, (LPARAM)sText);

	EnableWindow(GetDlgItem(hWnd, IDC_VIEWPREV), iRow > 0);
	EnableWindow(GetDlgItem(hWnd, IDC_VIEWNEXT), iRow + 1 < iCount);

	RenderDecode(hWnd, iRow);
	RenderBytes(hWnd);

	return true;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

INT_PTR CALLBACK ViewTextDialog(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	//--------------------------------------------------------------------------

	if(uMsg == WM_INITDIALOG) // Received A Initilize Dialog Message
	{
		hViewTextDialog = hWnd;

		HMENU hMenu = GetSystemMenu(hWnd, FALSE);
		AppendMenu(hMenu, MF_SEPARATOR, 0, 0);
		AppendMenu(hMenu, MF_STRING, VIEWTEXTDIALOG_MENU_ABOUT, "About");

		SendMessage(hWnd, (UINT)WM_SETTEXT, (WPARAM)0, (LPARAM)"Text View");
		SendMessage(hWnd, WM_SETICON, TRUE, (LPARAM) LoadIcon(ghAppInstance, MAKEINTRESOURCE(IDI_MAIN)));

		hTextBoxWrap = GetDlgItem(hWnd, IDC_VIEWTEXTWRAP);
		hTextBox = GetDlgItem(hWnd, IDC_VIEWTEXT);
		hDecodeBox = GetDlgItem(hWnd, IDC_VIEWDECODE);
		hOmitTCPHeader = GetDlgItem(hWnd, IDC_OMITTCPHEADER);

		//The default limit would truncate a large packet's dump.
		SendMessage(hTextBox, EM_SETLIMITTEXT, 0, 0);
		SendMessage(hTextBoxWrap, EM_SETLIMITTEXT, 0, 0);
		SendMessage(hDecodeBox, EM_SETLIMITTEXT, 0, 0);

		CheckDlgButton(hWnd, IDC_OMITTCPHEADER, BST_CHECKED);
		CheckDlgButton(hWnd, IDC_VIEWMODEHEX, BST_CHECKED);
		CheckDlgButton(hWnd, IDC_WRAPTEXT, BST_UNCHECKED);
		CheckDlgButton(hWnd, IDC_SHOWDECODE, BST_CHECKED);

		hResizeBar = CreateStatusWindow(WS_CHILD|WS_VISIBLE, "", hWnd, 1);
		int Widths[] = {300, 500, 800, -1};
		SendMessage(hResizeBar, (UINT)SB_SETPARTS, (WPARAM)4, (LPARAM)&Widths);

		HFONT hFont = MakeFont("Lucida Console", 9);
		if(hFont)
		{
			SetFont(hTextBox, hFont);
			SetFont(hTextBoxWrap, hFont);
			SetFont(hDecodeBox, hFont);
		}

		CenterOverOwner(hWnd);

		LayoutView(hWnd);

		if(!LoadRow(hWnd, giViewRow))
		{
			RenderBytes(hWnd);
		}

		return TRUE; // Return TRUE to set the keyboard focus, Otherwise return FALSE.
	}

	//--------------------------------------------------------------------------

	if(uMsg == WM_COMMAND)
	{
		if(wParam == IDCANCEL || wParam == IDOK)
		{
			EndDialog(hWnd, 0);
			return TRUE;
		}

		if(wParam == IDC_VIEWPREV)
		{
			LoadRow(hWnd, giViewRow - 1);
			return TRUE;
		}

		if(wParam == IDC_VIEWNEXT)
		{
			LoadRow(hWnd, giViewRow + 1);
			return TRUE;
		}

		if(wParam == IDC_SHOWDECODE)
		{
			LayoutView(hWnd);
			return FALSE;
		}

		if(wParam == IDC_OMITTCPHEADER
			|| wParam == IDC_WRAPTEXT
			|| wParam == IDC_VIEWMODEHEX
			|| wParam == IDC_VIEWMODETEXT
			|| wParam == IDC_VIEWMODERAW)
		{
			RenderBytes(hWnd);
		}

		return FALSE;
	}

	//--------------------------------------------------------------------------

	if(uMsg == WM_SHOWWINDOW)
	{
		SendMessage(hTextBox, EM_SETSEL, (WPARAM)0, (LPARAM)0);
		SendMessage(hTextBoxWrap, EM_SETSEL, (WPARAM)0, (LPARAM)0);
		SendMessage(hDecodeBox, EM_SETSEL, (WPARAM)0, (LPARAM)0);
		return TRUE;
	}

	//--------------------------------------------------------------------------

	if(uMsg == WM_SIZE)
	{
		LayoutView(hWnd);
		return FALSE; //Return false if we process WM_SIZE.
	}

	//--------------------------------------------------------------------------

	if(uMsg == WM_GETMINMAXINFO)
	{
		MINMAXINFO *pInfo = (MINMAXINFO *)lParam;
		pInfo->ptMinTrackSize.x = 420;
		pInfo->ptMinTrackSize.y = 300;
		return FALSE;
	}

	//--------------------------------------------------------------------------

	if(uMsg == WM_PAINT)
	{
		HDC ThisHDC;
		PAINTSTRUCT ThisPS;

		ThisHDC = BeginPaint(hWnd, &ThisPS);

		//- Any painting should be done here.

		EndPaint(hWnd, &ThisPS);
		return TRUE;
	}

	//--------------------------------------------------------------------------

	if(uMsg == WM_SYSCOMMAND) //- Received a system menu message.
	{
		if(LOWORD(wParam) == VIEWTEXTDIALOG_MENU_ABOUT) //- About.
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

	if(uMsg == WM_CLOSE) //- Received close message.
	{
		EndDialog(hWnd, 0);
		DestroyWindow(hWnd);

		hViewTextDialog = NULL;

		return TRUE;
	}

	//--------------------------------------------------------------------------

	return FALSE;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#endif
