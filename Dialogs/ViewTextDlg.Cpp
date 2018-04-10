#ifndef _ViewTextDlg_CPP
#define _ViewTextDlg_CPP
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include <Windows.H>
#include <Stdio.H>
#include <Stdlib.H>
#include <CommCtrl.h>

#include "../Source/Entry.H"

#include "../Dialogs/MainDlg.H"
#include "../Dialogs/ViewTextDlg.H"
#include "../Dialogs/NetLogoDlg.H"

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

using namespace NSWFL::Windows;
using namespace NSWFL::File;

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//---------------------(Variable Declarations)
HWND hViewTextDialog = NULL;

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

INT_PTR CALLBACK ViewTextDialog(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	static HWND hTextBox = NULL;
	static HWND hTextBoxWrap = NULL;
	static HWND hResizeBar = NULL;
	static HWND hOmitTCPHeader = NULL;

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
		hOmitTCPHeader = GetDlgItem(hWnd, IDC_OMITTCPHEADER);

		CheckDlgButton(hWnd, IDC_OMITTCPHEADER, BST_CHECKED);
		CheckDlgButton(hWnd, IDC_VIEWMODETEXT, BST_CHECKED);
		CheckDlgButton(hWnd, IDC_WRAPTEXT, BST_CHECKED);
		SendMessage(hWnd, WM_COMMAND, IDC_VIEWMODETEXT, 0);

		char sText[1024];
		char sPakSize[1024];

		hResizeBar = CreateStatusWindow(WS_CHILD|WS_VISIBLE, "", hWnd, 1);
		int Widths[] = {300, 500, 800, -1};
		SendMessage(hResizeBar, (UINT)SB_SETPARTS, (WPARAM)4, (LPARAM)&Widths);

		sprintf_s(sText, sizeof(sText), "Packet Size: %s",
			FileSizeFriendly(BinDataPointer->iLength, sPakSize, sizeof(sPakSize)));
		SendMessage(hResizeBar, (UINT)SB_SETTEXT, (WPARAM)1, (LPARAM)sText);

		HFONT hFont = MakeFont("Lucida Console", 9);
		if(hFont)
		{
			SetFont(hTextBox, hFont);
			SetFont(hTextBoxWrap, hFont);
		}

		CenterOverOwner(hWnd);

		RECT recDimensions;
		memset(&recDimensions, 0, sizeof(recDimensions));
		GetClientRect(hWnd, &recDimensions);

		SendMessage(hWnd, WM_SIZE, 0, MAKELONG(recDimensions.right, recDimensions.bottom));

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

		if(wParam == IDC_OMITTCPHEADER
			|| wParam == IDC_WRAPTEXT
			|| wParam == IDC_VIEWMODEHEX
			|| wParam == IDC_VIEWMODETEXT
			|| wParam == IDC_VIEWMODERAW)
		{

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
				sText += sizeof(IP_HDR);
				iSize -= sizeof(IP_HDR);

				if(BinDataPointer->iProtocol == IPPROTO_TCP)
				{
					sText += sizeof(TCP_HDR);
					iSize -= sizeof(TCP_HDR);
				}
				else if(BinDataPointer->iProtocol == IPPROTO_UDP)
				{
					sText += sizeof(UDP_HDR);
					iSize -= sizeof(UDP_HDR);
				}
			}

			if(IsDlgButtonChecked(hWnd, IDC_VIEWMODEHEX))
			{
				char *sCleanText = (char *) calloc((iSize * 4) + 1, sizeof(char));
				CleanHex(sText, iSize, sCleanText, (iSize * 4) + 1);
				Set_Text(hTextBox, sCleanText);
				Set_Text(hTextBoxWrap, sCleanText);
				free(sCleanText);
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

		return FALSE;
	}

	//--------------------------------------------------------------------------

	if(uMsg == WM_SHOWWINDOW)
	{
		SendMessage(hTextBox, EM_SETSEL, (WPARAM)0, (LPARAM)0);
		SendMessage(hTextBoxWrap, EM_SETSEL, (WPARAM)0, (LPARAM)0);
		return TRUE;
	}
	
	//--------------------------------------------------------------------------

	if(uMsg == WM_SIZE)
	{
		int nWidth = LOWORD(lParam);
		int nHeight = HIWORD(lParam);

		RECT recDimensions;
		memset(&recDimensions, 0, sizeof(recDimensions));
		GetClientRect(hOmitTCPHeader, &recDimensions);

		MoveWindow(hTextBox, recDimensions.right + 25, 1, nWidth - (recDimensions.right + 27), nHeight - 25, TRUE);
		MoveWindow(hTextBoxWrap, recDimensions.right + 25, 1, nWidth - (recDimensions.right + 27), nHeight - 25, TRUE);
		MoveWindow(hResizeBar, nWidth-0, nHeight-0, nWidth, nHeight, TRUE);

		return FALSE; //Return false if we process WM_SIZE.
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

