#ifndef _ExcludeFiltersDLG_CPP
#define _ExcludeFiltersDLG_CPP
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include <Windows.H>
#include <Stdio.H>
#include <Stdlib.H>
#include <CommCtrl.h>

#include "../Source/Entry.H"

#include "../Dialogs/ExcludeFiltersDlg.H"
#include "../Dialogs/NetLogoDlg.H"
#include "../Dialogs/MainDlg.H"

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

using namespace NSWFL::Windows;
using namespace NSWFL::ListBox;

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//---------------------(Variable Declarations)
HWND hExcludeFiltersDialog = NULL;

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

INT_PTR CALLBACK ExcludeFiltersDialog(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	//--------------------------------------------------------------------------

	static HWND hSIPList	= NULL;
	static HWND hDIPList	= NULL;
	static HWND hSPortList	= NULL;
	static HWND hDPortList	= NULL;
	static HWND hSIPEdit	= NULL;
	static HWND hDIPEdit	= NULL;
	static HWND hSPortEdit	= NULL;
	static HWND hDPortEdit	= NULL;

	//--------------------------------------------------------------------------

	if(uMsg == WM_INITDIALOG) // Received A Initilize Dialog Message
	{
		hExcludeFiltersDialog = hWnd;

		HMENU hMenu = GetSystemMenu(hWnd, FALSE);
		AppendMenu(hMenu, MF_SEPARATOR, 0, 0);
		AppendMenu(hMenu, MF_STRING, EXCLUDEFILTERSDIALOG_MENU_ABOUT, "About");

		SendMessage(hWnd, (UINT)WM_SETTEXT, (WPARAM)0, (LPARAM)"Exclude Filters");
		SendMessage(hWnd, WM_SETICON, TRUE, (LPARAM) LoadIcon(ghAppInstance, MAKEINTRESOURCE(IDI_MAIN)));

		hSIPList	= GetDlgItem(hWnd, IDC_LIST_SIP);
		hDIPList	= GetDlgItem(hWnd, IDC_LIST_DIP);
		hSPortList	= GetDlgItem(hWnd, IDC_LIST_SPORT);
		hDPortList	= GetDlgItem(hWnd, IDC_LIST_DPORT);

		hSIPEdit	= GetDlgItem(hWnd, IDC_EDIT_SIP);
		hDIPEdit	= GetDlgItem(hWnd, IDC_EDIT_DIP);
		hSPortEdit	= GetDlgItem(hWnd, IDC_EDIT_SPORT);
		hDPortEdit	= GetDlgItem(hWnd, IDC_EDIT_DPORT);

		AddEditHandler(hWnd, hSIPEdit);
		AddEditHandler(hWnd, hDIPEdit);
		AddEditHandler(hWnd, hSPortEdit);
		AddEditHandler(hWnd, hDPortEdit);

		AddListHandler(hWnd, hSIPList);
		AddListHandler(hWnd, hDIPList);
		AddListHandler(hWnd, hSPortList);
		AddListHandler(hWnd, hDPortList);

		PopListBoxFromArray(hSIPList, &gExcludeSourceIPFilter);
		PopListBoxFromArray(hDIPList, &gExcludeTargetIPFilter);
		PopListBoxFromArray(hSPortList, &gExcludeSourcePortFilter);
		PopListBoxFromArray(hDPortList, &gExcludeTargetPortFilter);

		CenterOverOwner(hWnd);

		return TRUE; // Return TRUE to set the keyboard focus, Otherwise return FALSE.
	}

	//--------------------------------------------------------------------------

	if(uMsg == WM_COMMAND)
	{
		if(wParam == IDC_BUTTON_SIP)
		{
			char sIP[255];
			char sIPMask[255];
			if(Get_Text(hSIPEdit, sIP, sizeof(sIP)) <= sizeof(sIP))
			{
				if(!IsValidIPAddress(sIP))
				{
					MessageBox(hWnd, "Enter a valid IP address.", gsTitleCaption, MB_ICONWARNING);
					return TRUE;
				}
				Set_Text(hSIPEdit, "");
				MakeIPMask(sIP, sIPMask, sizeof(sIPMask));
				InsertListBoxItemNoDuplicate(hSIPList, sIPMask);
			}
		}
		else if(wParam == IDC_BUTTON_DIP)
		{
			char sIP[255];
			char sIPMask[255];
			if(Get_Text(hDIPEdit, sIP, sizeof(sIP)) <= sizeof(sIP))
			{
				if(!IsValidIPAddress(sIP))
				{
					MessageBox(hWnd, "Enter a valid IP address.", gsTitleCaption, MB_ICONWARNING);
					return TRUE;
				}
				Set_Text(hDIPEdit, "");
				MakeIPMask(sIP, sIPMask, sizeof(sIPMask));
				InsertListBoxItemNoDuplicate(hDIPList, sIPMask);
			}
		}
		else if(wParam == IDC_BUTTON_SPORT)
		{
			char sText[255];
			if(Get_Text(hSPortEdit, sText, sizeof(sText)) <= sizeof(sText))
			{
				if(atol(sText) >= 0)
				{
					Set_Text(hSPortEdit, "");
					InsertListBoxItemNoDuplicate(hSPortList, sText);
				}
			}
		}
		else if(wParam == IDC_BUTTON_DPORT)
		{
			char sText[255];
			if(Get_Text(hDPortEdit, sText, sizeof(sText)) <= sizeof(sText))
			{
				if(atol(sText) >= 0)
				{
					Set_Text(hDPortEdit, "");
					InsertListBoxItemNoDuplicate(hDPortList, sText);
				}
			}
		}
		else if(wParam == IDC_BUTTON_SIP_DEL)
		{
			DeleteSingleListBoxItemFriendly(hSIPList);
		}
		else if(wParam == IDC_BUTTON_DIP_DEL)
		{
			DeleteSingleListBoxItemFriendly(hDIPList);
		}
		else if(wParam == IDC_BUTTON_SPORT_DEL)
		{
			DeleteSingleListBoxItemFriendly(hSPortList);
		}
		else if(wParam == IDC_BUTTON_DPORT_DEL)
		{
			DeleteSingleListBoxItemFriendly(hDPortList);
		}
		else if(wParam == IDC_CMD_OK || wParam == IDOK)
		{
			PopArrayFromListBox(hSIPList, &gExcludeSourceIPFilter);
			PopArrayFromListBox(hDIPList, &gExcludeTargetIPFilter);
			PopArrayFromListBox(hSPortList, &gExcludeSourcePortFilter);
			PopArrayFromListBox(hDPortList, &gExcludeTargetPortFilter);

			EndDialog(hWnd, 0);
			DestroyWindow(hWnd);

			hExcludeFiltersDialog = NULL;

			return TRUE;
		}
		else if(wParam == IDC_CMD_CANCEL || wParam == IDCANCEL)
		{
			EndDialog(hWnd, 0);
			DestroyWindow(hWnd);

			hExcludeFiltersDialog = NULL;

			return TRUE;
		}
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
		if(LOWORD(wParam) == EXCLUDEFILTERSDIALOG_MENU_ABOUT) //- About.
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

		hExcludeFiltersDialog = NULL;

		return TRUE;
	}

	//--------------------------------------------------------------------------

	return FALSE;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#endif

