#ifndef _BindToDlg_CPP
#define _BindToDlg_CPP
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include <Windows.H>
#include <Stdio.H>
#include <Stdlib.H>
#include <CommCtrl.h>

#include "../Source/Entry.H"

#include "../Dialogs/MainDlg.H"
#include "../Dialogs/BindToDlg.H"
#include "../Dialogs/NetLogoDlg.H"

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

using namespace NSWFL::Windows;
using namespace NSWFL::String;
using namespace NSWFL::Conversion;
using namespace NSWFL::ListView;

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

bool IsValidIPAddressV4(const char *sIP)
{
	char **sIPs = Split(sIP, ".");

	if(UBound(sIPs) != 4)
	{
		FreeArray(sIPs);
		return false;
	}

	int iOctLen = 0;

	for(unsigned short iOct = 0; iOct < 4; iOct++)
	{
		if((iOctLen = (int)strlen(sIPs[iOct])) > 3)
		{
			FreeArray(sIPs);
			return false;
		}

		for(int iPos = 0; iPos < iOctLen; iPos++)
		{
			if(!IsNumeric(sIPs[iOct][iPos]))
			{
				FreeArray(sIPs);
				return false;
			}
		}

		if(atol(sIPs[iOct]) > 255)
		{
			FreeArray(sIPs);
			return false;
		}
	}

	FreeArray(sIPs);

	return true;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void PopIPAddresses(HWND hList)
{
	char sHostName[1024];
	memset(sHostName, 0, sizeof(sHostName));

	if(gethostname(sHostName, sizeof(sHostName)) == 0)
	{
		struct hostent FAR *pHostent = gethostbyname(sHostName);
		if(pHostent)
		{
			struct in_addr Address;
			for(int i = 0; (*pHostent).h_addr_list[i]; i++)
			{
				memcpy(&Address.s_addr, (*pHostent).h_addr_list[i], (*pHostent).h_length);
				SendMessage(hList, (UINT) CB_ADDSTRING, (WPARAM) NULL, (LPARAM) inet_ntoa(Address));
			}

			Set_Text(hList, inet_ntoa(Address));
		}
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

INT_PTR CALLBACK BindToDialog(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    //--------------------------------------------------------------------------

    static HWND hIP = NULL;

    //--------------------------------------------------------------------------

    if(uMsg == WM_INITDIALOG)
    {
		CenterOverOwner(hWnd);

        HMENU hMenu = GetSystemMenu(hWnd, FALSE);
        AppendMenu(hMenu, MF_SEPARATOR, 0, 0);
        AppendMenu(hMenu, MF_STRING, GENERIC_MENU_ABOUT, "About");

        SendMessage(hWnd, (UINT)WM_SETTEXT, (WPARAM)0, (LPARAM)"IP Binding");
        SendMessage(hWnd, WM_SETICON, TRUE, (LPARAM) LoadIcon(ghAppInstance, MAKEINTRESOURCE(IDI_MAIN)));

        hIP = GetDlgItem(hWnd, IDC_IPADDRESS);

		PopIPAddresses(hIP);

		if(strlen(gsBindToIpAddress) > 0)
		{
			Set_Text(hIP, gsBindToIpAddress);
		}

		return TRUE; // Return TRUE to set the keyboard focus, Otherwise return FALSE.
    }
    //--------------------------------------------------------------------------
    else if(uMsg == WM_COMMAND)
    {
		if(wParam == IDC_CMD_OK || wParam == IDOK)
        {
			char sIP[sizeof(gsBindToIpAddress)];

			int iLength = Get_Text(hIP, sIP, sizeof(sIP));
			if(iLength <= 0 || iLength >= sizeof(sIP) || !IsValidIPAddressV4(sIP))
			{
				MessageBox(hWnd, "You must specify a valid v4 IP Address.", gsTitleCaption, MB_ICONINFORMATION);
				return FALSE;
			}

			strcpy_s(gsBindToIpAddress, sizeof(gsBindToIpAddress), sIP);

            EndDialog(hWnd, TRUE);
        }
        else if(wParam == IDC_CMD_CANCEL || wParam == IDCANCEL)
        {
            EndDialog(hWnd, FALSE);
        }
        return FALSE;
    }
    //--------------------------------------------------------------------------
	else if(uMsg == WM_PAINT)
    {
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
        if(LOWORD(wParam) == GENERIC_MENU_ABOUT) //- About.
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
        EndDialog(hWnd, FALSE);
        return TRUE;
    }
    //--------------------------------------------------------------------------

    return FALSE;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#endif
