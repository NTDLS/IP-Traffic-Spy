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

bool IsValidBindAddress(const char *sIP)
{
	unsigned char addr[16];
	bool bIsV6 = false;

	return ParseIPAddress(sIP, addr, &bIsV6, NULL);
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//Lists the IPv4 and IPv6 addresses of the adapters which are up. Selecting one captures on its adapter.
void PopIPAddresses(HWND hList)
{
	std::vector<LOCAL_ADDRESS> addresses;
	GetLocalAddresses(&addresses);

	const char *sFirst = NULL;

	for(size_t i = 0; i < addresses.size(); i++)
	{
		SendMessage(hList, (UINT) CB_ADDSTRING, (WPARAM) NULL, (LPARAM) addresses[i].Text);

		//Default to the first IPv4 address, that is what this used to list.
		if(sFirst == NULL && addresses[i].Family == AF_INET)
		{
			sFirst = addresses[i].Text;
		}
	}

	if(sFirst == NULL && addresses.size() > 0)
	{
		sFirst = addresses[0].Text;
	}

	if(sFirst)
	{
		Set_Text(hList, (char *)sFirst);
	}
}

///////

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
			if(iLength <= 0 || iLength >= sizeof(sIP) || !IsValidBindAddress(sIP))
			{
				MessageBox(hWnd, "You must specify a valid IPv4 or IPv6 address.", gsTitleCaption, MB_ICONINFORMATION);
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
