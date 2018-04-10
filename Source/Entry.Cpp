#ifndef _ENTRY_CPP
#define _ENTRY_CPP
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include <Windows.H>
#include <Stdio.H>
#include <Stdlib.H>

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include "Entry.H"
#include "Init.H"

#include "../Dialogs/MainDlg.H"

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

HINSTANCE ghAppInstance = NULL;

char gsAppCopyRight[64];
char gsFileVersion[10];
char gsTitleCaption[64];
char gsRegistryKey[255];
char gsBindToIpAddress[255];

char *sPackBuff = NULL;
char *sPackText = NULL;

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

bool DoEvents(void)
{
	int iReturnValue = 0;
	MSG uMsg;

	if((iReturnValue = GetMessage(&uMsg, hMainDialog, 0, 0)))
	{
		if(iReturnValue != -1)
		{
			if(uMsg.message == WM_KEYUP)
			{
				SendMessage(hMainDialog, uMsg.message, uMsg.wParam, uMsg.lParam);
			}

			TranslateMessage(&uMsg);
			DispatchMessage(&uMsg);
		}
		else {
			return false;
		}
	}

	return true;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevious, LPSTR CmdLine, int CmdShow)
{
	ghAppInstance = hInstance;

	if(!InitializeApp())
    {
        return 1;
    }

	if((hMainDialog = CreateDialog(ghAppInstance, MAKEINTRESOURCE(IDD_MAIN), NULL, MainDialog)))
	{
		while(DoEvents())
		{
		}
		Stop();
	}

    if(!UninitializeApp())
    {
        return 1;
    }

	return 0;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#endif

