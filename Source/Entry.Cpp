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

using namespace NSWFL::Debug;

HINSTANCE ghAppInstance = NULL;

char gsAppCopyRight[64];
char gsFileVersion[10];
char gsTitleCaption[64];
char gsRegistryKey[255];
char gsBindToIpAddress[255];
CRITICAL_SECTION gcsHostResolverCache;

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
			if(uMsg.message == WM_KEYUP && uMsg.hwnd != hMainDialog) //Do not deliver it twice if the dialog itself has the focus.
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

//Dispatches any pending messages without blocking. Used when waiting on another thread
//	which may be sending messages to the UI thread.
void PumpMessages(void)
{
	//Only service messages which were SENT to this thread (the listener sends them while it owns gCS). Posted input is
	//	left alone, otherwise a key press or click would re-enter a handler which is itself waiting on the listener.
	MSG uMsg;
	PeekMessage(&uMsg, NULL, 0, 0, PM_NOREMOVE | PM_QS_SENDMESSAGE);
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevious, LPSTR CmdLine, int CmdShow)
{
#ifdef DEBUG
	NSWFL::Debug::OpenDebugConsole("IP/Spy");
	NSWFL::Debug::DebugRedirectOutput();
#endif

	printf("%s v%s\n", gsTitleCaption, gsFileVersion);

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
		SaveFiltersToRegistry();
	}

    if(!UninitializeApp())
    {
        return 1;
    }

	return 0;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#endif
