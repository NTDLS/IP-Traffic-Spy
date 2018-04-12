#ifndef _INIT_CPP
#define _INIT_CPP
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include <Windows.H>
#include <WindowsX.H>
#include <ShellAPI.H>
#include <Stdio.H>
#include <Stdlib.H>

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include "Init.H"
#include "Entry.H"

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

bool InitializeApp(void)
{

	LoadString(ghAppInstance, IDS_APPCOPYRIGHT, gsAppCopyRight, sizeof(gsAppCopyRight));
	LoadString(ghAppInstance, IDS_FILEVERSION, gsFileVersion, sizeof(gsFileVersion));
	LoadString(ghAppInstance, IDS_TITLECAPTION, gsTitleCaption, sizeof(gsTitleCaption));
	LoadString(ghAppInstance, IDS_REGISTRYKEY, gsRegistryKey, sizeof(gsRegistryKey));

	sPackBuff = (char *)calloc(MAX_PACK_BUFF + 1, 1);
	sPackText = (char *)calloc(MAX_PACK_TEXT + 1, 1);

	InitializeCriticalSection(&gCS);

	WSADATA wsaData;
	WSAStartup(MAKEWORD(2,1), &wsaData);

	memset(gsBindToIpAddress, 0, sizeof(gsBindToIpAddress));

	return true;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

bool UninitializeApp(void)
{
	DeleteCriticalSection(&gCS);

	WSACleanup();

	return true;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#endif
