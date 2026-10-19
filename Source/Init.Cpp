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

	sPackBuff = (char *)calloc(MAX_PACK_BUFF + 128, 1);
	sPackText = (char *)calloc(MAX_PACK_TEXT + 1, 1);

	InitializeCriticalSection(&gCS);
	InitializeCriticalSection(&gcsHostResolverCache);

	WSADATA wsaData;
	WSAStartup(MAKEWORD(2,1), &wsaData);

	gbShutDownResolvers = false;
	for (int i = 0; i < RESOLVER_THREAD_COUNT; i++)
	{
		ghResolverThreads[i] = CreateThread(NULL, 0, ResolverThread, (LPVOID)0, 0, NULL);
	}

	memset(gsBindToIpAddress, 0, sizeof(gsBindToIpAddress));

	LoadFiltersFromRegistry();

	return true;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

bool UninitializeApp(void)
{
	//The resolvers use their own shutdown flag so that stopping/restarting the listener does not kill them.
	gbShutDownResolvers = true;
	bool bResolversStopped = true;
	for (int i = 0; i < RESOLVER_THREAD_COUNT; i++)
	{
		if (ghResolverThreads[i])
		{
			if (WaitForSingleObject(ghResolverThreads[i], 3000) != WAIT_OBJECT_0)
			{
				bResolversStopped = false; //Stuck in a slow DNS call, it still uses the critical sections.
			}
			CloseHandle(ghResolverThreads[i]);
			ghResolverThreads[i] = NULL;
		}
	}

	if (bResolversStopped)
	{
		DeleteCriticalSection(&gCS);
		DeleteCriticalSection(&gcsHostResolverCache);
	}

	WSACleanup();

	return true;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#endif
