#ifndef _ADAPTERS_CPP
#define _ADAPTERS_CPP
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include <WinSock2.h>
#include <Windows.H>
#include <WS2TcpIP.h>
#include <IPHlpApi.h>
#include <Stdio.H>
#include <Stdlib.H>
#include <string>

#include "Adapters.H"

#pragma comment(lib, "iphlpapi.lib")

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static bool IsLinkLocalV6(const unsigned char *pAddr16)
{
	return pAddr16[0] == 0xFE && (pAddr16[1] & 0xC0) == 0x80;
}

static void MapV4(const unsigned char *pV4, unsigned char *pAddr16)
{
	memset(pAddr16, 0, 10);
	pAddr16[10] = 0xFF;
	pAddr16[11] = 0xFF;
	memcpy(pAddr16 + 12, pV4, 4);
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

bool ParseIPAddress(const char *sText, unsigned char *pAddr16, bool *pbIsV6, unsigned int *puiScopeId)
{
	std::string s(sText ? sText : "");

	size_t iStart = 0;
	while (iStart < s.length() && isspace((unsigned char)s[iStart]))
	{
		iStart++;
	}
	size_t iEnd = s.length();
	while (iEnd > iStart && isspace((unsigned char)s[iEnd - 1]))
	{
		iEnd--;
	}
	s = s.substr(iStart, iEnd - iStart);

	unsigned int uiScope = 0;
	size_t iPercent = s.find('%');
	if (iPercent != std::string::npos)
	{
		uiScope = (unsigned int)strtoul(s.c_str() + iPercent + 1, NULL, 10);
		s = s.substr(0, iPercent);
	}

	if (s.empty() || s.length() > 64)
	{
		return false;
	}

	if (s.find(':') != std::string::npos)
	{
		IN6_ADDR addr6;
		if (InetPtonA(AF_INET6, s.c_str(), &addr6) != 1)
		{
			return false;
		}
		memcpy(pAddr16, &addr6, 16);
		if (pbIsV6) { *pbIsV6 = true; }
	}
	else
	{
		IN_ADDR addr4;
		if (InetPtonA(AF_INET, s.c_str(), &addr4) != 1)
		{
			return false;
		}
		MapV4((const unsigned char *)&addr4, pAddr16);
		if (pbIsV6) { *pbIsV6 = false; }
	}

	if (puiScopeId) { *puiScopeId = uiScope; }
	return true;
}

bool FormatIPAddress(const unsigned char *pAddr16, bool bIsV6, char *sOut, int iOutSz)
{
	if (bIsV6)
	{
		IN6_ADDR addr6;
		memcpy(&addr6, pAddr16, 16);
		return InetNtopA(AF_INET6, &addr6, sOut, iOutSz) != NULL;
	}

	IN_ADDR addr4;
	memcpy(&addr4, pAddr16 + 12, 4);
	return InetNtopA(AF_INET, &addr4, sOut, iOutSz) != NULL;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

bool GetLocalAddresses(std::vector<LOCAL_ADDRESS> *pList)
{
	pList->clear();

	ULONG ulSize = 16 * 1024;
	PIP_ADAPTER_ADDRESSES pAdapters = NULL;
	ULONG ulResult = ERROR_BUFFER_OVERFLOW;

	for (int iAttempt = 0; iAttempt < 4 && ulResult == ERROR_BUFFER_OVERFLOW; iAttempt++)
	{
		free(pAdapters);
		pAdapters = (PIP_ADAPTER_ADDRESSES)malloc(ulSize);
		if (pAdapters == NULL)
		{
			return false;
		}

		ulResult = GetAdaptersAddresses(AF_UNSPEC,
			GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER, NULL, pAdapters, &ulSize);
	}

	if (ulResult != NO_ERROR)
	{
		free(pAdapters);
		return false;
	}

	for (PIP_ADAPTER_ADDRESSES pAdapter = pAdapters; pAdapter != NULL; pAdapter = pAdapter->Next)
	{
		if (pAdapter->OperStatus != IfOperStatusUp || pAdapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK)
		{
			continue;
		}

		for (PIP_ADAPTER_UNICAST_ADDRESS pUnicast = pAdapter->FirstUnicastAddress; pUnicast != NULL; pUnicast = pUnicast->Next)
		{
			if (pUnicast->Address.lpSockaddr == NULL)
			{
				continue;
			}

			LOCAL_ADDRESS local;
			memset(&local, 0, sizeof(local));

			if (pUnicast->Address.lpSockaddr->sa_family == AF_INET)
			{
				const SOCKADDR_IN *pIn = (const SOCKADDR_IN *)pUnicast->Address.lpSockaddr;
				local.Family = AF_INET;
				MapV4((const unsigned char *)&pIn->sin_addr, local.Addr);
				FormatIPAddress(local.Addr, false, local.Text, sizeof(local.Text));
			}
			else if (pUnicast->Address.lpSockaddr->sa_family == AF_INET6)
			{
				//Skip tentative/duplicate addresses, they cannot be bound to.
				if (pUnicast->DadState != IpDadStatePreferred && pUnicast->DadState != IpDadStateDeprecated)
				{
					continue;
				}

				const SOCKADDR_IN6 *pIn6 = (const SOCKADDR_IN6 *)pUnicast->Address.lpSockaddr;
				local.Family = AF_INET6;
				memcpy(local.Addr, &pIn6->sin6_addr, 16);
				local.ScopeId = pIn6->sin6_scope_id;
				FormatIPAddress(local.Addr, true, local.Text, sizeof(local.Text));

				if (IsLinkLocalV6(local.Addr) && local.ScopeId != 0)
				{
					size_t iLength = strlen(local.Text);
					sprintf_s(local.Text + iLength, sizeof(local.Text) - iLength, "%%%u", local.ScopeId);
				}
			}
			else
			{
				continue;
			}

			local.IfIndex = (pAdapter->IfIndex != 0) ? pAdapter->IfIndex : pAdapter->Ipv6IfIndex;
			pList->push_back(local);
		}
	}

	free(pAdapters);
	return true;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static void FillV4(const LOCAL_ADDRESS &local, SOCKADDR_IN *pV4)
{
	memset(pV4, 0, sizeof(SOCKADDR_IN));
	pV4->sin_family = AF_INET;
	memcpy(&pV4->sin_addr, local.Addr + 12, 4);
}

static void FillV6(const LOCAL_ADDRESS &local, SOCKADDR_IN6 *pV6)
{
	memset(pV6, 0, sizeof(SOCKADDR_IN6));
	pV6->sin6_family = AF_INET6;
	memcpy(&pV6->sin6_addr, local.Addr, 16);
	if (IsLinkLocalV6(local.Addr))
	{
		pV6->sin6_scope_id = local.ScopeId;
	}
}

bool ResolveBindTargets(const char *sSelected, SOCKADDR_IN *pV4, bool *pbHasV4,
	SOCKADDR_IN6 *pV6, bool *pbHasV6, std::vector<LOCAL_ADDRESS> *pLocals)
{
	unsigned char selected[16];
	bool bSelectedV6 = false;
	unsigned int uiSelectedScope = 0;

	*pbHasV4 = false;
	*pbHasV6 = false;
	pLocals->clear();

	if (!ParseIPAddress(sSelected, selected, &bSelectedV6, &uiSelectedScope))
	{
		return false;
	}

	std::vector<LOCAL_ADDRESS> all;
	GetLocalAddresses(&all);

	//Find the adapter which owns the selected address.
	int iSelectedIndex = -1;
	for (size_t i = 0; i < all.size(); i++)
	{
		if ((all[i].Family == AF_INET6) == bSelectedV6 && memcmp(all[i].Addr, selected, 16) == 0
			&& (!bSelectedV6 || uiSelectedScope == 0 || all[i].ScopeId == uiSelectedScope || !IsLinkLocalV6(selected)))
		{
			iSelectedIndex = (int)i;
			break;
		}
	}

	if (iSelectedIndex < 0)
	{
		//Not one of ours (typed in), capture just that address.
		LOCAL_ADDRESS local;
		memset(&local, 0, sizeof(local));
		memcpy(local.Addr, selected, 16);
		local.Family = bSelectedV6 ? AF_INET6 : AF_INET;
		local.ScopeId = uiSelectedScope;
		FormatIPAddress(selected, bSelectedV6, local.Text, sizeof(local.Text));
		pLocals->push_back(local);

		if (bSelectedV6) { FillV6(local, pV6); *pbHasV6 = true; }
		else { FillV4(local, pV4); *pbHasV4 = true; }
		return true;
	}

	unsigned int uiIfIndex = all[iSelectedIndex].IfIndex;
	int iV4 = -1;
	int iV6 = -1;

	for (size_t i = 0; i < all.size(); i++)
	{
		if (all[i].IfIndex != uiIfIndex)
		{
			continue;
		}

		pLocals->push_back(all[i]);

		if (all[i].Family == AF_INET)
		{
			if (iV4 < 0 || (int)i == iSelectedIndex)
			{
				iV4 = (int)i;
			}
		}
		else
		{
			//Prefer the selected address, then a global address over a link-local one.
			bool bBetter = (iV6 < 0) || ((int)i == iSelectedIndex)
				|| (IsLinkLocalV6(all[iV6].Addr) && !IsLinkLocalV6(all[i].Addr) && iV6 != iSelectedIndex);
			if (bBetter)
			{
				iV6 = (int)i;
			}
		}
	}

	if (iV4 >= 0) { FillV4(all[iV4], pV4); *pbHasV4 = true; }
	if (iV6 >= 0) { FillV6(all[iV6], pV6); *pbHasV6 = true; }

	return *pbHasV4 || *pbHasV6;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#endif
