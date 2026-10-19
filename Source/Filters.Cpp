#ifndef _FILTERS_CPP
#define _FILTERS_CPP
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include <WinSock2.h>
#include <Windows.H>
#include <WS2TcpIP.h>
#include <Stdio.H>
#include <Stdlib.H>
#include <string>
#include <vector>
#include <map>
#include <ctype.h>

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include "Entry.H"
#include "Filters.H"

#include "../Dialogs/MainDlg.H"

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

using namespace NSWFL::Collections;

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#define FILTERS_REGISTRY_KEY "Software\\NetworkDLS\\IP Traffic Spy\\Filters"
#define FILTERS_REGISTRY_VALUE "Data"
#define MAX_FILTERS_FILE_SIZE (1024 * 1024)

StringBuilderArray gIncludeRules;
StringBuilderArray gExcludeRules;
volatile bool gbIncludeMatchAll = false;
volatile __int64 gi64FilteredOut = 0;

typedef struct _TAG_ADDR16 { unsigned char Bytes[16]; } ADDR16;
static std::vector<ADDR16> gLocalAddresses;

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Compiled representations. The string lists are what the user sees/edits, these are what the listener evaluates.
// The compiled vectors are always index-for-index parallel with their string lists.

typedef struct _TAG_IP_MATCHER
{
	bool Valid;
	bool Legacy;				//An IPv4 "10.0.?.?" style mask, compared by digit.
	unsigned char Net[16];		//Otherwise a network (IPv4 is mapped, so its prefix is increased by 96).
	int Prefix;
	char Text[MAX_ADDR_LEN];	//Legacy only.
} IP_MATCHER;

typedef struct _TAG_PORT_MATCHER
{
	int Low;	//-1 when invalid.
	int High;
} PORT_MATCHER;

typedef enum _TAG_TERM_TYPE
{
	TERM_SRC_IP, TERM_DST_IP, TERM_ANY_IP,
	TERM_SRC_PORT, TERM_DST_PORT, TERM_ANY_PORT,
	TERM_PROTO, TERM_FLAGS,
	TERM_SRC_HOST, TERM_DST_HOST, TERM_ANY_HOST,
	TERM_CONTAINS
} TERM_TYPE;

typedef struct _TAG_TERM
{
	TERM_TYPE Type;
	IP_MATCHER IP;
	PORT_MATCHER Port;
	int Proto;
	int FlagMask;
	int FlagValue;
	std::string Text; //Lower-cased host pattern or search text.
} TERM;

typedef struct _TAG_RULE
{
	bool Valid;
	std::vector<TERM> Terms;
} RULE;

typedef struct _TAG_FILTER_SET
{
	std::vector<IP_MATCHER> SourceIP;
	std::vector<IP_MATCHER> DestIP;
	std::vector<PORT_MATCHER> SourcePort;
	std::vector<PORT_MATCHER> DestPort;
	std::vector<RULE> Rules;
} FILTER_SET;

static FILTER_SET gIncludeSet;
static FILTER_SET gExcludeSet;
static bool gbNeedHostNames = false;

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static std::string Trim(const char *sText)
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

	return s.substr(iStart, iEnd - iStart);
}

static std::string Lower(const std::string &s)
{
	std::string r(s);
	for (size_t i = 0; i < r.length(); i++)
	{
		r[i] = (char)tolower((unsigned char)r[i]);
	}
	return r;
}

static bool IsAllDigits(const std::string &s)
{
	if (s.empty())
	{
		return false;
	}
	for (size_t i = 0; i < s.length(); i++)
	{
		if (s[i] < '0' || s[i] > '9')
		{
			return false;
		}
	}
	return true;
}

static void MaskAddress(unsigned char *pAddr16, int iPrefix)
{
	for (int i = 0; i < 16; i++)
	{
		int iBits = iPrefix - (i * 8);
		if (iBits >= 8)
		{
			continue;
		}
		pAddr16[i] &= (iBits <= 0) ? 0 : (unsigned char)(0xFF << (8 - iBits));
	}
}

static bool PrefixMatches(const unsigned char *pA, const unsigned char *pB, int iPrefix)
{
	for (int i = 0; i < 16; i++)
	{
		int iBits = iPrefix - (i * 8);
		if (iBits <= 0)
		{
			break;
		}
		unsigned char mask = (iBits >= 8) ? 0xFF : (unsigned char)(0xFF << (8 - iBits));
		if ((pA[i] & mask) != (pB[i] & mask))
		{
			return false;
		}
	}
	return true;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// IP filters.

bool NormalizeIPFilter(const char *sIn, char *sOut, int iOutSz)
{
	std::string s = Trim(sIn);

	if (s.empty() || s.length() >= 80 || iOutSz < MAX_IP_TEXT + 8)
	{
		return false;
	}

	size_t iSlash = s.find('/');
	std::string sAddress = Trim((iSlash == std::string::npos ? s : s.substr(0, iSlash)).c_str());

	//CIDR blocks and anything IPv6.
	if (iSlash != std::string::npos || sAddress.find(':') != std::string::npos)
	{
		unsigned char addr[16];
		bool bV6 = false;

		if (!ParseIPAddress(sAddress.c_str(), addr, &bV6, NULL))
		{
			return false;
		}

		int iPrefix = bV6 ? 128 : 32;

		if (iSlash != std::string::npos)
		{
			std::string sPrefix = Trim(s.substr(iSlash + 1).c_str());
			if (!IsAllDigits(sPrefix) || sPrefix.length() > 3 || atoi(sPrefix.c_str()) > iPrefix)
			{
				return false;
			}
			iPrefix = atoi(sPrefix.c_str());
		}

		MaskAddress(addr, bV6 ? iPrefix : iPrefix + 96);

		char sText[MAX_IP_TEXT];
		if (!FormatIPAddress(addr, bV6, sText, sizeof(sText)))
		{
			return false;
		}

		if (iSlash == std::string::npos)
		{
			sprintf_s(sOut, iOutSz, "%s", sText); //A single IPv6 address.
		}
		else
		{
			sprintf_s(sOut, iOutSz, "%s/%d", sText, iPrefix);
		}
		return true;
	}

	//A single IPv4 address, or one with "?" wildcards.
	if (!IsValidIPAddress(s.c_str()))
	{
		return false;
	}

	MakeIPMask(s.c_str(), sOut, iOutSz);
	return true;
}

static IP_MATCHER CompileIP(const char *sNormalized)
{
	IP_MATCHER m;
	memset(&m, 0, sizeof(m));

	const char *sSlash = strchr(sNormalized, '/');

	if (sSlash || strchr(sNormalized, ':'))
	{
		std::string sAddress(sNormalized, sSlash ? (size_t)(sSlash - sNormalized) : strlen(sNormalized));
		bool bV6 = false;

		if (ParseIPAddress(sAddress.c_str(), m.Net, &bV6, NULL))
		{
			int iPrefix = sSlash ? atoi(sSlash + 1) : (bV6 ? 128 : 32);
			if (iPrefix >= 0 && iPrefix <= (bV6 ? 128 : 32))
			{
				m.Prefix = bV6 ? iPrefix : iPrefix + 96;
				MaskAddress(m.Net, m.Prefix);
				m.Valid = true;
			}
		}
	}
	else if (strlen(sNormalized) == MAX_ADDR_LEN - 1)
	{
		m.Legacy = true;
		strcpy_s(m.Text, sizeof(m.Text), sNormalized);
		m.Valid = true;
	}

	return m;
}

static bool MatchIP(const IP_MATCHER &m, const unsigned char *pAddr16, bool bIsV6, const char *sMask)
{
	if (!m.Valid)
	{
		return false;
	}
	if (m.Legacy)
	{
		return !bIsV6 && CompareIPs(m.Text, sMask);
	}
	return PrefixMatches(m.Net, pAddr16, m.Prefix);
}

///////
// Port filters.

static bool ParsePortRange(const std::string &sIn, int *piLow, int *piHigh)
{
	std::string s = Trim(sIn.c_str());
	std::string sLow = s;
	std::string sHigh = s;

	size_t iDash = s.find('-');
	if (iDash != std::string::npos)
	{
		sLow = Trim(s.substr(0, iDash).c_str());
		sHigh = Trim(s.substr(iDash + 1).c_str());
	}

	if (!IsAllDigits(sLow) || !IsAllDigits(sHigh) || sLow.length() > 5 || sHigh.length() > 5)
	{
		return false;
	}

	int iLow = atoi(sLow.c_str());
	int iHigh = atoi(sHigh.c_str());

	if (iLow > 65535 || iHigh > 65535 || iLow > iHigh)
	{
		return false;
	}

	*piLow = iLow;
	*piHigh = iHigh;
	return true;
}

bool NormalizePortFilter(const char *sIn, char *sOut, int iOutSz)
{
	int iLow = 0;
	int iHigh = 0;

	if (!ParsePortRange(sIn ? sIn : "", &iLow, &iHigh))
	{
		return false;
	}

	if (iLow == iHigh)
	{
		sprintf_s(sOut, iOutSz, "%d", iLow);
	}
	else
	{
		sprintf_s(sOut, iOutSz, "%d-%d", iLow, iHigh);
	}
	return true;
}

static PORT_MATCHER CompilePort(const char *sNormalized)
{
	PORT_MATCHER m;
	if (!ParsePortRange(sNormalized, &m.Low, &m.High))
	{
		m.Low = -1;
		m.High = -1;
	}
	return m;
}

static bool MatchPort(const PORT_MATCHER &m, int iPort)
{
	return m.Low >= 0 && iPort >= m.Low && iPort <= m.High;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Advanced rules.

typedef struct _TAG_TOKEN
{
	std::string Text;
	bool Quoted;
} TOKEN;

static bool Tokenize(const char *sText, std::vector<TOKEN> *pTokens)
{
	size_t i = 0;
	size_t iLength = strlen(sText);

	while (i < iLength)
	{
		if (isspace((unsigned char)sText[i]))
		{
			i++;
			continue;
		}

		TOKEN token;
		token.Quoted = false;

		if (sText[i] == '"')
		{
			token.Quoted = true;
			i++;
			while (i < iLength && sText[i] != '"')
			{
				token.Text += sText[i++];
			}
			if (i >= iLength)
			{
				return false; //Unterminated quote.
			}
			i++;
		}
		else
		{
			while (i < iLength && !isspace((unsigned char)sText[i]))
			{
				token.Text += sText[i++];
			}
		}

		pTokens->push_back(token);
	}

	return true;
}

static bool ParseProtocol(const std::string &sIn, int *piProto)
{
	std::string s = Lower(sIn);

	static const struct { const char *Name; int Value; } protocols[] = {
		{"icmp", 1}, {"igmp", 2}, {"tcp", 6}, {"udp", 17}, {"gre", 47}, {"esp", 50}, {"ah", 51}, {"icmpv6", 58}, {"sctp", 132}
	};

	for (int i = 0; i < (int)(sizeof(protocols) / sizeof(protocols[0])); i++)
	{
		if (s == protocols[i].Name)
		{
			*piProto = protocols[i].Value;
			return true;
		}
	}

	if (IsAllDigits(s) && s.length() <= 3 && atoi(s.c_str()) <= 255)
	{
		*piProto = atoi(s.c_str());
		return true;
	}

	return false;
}

static bool ParseFlags(const std::string &sIn, int *piMask, int *piValue)
{
	static const struct { const char *Name; int Bit; } flags[] = {
		{"fin", 0x01}, {"syn", 0x02}, {"rst", 0x04}, {"psh", 0x08}, {"ack", 0x10}, {"urg", 0x20}, {"ece", 0x40}, {"cwr", 0x80}
	};

	*piMask = 0;
	*piValue = 0;

	std::string s = Lower(sIn);
	size_t iPos = 0;

	while (iPos <= s.length())
	{
		size_t iComma = s.find(',', iPos);
		std::string sName = Trim(s.substr(iPos, iComma == std::string::npos ? std::string::npos : iComma - iPos).c_str());
		iPos = (iComma == std::string::npos) ? s.length() + 1 : iComma + 1;

		bool bClear = false;
		if (!sName.empty() && sName[0] == '!')
		{
			bClear = true;
			sName = sName.substr(1);
		}

		bool bFound = false;
		for (int i = 0; i < (int)(sizeof(flags) / sizeof(flags[0])); i++)
		{
			if (sName == flags[i].Name)
			{
				*piMask |= flags[i].Bit;
				if (bClear)
				{
					*piValue &= ~flags[i].Bit;
				}
				else
				{
					*piValue |= flags[i].Bit;
				}
				bFound = true;
				break;
			}
		}

		if (!bFound)
		{
			return false;
		}
	}

	return *piMask != 0;
}

static void SetError(char *sError, int iErrorSz, const char *sFormat, const char *sArg)
{
	if (sError && iErrorSz > 0)
	{
		sprintf_s(sError, iErrorSz, sFormat, sArg);
	}
}

static bool ParseRule(const char *sText, RULE *pRule, char *sError, int iErrorSz)
{
	pRule->Valid = false;
	pRule->Terms.clear();

	std::vector<TOKEN> tokens;
	if (!Tokenize(sText, &tokens))
	{
		SetError(sError, iErrorSz, "%s", "Unterminated quote.");
		return false;
	}

	size_t i = 0;
	while (i < tokens.size())
	{
		std::string sKeyword = Lower(tokens[i].Text);

		if (!tokens[i].Quoted && sKeyword == "and")
		{
			i++;
			continue;
		}

		if (i + 1 >= tokens.size())
		{
			SetError(sError, iErrorSz, "Missing value after '%s'.", sKeyword.c_str());
			return false;
		}

		const std::string &sValue = tokens[i + 1].Text;

		TERM term;
		memset(&term.IP, 0, sizeof(term.IP));
		term.Port.Low = term.Port.High = -1;
		term.Proto = 0;
		term.FlagMask = term.FlagValue = 0;

		char sNormalized[128];

		if (sKeyword == "src" || sKeyword == "dst" || sKeyword == "ip")
		{
			if (!NormalizeIPFilter(sValue.c_str(), sNormalized, sizeof(sNormalized)))
			{
				SetError(sError, iErrorSz, "'%s' is not a valid IP address, mask or CIDR block.", sValue.c_str());
				return false;
			}
			term.Type = (sKeyword == "src") ? TERM_SRC_IP : (sKeyword == "dst") ? TERM_DST_IP : TERM_ANY_IP;
			term.IP = CompileIP(sNormalized);
		}
		else if (sKeyword == "sport" || sKeyword == "dport" || sKeyword == "port")
		{
			if (!NormalizePortFilter(sValue.c_str(), sNormalized, sizeof(sNormalized)))
			{
				SetError(sError, iErrorSz, "'%s' is not a valid port or port range.", sValue.c_str());
				return false;
			}
			term.Type = (sKeyword == "sport") ? TERM_SRC_PORT : (sKeyword == "dport") ? TERM_DST_PORT : TERM_ANY_PORT;
			term.Port = CompilePort(sNormalized);
		}
		else if (sKeyword == "proto")
		{
			if (!ParseProtocol(sValue, &term.Proto))
			{
				SetError(sError, iErrorSz, "'%s' is not a known protocol (tcp, udp, icmp, igmp or 0-255).", sValue.c_str());
				return false;
			}
			term.Type = TERM_PROTO;
		}
		else if (sKeyword == "flags")
		{
			if (!ParseFlags(sValue, &term.FlagMask, &term.FlagValue))
			{
				SetError(sError, iErrorSz, "'%s' is not a valid flag list (fin,syn,rst,psh,ack,urg; prefix with ! for clear).", sValue.c_str());
				return false;
			}
			term.Type = TERM_FLAGS;
		}
		else if (sKeyword == "shost" || sKeyword == "dhost" || sKeyword == "host")
		{
			if (sValue.empty())
			{
				SetError(sError, iErrorSz, "Missing value after '%s'.", sKeyword.c_str());
				return false;
			}
			term.Type = (sKeyword == "shost") ? TERM_SRC_HOST : (sKeyword == "dhost") ? TERM_DST_HOST : TERM_ANY_HOST;
			term.Text = Lower(sValue);
		}
		else if (sKeyword == "contains")
		{
			if (sValue.empty())
			{
				SetError(sError, iErrorSz, "Missing value after '%s'.", sKeyword.c_str());
				return false;
			}
			term.Type = TERM_CONTAINS;
			term.Text = Lower(sValue);
		}
		else
		{
			SetError(sError, iErrorSz, "Unknown term '%s'.", sKeyword.c_str());
			return false;
		}

		pRule->Terms.push_back(term);
		i += 2;
	}

	if (pRule->Terms.empty())
	{
		SetError(sError, iErrorSz, "%s", "The rule is empty.");
		return false;
	}

	pRule->Valid = true;
	return true;
}

bool ValidateRule(const char *sIn, char *sError, int iErrorSz)
{
	RULE rule;
	return ParseRule(sIn, &rule, sError, iErrorSz);
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static bool GlobMatch(const char *sPattern, const char *sText)
{
	while (*sPattern)
	{
		if (*sPattern == '*')
		{
			while (*sPattern == '*')
			{
				sPattern++;
			}
			if (!*sPattern)
			{
				return true;
			}
			for (; *sText; sText++)
			{
				if (GlobMatch(sPattern, sText))
				{
					return true;
				}
			}
			return false;
		}

		if (!*sText || (*sPattern != '?' && *sPattern != *sText))
		{
			return false;
		}

		sPattern++;
		sText++;
	}

	return *sText == '\0';
}

//---------------------------------------------------------------------------------------------------------------------
// Forward lookups of literal host names. Guarded by gcsHostResolverCache.

typedef struct _TAG_FORWARD_ENTRY
{
	std::vector<ADDR16> Addresses;
	DWORD LastAttempt;		//GetTickCount() of the last lookup.
	bool Resolved;			//True once a lookup has succeeded (re-checked every few minutes).
	bool InFlight;
	bool EverAttempted;
} FORWARD_ENTRY;

static std::map<std::string, FORWARD_ENTRY> gForwardCache;

//Only plain names are looked up, wildcards can only be matched against the reverse DNS name.
static bool IsLiteralHostName(const std::string &sPattern)
{
	return sPattern.find_first_of("*?:") == std::string::npos && sPattern.find('.') != std::string::npos;
}

static void RegisterForwardNames(const FILTER_SET &set)
{
	for (size_t i = 0; i < set.Rules.size(); i++)
	{
		for (size_t j = 0; j < set.Rules[i].Terms.size(); j++)
		{
			const TERM &t = set.Rules[i].Terms[j];
			if ((t.Type == TERM_SRC_HOST || t.Type == TERM_DST_HOST || t.Type == TERM_ANY_HOST) && IsLiteralHostName(t.Text))
			{
				if (gForwardCache.find(t.Text) == gForwardCache.end())
				{
					FORWARD_ENTRY entry;
					entry.LastAttempt = 0;
					entry.Resolved = false;
					entry.InFlight = false;
					entry.EverAttempted = false;
					gForwardCache[t.Text] = entry;
				}
			}
		}
	}
}

bool GetNextForwardLookup(char *sName, int iNameSz)
{
	bool bFound = false;
	DWORD dwNow = GetTickCount();

	EnterCriticalSection(&gcsHostResolverCache);
	for (std::map<std::string, FORWARD_ENTRY>::iterator it = gForwardCache.begin(); it != gForwardCache.end(); ++it)
	{
		FORWARD_ENTRY &e = it->second;

		//Refresh good results every 5 minutes (addresses rotate), retry failures after 30 seconds.
		DWORD dwInterval = e.Resolved ? 300000 : 30000;

		if (!e.InFlight && (!e.EverAttempted || (DWORD)(dwNow - e.LastAttempt) > dwInterval)
			&& it->first.length() < (size_t)iNameSz)
		{
			e.InFlight = true;
			strcpy_s(sName, iNameSz, it->first.c_str());
			bFound = true;
			break;
		}
	}
	LeaveCriticalSection(&gcsHostResolverCache);

	return bFound;
}

void SetForwardAddresses(const char *sName, const std::vector<LOCAL_ADDRESS> &addresses, bool bSucceeded)
{
	EnterCriticalSection(&gcsHostResolverCache);

	std::map<std::string, FORWARD_ENTRY>::iterator it = gForwardCache.find(sName);
	if (it != gForwardCache.end())
	{
		FORWARD_ENTRY &e = it->second;

		if (bSucceeded)
		{
			e.Addresses.clear();
			for (size_t i = 0; i < addresses.size(); i++)
			{
				ADDR16 addr;
				memcpy(addr.Bytes, addresses[i].Addr, 16);
				e.Addresses.push_back(addr);
			}
			e.Resolved = true;
		}

		e.LastAttempt = GetTickCount();
		e.EverAttempted = true;
		e.InFlight = false;
	}

	LeaveCriticalSection(&gcsHostResolverCache);
}

static bool ForwardMatches(const std::string &sPattern, const unsigned char *pAddr16)
{
	if (!IsLiteralHostName(sPattern))
	{
		return false;
	}

	bool bMatch = false;

	EnterCriticalSection(&gcsHostResolverCache);

	std::map<std::string, FORWARD_ENTRY>::iterator it = gForwardCache.find(sPattern);
	if (it != gForwardCache.end())
	{
		for (size_t i = 0; i < it->second.Addresses.size() && !bMatch; i++)
		{
			bMatch = memcmp(it->second.Addresses[i].Bytes, pAddr16, 16) == 0;
		}
	}

	LeaveCriticalSection(&gcsHostResolverCache);

	return bMatch;
}

static bool HostMatches(const std::string &sPattern, const char *sHost)
{
	if (!sHost || !*sHost || strcmp(sHost, "...") == 0)
	{
		return false;
	}

	std::string sLowerHost = Lower(sHost);

	if (sPattern.find_first_of("*?") != std::string::npos)
	{
		return GlobMatch(sPattern.c_str(), sLowerHost.c_str());
	}

	return sLowerHost.find(sPattern) != std::string::npos;
}

static bool PayloadContains(const PACKET_INFO *pInfo, const std::string &sNeedle)
{
	int iNeedle = (int)sNeedle.length();

	if (iNeedle == 0 || pInfo->PayloadLength < iNeedle)
	{
		return false;
	}

	for (int iPos = 0; iPos <= pInfo->PayloadLength - iNeedle; iPos++)
	{
		int iMatch = 0;
		while (iMatch < iNeedle && tolower((unsigned char)pInfo->Payload[iPos + iMatch]) == (unsigned char)sNeedle[iMatch])
		{
			iMatch++;
		}
		if (iMatch == iNeedle)
		{
			return true;
		}
	}

	return false;
}

static bool TermMatches(const TERM &t, const PACKET_INFO *pi, const char *sSourceHost, const char *sDestHost)
{
	switch (t.Type)
	{
	case TERM_SRC_IP:	return MatchIP(t.IP, pi->SourceAddr, pi->IsIPv6, pi->SourceMask);
	case TERM_DST_IP:	return MatchIP(t.IP, pi->DestAddr, pi->IsIPv6, pi->DestMask);
	case TERM_ANY_IP:	return MatchIP(t.IP, pi->SourceAddr, pi->IsIPv6, pi->SourceMask) || MatchIP(t.IP, pi->DestAddr, pi->IsIPv6, pi->DestMask);
	case TERM_SRC_PORT:	return MatchPort(t.Port, pi->SourcePort);
	case TERM_DST_PORT:	return MatchPort(t.Port, pi->DestPort);
	case TERM_ANY_PORT:	return MatchPort(t.Port, pi->SourcePort) || MatchPort(t.Port, pi->DestPort);
	case TERM_PROTO:	return pi->Protocol == t.Proto;
	case TERM_FLAGS:	return pi->TcpFlags >= 0 && (pi->TcpFlags & t.FlagMask) == t.FlagValue;
	case TERM_SRC_HOST:	return HostMatches(t.Text, sSourceHost) || ForwardMatches(t.Text, pi->SourceAddr);
	case TERM_DST_HOST:	return HostMatches(t.Text, sDestHost) || ForwardMatches(t.Text, pi->DestAddr);
	case TERM_ANY_HOST:	return HostMatches(t.Text, sSourceHost) || HostMatches(t.Text, sDestHost)
							|| ForwardMatches(t.Text, pi->SourceAddr) || ForwardMatches(t.Text, pi->DestAddr);
	case TERM_CONTAINS:	return PayloadContains(pi, t.Text);
	}
	return false;
}

static bool RuleMatches(const RULE &r, const PACKET_INFO *pi, const char *sSourceHost, const char *sDestHost)
{
	if (!r.Valid)
	{
		return false;
	}
	for (size_t i = 0; i < r.Terms.size(); i++)
	{
		if (!TermMatches(r.Terms[i], pi, sSourceHost, sDestHost))
		{
			return false;
		}
	}
	return true;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Building the compiled sets.

static void CompileSet(FILTER_SET *pSet, StringBuilderArray *pSourceIP, StringBuilderArray *pDestIP,
	StringBuilderArray *pSourcePort, StringBuilderArray *pDestPort, StringBuilderArray *pRules)
{
	pSet->SourceIP.clear();
	pSet->DestIP.clear();
	pSet->SourcePort.clear();
	pSet->DestPort.clear();
	pSet->Rules.clear();

	for (int i = 0; i < pSourceIP->Count(); i++)
	{
		pSet->SourceIP.push_back(CompileIP(pSourceIP->at(i)->Buffer));
	}
	for (int i = 0; i < pDestIP->Count(); i++)
	{
		pSet->DestIP.push_back(CompileIP(pDestIP->at(i)->Buffer));
	}
	for (int i = 0; i < pSourcePort->Count(); i++)
	{
		pSet->SourcePort.push_back(CompilePort(pSourcePort->at(i)->Buffer));
	}
	for (int i = 0; i < pDestPort->Count(); i++)
	{
		pSet->DestPort.push_back(CompilePort(pDestPort->at(i)->Buffer));
	}
	for (int i = 0; i < pRules->Count(); i++)
	{
		RULE rule;
		ParseRule(pRules->at(i)->Buffer, &rule, NULL, 0);
		pSet->Rules.push_back(rule);
	}
}

static bool SetNeedsHosts(const FILTER_SET &set)
{
	for (size_t i = 0; i < set.Rules.size(); i++)
	{
		for (size_t j = 0; j < set.Rules[i].Terms.size(); j++)
		{
			TERM_TYPE t = set.Rules[i].Terms[j].Type;
			if (t == TERM_SRC_HOST || t == TERM_DST_HOST || t == TERM_ANY_HOST)
			{
				return true;
			}
		}
	}
	return false;
}

void RebuildFilters(void)
{
	CompileSet(&gIncludeSet, &gIncludeSourceIPFilter, &gIncludeTargetIPFilter,
		&gIncludeSourcePortFilter, &gIncludeTargetPortFilter, &gIncludeRules);
	CompileSet(&gExcludeSet, &gExcludeSourceIPFilter, &gExcludeTargetIPFilter,
		&gExcludeSourcePortFilter, &gExcludeTargetPortFilter, &gExcludeRules);

	gbNeedHostNames = SetNeedsHosts(gIncludeSet) || SetNeedsHosts(gExcludeSet);

	EnterCriticalSection(&gcsHostResolverCache);
	RegisterForwardNames(gIncludeSet);
	RegisterForwardNames(gExcludeSet);
	LeaveCriticalSection(&gcsHostResolverCache);
}

bool FiltersNeedHostNames(void)
{
	return gbNeedHostNames;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Evaluation.

bool ParsePacket(const char *sPacket, int iSize, PACKET_INFO *pInfo)
{
	int iProtocol = 0;
	int iTransportOffset = 0;
	bool bHasTransport = false;
	bool bIsV6 = false;
	bool bIsFragment = false;

	if (!WalkIPHeaders(sPacket, iSize, &iProtocol, &iTransportOffset, &bHasTransport, &bIsV6, &bIsFragment))
	{
		return false;
	}

	memset(pInfo, 0, sizeof(PACKET_INFO));

	pInfo->Protocol = iProtocol;
	pInfo->IsIPv6 = bIsV6;
	pInfo->IsFragment = bIsFragment;
	pInfo->SourcePort = -1;
	pInfo->DestPort = -1;
	pInfo->TcpFlags = -1;

	if (bIsV6)
	{
		const IP6_HDR *pIP = (const IP6_HDR *)sPacket;
		pInfo->Ttl = pIP->hop_limit;
		memcpy(pInfo->SourceAddr, pIP->sourceIP, 16);
		memcpy(pInfo->DestAddr, pIP->destIP, 16);
	}
	else
	{
		const IP_HDR *pIP = (const IP_HDR *)sPacket;
		pInfo->Ttl = pIP->ttl;

		memset(pInfo->SourceAddr, 0, 10);
		pInfo->SourceAddr[10] = pInfo->SourceAddr[11] = 0xFF;
		memcpy(pInfo->SourceAddr + 12, &pIP->sourceIP, 4);

		memset(pInfo->DestAddr, 0, 10);
		pInfo->DestAddr[10] = pInfo->DestAddr[11] = 0xFF;
		memcpy(pInfo->DestAddr + 12, &pIP->destIP, 4);
	}

	if (!FormatIPAddress(pInfo->SourceAddr, bIsV6, pInfo->SourceIPText, sizeof(pInfo->SourceIPText)))
	{
		strcpy_s(pInfo->SourceIPText, sizeof(pInfo->SourceIPText), bIsV6 ? "::" : "0.0.0.0");
	}
	if (!FormatIPAddress(pInfo->DestAddr, bIsV6, pInfo->DestIPText, sizeof(pInfo->DestIPText)))
	{
		strcpy_s(pInfo->DestIPText, sizeof(pInfo->DestIPText), bIsV6 ? "::" : "0.0.0.0");
	}

	if (!bIsV6)
	{
		MakeIPMask(pInfo->SourceIPText, pInfo->SourceMask, sizeof(pInfo->SourceMask));
		MakeIPMask(pInfo->DestIPText, pInfo->DestMask, sizeof(pInfo->DestMask));
	}

	//Ports/flags are only available when the packet carries a complete transport header.
	if (bHasTransport)
	{
		if (iProtocol == IPPROTO_TCP && iSize - iTransportOffset >= (int)sizeof(TCP_HDR))
		{
			const TCP_HDR *pTCP = (const TCP_HDR *)(sPacket + iTransportOffset);
			pInfo->SourcePort = ntohs(pTCP->sport);
			pInfo->DestPort = ntohs(pTCP->dport);
			pInfo->TcpFlags = pTCP->Flags;
		}
		else if (iProtocol == IPPROTO_UDP && iSize - iTransportOffset >= (int)sizeof(UDP_HDR))
		{
			const UDP_HDR *pUDP = (const UDP_HDR *)(sPacket + iTransportOffset);
			pInfo->SourcePort = ntohs(pUDP->sport);
			pInfo->DestPort = ntohs(pUDP->dport);
		}
	}

	int iPayloadOffset = GetPayloadOffset(sPacket, iSize, iProtocol);
	pInfo->Payload = sPacket + iPayloadOffset;
	pInfo->PayloadLength = iSize - iPayloadOffset;

	return true;
}

void SetLocalAddresses(const std::vector<LOCAL_ADDRESS> &addresses)
{
	gLocalAddresses.clear();
	for (size_t i = 0; i < addresses.size(); i++)
	{
		ADDR16 addr;
		memcpy(addr.Bytes, addresses[i].Addr, 16);
		gLocalAddresses.push_back(addr);
	}
}

bool IsLocalAddress(const unsigned char *pAddr16)
{
	for (size_t i = 0; i < gLocalAddresses.size(); i++)
	{
		if (memcmp(gLocalAddresses[i].Bytes, pAddr16, 16) == 0)
		{
			return true;
		}
	}
	return false;
}

template <typename T, typename F>
static bool AnyMatch(const std::vector<T> &items, F matcher)
{
	for (size_t i = 0; i < items.size(); i++)
	{
		if (matcher(items[i]))
		{
			return true;
		}
	}
	return false;
}

//Evaluates the five groups of a set. Calls back with the group result so include and exclude can combine them differently.
static void EvaluateGroups(const FILTER_SET &set, const PACKET_INFO *pi, const char *sSourceHost, const char *sDestHost,
	bool *pbAnyGroup, bool *pbAnyMatch, bool *pbAllMatch)
{
	*pbAnyGroup = false;
	*pbAnyMatch = false;
	*pbAllMatch = true;

	bool bGroupMatch = false;

	#define TALLY_GROUP(vec, expr) \
		if (!(vec).empty()) \
		{ \
			*pbAnyGroup = true; \
			bGroupMatch = AnyMatch(vec, expr); \
			if (bGroupMatch) { *pbAnyMatch = true; } else { *pbAllMatch = false; } \
		}

	TALLY_GROUP(set.SourceIP, [&](const IP_MATCHER &m) { return MatchIP(m, pi->SourceAddr, pi->IsIPv6, pi->SourceMask); });
	TALLY_GROUP(set.DestIP, [&](const IP_MATCHER &m) { return MatchIP(m, pi->DestAddr, pi->IsIPv6, pi->DestMask); });
	TALLY_GROUP(set.SourcePort, [&](const PORT_MATCHER &m) { return MatchPort(m, pi->SourcePort); });
	TALLY_GROUP(set.DestPort, [&](const PORT_MATCHER &m) { return MatchPort(m, pi->DestPort); });
	TALLY_GROUP(set.Rules, [&](const RULE &r) { return RuleMatches(r, pi, sSourceHost, sDestHost); });

	#undef TALLY_GROUP
}

FILTER_RESULT EvaluatePacket(const PACKET_INFO *pInfo, const char *sSourceHost, const char *sDestHost, int *piImage)
{
	bool bShow = true;
	int iImage = 0;

	if (IsLocalAddress(pInfo->SourceAddr))
	{
		iImage = 1; //Outbound
		bShow = bFilterIncludeOutboundPackets;
	}
	else if (IsLocalAddress(pInfo->DestAddr))
	{
		iImage = 2; //Inbound
		bShow = bFilterIncludeInbpoundPackets;
	}
	else
	{
		iImage = 0; //Broadcast.
		bShow = bFilterIncludeBroadcastPackets;
	}

	if (piImage)
	{
		*piImage = iImage;
	}

	if (!bShow)
	{
		return FILTER_HIDDEN_BY_TOGGLE;
	}

	bool bAnyGroup, bAnyMatch, bAllMatch;

	EvaluateGroups(gIncludeSet, pInfo, sSourceHost, sDestHost, &bAnyGroup, &bAnyMatch, &bAllMatch);
	if (bAnyGroup && !(gbIncludeMatchAll ? bAllMatch : bAnyMatch))
	{
		return FILTER_HIDDEN_BY_RULES;
	}

	EvaluateGroups(gExcludeSet, pInfo, sSourceHost, sDestHost, &bAnyGroup, &bAnyMatch, &bAllMatch);
	if (bAnyGroup && bAnyMatch)
	{
		return FILTER_HIDDEN_BY_RULES;
	}

	if (pInfo->Protocol == IPPROTO_TCP)
	{
		return bFilterIncludeTPC ? FILTER_SHOW : FILTER_HIDDEN_BY_TOGGLE;
	}
	else if (pInfo->Protocol == IPPROTO_UDP)
	{
		return bFilterIncludeUDP ? FILTER_SHOW : FILTER_HIDDEN_BY_TOGGLE;
	}

	return bFilterIncludeOtherProtocols ? FILTER_SHOW : FILTER_HIDDEN_BY_TOGGLE;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Which include entries matched.

void DescribeIncludeMatches(const PACKET_INFO *pi, const char *sSourceHost, const char *sDestHost, char *sOut, int iOutSz)
{
	std::string s;
	sOut[0] = '\0';

	#define APPEND_MATCH(label, text) \
		{ if (!s.empty()) { s += "; "; } s += label; s += text; }

	for (size_t i = 0; i < gIncludeSet.SourceIP.size(); i++)
	{
		if (MatchIP(gIncludeSet.SourceIP[i], pi->SourceAddr, pi->IsIPv6, pi->SourceMask))
		{
			APPEND_MATCH("S-IP ", gIncludeSourceIPFilter.at((int)i)->Buffer);
			break;
		}
	}
	for (size_t i = 0; i < gIncludeSet.DestIP.size(); i++)
	{
		if (MatchIP(gIncludeSet.DestIP[i], pi->DestAddr, pi->IsIPv6, pi->DestMask))
		{
			APPEND_MATCH("D-IP ", gIncludeTargetIPFilter.at((int)i)->Buffer);
			break;
		}
	}
	for (size_t i = 0; i < gIncludeSet.SourcePort.size(); i++)
	{
		if (MatchPort(gIncludeSet.SourcePort[i], pi->SourcePort))
		{
			APPEND_MATCH("S-Port ", gIncludeSourcePortFilter.at((int)i)->Buffer);
			break;
		}
	}
	for (size_t i = 0; i < gIncludeSet.DestPort.size(); i++)
	{
		if (MatchPort(gIncludeSet.DestPort[i], pi->DestPort))
		{
			APPEND_MATCH("D-Port ", gIncludeTargetPortFilter.at((int)i)->Buffer);
			break;
		}
	}
	for (size_t i = 0; i < gIncludeSet.Rules.size(); i++)
	{
		if (RuleMatches(gIncludeSet.Rules[i], pi, sSourceHost, sDestHost))
		{
			APPEND_MATCH("Rule: ", gIncludeRules.at((int)i)->Buffer);
			break;
		}
	}

	#undef APPEND_MATCH

	strncpy_s(sOut, iOutSz, s.c_str(), _TRUNCATE);
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Readable descriptions of well-known payloads.

static void CopyDescription(const std::string &s, char *sOut, int iOutSz)
{
	std::string clean(s);
	for (size_t i = 0; i < clean.length(); i++)
	{
		unsigned char c = (unsigned char)clean[i];
		if (c < 32 || c > 126)
		{
			clean[i] = '?';
		}
	}
	strncpy_s(sOut, iOutSz, clean.c_str(), _TRUNCATE);
}

//Reads a (possibly compressed) DNS name.
static bool DnsReadName(const unsigned char *d, int n, int off, std::string *pName)
{
	pName->clear();

	for (int hops = 0; off < n && hops < 32; hops++)
	{
		int len = d[off];

		if (len == 0)
		{
			if (pName->empty())
			{
				*pName = ".";
			}
			return true;
		}
		if ((len & 0xC0) == 0xC0)
		{
			if (off + 1 >= n)
			{
				return false;
			}
			off = ((len & 0x3F) << 8) | d[off + 1];
			continue;
		}
		if ((len & 0xC0) != 0 || off + 1 + len > n)
		{
			return false;
		}
		if (!pName->empty())
		{
			*pName += '.';
		}
		pName->append((const char *)d + off + 1, len);
		off += 1 + len;
	}

	return false;
}

//Returns the offset following a name (a compression pointer ends it), or -1.
static int DnsSkipName(const unsigned char *d, int n, int off)
{
	while (off < n)
	{
		int len = d[off];
		if (len == 0)
		{
			return off + 1;
		}
		if ((len & 0xC0) == 0xC0)
		{
			return (off + 2 <= n) ? off + 2 : -1;
		}
		if ((len & 0xC0) != 0)
		{
			return -1;
		}
		off += 1 + len;
	}
	return -1;
}

static std::string DnsTypeName(int iType)
{
	switch (iType)
	{
	case 1: return "A";
	case 2: return "NS";
	case 5: return "CNAME";
	case 6: return "SOA";
	case 12: return "PTR";
	case 15: return "MX";
	case 16: return "TXT";
	case 28: return "AAAA";
	case 33: return "SRV";
	case 64: return "SVCB";
	case 65: return "HTTPS";
	case 255: return "ANY";
	}
	char sBuf[32];
	sprintf_s(sBuf, sizeof(sBuf), "TYPE%d", iType);
	return sBuf;
}

static bool DescribeDns(const unsigned char *d, int n, char *sOut, int iOutSz)
{
	if (n < 12)
	{
		return false;
	}

	int iFlags = (d[2] << 8) | d[3];
	int iQuestions = (d[4] << 8) | d[5];
	int iAnswers = (d[6] << 8) | d[7];

	//Sanity checks so ordinary payloads which happen to use port 53/5353 are not misdescribed.
	if (iQuestions < 1 || iQuestions > 8 || ((iFlags >> 11) & 0xF) > 5)
	{
		return false;
	}

	std::string sName;
	int iAfterName = DnsSkipName(d, n, 12);
	if (!DnsReadName(d, n, 12, &sName) || iAfterName < 0 || iAfterName + 4 > n)
	{
		return false;
	}

	int iType = (d[iAfterName] << 8) | d[iAfterName + 1];
	bool bResponse = (iFlags & 0x8000) != 0;
	int iRcode = iFlags & 0xF;

	std::string s = bResponse ? "DNS response " : "DNS query ";
	s += DnsTypeName(iType) + " " + sName;

	if (bResponse)
	{
		if (iRcode != 0)
		{
			static const char *rcodes[] = { "", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED" };
			char sBuf[32];
			if (iRcode < 6) { sprintf_s(sBuf, sizeof(sBuf), " - %s", rcodes[iRcode]); }
			else { sprintf_s(sBuf, sizeof(sBuf), " - rcode %d", iRcode); }
			s += sBuf;
		}
		else
		{
			//Skip the questions then collect a few answers.
			int iOff = 12;
			bool bOk = true;
			for (int q = 0; q < iQuestions && bOk; q++)
			{
				iOff = DnsSkipName(d, n, iOff);
				if (iOff < 0 || iOff + 4 > n) { bOk = false; }
				else { iOff += 4; }
			}

			std::string sAnswers;
			int iShown = 0;
			for (int a = 0; a < iAnswers && bOk && iShown < 4; a++)
			{
				iOff = DnsSkipName(d, n, iOff);
				if (iOff < 0 || iOff + 10 > n) { break; }

				int iRType = (d[iOff] << 8) | d[iOff + 1];
				int iRdLen = (d[iOff + 8] << 8) | d[iOff + 9];
				const unsigned char *pData = d + iOff + 10;

				if (iOff + 10 + iRdLen > n) { break; }

				char sText[96] = "";
				if (iRType == 1 && iRdLen == 4)
				{
					unsigned char addr[16];
					memset(addr, 0, 10); addr[10] = addr[11] = 0xFF; memcpy(addr + 12, pData, 4);
					FormatIPAddress(addr, false, sText, sizeof(sText));
				}
				else if (iRType == 28 && iRdLen == 16)
				{
					FormatIPAddress(pData, true, sText, sizeof(sText));
				}
				else if (iRType == 5 || iRType == 12)
				{
					std::string sTarget;
					if (DnsReadName(d, n, iOff + 10, &sTarget))
					{
						strncpy_s(sText, sizeof(sText), sTarget.c_str(), _TRUNCATE);
					}
				}

				if (sText[0])
				{
					sAnswers += (iShown ? ", " : "") + std::string(sText);
					iShown++;
				}

				iOff += 10 + iRdLen;
			}

			if (!sAnswers.empty())
			{
				s += " -> " + sAnswers + (iAnswers > iShown ? ", ..." : "");
			}
			else
			{
				char sBuf[48];
				sprintf_s(sBuf, sizeof(sBuf), " (%d answer%s)", iAnswers, iAnswers == 1 ? "" : "s");
				s += sBuf;
			}
		}
	}

	CopyDescription(s, sOut, iOutSz);
	return true;
}

static bool DescribeHttp(const unsigned char *p, int n, char *sOut, int iOutSz)
{
	static const char *starts[] = { "GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT ", "HTTP/1.", "HTTP/2" };

	bool bMatch = false;
	for (int i = 0; i < (int)(sizeof(starts) / sizeof(starts[0])) && !bMatch; i++)
	{
		int iLen = (int)strlen(starts[i]);
		bMatch = n >= iLen && memcmp(p, starts[i], iLen) == 0;
	}
	if (!bMatch)
	{
		return false;
	}

	int iEnd = 0;
	while (iEnd < n && iEnd < 200 && p[iEnd] != '\r' && p[iEnd] != '\n')
	{
		iEnd++;
	}

	std::string s = "HTTP " + std::string((const char *)p, iEnd);

	//The Host header of a request.
	int iLimit = n < 2048 ? n : 2048;
	for (int i = 0; i + 6 < iLimit; i++)
	{
		if (p[i] == '\n' && _strnicmp((const char *)p + i + 1, "host:", 5) == 0)
		{
			int iStart = i + 6;
			while (iStart < iLimit && (p[iStart] == ' ' || p[iStart] == '\t')) { iStart++; }
			int iHostEnd = iStart;
			while (iHostEnd < iLimit && p[iHostEnd] != '\r' && p[iHostEnd] != '\n') { iHostEnd++; }
			s += " | Host: " + std::string((const char *)p + iStart, iHostEnd - iStart);
			break;
		}
	}

	CopyDescription(s, sOut, iOutSz);
	return true;
}

//Finds the server name in a TLS ClientHello.
static bool DescribeTls(const unsigned char *p, int n, char *sOut, int iOutSz)
{
	if (n < 48 || p[0] != 0x16 || p[1] != 0x03 || p[5] != 0x01)
	{
		return false;
	}

	int iOff = 5 + 4 + 2 + 32; //Record header, handshake header, version, random.

	#define NEED(bytes) if (iOff + (bytes) > n) { return false; }

	NEED(1); iOff += 1 + p[iOff];				//Session id.
	NEED(2); iOff += 2 + ((p[iOff] << 8) | p[iOff + 1]);	//Cipher suites.
	NEED(1); iOff += 1 + p[iOff];				//Compression methods.
	NEED(2); int iExtensionsEnd = iOff + 2 + ((p[iOff] << 8) | p[iOff + 1]); iOff += 2;

	if (iExtensionsEnd > n)
	{
		iExtensionsEnd = n;
	}

	while (iOff + 4 <= iExtensionsEnd)
	{
		int iType = (p[iOff] << 8) | p[iOff + 1];
		int iLen = (p[iOff + 2] << 8) | p[iOff + 3];
		iOff += 4;

		if (iType == 0 && iOff + 5 <= iExtensionsEnd) //server_name
		{
			int iNameLen = (p[iOff + 3] << 8) | p[iOff + 4];
			if (p[iOff + 2] == 0 && iNameLen > 0 && iOff + 5 + iNameLen <= n)
			{
				std::string s = "TLS ClientHello SNI: " + std::string((const char *)p + iOff + 5, iNameLen);
				CopyDescription(s, sOut, iOutSz);
				return true;
			}
			return false;
		}

		iOff += iLen;
	}

	#undef NEED

	CopyDescription("TLS ClientHello (no SNI)", sOut, iOutSz);
	return true;
}

bool DescribePayload(const PACKET_INFO *pi, char *sOut, int iOutSz)
{
	if (pi->Payload == NULL || pi->PayloadLength <= 0)
	{
		return false;
	}

	const unsigned char *p = (const unsigned char *)pi->Payload;
	int n = pi->PayloadLength;

	bool bDnsPort = pi->SourcePort == 53 || pi->DestPort == 53 || pi->SourcePort == 5353 || pi->DestPort == 5353
		|| pi->SourcePort == 5355 || pi->DestPort == 5355;

	if (pi->Protocol == IPPROTO_UDP && bDnsPort)
	{
		return DescribeDns(p, n, sOut, iOutSz);
	}

	if (pi->Protocol == IPPROTO_TCP)
	{
		if ((pi->SourcePort == 53 || pi->DestPort == 53) && n > 2 && DescribeDns(p + 2, n - 2, sOut, iOutSz))
		{
			return true;
		}
		if (DescribeTls(p, n, sOut, iOutSz))
		{
			return true;
		}
		return DescribeHttp(p, n, sOut, iOutSz);
	}

	return false;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// This program's own DNS lookups.

static std::map<std::string, DWORD> gOwnLookups; //Lower case name -> when it was last noted. Guarded by gcsHostResolverCache.

void NoteOwnLookup(const char *sName)
{
	if (sName == NULL || *sName == '\0')
	{
		return;
	}

	std::string sLower = Lower(sName);
	while (!sLower.empty() && sLower[sLower.length() - 1] == '.')
	{
		sLower.erase(sLower.length() - 1);
	}

	DWORD dwNow = GetTickCount();

	EnterCriticalSection(&gcsHostResolverCache);

	//Forget old entries so this cannot grow without bound.
	if (gOwnLookups.size() > 2000)
	{
		for (std::map<std::string, DWORD>::iterator it = gOwnLookups.begin(); it != gOwnLookups.end();)
		{
			if ((DWORD)(dwNow - it->second) > 60000) { gOwnLookups.erase(it++); }
			else { ++it; }
		}
	}

	gOwnLookups[sLower] = dwNow;

	LeaveCriticalSection(&gcsHostResolverCache);
}

bool IsOwnLookup(const PACKET_INFO *pi)
{
	if (!bFilterHideOwnDns || pi->Payload == NULL || pi->PayloadLength < 12)
	{
		return false;
	}

	bool bUdp = pi->Protocol == IPPROTO_UDP;
	bool bTcp = pi->Protocol == IPPROTO_TCP;

	bool bDnsPort = pi->SourcePort == 53 || pi->DestPort == 53
		|| (bUdp && (pi->SourcePort == 5353 || pi->DestPort == 5353 || pi->SourcePort == 5355 || pi->DestPort == 5355));

	if (!bDnsPort || !(bUdp || bTcp))
	{
		return false;
	}

	const unsigned char *d = (const unsigned char *)pi->Payload;
	int n = pi->PayloadLength;

	if (bTcp)
	{
		d += 2; //Two byte length prefix.
		n -= 2;
		if (n < 12) { return false; }
	}

	int iQuestions = (d[4] << 8) | d[5];
	if (iQuestions < 1 || iQuestions > 8)
	{
		return false;
	}

	std::string sName;
	if (!DnsReadName(d, n, 12, &sName))
	{
		return false;
	}

	sName = Lower(sName);
	while (!sName.empty() && sName[sName.length() - 1] == '.')
	{
		sName.erase(sName.length() - 1);
	}

	bool bOwn = false;
	DWORD dwNow = GetTickCount();

	EnterCriticalSection(&gcsHostResolverCache);
	std::map<std::string, DWORD>::iterator it = gOwnLookups.find(sName);
	if (it != gOwnLookups.end())
	{
		//The lookup may be slow and retried, so allow plenty of time for its packets.
		bOwn = (DWORD)(dwNow - it->second) < 60000;
	}
	LeaveCriticalSection(&gcsHostResolverCache);

	return bOwn;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Maintenance.

//StringBuilderArray::DeleteAt always returns false, so detect the removal by the count.
static bool RemoveAt(StringBuilderArray *pList, int iIndex)
{
	int iBefore = pList->Count();
	pList->DeleteAt(iIndex);
	return pList->Count() < iBefore;
}

static int RemoveMatching(StringBuilderArray *pSourceIP, StringBuilderArray *pDestIP, StringBuilderArray *pSourcePort,
	StringBuilderArray *pDestPort, StringBuilderArray *pRules, const FILTER_SET &set,
	const PACKET_INFO *pi, const char *sSourceHost, const char *sDestHost)
{
	int iRemoved = 0;

	for (int i = (int)set.SourceIP.size() - 1; i >= 0; i--)
	{
		if (MatchIP(set.SourceIP[i], pi->SourceAddr, pi->IsIPv6, pi->SourceMask) && RemoveAt(pSourceIP, i)) { iRemoved++; }
	}
	for (int i = (int)set.DestIP.size() - 1; i >= 0; i--)
	{
		if (MatchIP(set.DestIP[i], pi->DestAddr, pi->IsIPv6, pi->DestMask) && RemoveAt(pDestIP, i)) { iRemoved++; }
	}
	for (int i = (int)set.SourcePort.size() - 1; i >= 0; i--)
	{
		if (MatchPort(set.SourcePort[i], pi->SourcePort) && RemoveAt(pSourcePort, i)) { iRemoved++; }
	}
	for (int i = (int)set.DestPort.size() - 1; i >= 0; i--)
	{
		if (MatchPort(set.DestPort[i], pi->DestPort) && RemoveAt(pDestPort, i)) { iRemoved++; }
	}
	for (int i = (int)set.Rules.size() - 1; i >= 0; i--)
	{
		if (RuleMatches(set.Rules[i], pi, sSourceHost, sDestHost) && RemoveAt(pRules, i)) { iRemoved++; }
	}

	return iRemoved;
}

int RemoveFiltersMatching(const PACKET_INFO *pInfo, const char *sSourceHost, const char *sDestHost)
{
	int iRemoved = 0;

	iRemoved += RemoveMatching(&gIncludeSourceIPFilter, &gIncludeTargetIPFilter, &gIncludeSourcePortFilter,
		&gIncludeTargetPortFilter, &gIncludeRules, gIncludeSet, pInfo, sSourceHost, sDestHost);
	iRemoved += RemoveMatching(&gExcludeSourceIPFilter, &gExcludeTargetIPFilter, &gExcludeSourcePortFilter,
		&gExcludeTargetPortFilter, &gExcludeRules, gExcludeSet, pInfo, sSourceHost, sDestHost);

	RebuildFilters();
	return iRemoved;
}

static StringBuilderArray *AllLists[] = {
	&gIncludeSourceIPFilter, &gIncludeTargetIPFilter, &gIncludeSourcePortFilter, &gIncludeTargetPortFilter, &gIncludeRules,
	&gExcludeSourceIPFilter, &gExcludeTargetIPFilter, &gExcludeSourcePortFilter, &gExcludeTargetPortFilter, &gExcludeRules
};

static const char *AllListKeys[] = {
	"include.sip", "include.dip", "include.sport", "include.dport", "include.rule",
	"exclude.sip", "exclude.dip", "exclude.sport", "exclude.dport", "exclude.rule"
};

#define LIST_COUNT 10

int CountFilters(void)
{
	int iCount = 0;
	for (int i = 0; i < LIST_COUNT; i++)
	{
		iCount += AllLists[i]->Count();
	}
	return iCount;
}

static char gsFilterMessage[128];
static DWORD gdwFilterMessageUntil = 0;

void SetFilterMessage(const char *sMessage)
{
	strcpy_s(gsFilterMessage, sizeof(gsFilterMessage), sMessage);
	gdwFilterMessageUntil = GetTickCount() + 4000;
}

void GetFilterSummary(char *sOut, int iOutSz)
{
	if (gsFilterMessage[0] && (int)(gdwFilterMessageUntil - GetTickCount()) > 0)
	{
		strcpy_s(sOut, iOutSz, gsFilterMessage);
		return;
	}

	int iInclude = gIncludeSourceIPFilter.Count() + gIncludeTargetIPFilter.Count() + gIncludeSourcePortFilter.Count()
		+ gIncludeTargetPortFilter.Count() + gIncludeRules.Count();
	int iExclude = CountFilters() - iInclude;

	if (iInclude + iExclude == 0)
	{
		sprintf_s(sOut, iOutSz, "Filters: none");
	}
	else
	{
		sprintf_s(sOut, iOutSz, "Filters: %d include%s, %d exclude | Hidden: %lld",
			iInclude, (iInclude > 1 && gbIncludeMatchAll) ? " (match all)" : "", iExclude, gi64FilteredOut);
	}
}

void ClearAllFilters(void)
{
	for (int i = 0; i < LIST_COUNT; i++)
	{
		AllLists[i]->Clear();
	}
	gbIncludeMatchAll = false;
	RebuildFilters();
}

bool AddFilterEntry(StringBuilderArray *pList, const char *sEntry)
{
	if (pList->Contiains((char *)sEntry))
	{
		return false;
	}
	pList->Add((char *)sEntry);
	return true;
}

void AddNoiseExclusions(void)
{
	static const char *rules[] = {
		"port 53", "port 123", "port 137-139", "port 1900", "port 5353", "port 5355",
		"ip 224.0.0.0/4", "ip 255.255.255.255", "proto igmp"
	};

	for (int i = 0; i < (int)(sizeof(rules) / sizeof(rules[0])); i++)
	{
		AddFilterEntry(&gExcludeRules, rules[i]);
	}
	RebuildFilters();
}

void AddWebOnlyInclusions(void)
{
	static const char *rules[] = { "port 80", "port 443", "port 8080", "port 8443" };

	for (int i = 0; i < (int)(sizeof(rules) / sizeof(rules[0])); i++)
	{
		AddFilterEntry(&gIncludeRules, rules[i]);
	}
	RebuildFilters();
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Persistence.

static std::string SerializeFilters(void)
{
	std::string s = "# IP Traffic Spy filters\r\n";

	s += gbIncludeMatchAll ? "include.matchall=1\r\n" : "include.matchall=0\r\n";

	for (int iList = 0; iList < LIST_COUNT; iList++)
	{
		for (int i = 0; i < AllLists[iList]->Count(); i++)
		{
			s += AllListKeys[iList];
			s += "=";
			s += AllLists[iList]->at(i)->Buffer;
			s += "\r\n";
		}
	}

	return s;
}

//Validates and normalizes an entry for the given list. Returns false if the entry is not valid for that list.
static bool NormalizeForList(int iList, const std::string &sValue, std::string *psNormalized)
{
	char sBuf[256];

	switch (iList % 5)
	{
	case 0:
	case 1:
		if (!NormalizeIPFilter(sValue.c_str(), sBuf, sizeof(sBuf))) { return false; }
		break;
	case 2:
	case 3:
		if (!NormalizePortFilter(sValue.c_str(), sBuf, sizeof(sBuf))) { return false; }
		break;
	default:
		if (!ValidateRule(sValue.c_str(), NULL, 0)) { return false; }
		*psNormalized = Trim(sValue.c_str());
		return true;
	}

	*psNormalized = sBuf;
	return true;
}

static bool LoadFiltersFromText(const char *sText)
{
	std::vector< std::pair<int, std::string> > entries;
	bool bRecognized = false;
	bool bMatchAll = false;

	std::string sContent(sText);
	size_t iPos = 0;

	while (iPos < sContent.length())
	{
		size_t iEnd = sContent.find('\n', iPos);
		std::string sLine = Trim(sContent.substr(iPos, iEnd == std::string::npos ? std::string::npos : iEnd - iPos).c_str());
		iPos = (iEnd == std::string::npos) ? sContent.length() : iEnd + 1;

		size_t iEquals = sLine.find('=');
		if (sLine.empty() || sLine[0] == '#' || iEquals == std::string::npos)
		{
			continue;
		}

		std::string sKey = Lower(Trim(sLine.substr(0, iEquals).c_str()));
		std::string sValue = Trim(sLine.substr(iEquals + 1).c_str());

		if (sKey == "include.matchall")
		{
			bMatchAll = (sValue == "1");
			bRecognized = true;
			continue;
		}

		for (int iList = 0; iList < LIST_COUNT; iList++)
		{
			if (sKey == AllListKeys[iList])
			{
				std::string sNormalized;
				if (NormalizeForList(iList, sValue, &sNormalized))
				{
					entries.push_back(std::make_pair(iList, sNormalized));
				}
				bRecognized = true;
				break;
			}
		}
	}

	if (!bRecognized)
	{
		return false;
	}

	for (int i = 0; i < LIST_COUNT; i++)
	{
		AllLists[i]->Clear();
	}

	for (size_t i = 0; i < entries.size(); i++)
	{
		AddFilterEntry(AllLists[entries[i].first], entries[i].second.c_str());
	}

	gbIncludeMatchAll = bMatchAll;
	RebuildFilters();
	return true;
}

bool SaveFiltersToFile(const char *sFileName)
{
	FILE *fTarget = NULL;
	if (fopen_s(&fTarget, sFileName, "wb") != 0 || fTarget == NULL)
	{
		return false;
	}

	std::string s = SerializeFilters();
	bool bResult = fwrite(s.c_str(), 1, s.length(), fTarget) == s.length();

	fclose(fTarget);
	return bResult;
}

bool LoadFiltersFromFile(const char *sFileName)
{
	FILE *fSource = NULL;
	if (fopen_s(&fSource, sFileName, "rb") != 0 || fSource == NULL)
	{
		return false;
	}

	std::string s;
	char sBuf[4096];
	size_t iRead = 0;

	while ((iRead = fread(sBuf, 1, sizeof(sBuf), fSource)) > 0)
	{
		s.append(sBuf, iRead);
		if (s.length() > MAX_FILTERS_FILE_SIZE)
		{
			fclose(fSource);
			return false;
		}
	}
	fclose(fSource);

	return LoadFiltersFromText(s.c_str());
}

void SaveFiltersToRegistry(void)
{
	HKEY hKey = NULL;

	if (RegCreateKeyExA(HKEY_CURRENT_USER, FILTERS_REGISTRY_KEY, 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS)
	{
		std::string s = SerializeFilters();
		RegSetValueExA(hKey, FILTERS_REGISTRY_VALUE, 0, REG_SZ, (const BYTE *)s.c_str(), (DWORD)s.length() + 1);
		RegCloseKey(hKey);
	}
}

void LoadFiltersFromRegistry(void)
{
	HKEY hKey = NULL;

	if (RegOpenKeyExA(HKEY_CURRENT_USER, FILTERS_REGISTRY_KEY, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
	{
		return;
	}

	DWORD dwType = 0;
	DWORD dwSize = 0;

	if (RegQueryValueExA(hKey, FILTERS_REGISTRY_VALUE, NULL, &dwType, NULL, &dwSize) == ERROR_SUCCESS
		&& dwType == REG_SZ && dwSize > 0 && dwSize <= MAX_FILTERS_FILE_SIZE)
	{
		char *sBuf = (char *)calloc(dwSize + 1, 1);
		if (sBuf)
		{
			if (RegQueryValueExA(hKey, FILTERS_REGISTRY_VALUE, NULL, &dwType, (LPBYTE)sBuf, &dwSize) == ERROR_SUCCESS)
			{
				LoadFiltersFromText(sBuf);
			}
			free(sBuf);
		}
	}

	RegCloseKey(hKey);
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#endif
