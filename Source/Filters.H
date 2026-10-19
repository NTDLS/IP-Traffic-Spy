#ifndef _FILTERS_H
#define _FILTERS_H
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include "Routines.H"
#include "Adapters.H"

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// Filter entry syntax (what is stored in the filter lists):
//
//	IP entries:		1.2.3.4, 10.0.?.? (per-digit IPv4 wildcards), or IPv4/IPv6 addresses and CIDR blocks such as
//					10.0.0.0/8, 2001:db8::1 or fe80::/10. Stored normalized.
//	Port entries:	80, or an inclusive range such as 1024-65535.
//	Rule entries:	One or more terms which must ALL match (optionally separated by "and"):
//						src|dst|ip <ip>			source / destination / either IP
//						sport|dport|port <port>	source / destination / either port
//						proto <tcp|udp|icmp|igmp|number>
//						flags <syn,!ack,...>	TCP flags that must be set (or clear with !)
//						shost|dhost|host <text>	resolved host name (* and ? wildcards, otherwise substring)
//						contains <text>			case-insensitive payload search (use "quotes" for spaces)
//
// Within a filter list, entries are OR'd. Include filters can optionally require every non-empty group to match.
//
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

typedef struct _TAG_PACKET_INFO
{
	unsigned char SourceAddr[16];	//IPv4 addresses are IPv4-mapped (::ffff:a.b.c.d).
	unsigned char DestAddr[16];
	bool IsIPv6;
	char SourceMask[MAX_ADDR_LEN];	//IPv4 only: zero-padded "000.000.000.000" form (used by the "10.0.?.?" wildcards).
	char DestMask[MAX_ADDR_LEN];
	char SourceIPText[MAX_IP_TEXT];
	char DestIPText[MAX_IP_TEXT];
	int Protocol;				//Upper layer protocol (for IPv6, after any extension headers).
	int SourcePort;				//-1 if the packet has no (complete) transport header.
	int DestPort;
	int TcpFlags;				//-1 if not a TCP packet with a complete header.
	int Ttl;					//IPv4 TTL / IPv6 hop limit (0 when unknown).
	bool IsFragment;			//Part of a fragmented datagram.
	const char *Payload;
	int PayloadLength;
} PACKET_INFO;

typedef enum _TAG_FILTER_RESULT
{
	FILTER_SHOW = 0,
	FILTER_HIDDEN_BY_TOGGLE,	//Protocol/direction menu toggles.
	FILTER_HIDDEN_BY_RULES		//Include/exclude filters.
} FILTER_RESULT;

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

extern StringBuilderArray gIncludeRules;
extern StringBuilderArray gExcludeRules;
extern volatile bool gbIncludeMatchAll;
extern volatile __int64 gi64FilteredOut;

//The addresses of the interface being captured on, used to determine the direction of a packet.
void SetLocalAddresses(const std::vector<LOCAL_ADDRESS> &addresses);
bool IsLocalAddress(const unsigned char *pAddr16);

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//Validation / normalization of user input. Return false (and fill sError where applicable) when invalid.
bool NormalizeIPFilter(const char *sIn, char *sOut, int iOutSz);
bool NormalizePortFilter(const char *sIn, char *sOut, int iOutSz);
bool ValidateRule(const char *sIn, char *sError, int iErrorSz);

//Must be called (with the listener paused) any time the filter lists are modified.
void RebuildFilters(void);

bool ParsePacket(const char *sPacket, int iSize, PACKET_INFO *pInfo);
bool FiltersNeedHostNames(void);
FILTER_RESULT EvaluatePacket(const PACKET_INFO *pInfo, const char *sSourceHost, const char *sDestHost, int *piImage);

//Describes which include entries let the packet through (empty when there are no include filters).
void DescribeIncludeMatches(const PACKET_INFO *pInfo, const char *sSourceHost, const char *sDestHost, char *sOut, int iOutSz);

//Produces a readable one-line description for DNS, HTTP and TLS (SNI) payloads. Returns false for anything else.
bool DescribePayload(const PACKET_INFO *pInfo, char *sOut, int iOutSz);

//Removes the filter entries which match the packet. Returns the number of entries removed.
int RemoveFiltersMatching(const PACKET_INFO *pInfo, const char *sSourceHost, const char *sDestHost);

int CountFilters(void);
void GetFilterSummary(char *sOut, int iOutSz);
void SetFilterMessage(const char *sMessage); //Shown in place of the summary for a few seconds.
void ClearAllFilters(void);

//Adds an entry to a list if it is not already present. Returns true if it was added.
bool AddFilterEntry(StringBuilderArray *pList, const char *sEntry);

//Literal host names in rules (e.g. "host example.com") are also resolved forward so they match the site's IP addresses,
//	not just whatever reverse DNS says. The resolver threads drive this.
bool GetNextForwardLookup(char *sName, int iNameSz);
void SetForwardAddresses(const char *sName, const std::vector<LOCAL_ADDRESS> &addresses, bool bSucceeded);

//The DNS lookups made by this program itself. The resolver records the names it asks for, and IsOwnLookup() recognizes
//	the resulting packets (queries and answers, DNS / mDNS / LLMNR) so they can be left out of the grid.
void NoteOwnLookup(const char *sName);
bool IsOwnLookup(const PACKET_INFO *pInfo);

//Built-in presets.
void AddNoiseExclusions(void);
void AddWebOnlyInclusions(void);

//Persistence. Load* replaces the current filters. Call RebuildFilters() afterwards (the Load functions do it for you).
bool SaveFiltersToFile(const char *sFileName);
bool LoadFiltersFromFile(const char *sFileName);
void SaveFiltersToRegistry(void);
void LoadFiltersFromRegistry(void);

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#endif
