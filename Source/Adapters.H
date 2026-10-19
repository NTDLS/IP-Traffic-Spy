#ifndef _ADAPTERS_H
#define _ADAPTERS_H
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include <vector>

//Deliberately no socket headers here, this is included before them in places.
struct sockaddr_in;
struct sockaddr_in6;

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// All addresses are handled internally as 16 bytes. IPv4 addresses are stored IPv4-mapped (::ffff:a.b.c.d).
//
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

typedef struct _TAG_LOCAL_ADDRESS
{
	char Text[72];			//Display text, link-local IPv6 addresses carry a "%scope".
	int Family;				//AF_INET or AF_INET6
	unsigned int IfIndex;
	unsigned int ScopeId;	//IPv6 only.
	unsigned char Addr[16];
} LOCAL_ADDRESS;

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//Parses a dotted-quad IPv4 or IPv6 address (an optional "%scope" is accepted for IPv6).
bool ParseIPAddress(const char *sText, unsigned char *pAddr16, bool *pbIsV6, unsigned int *puiScopeId);

//Formats a 16 byte address as text. IPv4-mapped addresses are formatted as plain IPv4 when bIsV6 is false.
bool FormatIPAddress(const unsigned char *pAddr16, bool bIsV6, char *sOut, int iOutSz);

//Returns the unicast addresses of every adapter which is up (loopback excluded).
bool GetLocalAddresses(std::vector<LOCAL_ADDRESS> *pList);

//Works out what to capture from the address the user selected: the adapter which owns it is found and its IPv4 and
//	IPv6 addresses are chosen. All of the adapter's addresses are returned in pLocals (used to detect direction).
bool ResolveBindTargets(const char *sSelected, struct sockaddr_in *pV4, bool *pbHasV4,
	struct sockaddr_in6 *pV6, bool *pbHasV6, std::vector<LOCAL_ADDRESS> *pLocals);

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#endif
