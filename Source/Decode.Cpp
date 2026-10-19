#ifndef _DECODE_CPP
#define _DECODE_CPP
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include <WinSock2.h>
#include <Windows.H>
#include <WS2TcpIP.h>
#include <Stdio.H>
#include <Stdlib.H>
#include <Stdarg.H>
#include <string>
#include <vector>

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include "Entry.H"
#include "Decode.H"

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

typedef struct _TAG_DECODE_OUT
{
	std::string Text;

	void Line(const char *sFormat, ...)
	{
		char sBuf[2048];
		va_list args;
		va_start(args, sFormat);
		vsnprintf_s(sBuf, sizeof(sBuf), _TRUNCATE, sFormat, args);
		va_end(args);

		//Never let raw packet bytes inject control characters.
		for (char *p = sBuf; *p; p++)
		{
			if ((unsigned char)*p < 32 || (unsigned char)*p > 126)
			{
				*p = '?';
			}
		}

		Text += sBuf;
		Text += "\r\n";
	}

	void Blank()
	{
		Text += "\r\n";
	}
} DECODE_OUT;

static unsigned int Be16(const unsigned char *p) { return ((unsigned int)p[0] << 8) | p[1]; }
static unsigned int Be32(const unsigned char *p) { return ((unsigned int)p[0] << 24) | ((unsigned int)p[1] << 16) | ((unsigned int)p[2] << 8) | p[3]; }

static std::string Hex(const unsigned char *p, int n, int iMax = 32)
{
	std::string s;
	char sBuf[8];
	for (int i = 0; i < n && i < iMax; i++)
	{
		sprintf_s(sBuf, sizeof(sBuf), "%s%02X", i ? " " : "", p[i]);
		s += sBuf;
	}
	if (n > iMax)
	{
		s += " ...";
	}
	return s;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Name tables.

static const char *ProtocolName(int iProto)
{
	switch (iProto)
	{
	case 0: return "HOPOPT";
	case 1: return "ICMP";
	case 2: return "IGMP";
	case 4: return "IP-in-IP";
	case 6: return "TCP";
	case 17: return "UDP";
	case 41: return "IPv6 encapsulation";
	case 43: return "IPv6 Routing";
	case 44: return "IPv6 Fragment";
	case 47: return "GRE";
	case 50: return "ESP";
	case 51: return "AH";
	case 58: return "ICMPv6";
	case 59: return "No next header";
	case 60: return "IPv6 Destination Options";
	case 89: return "OSPF";
	case 103: return "PIM";
	case 112: return "VRRP";
	case 132: return "SCTP";
	}
	return "unknown";
}

static const char *ServiceName(int iPort)
{
	static const struct { int Port; const char *Name; } services[] = {
		{20, "ftp-data"}, {21, "ftp"}, {22, "ssh"}, {23, "telnet"}, {25, "smtp"}, {53, "dns"}, {67, "dhcp-server"}, {68, "dhcp-client"},
		{80, "http"}, {110, "pop3"}, {119, "nntp"}, {123, "ntp"}, {137, "netbios-ns"}, {138, "netbios-dgm"}, {139, "netbios-ssn"},
		{143, "imap"}, {161, "snmp"}, {162, "snmp-trap"}, {389, "ldap"}, {443, "https"}, {445, "smb"}, {465, "smtps"}, {500, "isakmp"},
		{514, "syslog"}, {587, "submission"}, {636, "ldaps"}, {853, "dns-over-tls"}, {993, "imaps"}, {995, "pop3s"}, {1433, "mssql"},
		{1900, "ssdp"}, {3306, "mysql"}, {3389, "rdp"}, {5060, "sip"}, {5353, "mdns"}, {5355, "llmnr"}, {5432, "postgres"},
		{5900, "vnc"}, {8080, "http-alt"}, {8443, "https-alt"}
	};

	for (int i = 0; i < (int)(sizeof(services) / sizeof(services[0])); i++)
	{
		if (services[i].Port == iPort)
		{
			return services[i].Name;
		}
	}
	return NULL;
}

static std::string PortText(int iPort)
{
	char sBuf[64];
	const char *sName = ServiceName(iPort);
	if (sName)
	{
		sprintf_s(sBuf, sizeof(sBuf), "%d (%s)", iPort, sName);
	}
	else
	{
		sprintf_s(sBuf, sizeof(sBuf), "%d", iPort);
	}
	return sBuf;
}

static std::string AddressText(const unsigned char *p, bool bV6)
{
	unsigned char addr[16];
	char sBuf[MAX_IP_TEXT];

	if (bV6)
	{
		memcpy(addr, p, 16);
	}
	else
	{
		memset(addr, 0, 10);
		addr[10] = addr[11] = 0xFF;
		memcpy(addr + 12, p, 4);
	}

	if (!FormatIPAddress(addr, bV6, sBuf, sizeof(sBuf)))
	{
		return "?";
	}
	return sBuf;
}

static std::string FlagsText(int iFlags)
{
	static const struct { int Bit; const char *Name; } names[] = {
		{0x02, "SYN"}, {0x10, "ACK"}, {0x01, "FIN"}, {0x04, "RST"}, {0x08, "PSH"}, {0x20, "URG"}, {0x40, "ECE"}, {0x80, "CWR"}
	};

	std::string s;
	for (int i = 0; i < (int)(sizeof(names) / sizeof(names[0])); i++)
	{
		if (iFlags & names[i].Bit)
		{
			s += (s.empty() ? "" : " ");
			s += names[i].Name;
		}
	}
	return s.empty() ? "none" : s;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Hex dump.

void HexDumpText(const char *sData, int iSize, std::string *pOut)
{
	const unsigned char *p = (const unsigned char *)sData;
	char sLine[128];

	pOut->reserve(pOut->size() + (iSize / 16 + 1) * 80);

	for (int iOff = 0; iOff < iSize; iOff += 16)
	{
		int iLen = iSize - iOff < 16 ? iSize - iOff : 16;
		int iPos = sprintf_s(sLine, sizeof(sLine), "%08X  ", iOff);

		for (int i = 0; i < 16; i++)
		{
			if (i < iLen)
			{
				iPos += sprintf_s(sLine + iPos, sizeof(sLine) - iPos, "%02X ", p[iOff + i]);
			}
			else
			{
				iPos += sprintf_s(sLine + iPos, sizeof(sLine) - iPos, "   ");
			}
			if (i == 7)
			{
				sLine[iPos++] = ' ';
			}
		}

		sLine[iPos++] = ' ';
		sLine[iPos++] = '|';
		for (int i = 0; i < iLen; i++)
		{
			unsigned char c = p[iOff + i];
			sLine[iPos++] = (c >= 32 && c <= 126) ? (char)c : '.';
		}
		sLine[iPos++] = '|';
		sLine[iPos++] = '\r';
		sLine[iPos++] = '\n';
		sLine[iPos] = '\0';

		*pOut += sLine;
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// DNS.

static bool DnsReadName(const unsigned char *d, int n, int off, std::string *pName)
{
	pName->clear();

	for (int hops = 0; off < n && hops < 32; hops++)
	{
		int len = d[off];

		if (len == 0)
		{
			if (pName->empty()) { *pName = "."; }
			return true;
		}
		if ((len & 0xC0) == 0xC0)
		{
			if (off + 1 >= n) { return false; }
			off = ((len & 0x3F) << 8) | d[off + 1];
			continue;
		}
		if ((len & 0xC0) != 0 || off + 1 + len > n)
		{
			return false;
		}
		if (!pName->empty()) { *pName += '.'; }
		pName->append((const char *)d + off + 1, len);
		off += 1 + len;
	}

	return false;
}

static int DnsSkipName(const unsigned char *d, int n, int off)
{
	while (off < n)
	{
		int len = d[off];
		if (len == 0) { return off + 1; }
		if ((len & 0xC0) == 0xC0) { return (off + 2 <= n) ? off + 2 : -1; }
		if ((len & 0xC0) != 0) { return -1; }
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
	case 41: return "OPT";
	case 43: return "DS";
	case 46: return "RRSIG";
	case 47: return "NSEC";
	case 48: return "DNSKEY";
	case 64: return "SVCB";
	case 65: return "HTTPS";
	case 255: return "ANY";
	}
	char sBuf[32];
	sprintf_s(sBuf, sizeof(sBuf), "TYPE%d", iType);
	return sBuf;
}

static std::string DnsRData(const unsigned char *d, int n, int iOff, int iType, int iLen)
{
	const unsigned char *p = d + iOff;
	std::string sName;
	char sBuf[256];

	switch (iType)
	{
	case 1:
		if (iLen == 4) { return AddressText(p, false); }
		break;
	case 28:
		if (iLen == 16) { return AddressText(p, true); }
		break;
	case 2: case 5: case 12:
		if (DnsReadName(d, n, iOff, &sName)) { return sName; }
		break;
	case 15:
		if (iLen >= 3 && DnsReadName(d, n, iOff + 2, &sName))
		{
			sprintf_s(sBuf, sizeof(sBuf), "preference %u, %s", Be16(p), sName.c_str());
			return sBuf;
		}
		break;
	case 33:
		if (iLen >= 7 && DnsReadName(d, n, iOff + 6, &sName))
		{
			sprintf_s(sBuf, sizeof(sBuf), "priority %u, weight %u, port %u, %s", Be16(p), Be16(p + 2), Be16(p + 4), sName.c_str());
			return sBuf;
		}
		break;
	case 16:
	{
		std::string s;
		int i = 0;
		while (i < iLen)
		{
			int l = p[i];
			if (i + 1 + l > iLen) { break; }
			s += (s.empty() ? "\"" : " \"") + std::string((const char *)p + i + 1, l) + "\"";
			i += 1 + l;
		}
		return s;
	}
	case 6:
	{
		std::string sMName, sRName;
		int iNext = DnsSkipName(d, n, iOff);
		if (iNext > 0 && DnsReadName(d, n, iOff, &sMName) && DnsReadName(d, n, iNext, &sRName))
		{
			int iAfter = DnsSkipName(d, n, iNext);
			if (iAfter > 0 && iAfter + 20 <= n)
			{
				sprintf_s(sBuf, sizeof(sBuf), "%s %s serial %u refresh %u retry %u expire %u minimum %u", sMName.c_str(), sRName.c_str(),
					Be32(d + iAfter), Be32(d + iAfter + 4), Be32(d + iAfter + 8), Be32(d + iAfter + 12), Be32(d + iAfter + 16));
				return sBuf;
			}
		}
		break;
	}
	}

	sprintf_s(sBuf, sizeof(sBuf), "%d bytes: ", iLen);
	return sBuf + Hex(p, iLen, 16);
}

static bool DecodeDns(const unsigned char *d, int n, DECODE_OUT *o)
{
	if (n < 12)
	{
		return false;
	}

	int iFlags = (int)Be16(d + 2);
	int iQuestions = (int)Be16(d + 4);
	int iAnswers = (int)Be16(d + 6);
	int iAuthority = (int)Be16(d + 8);
	int iAdditional = (int)Be16(d + 10);

	int iOpcode = (iFlags >> 11) & 0xF;
	if (iQuestions < 1 || iQuestions > 16 || iOpcode > 5)
	{
		return false;
	}

	static const char *opcodes[] = { "QUERY", "IQUERY", "STATUS", "?", "NOTIFY", "UPDATE" };
	static const char *rcodes[] = { "NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED" };
	int iRcode = iFlags & 0xF;

	std::string sFlagNames;
	if (iFlags & 0x0400) { sFlagNames += " AA"; }
	if (iFlags & 0x0200) { sFlagNames += " TC"; }
	if (iFlags & 0x0100) { sFlagNames += " RD"; }
	if (iFlags & 0x0080) { sFlagNames += " RA"; }
	if (iFlags & 0x0020) { sFlagNames += " AD"; }
	if (iFlags & 0x0010) { sFlagNames += " CD"; }

	o->Blank();
	o->Line("DNS %s", (iFlags & 0x8000) ? "response" : "query");
	o->Line("  Transaction id: 0x%04X", Be16(d));
	o->Line("  Opcode: %s    Flags:%s    Response code: %s", opcodes[iOpcode], sFlagNames.empty() ? " none" : sFlagNames.c_str(),
		iRcode < 6 ? rcodes[iRcode] : "other");
	o->Line("  Questions: %d    Answers: %d    Authority: %d    Additional: %d", iQuestions, iAnswers, iAuthority, iAdditional);

	int iOff = 12;

	for (int q = 0; q < iQuestions; q++)
	{
		std::string sName;
		int iNext = DnsSkipName(d, n, iOff);
		if (iNext < 0 || iNext + 4 > n || !DnsReadName(d, n, iOff, &sName))
		{
			o->Line("  (question %d is truncated)", q + 1);
			return true;
		}
		o->Line("  Question: %s  %s  class %u", sName.c_str(), DnsTypeName((int)Be16(d + iNext)).c_str(), Be16(d + iNext + 2) & 0x7FFF);
		iOff = iNext + 4;
	}

	struct { const char *Title; int Count; } sections[] = { {"Answer", iAnswers}, {"Authority", iAuthority}, {"Additional", iAdditional} };

	for (int s = 0; s < 3; s++)
	{
		for (int r = 0; r < sections[s].Count && r < 64; r++)
		{
			std::string sName;
			int iNext = DnsSkipName(d, n, iOff);
			if (iNext < 0 || iNext + 10 > n || !DnsReadName(d, n, iOff, &sName))
			{
				o->Line("  (%s records are truncated)", sections[s].Title);
				return true;
			}

			int iType = (int)Be16(d + iNext);
			unsigned int uiTtl = Be32(d + iNext + 4);
			int iLen = (int)Be16(d + iNext + 8);

			if (iNext + 10 + iLen > n)
			{
				o->Line("  (%s record is truncated)", sections[s].Title);
				return true;
			}

			o->Line("  %s: %s  %s  ttl %u  %s", sections[s].Title, sName.c_str(), DnsTypeName(iType).c_str(), uiTtl,
				DnsRData(d, n, iNext + 10, iType, iLen).c_str());
			iOff = iNext + 10 + iLen;
		}
	}

	return true;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// HTTP.

static bool DecodeHttp(const unsigned char *p, int n, DECODE_OUT *o)
{
	static const char *starts[] = { "GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE ", "HTTP/1.", "HTTP/2" };

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

	o->Blank();
	o->Line("HTTP");

	int iPos = 0;
	int iLine = 0;
	bool bHeadersEnded = false;

	while (iPos < n && iLine < 100)
	{
		int iEnd = iPos;
		while (iEnd < n && p[iEnd] != '\n') { iEnd++; }

		int iLen = iEnd - iPos;
		if (iLen > 0 && p[iPos + iLen - 1] == '\r') { iLen--; }

		if (iLen == 0)
		{
			bHeadersEnded = true;
			iPos = (iEnd < n) ? iEnd + 1 : n;
			break;
		}

		std::string sLine((const char *)p + iPos, iLen > 300 ? 300 : iLen);
		o->Line(iLine == 0 ? "  %s" : "  %s", sLine.c_str());

		iPos = (iEnd < n) ? iEnd + 1 : n;
		iLine++;
	}

	if (bHeadersEnded)
	{
		o->Line("  (end of headers, %d body byte%s in this packet)", n - iPos, n - iPos == 1 ? "" : "s");
	}
	else if (iPos >= n)
	{
		o->Line("  (headers continue in a following packet)");
	}

	return true;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// TLS.

static std::string TlsVersionName(unsigned int uiVersion)
{
	switch (uiVersion)
	{
	case 0x0300: return "SSL 3.0";
	case 0x0301: return "TLS 1.0";
	case 0x0302: return "TLS 1.1";
	case 0x0303: return "TLS 1.2";
	case 0x0304: return "TLS 1.3";
	}
	char sBuf[16];
	sprintf_s(sBuf, sizeof(sBuf), "0x%04X", uiVersion);
	return sBuf;
}

static bool IsGrease(unsigned int v)
{
	return (v & 0x0F0F) == 0x0A0A && ((v >> 8) == (v & 0xFF));
}

static std::string CipherName(unsigned int uiSuite)
{
	static const struct { unsigned int Id; const char *Name; } suites[] = {
		{0x1301, "TLS_AES_128_GCM_SHA256"}, {0x1302, "TLS_AES_256_GCM_SHA384"}, {0x1303, "TLS_CHACHA20_POLY1305_SHA256"},
		{0xC02B, "ECDHE_ECDSA_AES128_GCM_SHA256"}, {0xC02C, "ECDHE_ECDSA_AES256_GCM_SHA384"},
		{0xC02F, "ECDHE_RSA_AES128_GCM_SHA256"}, {0xC030, "ECDHE_RSA_AES256_GCM_SHA384"},
		{0xCCA8, "ECDHE_RSA_CHACHA20_POLY1305"}, {0xCCA9, "ECDHE_ECDSA_CHACHA20_POLY1305"},
		{0xC009, "ECDHE_ECDSA_AES128_CBC_SHA"}, {0xC00A, "ECDHE_ECDSA_AES256_CBC_SHA"},
		{0xC013, "ECDHE_RSA_AES128_CBC_SHA"}, {0xC014, "ECDHE_RSA_AES256_CBC_SHA"},
		{0x009C, "RSA_AES128_GCM_SHA256"}, {0x009D, "RSA_AES256_GCM_SHA384"},
		{0x002F, "RSA_AES128_CBC_SHA"}, {0x0035, "RSA_AES256_CBC_SHA"}, {0x000A, "RSA_3DES_EDE_CBC_SHA"},
		{0x00FF, "EMPTY_RENEGOTIATION_INFO_SCSV"}, {0x5600, "FALLBACK_SCSV"}
	};

	if (IsGrease(uiSuite))
	{
		return "GREASE";
	}

	for (int i = 0; i < (int)(sizeof(suites) / sizeof(suites[0])); i++)
	{
		if (suites[i].Id == uiSuite)
		{
			return suites[i].Name;
		}
	}

	char sBuf[16];
	sprintf_s(sBuf, sizeof(sBuf), "0x%04X", uiSuite);
	return sBuf;
}

static std::string GroupName(unsigned int uiGroup)
{
	if (IsGrease(uiGroup)) { return "GREASE"; }

	switch (uiGroup)
	{
	case 0x0017: return "secp256r1";
	case 0x0018: return "secp384r1";
	case 0x0019: return "secp521r1";
	case 0x001D: return "x25519";
	case 0x001E: return "x448";
	case 0x0100: return "ffdhe2048";
	case 0x0101: return "ffdhe3072";
	case 0x11EC: return "X25519MLKEM768";
	case 0x6399: return "X25519Kyber768";
	}
	char sBuf[16];
	sprintf_s(sBuf, sizeof(sBuf), "0x%04X", uiGroup);
	return sBuf;
}

static std::string ExtensionName(unsigned int uiExtension)
{
	if (IsGrease(uiExtension)) { return "GREASE"; }

	switch (uiExtension)
	{
	case 0: return "server_name";
	case 5: return "status_request";
	case 10: return "supported_groups";
	case 11: return "ec_point_formats";
	case 13: return "signature_algorithms";
	case 16: return "alpn";
	case 18: return "signed_certificate_timestamp";
	case 21: return "padding";
	case 23: return "extended_master_secret";
	case 27: return "compress_certificate";
	case 35: return "session_ticket";
	case 43: return "supported_versions";
	case 45: return "psk_key_exchange_modes";
	case 51: return "key_share";
	case 0xFE0D: return "encrypted_client_hello";
	case 0xFF01: return "renegotiation_info";
	}
	char sBuf[32];
	sprintf_s(sBuf, sizeof(sBuf), "extension %u", uiExtension);
	return sBuf;
}

//Decodes the extensions block of a hello. bServer selects ServerHello encodings where they differ.
static void DecodeTlsExtensions(const unsigned char *p, int n, int iOff, bool bServer, DECODE_OUT *o)
{
	if (iOff + 2 > n)
	{
		return;
	}

	int iEnd = iOff + 2 + (int)Be16(p + iOff);
	iOff += 2;
	if (iEnd > n) { iEnd = n; }

	o->Line("    Extensions:");

	while (iOff + 4 <= iEnd)
	{
		unsigned int uiType = Be16(p + iOff);
		int iLen = (int)Be16(p + iOff + 2);
		const unsigned char *d = p + iOff + 4;
		iOff += 4;

		if (iOff + iLen > iEnd)
		{
			o->Line("      %s (truncated)", ExtensionName(uiType).c_str());
			break;
		}

		std::string sDetail;
		char sBuf[96];

		if (uiType == 0 && iLen >= 5 && !bServer)
		{
			int iNameLen = (int)Be16(d + 3);
			if (5 + iNameLen <= iLen) { sDetail = std::string((const char *)d + 5, iNameLen); }
		}
		else if (uiType == 43)
		{
			if (bServer && iLen == 2)
			{
				sDetail = TlsVersionName(Be16(d));
			}
			else if (!bServer && iLen >= 1)
			{
				for (int i = 1; i + 1 < iLen && i < 1 + d[0]; i += 2)
				{
					sDetail += (sDetail.empty() ? "" : ", ") + (IsGrease(Be16(d + i)) ? std::string("GREASE") : TlsVersionName(Be16(d + i)));
				}
			}
		}
		else if (uiType == 10 && iLen >= 2)
		{
			for (int i = 2; i + 1 < iLen; i += 2)
			{
				sDetail += (sDetail.empty() ? "" : ", ") + GroupName(Be16(d + i));
			}
		}
		else if (uiType == 51)
		{
			if (bServer && iLen >= 2)
			{
				sDetail = "selected " + GroupName(Be16(d));
			}
			else if (!bServer && iLen >= 2)
			{
				int iPos = 2;
				while (iPos + 4 <= iLen && iPos < 2 + (int)Be16(d))
				{
					sprintf_s(sBuf, sizeof(sBuf), "%s(%u bytes)", GroupName(Be16(d + iPos)).c_str(), Be16(d + iPos + 2));
					sDetail += (sDetail.empty() ? "" : ", ") + std::string(sBuf);
					iPos += 4 + (int)Be16(d + iPos + 2);
				}
			}
		}
		else if (uiType == 16 && iLen >= 3)
		{
			int iPos = 2;
			while (iPos < iLen && iPos < 2 + (int)Be16(d))
			{
				int l = d[iPos];
				if (iPos + 1 + l > iLen) { break; }
				sDetail += (sDetail.empty() ? "" : ", ") + std::string((const char *)d + iPos + 1, l);
				iPos += 1 + l;
			}
		}
		else if (uiType == 13 && iLen >= 2)
		{
			sprintf_s(sBuf, sizeof(sBuf), "%u algorithms", Be16(d) / 2);
			sDetail = sBuf;
		}
		else if (uiType == 11 && iLen >= 1)
		{
			sprintf_s(sBuf, sizeof(sBuf), "%d formats", d[0]);
			sDetail = sBuf;
		}
		else
		{
			sprintf_s(sBuf, sizeof(sBuf), "%d bytes", iLen);
			sDetail = sBuf;
		}

		o->Line("      %s: %s", ExtensionName(uiType).c_str(), sDetail.c_str());
		iOff += iLen;
	}
}

static void DecodeTlsHandshake(const unsigned char *p, int n, DECODE_OUT *o)
{
	if (n < 4)
	{
		return;
	}

	int iType = p[0];
	int iLen = (int)((p[1] << 16) | (p[2] << 8) | p[3]);

	static const struct { int Id; const char *Name; } types[] = {
		{0, "HelloRequest"}, {1, "ClientHello"}, {2, "ServerHello"}, {4, "NewSessionTicket"}, {8, "EncryptedExtensions"},
		{11, "Certificate"}, {12, "ServerKeyExchange"}, {13, "CertificateRequest"}, {14, "ServerHelloDone"},
		{15, "CertificateVerify"}, {16, "ClientKeyExchange"}, {20, "Finished"}
	};

	const char *sName = "unknown";
	for (int i = 0; i < (int)(sizeof(types) / sizeof(types[0])); i++)
	{
		if (types[i].Id == iType) { sName = types[i].Name; }
	}

	o->Line("  Handshake: %s (%d bytes%s)", sName, iLen, 4 + iLen > n ? ", continues in a following packet" : "");

	if ((iType != 1 && iType != 2) || n < 4 + 2 + 32 + 1)
	{
		return;
	}

	bool bServer = iType == 2;
	const unsigned char *h = p + 4;
	int hn = n - 4;
	int iOff = 0;

	o->Line("    Version: %s    Random: %s ...", TlsVersionName(Be16(h)).c_str(), Hex(h + 2, 8).c_str());
	iOff = 2 + 32;

	int iSession = h[iOff];
	iOff += 1 + iSession;
	o->Line("    Session id: %d bytes", iSession);

	if (bServer)
	{
		if (iOff + 3 > hn) { return; }
		o->Line("    Cipher suite: %s", CipherName(Be16(h + iOff)).c_str());
		o->Line("    Compression: %d", h[iOff + 2]);
		iOff += 3;
	}
	else
	{
		if (iOff + 2 > hn) { return; }
		int iSuites = (int)Be16(h + iOff);
		iOff += 2;

		std::string sSuites;
		for (int i = 0; i + 1 < iSuites && iOff + i + 1 < hn && i < 2 * 40; i += 2)
		{
			sSuites += (sSuites.empty() ? "" : ", ") + CipherName(Be16(h + iOff + i));
		}
		o->Line("    Cipher suites (%d): %s%s", iSuites / 2, sSuites.c_str(), iSuites > 80 ? ", ..." : "");
		iOff += iSuites;

		if (iOff + 1 > hn) { return; }
		iOff += 1 + h[iOff];
	}

	DecodeTlsExtensions(h, hn, iOff, bServer, o);
}

static bool DecodeTls(const unsigned char *p, int n, DECODE_OUT *o)
{
	if (n < 5 || p[0] < 20 || p[0] > 24 || p[1] != 3 || p[2] > 4)
	{
		return false;
	}

	o->Blank();
	o->Line("TLS");

	static const char *recordTypes[] = { "ChangeCipherSpec", "Alert", "Handshake", "Application Data", "Heartbeat" };

	int iOff = 0;
	for (int iRecord = 0; iRecord < 8 && iOff + 5 <= n; iRecord++)
	{
		int iType = p[iOff];
		if (iType < 20 || iType > 24 || p[iOff + 1] != 3)
		{
			break;
		}

		int iLen = (int)Be16(p + iOff + 3);
		int iAvailable = n - (iOff + 5);

		o->Line("  Record: %s, %s, %d bytes%s", recordTypes[iType - 20], TlsVersionName(Be16(p + iOff + 1)).c_str(), iLen,
			iLen > iAvailable ? " (continues in a following packet)" : "");

		if (iType == 22)
		{
			DecodeTlsHandshake(p + iOff + 5, iLen < iAvailable ? iLen : iAvailable, o);
		}
		else if (iType == 21 && iLen >= 2 && iAvailable >= 2)
		{
			o->Line("  Alert: level %d, description %d%s", p[iOff + 5], p[iOff + 6], iLen == 2 ? "" : " (possibly encrypted)");
		}

		iOff += 5 + iLen;
	}

	return true;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Transport headers.

static void DecodeTcpHeader(const unsigned char *p, int n, DECODE_OUT *o, int *piHeaderLen)
{
	int iHeader = (p[12] >> 4) * 4;
	if (iHeader < 20 || iHeader > n) { iHeader = 20; }
	*piHeaderLen = iHeader;

	o->Blank();
	o->Line("TCP header (%d bytes)", iHeader);
	o->Line("  Source port: %s", PortText((int)Be16(p)).c_str());
	o->Line("  Destination port: %s", PortText((int)Be16(p + 2)).c_str());
	o->Line("  Sequence number: %u", Be32(p + 4));
	o->Line("  Acknowledgment number: %u", Be32(p + 8));
	o->Line("  Header length: %d bytes", iHeader);
	o->Line("  Flags: 0x%03X (%s)", ((p[12] & 0x01) << 8) | p[13], FlagsText(p[13]).c_str());
	o->Line("  Window: %u", Be16(p + 14));
	o->Line("  Checksum: 0x%04X", Be16(p + 16));
	o->Line("  Urgent pointer: %u", Be16(p + 18));

	int iOff = 20;
	bool bAny = false;

	while (iOff < iHeader)
	{
		int iKind = p[iOff];
		if (iKind == 0) { break; }
		if (iKind == 1) { iOff++; continue; }

		if (iOff + 1 >= iHeader) { break; }
		int iLen = p[iOff + 1];
		if (iLen < 2 || iOff + iLen > iHeader) { break; }

		if (!bAny)
		{
			o->Line("  Options:");
			bAny = true;
		}

		const unsigned char *d = p + iOff + 2;
		switch (iKind)
		{
		case 2:
			if (iLen == 4) { o->Line("    Maximum segment size: %u", Be16(d)); }
			break;
		case 3:
			if (iLen == 3) { o->Line("    Window scale: %d (x%u)", d[0], 1u << (d[0] > 30 ? 30 : d[0])); }
			break;
		case 4:
			o->Line("    SACK permitted");
			break;
		case 5:
			o->Line("    SACK blocks: %d", (iLen - 2) / 8);
			break;
		case 8:
			if (iLen == 10) { o->Line("    Timestamps: value %u, echo reply %u", Be32(d), Be32(d + 4)); }
			break;
		case 34:
			o->Line("    TCP Fast Open cookie (%d bytes)", iLen - 2);
			break;
		default:
			o->Line("    Option %d (%d bytes)", iKind, iLen);
			break;
		}

		iOff += iLen;
	}
}

static const char *IcmpTypeName(int iType, int iCode)
{
	switch (iType)
	{
	case 0: return "Echo reply";
	case 3:
		switch (iCode)
		{
		case 0: return "Destination unreachable: network unreachable";
		case 1: return "Destination unreachable: host unreachable";
		case 2: return "Destination unreachable: protocol unreachable";
		case 3: return "Destination unreachable: port unreachable";
		case 4: return "Destination unreachable: fragmentation needed";
		case 13: return "Destination unreachable: administratively prohibited";
		}
		return "Destination unreachable";
	case 4: return "Source quench";
	case 5: return "Redirect";
	case 8: return "Echo request";
	case 9: return "Router advertisement";
	case 10: return "Router solicitation";
	case 11: return iCode == 0 ? "Time exceeded: TTL expired in transit" : "Time exceeded: fragment reassembly";
	case 12: return "Parameter problem";
	case 13: return "Timestamp request";
	case 14: return "Timestamp reply";
	}
	return "unknown";
}

static const char *Icmp6TypeName(int iType)
{
	switch (iType)
	{
	case 1: return "Destination unreachable";
	case 2: return "Packet too big";
	case 3: return "Time exceeded";
	case 4: return "Parameter problem";
	case 128: return "Echo request";
	case 129: return "Echo reply";
	case 130: return "Multicast listener query";
	case 131: return "Multicast listener report";
	case 133: return "Router solicitation";
	case 134: return "Router advertisement";
	case 135: return "Neighbor solicitation";
	case 136: return "Neighbor advertisement";
	case 137: return "Redirect";
	case 143: return "Multicast listener report v2";
	}
	return "unknown";
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Packet.

void DecodePacketText(const char *sPacket, int iSize, std::string *pOut)
{
	DECODE_OUT o;
	const unsigned char *p = (const unsigned char *)sPacket;

	int iProtocol = 0;
	int iTransportOffset = 0;
	bool bHasTransport = false;
	bool bIsV6 = false;

	if (!WalkIPHeaders(sPacket, iSize, &iProtocol, &iTransportOffset, &bHasTransport, &bIsV6))
	{
		o.Line("Not a recognizable IPv4 or IPv6 packet (%d bytes).", iSize);
		*pOut = o.Text;
		return;
	}

	if (!bIsV6)
	{
		const IP_HDR *ip = (const IP_HDR *)sPacket;
		int iHeader = (ip->h_lenver & 0x0F) * 4;
		if (iHeader < 20 || iHeader > iSize) { iHeader = 20; }

		unsigned int uiFlagsField = ntohs(ip->frag_and_flags);

		//Header checksum: the one's complement sum over the whole header is 0xFFFF when it is correct.
		unsigned int uiSum = 0;
		for (int i = 0; i + 1 < iHeader; i += 2) { uiSum += (p[i] << 8) | p[i + 1]; }
		while (uiSum >> 16) { uiSum = (uiSum & 0xFFFF) + (uiSum >> 16); }

		o.Line("IPv4 header (%d bytes)", iHeader);
		o.Line("  Version: 4    Header length: %d bytes", iHeader);
		o.Line("  Type of service: 0x%02X (DSCP %d, ECN %d)", ip->tos, ip->tos >> 2, ip->tos & 3);
		o.Line("  Total length: %u bytes (captured %d)", ntohs(ip->total_len), iSize);
		o.Line("  Identification: 0x%04X (%u)", ntohs(ip->ident), ntohs(ip->ident));
		o.Line("  Flags:%s%s%s    Fragment offset: %u bytes", (uiFlagsField & 0x4000) ? " DF" : "", (uiFlagsField & 0x2000) ? " MF" : "",
			(uiFlagsField & 0x6000) == 0 ? " none" : "", (uiFlagsField & 0x1FFF) * 8);
		o.Line("  Time to live: %d", ip->ttl);
		o.Line("  Protocol: %d (%s)", ip->proto, ProtocolName(ip->proto));
		o.Line("  Header checksum: 0x%04X (%s)", ntohs(ip->checksum),
			uiSum == 0xFFFF ? "valid" : "not valid - often just checksum offload on packets this machine sent");
		o.Line("  Source: %s", AddressText(p + 12, false).c_str());
		o.Line("  Destination: %s", AddressText(p + 16, false).c_str());
		if (iHeader > 20)
		{
			o.Line("  Options: %s", Hex(p + 20, iHeader - 20).c_str());
		}
	}
	else
	{
		const IP6_HDR *ip = (const IP6_HDR *)sPacket;
		unsigned int uiFlow = ntohl(ip->vtc_flow);

		o.Line("IPv6 header (40 bytes)");
		o.Line("  Version: 6    Traffic class: 0x%02X    Flow label: 0x%05X", (uiFlow >> 20) & 0xFF, uiFlow & 0xFFFFF);
		o.Line("  Payload length: %u bytes (captured %d)", ntohs(ip->payload_len), iSize - 40);
		o.Line("  Next header: %d (%s)", ip->next_header, ProtocolName(ip->next_header));
		o.Line("  Hop limit: %d%s", ip->hop_limit, ip->hop_limit == 0 ? " (not available)" : "");
		o.Line("  Source: %s", AddressText(ip->sourceIP, true).c_str());
		o.Line("  Destination: %s", AddressText(ip->destIP, true).c_str());

		//Extension headers.
		int iNext = ip->next_header;
		int iOff = 40;
		for (int iHeader = 0; iHeader < 16 && iOff + 8 <= iSize; iHeader++)
		{
			if (iNext == 0 || iNext == 43 || iNext == 60)
			{
				int iLen = (p[iOff + 1] + 1) * 8;
				o.Blank();
				o.Line("IPv6 extension header: %s (%d bytes)", ProtocolName(iNext), iLen);
				if (iNext == 43) { o.Line("  Routing type: %d, segments left: %d", p[iOff + 2], p[iOff + 3]); }
				iNext = p[iOff];
				iOff += iLen;
			}
			else if (iNext == 44)
			{
				o.Blank();
				o.Line("IPv6 extension header: Fragment (8 bytes)");
				o.Line("  Fragment offset: %u bytes    More fragments: %s    Identification: 0x%08X", (Be16(p + iOff + 2) >> 3) * 8,
					(p[iOff + 3] & 1) ? "yes" : "no", Be32(p + iOff + 4));
				iNext = p[iOff];
				iOff += 8;
			}
			else if (iNext == 51)
			{
				int iLen = (p[iOff + 1] + 2) * 4;
				o.Blank();
				o.Line("IPv6 extension header: Authentication Header (%d bytes)", iLen);
				iNext = p[iOff];
				iOff += iLen;
			}
			else
			{
				break;
			}
		}
	}

	int iPayloadOffset = iTransportOffset;

	if (!bHasTransport)
	{
		o.Blank();
		o.Line("No transport header: this is a non-first fragment of a larger datagram.");
	}
	else if (iProtocol == IPPROTO_TCP && iSize - iTransportOffset >= 20)
	{
		int iHeaderLen = 20;
		DecodeTcpHeader(p + iTransportOffset, iSize - iTransportOffset, &o, &iHeaderLen);
		iPayloadOffset = iTransportOffset + iHeaderLen;
	}
	else if (iProtocol == IPPROTO_UDP && iSize - iTransportOffset >= 8)
	{
		const unsigned char *u = p + iTransportOffset;
		o.Blank();
		o.Line("UDP header (8 bytes)");
		o.Line("  Source port: %s", PortText((int)Be16(u)).c_str());
		o.Line("  Destination port: %s", PortText((int)Be16(u + 2)).c_str());
		o.Line("  Length: %u bytes", Be16(u + 4));
		o.Line("  Checksum: 0x%04X%s", Be16(u + 6), (Be16(u + 6) == 0 && !bIsV6) ? " (none)" : "");
		iPayloadOffset = iTransportOffset + 8;
	}
	else if ((iProtocol == IPPROTO_ICMP || iProtocol == IPPROTO_ICMPV6) && iSize - iTransportOffset >= 4)
	{
		const unsigned char *c = p + iTransportOffset;
		bool bV6 = iProtocol == IPPROTO_ICMPV6;
		o.Blank();
		o.Line("%s header", bV6 ? "ICMPv6" : "ICMP");
		o.Line("  Type: %d (%s)", c[0], bV6 ? Icmp6TypeName(c[0]) : IcmpTypeName(c[0], c[1]));
		o.Line("  Code: %d", c[1]);
		o.Line("  Checksum: 0x%04X", Be16(c + 2));

		bool bEcho = bV6 ? (c[0] == 128 || c[0] == 129) : (c[0] == 0 || c[0] == 8);
		if (bEcho && iSize - iTransportOffset >= 8)
		{
			o.Line("  Identifier: %u    Sequence: %u", Be16(c + 4), Be16(c + 6));
			iPayloadOffset = iTransportOffset + 8;
		}
		else if (iSize - iTransportOffset >= 8)
		{
			iPayloadOffset = iTransportOffset + 8;
		}
	}
	else
	{
		o.Blank();
		o.Line("Protocol %d (%s)", iProtocol, ProtocolName(iProtocol));
	}

	if (iPayloadOffset > iSize) { iPayloadOffset = iSize; }

	const unsigned char *pPayload = p + iPayloadOffset;
	int iPayload = iSize - iPayloadOffset;

	o.Blank();
	o.Line("Payload: %d byte%s at offset %d", iPayload, iPayload == 1 ? "" : "s", iPayloadOffset);

	if (iPayload > 0 && bHasTransport)
	{
		bool bDnsPort = false;
		bool bTcp = iProtocol == IPPROTO_TCP;

		if ((bTcp || iProtocol == IPPROTO_UDP) && iPayloadOffset - iTransportOffset >= 8)
		{
			int iSourcePort = (int)Be16(p + iTransportOffset);
			int iDestPort = (int)Be16(p + iTransportOffset + 2);
			bDnsPort = iSourcePort == 53 || iDestPort == 53 || (!bTcp && (iSourcePort == 5353 || iDestPort == 5353 || iSourcePort == 5355 || iDestPort == 5355));
		}

		if (bDnsPort)
		{
			if (bTcp)
			{
				if (iPayload > 2) { DecodeDns(pPayload + 2, iPayload - 2, &o); }
			}
			else
			{
				DecodeDns(pPayload, iPayload, &o);
			}
		}
		else if (bTcp)
		{
			if (!DecodeTls(pPayload, iPayload, &o))
			{
				DecodeHttp(pPayload, iPayload, &o);
			}
		}
	}

	*pOut = o.Text;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#endif
