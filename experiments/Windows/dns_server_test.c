// DnsQueryEx experiment: test server failover, TTL, and retry behavior
// Based on Microsoft's DnsQueryEx sample pattern for DNS_ADDR_ARRAY setup.
//
// Run with Wireshark (filter: "dns") to observe which servers are queried.

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <windns.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "dnsapi.lib")
#pragma comment(lib, "ws2_32.lib")

// Build DNS_ADDR_ARRAY using WSAStringToAddress (matches MS sample pattern)
static DWORD BuildServerList(
    const wchar_t** servers, int count,
    PDNS_ADDR_ARRAY pArray, size_t arraySize)
{
    ZeroMemory(pArray, arraySize);
    pArray->MaxCount = count;
    pArray->AddrCount = count;

    for (int i = 0; i < count; i++) {
        SOCKADDR_STORAGE sa;
        INT saLen = sizeof(sa);

        // Try IPv4
        int err = WSAStringToAddressW((LPWSTR)servers[i], AF_INET, NULL,
                                       (LPSOCKADDR)&sa, &saLen);
        if (err != 0) {
            // Try IPv6
            saLen = sizeof(sa);
            err = WSAStringToAddressW((LPWSTR)servers[i], AF_INET6, NULL,
                                       (LPSOCKADDR)&sa, &saLen);
        }
        if (err != 0) {
            wprintf(L"WSAStringToAddress failed for %s: %d\n", servers[i], WSAGetLastError());
            return WSAGetLastError();
        }

        CopyMemory(pArray->AddrArray[i].MaxSa, &sa, DNS_ADDR_MAX_SOCKADDR_LENGTH);
    }
    return ERROR_SUCCESS;
}

// Build a DNS query message (RFC 1035). Returns length on success, -1 on failure.
static int BuildDnsQuery(const char* name, WORD qtype, BYTE* buf, int bufsize) {
    if (bufsize < 12) return -1;
    // Header: ID=0x1234, flags=0x0100 (RD), QDCOUNT=1, rest=0
    buf[0] = 0x12; buf[1] = 0x34;
    buf[2] = 0x01; buf[3] = 0x00;
    buf[4] = 0x00; buf[5] = 0x01;
    buf[6] = buf[7] = buf[8] = buf[9] = buf[10] = buf[11] = 0;
    int pos = 12;

    // QNAME as length-prefixed labels
    const char* p = name;
    while (*p) {
        const char* dot = strchr(p, '.');
        int len = dot ? (int)(dot - p) : (int)strlen(p);
        if (len == 0 || len > 63 || pos + 1 + len >= bufsize) return -1;
        buf[pos++] = (BYTE)len;
        memcpy(buf + pos, p, len);
        pos += len;
        if (!dot) break;
        p = dot + 1;
    }
    if (pos >= bufsize) return -1;
    buf[pos++] = 0;  // root label

    // QTYPE + QCLASS(IN)
    if (pos + 4 > bufsize) return -1;
    buf[pos++] = (BYTE)(qtype >> 8);
    buf[pos++] = (BYTE)(qtype & 0xFF);
    buf[pos++] = 0;
    buf[pos++] = 1;
    return pos;
}

static void HexDump(const BYTE* data, int len) {
    for (int i = 0; i < len; i += 16) {
        wprintf(L"  %04x: ", i);
        for (int j = 0; j < 16; j++) {
            if (i + j < len) wprintf(L"%02x ", data[i + j]);
            else              wprintf(L"   ");
        }
        wprintf(L" |");
        for (int j = 0; j < 16 && i + j < len; j++) {
            BYTE b = data[i + j];
            wprintf(L"%hc", (b >= 32 && b < 127) ? b : '.');
        }
        wprintf(L"|\n");
    }
}

// Send a raw DNS query via UDP and print the wire response for comparison
// with what DnsQueryEx surfaces. Useful for observing the additional section.
static void RunRawQuery(const char* name, WORD qtype, const char* serverIp) {
    BYTE query[512];
    int qlen = BuildDnsQuery(name, qtype, query, sizeof(query));
    if (qlen < 0) { wprintf(L"  Failed to build query\n"); return; }

    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) { wprintf(L"  socket() failed: %d\n", WSAGetLastError()); return; }

    DWORD timeout = 5000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));

    struct sockaddr_in addr;
    ZeroMemory(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(53);
    inet_pton(AF_INET, serverIp, &addr.sin_addr);

    if (sendto(s, (const char*)query, qlen, 0, (struct sockaddr*)&addr, sizeof(addr)) != qlen) {
        wprintf(L"  sendto failed: %d\n", WSAGetLastError());
        closesocket(s);
        return;
    }

    BYTE response[4096];
    int received = recvfrom(s, (char*)response, sizeof(response), 0, NULL, NULL);
    closesocket(s);

    if (received <= 0) {
        wprintf(L"  recvfrom failed: %d\n", WSAGetLastError());
        return;
    }

    wprintf(L"  Received %d bytes from %hs\n", received, serverIp);
    if (received >= 12) {
        WORD flags = (WORD)((response[2] << 8) | response[3]);
        WORD qd = (WORD)((response[4] << 8) | response[5]);
        WORD an = (WORD)((response[6] << 8) | response[7]);
        WORD ns = (WORD)((response[8] << 8) | response[9]);
        WORD ar = (WORD)((response[10] << 8) | response[11]);
        wprintf(L"  Header: flags=0x%04x RCODE=%d QD=%u AN=%u NS=%u AR=%u\n",
                flags, flags & 0xF, qd, an, ns, ar);
    }
    HexDump(response, received);
}

static void PrintRecords(PDNS_RECORD pRecord) {
    for (PDNS_RECORD p = pRecord; p != NULL; p = p->pNext) {
        char ipStr[INET6_ADDRSTRLEN] = {0};
        if (p->wType == DNS_TYPE_A) {
            IN_ADDR addr;
            addr.S_un.S_addr = p->Data.A.IpAddress;
            inet_ntop(AF_INET, &addr, ipStr, sizeof(ipStr));
            wprintf(L"  Name: %s  Type: A (%d)  TTL: %u  %hs\n",
                   p->pName, p->wType, p->dwTtl, ipStr);
        } else if (p->wType == DNS_TYPE_AAAA) {
            inet_ntop(AF_INET6, &p->Data.AAAA.Ip6Address, ipStr, sizeof(ipStr));
            wprintf(L"  Name: %s  Type: AAAA (%d)  TTL: %u  %hs\n",
                   p->pName, p->wType, p->dwTtl, ipStr);
        } else if (p->wType == DNS_TYPE_SRV) {
            wprintf(L"  Name: %s  Type: SRV (%d)  TTL: %u  Prio: %u  Weight: %u  Port: %u  Target: %s\n",
                   p->pName, p->wType, p->dwTtl,
                   p->Data.Srv.wPriority, p->Data.Srv.wWeight,
                   p->Data.Srv.wPort, p->Data.Srv.pNameTarget);
        } else {
            wprintf(L"  Name: %s  Type: %d  TTL: %u\n",
                   p->pName, p->wType, p->dwTtl);
        }
    }
}

// Synchronous DnsQueryEx wrapper
static DNS_STATUS RunQuery(
    const wchar_t* queryName, WORD queryType, ULONG64 options,
    const wchar_t** servers, int serverCount)
{
    // Allocate DNS_ADDR_ARRAY large enough for serverCount entries
    size_t arrSize = sizeof(DNS_ADDR_ARRAY) +
        (serverCount > 1 ? (serverCount - 1) * sizeof(DNS_ADDR) : 0);
    PDNS_ADDR_ARRAY pServerList = NULL;

    if (servers && serverCount > 0) {
        pServerList = (PDNS_ADDR_ARRAY)calloc(1, arrSize);
        if (!pServerList) return ERROR_OUTOFMEMORY;
        DWORD err = BuildServerList(servers, serverCount, pServerList, arrSize);
        if (err != ERROR_SUCCESS) {
            free(pServerList);
            return err;
        }
    }

    DNS_QUERY_REQUEST request;
    ZeroMemory(&request, sizeof(request));
    request.Version = DNS_QUERY_REQUEST_VERSION1;
    request.QueryName = (PWSTR)queryName;
    request.QueryType = queryType;
    request.QueryOptions = options;
    request.pDnsServerList = pServerList;
    request.pQueryCompletionCallback = NULL;  // synchronous

    DNS_QUERY_RESULT result;
    ZeroMemory(&result, sizeof(result));
    result.Version = DNS_QUERY_RESULTS_VERSION1;

    DWORD t0 = GetTickCount();
    DNS_STATUS status = DnsQueryEx(&request, &result, NULL);
    DWORD elapsed = GetTickCount() - t0;

    wprintf(L"  Status: %lu  Elapsed: %lu ms\n", status, elapsed);

    if (status == ERROR_SUCCESS && result.pQueryRecords) {
        PrintRecords(result.pQueryRecords);
        DnsRecordListFree(result.pQueryRecords, DnsFreeRecordList);
    }

    free(pServerList);
    return status;
}

// Callback context for DnsQueryRaw (async completion)
typedef struct {
    DNS_QUERY_RAW_RESULT* result;
    HANDLE                event;
} RawCallbackContext;

static VOID CALLBACK DnsQueryRawCallback(
    _In_ VOID* queryContext,
    _In_ DNS_QUERY_RAW_RESULT* queryResults)
{
    RawCallbackContext* ctx = (RawCallbackContext*)queryContext;
    ctx->result = queryResults;  // caller frees via DnsQueryRawResultFree
    SetEvent(ctx->event);
}

// DnsQueryRaw wrapper (Windows 11 22H2+ / Server 2025+). Returns both parsed
// records and the raw wire response — useful for observing the additional
// section (glue records) that DnsQueryEx strips.
static DNS_STATUS RunQueryRaw(
    const wchar_t* queryName, WORD queryType, ULONG64 options)
{
    RawCallbackContext ctx = {0};
    ctx.event = CreateEventW(NULL, FALSE, FALSE, NULL);
    if (!ctx.event) return GetLastError();

    DNS_QUERY_RAW_REQUEST request;
    ZeroMemory(&request, sizeof(request));
    request.version                 = DNS_QUERY_RAW_REQUEST_VERSION1;
    request.resultsVersion          = DNS_QUERY_RAW_RESULTS_VERSION1;
    request.dnsQueryRaw             = NULL;
    request.dnsQueryRawSize         = 0;
    request.dnsQueryName            = (PWSTR)queryName;
    request.dnsQueryType            = queryType;
    request.queryOptions            = options;
    request.interfaceIndex          = 0;
    request.queryCompletionCallback = DnsQueryRawCallback;
    request.queryContext            = &ctx;
    request.queryRawOptions         = 0;
    request.customServersSize       = 0;
    request.customServers           = NULL;
    request.protocol                = DNS_PROTOCOL_UDP;

    DNS_QUERY_RAW_CANCEL cancel = {0};

    DWORD t0 = GetTickCount();
    DNS_STATUS status = DnsQueryRaw(&request, &cancel);
    if (status == DNS_REQUEST_PENDING) {
        WaitForSingleObject(ctx.event, INFINITE);
        status = ctx.result ? ctx.result->queryStatus : ERROR_GEN_FAILURE;
    }
    DWORD elapsed = GetTickCount() - t0;

    wprintf(L"  Status: %lu  Elapsed: %lu ms\n", status, elapsed);

    if (ctx.result) {
        ULONG rlen = ctx.result->queryRawResponseSize;
        const BYTE* resp = (const BYTE*)ctx.result->queryRawResponse;
        wprintf(L"  Raw response size: %lu bytes\n", rlen);
        if (resp && rlen >= 12) {
            WORD flags = (WORD)((resp[2] << 8) | resp[3]);
            WORD qd = (WORD)((resp[4] << 8) | resp[5]);
            WORD an = (WORD)((resp[6] << 8) | resp[7]);
            WORD ns = (WORD)((resp[8] << 8) | resp[9]);
            WORD ar = (WORD)((resp[10] << 8) | resp[11]);
            wprintf(L"  Header: flags=0x%04x RCODE=%d QD=%u AN=%u NS=%u AR=%u\n",
                    flags, flags & 0xF, qd, an, ns, ar);
            HexDump(resp, (int)rlen);
        }
        if (ctx.result->queryRecords) {
            wprintf(L"  Parsed records:\n");
            PrintRecords(ctx.result->queryRecords);
        }
        DnsQueryRawResultFree(ctx.result);
    }

    CloseHandle(ctx.event);
    return status;
}

int wmain(int argc, wchar_t* argv[]) {
    const wchar_t* queryName = L"example.com";
    if (argc > 1) queryName = argv[1];

    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    wprintf(L"Query target: %s\n", queryName);

    // Test 0: System default servers (no custom list)
    wprintf(L"\n=== Test 0: System default servers ===\n");
    RunQuery(queryName, DNS_TYPE_A, DNS_QUERY_BYPASS_CACHE, NULL, 0);

    // Test 1: Single valid server (use system DNS)
    {
        wprintf(L"\n=== Test 1: Single server (10.50.50.50) ===\n");
        const wchar_t* servers[] = { L"10.50.50.50" };
        RunQuery(queryName, DNS_TYPE_A, DNS_QUERY_BYPASS_CACHE, servers, 1);
    }

    // Test 2: Two valid servers — watch Wireshark to see if only first is queried
    {
        wprintf(L"\n=== Test 2: Two valid servers (10.50.50.50 + 10.50.10.50) ===\n");
        const wchar_t* servers[] = { L"10.50.50.50", L"10.50.10.50" };
        RunQuery(queryName, DNS_TYPE_A, DNS_QUERY_BYPASS_CACHE, servers, 2);
    }

    // Test 3: Unreachable first, valid second — measures failover time
    {
        wprintf(L"\n=== Test 3: Unreachable + valid (192.0.2.1 + 10.50.50.50) ===\n");
        wprintf(L"  (may take a while if failover happens...)\n");
        const wchar_t* servers[] = { L"192.0.2.1", L"10.50.50.50" };
        RunQuery(queryName, DNS_TYPE_A, DNS_QUERY_BYPASS_CACHE, servers, 2);
    }

    // Test 4: All unreachable — measures total timeout
    {
        wprintf(L"\n=== Test 4: All unreachable (192.0.2.1 + 192.0.2.2) ===\n");
        wprintf(L"  (expecting full timeout...)\n");
        wprintf(L"  (skipping...)\n");
        // const wchar_t* servers[] = { L"192.0.2.1", L"192.0.2.2" };
        // RunQuery(queryName, DNS_TYPE_A, DNS_QUERY_BYPASS_CACHE, servers, 2);
    }

    // Test 5: TTL comparison — bypass cache vs standard
    {
        wprintf(L"\n=== Test 5a: TTL - bypass cache ===\n");
        RunQuery(queryName, DNS_TYPE_A, DNS_QUERY_BYPASS_CACHE, NULL, 0);

        wprintf(L"\n=== Test 5b: TTL - standard (may be cached) ===\n");
        RunQuery(queryName, DNS_TYPE_A, DNS_QUERY_STANDARD, NULL, 0);
    }

    // Test 6: SRV query — verify whether the different Windows APIs surface
    // additional-section A/AAAA "glue" records for SRV targets.
    //   6a: DnsQueryEx  — parsed records only (may strip additional section)
    //   6b: raw UDP to 8.8.8.8 — ground-truth wire response
    //   6c: DnsQueryRaw — parsed records + raw wire response (Win11 22H2+)
    {
        wprintf(L"\n=== Test 6a: SRV _caldavs._tcp.google.com via DnsQueryEx ===\n");
        RunQuery(L"_caldavs._tcp.google.com", DNS_TYPE_SRV, DNS_QUERY_BYPASS_CACHE, NULL, 0);

        wprintf(L"\n=== Test 6b: SRV _caldavs._tcp.google.com via raw UDP (8.8.8.8) ===\n");
        RunRawQuery("_caldavs._tcp.google.com", DNS_TYPE_SRV, "8.8.8.8");

        wprintf(L"\n=== Test 6c: SRV _caldavs._tcp.google.com via DnsQueryRaw ===\n");
        RunQueryRaw(L"_caldavs._tcp.google.com", DNS_TYPE_SRV, DNS_QUERY_BYPASS_CACHE);
    }

    WSACleanup();
    return 0;
}
