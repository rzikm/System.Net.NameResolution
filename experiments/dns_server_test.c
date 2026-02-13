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

static void PrintRecords(PDNS_RECORD pRecord) {
    for (PDNS_RECORD p = pRecord; p != NULL; p = p->pNext) {
        char ipStr[INET6_ADDRSTRLEN] = {0};
        if (p->wType == DNS_TYPE_A) {
            IN_ADDR addr;
            addr.S_un.S_addr = p->Data.A.IpAddress;
            inet_ntop(AF_INET, &addr, ipStr, sizeof(ipStr));
        } else if (p->wType == DNS_TYPE_AAAA) {
            inet_ntop(AF_INET6, &p->Data.AAAA.Ip6Address, ipStr, sizeof(ipStr));
        }
        wprintf(L"  Name: %s  Type: %d  TTL: %u  %hs\n",
               p->pName, p->wType, p->dwTtl, ipStr);
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
        const wchar_t* servers[] = { L"192.0.2.1", L"192.0.2.2" };
        RunQuery(queryName, DNS_TYPE_A, DNS_QUERY_BYPASS_CACHE, servers, 2);
    }

    // Test 5: TTL comparison — bypass cache vs standard
    {
        wprintf(L"\n=== Test 5a: TTL - bypass cache ===\n");
        RunQuery(queryName, DNS_TYPE_A, DNS_QUERY_BYPASS_CACHE, NULL, 0);

        wprintf(L"\n=== Test 5b: TTL - standard (may be cached) ===\n");
        RunQuery(queryName, DNS_TYPE_A, DNS_QUERY_STANDARD, NULL, 0);
    }

    WSACleanup();
    return 0;
}
