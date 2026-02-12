# System.Net.NameResolution API Design

## Motivation

The existing `System.Net.Dns` class does not expose TTL (Time-To-Live) information from DNS responses. This forces consumers — most notably `SocketsHttpHandler` and the broader HTTP stack — to use conservative heuristics when deciding whether cached DNS results are still valid. In practice, this leads to premature disposal of HTTP connections in order to react to potential DNS-level changes (e.g., failover, load balancing rotation), even when the DNS records haven't actually changed. A TTL-aware API would allow consumers to know exactly when endpoint addresses should be rechecked, reducing unnecessary connection churn and improving performance.

Another motivation exposing more granular access to DNS records, currently, there is no API to retrieve TXT, MX, and many other record types.

## Goals

- **Expose TTL information** from DNS responses through high-level resolution APIs, enabling callers to make informed caching and connection lifetime decisions.
- **Provide low-level DNS message APIs** for composing DNS query messages and reading DNS response messages. This is necessary because on some platforms (notably Linux), the OS-provided resolution APIs (glibc's `getaddrinfo`) are synchronous-only and do not return TTL values. The low-level APIs also serve advanced users who need fine-grained control over DNS queries.
- **Minimize allocations** in the low-level APIs by using struct-based reader/writer types that operate over caller-provided buffers.
- **Support cross-platform operation**, accounting for differences in platform capabilities:
  - On **Windows**, OS-level APIs can return TTL information directly.
  - On **Linux/macOS**, the high-level TTL-aware API will be backed by a built-in stub resolver that communicates with the configured DNS server (from `/etc/resolv.conf`).
- **Respect existing platform resolution behavior** where possible, including:
  - Hosts file entries (`/etc/hosts`, `%SystemRoot%\System32\drivers\etc\hosts`).
  - Local stub resolvers such as `systemd-resolved` (by delegating to the configured nameserver, which may be `127.0.0.53`).
  - Search domains and other `resolv.conf` directives.
- **Provide a testable, configurable API** through an instance-based resolver class that supports dependency injection, custom DNS server configuration, and per-instance settings (timeouts, retry policy, etc.).
- **Implement a stub resolver only** — the built-in resolver will not perform recursive resolution. It assumes the target DNS server (typically a local or ISP recursive resolver) handles recursion.

## Non-Goals

- **Full recursive resolver** — the implementation delegates recursion to the configured upstream DNS server.
- **DNSSEC validation** — the resolver may surface the AD (Authenticated Data) flag from responses, but will not perform its own DNSSEC validation.
- **DNS-over-HTTPS (DoH) / DNS-over-TLS (DoT)** — encrypted transport is out of scope for the initial design, though the architecture should not preclude future support.
- **mDNS / LLMNR** — multicast DNS and link-local multicast name resolution are out of scope.
- **Full `nsswitch.conf` implementation** — the resolver will handle hosts file lookup and DNS, but will not implement the full NSS plugin pipeline.

## Platform Research: Windows DNS APIs

### Available APIs

Windows provides three levels of DNS query APIs, all in `dnsapi.dll`:

| API | Min Version | Async | Custom Servers | IPv6 Servers | Notes |
|-----|-------------|-------|----------------|--------------|-------|
| `DnsQuery_W` | Win2000 | No | Undocumented (IPv4 only via `pExtra`) | No | Synchronous only, simplest API |
| `DnsQueryEx` (`DNS_QUERY_REQUEST` v1) | Win8 / Server 2012 | Yes (callback) | Yes (`pDnsServerList` → `DNS_ADDR_ARRAY`) | Yes | Preferred for most scenarios |
| `DnsQueryEx` (`DNS_QUERY_REQUEST3` v3) | Win11 Build 22000 | Yes (callback) | Yes (`pCustomServers` → `DNS_CUSTOM_SERVER[]`) | Yes | Adds custom server with port/protocol control |

### TTL Exposure

- Every `DNS_RECORD` in the returned linked list contains a `dwTtl` field (DWORD, in seconds).
- The TTL value represents the **remaining** TTL, not the original TTL from the authoritative server. When results come from the Windows DNS resolver cache, the TTL decrements each second. Fresh wire responses contain the original TTL.
- The `DNS_QUERY_BYPASS_CACHE` flag (`0x00000008`) forces a wire query, bypassing the resolver cache. The `DNS_QUERY_DONT_RESET_TTL_VALUES` flag (`0x00100000`) prevents the API from resetting TTL values on cached records.

### Resource Record Support

`DnsQueryEx` supports querying for **any** DNS record type via the `QueryType` field. The returned `DNS_RECORD` union has typed data members for all standard record types, including:

- A, AAAA (address records)
- SRV (service discovery)
- MX (mail exchange)
- TXT (text records)
- CNAME, PTR, NS, SOA
- NAPTR, SVCB/HTTPS (newer types)
- DNSSEC-related: DNSKEY, RRSIG, NSEC, NSEC3, DS
- Generic/unknown record types via `DNS_UNKNOWN_DATA`

### Custom DNS Server Support

- **`DNS_QUERY_REQUEST` (v1)**: The `pDnsServerList` field accepts a `DNS_ADDR_ARRAY` with IPv4 and IPv6 server addresses. Custom servers **replace** the system-configured servers entirely.
- **`DNS_QUERY_REQUEST3` (v3)**: Adds `pCustomServers` field pointing to `DNS_CUSTOM_SERVER[]`, which allows specifying server address, port, and protocol (UDP/TCP). Only one of `pDnsServerList` and `pCustomServers` may be non-null. Note: custom servers are ignored if the query name matches a **Name Resolution Policy Table (NRPT)** rule.

### Hosts File Behavior

- By default, `DnsQueryEx` **respects the hosts file** — entries in the hosts file are returned before querying DNS servers.
- The `DNS_QUERY_NO_HOSTS_FILE` flag (`0x00000040`) skips the hosts file lookup.
- The `DNS_QUERY_WIRE_ONLY` flag (`0x00000100`) bypasses both the cache and the hosts file, sending the query directly over the network.

### Async Operation

- When `pQueryCompletionCallback` is set in the request structure, `DnsQueryEx` returns `DNS_REQUEST_PENDING` and invokes the callback when complete.
- When `pQueryCompletionCallback` is NULL, the call is synchronous.
- Async queries can be cancelled via `DnsCancelQuery` using the `DNS_QUERY_CANCEL` handle.
- Note: some scenarios always execute synchronously regardless of the callback (e.g., local machine name queries, IP address queries, error cases).

### Raw Message Access

The `DNS_QUERY_RETURN_MESSAGE` flag (`0x00020000`) causes `DnsQueryEx` to populate `pbDnsResponseMessage` and `cbDnsResponseMessage` in the result structure with the raw wire-format DNS response. This provides access to the complete DNS message, including all sections and flags, for custom parsing.

### Known Quirks and Limitations

- There have been reports of bugs in `DnsQueryEx`'s async/sync handling on certain Windows builds ([reference](https://dblohm7.ca/blog/2022/05/06/dnsqueryex-needs-love/)).
- Setting both `pDnsServerList` and `InterfaceIndex` simultaneously can cause failures unless the interface index is valid for the given servers.
- Windows may hard-code resolution of certain Microsoft domains regardless of hosts file entries (security measure).

### Implications for Our Design

1. **On Windows, we can use `DnsQueryEx` for the high-level TTL-aware API** — it provides TTL, supports all record types, respects the hosts file, and supports async operation. No need for our own stub resolver on Windows.
2. **Custom DNS server support maps naturally** — `DnsResolverOptions.Servers` can map to `pDnsServerList` or `pCustomServers`.
3. **The TTL is "remaining" TTL, not "original"** — this is actually what consumers want (how long until this record expires), so it maps well to our `ExpiresAt` pattern.
4. **`DNS_QUERY_REQUEST3` (v3) adds port/protocol control** but requires Win11 Build 22000+. We may need a fallback to v1 on older Windows versions.
5. **The low-level message APIs (reader/writer) are still needed** for Linux/macOS and for advanced scenarios on all platforms, but on Windows we don't need them for the common high-level path.
