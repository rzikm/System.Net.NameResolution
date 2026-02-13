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

### Server Failover and Timeout Behavior

Experimental testing (see `experiments/dns_server_test.c`) confirmed the following behavior when `pDnsServerList` contains multiple servers:

| Scenario | Result | Duration |
|----------|--------|----------|
| Two valid servers | Success | ~16ms |
| Unreachable first + valid second | Success (failover) | ~1031ms |
| Two unreachable servers | Timeout (`DNS_ERROR_RCODE_SERVER_FAILURE`) | ~12047ms |
| System default (no custom servers) | Success | ~31ms |

**Key observations:**

- **`DnsQueryEx` handles server failover internally.** When the first server is unreachable, it automatically tries the next server after ~1 second.
- **The total timeout for all-unreachable servers (~12s for 2 servers) suggests internal retry logic** — roughly 3 attempts per server at ~2s each, or a similar internal retry schedule. This is not documented by Microsoft and may vary across Windows versions.
- **When multiple valid servers are provided, only the first appears to be queried** (identical TTL values across runs), meaning `DnsQueryEx` does not load-balance across servers.
- **There is no public API to control per-server timeout, retry count, or the overall timeout** when using `DnsQueryEx`. The retry/failover behavior is entirely internal to the Windows DNS client.

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
6. **Server failover is handled by `DnsQueryEx` on Windows** — the API automatically tries the next server in the list after ~1s. Retry count and per-server timeout are not configurable through public API, which constrains how much control we can offer on Windows through `DnsResolverOptions`.

## Low-Level API: DNS Message Primitives (Draft)

The low-level API provides non-allocating, type-safe primitives for constructing DNS query messages and parsing DNS response messages. These types operate over caller-provided `Span<byte>` / `ReadOnlySpan<byte>` buffers.

### Design Principles

- **`ref struct`-based**: Reader, writer, and related types like `DnsName` are `ref struct`s because they hold `Span<T>` references. This ensures stack-only usage and prevents accidental heap allocation.
- **`Try*` pattern**: All operations return `bool` to indicate success/failure (buffer too small, malformed data), rather than throwing exceptions. This is consistent with low-level .NET APIs.
- **Sequential cursor**: Both reader and writer maintain an internal position that advances with each operation. DNS messages are inherently sequential (header → questions → answers → authority → additional).
- **Lazy domain name resolution**: `DnsName` holds a reference to the full message buffer and resolves compression pointers on demand, avoiding intermediate copies.

### Enums

```csharp
namespace System.Net;

public enum DnsRecordType : ushort
{
    A       = 1,
    NS      = 2,
    CNAME   = 5,
    SOA     = 6,
    PTR     = 12,
    MX      = 15,
    TXT     = 16,
    AAAA    = 28,
    SRV     = 33,
    NAPTR   = 35,
    OPT     = 41,    // EDNS0
    SVCB    = 64,
    HTTPS   = 65,
}

public enum DnsRecordClass : ushort
{
    Internet = 1,   // IN
    Chaos    = 3,   // CH
    Hesiod   = 4,   // HS
    Any      = 255,
}

public enum DnsResponseCode : ushort
{
    NoError        = 0,
    FormatError    = 1,
    ServerFailure  = 2,
    NameError      = 3,    // NXDOMAIN
    NotImplemented = 4,
    Refused        = 5,
}

public enum DnsOpCode : byte
{
    Query        = 0,
    InverseQuery = 1,
    Status       = 2,
    Notify       = 4,
    Update       = 5,
}

[Flags]
public enum DnsHeaderFlags : ushort
{
    None                = 0,
    AuthoritativeAnswer = 1 << 0,  // AA
    Truncation          = 1 << 1,  // TC
    RecursionDesired    = 1 << 2,  // RD
    RecursionAvailable  = 1 << 3,  // RA
    AuthenticData       = 1 << 4,  // AD (RFC 4035)
    CheckingDisabled    = 1 << 5,  // CD (RFC 4035)
}
```

### DnsMessageHeader

A readonly struct representing the fixed 12-byte DNS message header. Used by both reader and writer.

```csharp
namespace System.Net;

public readonly struct DnsMessageHeader
{
    // Properties (all read-only)
    public ushort Id { get; }
    public bool IsResponse { get; }              // QR bit
    public DnsOpCode OpCode { get; }
    public DnsHeaderFlags Flags { get; }
    public DnsResponseCode ResponseCode { get; } // RCODE
    public ushort QuestionCount { get; }         // QDCOUNT
    public ushort AnswerCount { get; }           // ANCOUNT
    public ushort AuthorityCount { get; }        // NSCOUNT
    public ushort AdditionalCount { get; }       // ARCOUNT

    // Full constructor
    public DnsMessageHeader(
        ushort id, bool isResponse, DnsOpCode opCode,
        DnsHeaderFlags flags, DnsResponseCode responseCode,
        ushort questionCount, ushort answerCount,
        ushort authorityCount, ushort additionalCount);

    // Convenience factory for the common case: standard recursive query
    public static DnsMessageHeader CreateStandardQuery(
        ushort id,
        ushort questionCount = 1,
        DnsHeaderFlags flags = DnsHeaderFlags.RecursionDesired);
}
```

### DnsName

Represents a domain name in DNS wire format. Used by both the read path (names parsed from response messages) and the write path (names created from strings for query messages).

Internally holds `(ReadOnlySpan<byte> buffer, int offset)`. For names parsed from responses, `buffer` is the full message (needed to follow compression pointers per RFC 1035 §4.1.4). For names created from strings, `buffer` is a small caller-provided encode buffer with flat labels (no compression pointers). Label enumeration handles compression pointers transparently.

Comparison is case-insensitive per DNS specification.

```csharp
namespace System.Net;

public readonly ref struct DnsName
{
    // Maximum wire-format size of any valid domain name
    // (including length prefixes and root label terminator).
    public const int MaxEncodedLength = 255;

    // --- Write path: create from a dotted string ---

    // Validates the name against RFC 1035 rules (label max 63 bytes, total max 253 chars,
    // valid characters) and encodes into wire format in the destination buffer.
    // Returns:
    //   Done          - success
    //   InvalidData   - name violates DNS rules
    //   DestinationTooSmall - destination buffer too small
    public static OperationStatus TryCreate(
        ReadOnlySpan<char> name,
        Span<byte> destination,
        out DnsName result,
        out int bytesWritten);

    // --- Shared: works identically for parsed and created names ---

    // Compares this name to a dotted string representation (e.g., "example.com").
    // Case-insensitive. Does not allocate.
    public bool Equals(ReadOnlySpan<char> name);

    // Decodes the domain name into the destination buffer as a dotted string.
    public bool TryFormat(Span<char> destination, out int charsWritten);

    // Returns the character count of the decoded dotted string representation.
    public int GetFormattedLength();

    // Enumerates the individual labels (e.g., "example" then "com").
    // Each label is a ReadOnlySpan<byte> of the raw ASCII bytes (no length prefix, no dot).
    // Follows compression pointers transparently.
    public DnsLabelEnumerator EnumerateLabels();

    // Convenience method. Allocates a string.
    public override string ToString();
}

// Duck-typed enumerator for foreach support (same pattern as Span<T>.Enumerator).
public ref struct DnsLabelEnumerator
{
    public ReadOnlySpan<byte> Current { get; }
    public bool MoveNext();
    public DnsLabelEnumerator GetEnumerator();
}
```

### DnsMessageWriter

A ref struct that writes DNS query messages into a caller-provided buffer. Only supports writing request messages (header + questions). Name compression is not supported — request messages typically contain only one or two questions, offering no meaningful opportunity for compression.

The caller is responsible for ensuring the header's `QuestionCount` matches the number of questions written.

```csharp
namespace System.Net;

public ref struct DnsMessageWriter
{
    public DnsMessageWriter(Span<byte> destination);

    // Number of bytes written so far.
    public int BytesWritten { get; }

    // Writes the 12-byte message header at the current position.
    // Typically called first. The header's QuestionCount must match the
    // number of questions subsequently written.
    public bool TryWriteHeader(in DnsMessageHeader header);

    // Writes a question entry: pre-validated encoded domain name + type + class.
    // Returns false only if the destination buffer is too small.
    public bool TryWriteQuestion(
        DnsName name,
        DnsRecordType type,
        DnsRecordClass @class = DnsRecordClass.Internet);
}
```

### DnsMessageReader

A ref struct that reads DNS messages from a buffer. Reads sequentially: header (parsed eagerly in constructor), then questions, then resource records (answers, authority, additional in order).

The caller uses `Header.QuestionCount`, `Header.AnswerCount`, `Header.AuthorityCount`, and `Header.AdditionalCount` to determine how many items to read and which section each record belongs to.

```csharp
namespace System.Net;

public ref struct DnsMessageReader
{
    // Parses the header eagerly. Fails if the buffer is too small for a valid header.
    public DnsMessageReader(ReadOnlySpan<byte> message);

    // The parsed message header.
    public DnsMessageHeader Header { get; }

    // Reads the next question from the message.
    // Call Header.QuestionCount times.
    public bool TryReadQuestion(out DnsQuestion question);

    // Reads the next resource record from the message.
    // Call (Header.AnswerCount + Header.AuthorityCount + Header.AdditionalCount) times.
    // Use the header counts to determine which section each record belongs to.
    public bool TryReadRecord(out DnsRecord record);
}
```

### DnsQuestion

Represents a parsed question entry from the question section.

```csharp
namespace System.Net;

public readonly ref struct DnsQuestion
{
    public DnsName Name { get; }
    public DnsRecordType Type { get; }
    public DnsRecordClass Class { get; }
}
```

### DnsRecord

Represents a parsed resource record from any section (answer, authority, additional). Carries a reference to the full message buffer and the RDATA offset, enabling typed record data accessors to resolve domain name compression pointers. These fields are also exposed publicly so that users can implement their own parsers for custom or unsupported record types.

```csharp
namespace System.Net;

public readonly ref struct DnsRecord
{
    public DnsName Name { get; }
    public DnsRecordType Type { get; }
    public DnsRecordClass Class { get; }
    public uint TimeToLive { get; }

    // Raw RDATA bytes. A slice of Message starting at DataOffset.
    public ReadOnlySpan<byte> Data { get; }

    // The full DNS message buffer. Exposed for custom record type parsers
    // that need to resolve domain name compression pointers within RDATA.
    public ReadOnlySpan<byte> Message { get; }

    // Offset of Data within Message. Together with Message, provides
    // the context needed to resolve compression pointers in RDATA.
    public int DataOffset { get; }
}
```

> **Alternative design considered**: Instead of exposing `Message` and `DataOffset`, provide a helper method on `DnsRecord` for the specific need of resolving domain names within RDATA:
> ```csharp
> // Reads a domain name at the given byte offset within this record's RDATA.
> // Handles compression pointers using the underlying message context.
> public bool TryReadName(int rdataOffset, out DnsName name, out int bytesConsumed);
> ```
> This would be more encapsulated — users wouldn't need to understand message-level offsets and compression — but less flexible for arbitrary custom parsing. We chose to expose the raw context since the target audience (low-level DNS users) already understands the wire format.

### Typed Record Data Accessors

Strongly-typed `readonly ref struct`s for interpreting RDATA of common record types. All are non-allocating. Parsing is exposed as **extension methods on `DnsRecord`**, keeping `DnsRecord` itself lean while providing discoverable `record.TryParse*` call-site ergonomics. Users can define their own extension methods for custom record types following the same pattern.

```csharp
namespace System.Net;

// --- Data types (readonly ref structs holding parsed RDATA) ---

public readonly ref struct DnsARecordData
{
    public ReadOnlySpan<byte> AddressBytes { get; } // 4 bytes, network byte order
    public IPAddress ToIPAddress(); // convenience, allocates
}

public readonly ref struct DnsAAAARecordData
{
    public ReadOnlySpan<byte> AddressBytes { get; } // 16 bytes, network byte order
    public IPAddress ToIPAddress(); // convenience, allocates
}

public readonly ref struct DnsCNameRecordData
{
    public DnsName CName { get; }
}

public readonly ref struct DnsMxRecordData
{
    public ushort Preference { get; }
    public DnsName Exchange { get; }
}

public readonly ref struct DnsSrvRecordData
{
    public ushort Priority { get; }
    public ushort Weight { get; }
    public ushort Port { get; }
    public DnsName Target { get; }
}

public readonly ref struct DnsSoaRecordData
{
    public DnsName PrimaryNameServer { get; }
    public DnsName ResponsibleMailbox { get; }
    public uint SerialNumber { get; }
    public uint RefreshInterval { get; }
    public uint RetryInterval { get; }
    public uint ExpireLimit { get; }
    public uint MinimumTtl { get; }
}

public readonly ref struct DnsTxtRecordData
{
    // TXT records contain one or more character-strings.
    // Each string is a length-prefixed byte sequence (max 255 bytes).
    public DnsTxtEnumerator EnumerateStrings();
}

public ref struct DnsTxtEnumerator
{
    public ReadOnlySpan<byte> Current { get; }
    public bool MoveNext();
    public DnsTxtEnumerator GetEnumerator();
}

public readonly ref struct DnsPtrRecordData
{
    public DnsName Name { get; }
}

public readonly ref struct DnsNsRecordData
{
    public DnsName Name { get; }
}

// --- Extension methods for parsing typed records ---

public static class DnsRecordExtensions
{
    public static bool TryParseARecord(this DnsRecord record, out DnsARecordData result);
    public static bool TryParseAAAARecord(this DnsRecord record, out DnsAAAARecordData result);
    public static bool TryParseCNameRecord(this DnsRecord record, out DnsCNameRecordData result);
    public static bool TryParseMxRecord(this DnsRecord record, out DnsMxRecordData result);
    public static bool TryParseSrvRecord(this DnsRecord record, out DnsSrvRecordData result);
    public static bool TryParseSoaRecord(this DnsRecord record, out DnsSoaRecordData result);
    public static bool TryParseTxtRecord(this DnsRecord record, out DnsTxtRecordData result);
    public static bool TryParsePtrRecord(this DnsRecord record, out DnsPtrRecordData result);
    public static bool TryParseNsRecord(this DnsRecord record, out DnsNsRecordData result);
}
```

> **Alternative designs considered:**
>
> *Instance methods on `DnsRecord`*: Same call-site ergonomics (`record.TryParseARecord(...)`) without needing the right `using` directive, but couples `DnsRecord` to every known record type and prevents users from adding new ones in the same style.
>
> *Static `TryRead` on data types*: Each data type has `DnsARecordData.TryRead(record, out var result)`. Fully decoupled, but less discoverable — the caller must know the target type name upfront rather than discovering available parsers via IntelliSense on `record.`.

### Usage Examples

#### Constructing a standard A record query

```csharp
// Phase 1: Validate and encode the domain name
Span<byte> nameBuffer = stackalloc byte[DnsName.MaxEncodedLength];
var status = DnsName.TryCreate("example.com", nameBuffer, out var name, out _);
if (status != OperationStatus.Done) { /* handle invalid name */ }

// Phase 2: Write the message
Span<byte> buffer = stackalloc byte[512];
var writer = new DnsMessageWriter(buffer);

var header = DnsMessageHeader.CreateStandardQuery(id: 0x1234);
writer.TryWriteHeader(in header);
writer.TryWriteQuestion(name, DnsRecordType.A);

ReadOnlySpan<byte> message = buffer[..writer.BytesWritten];
// Send 'message' over UDP to DNS server...
```

#### Parsing a DNS response

```csharp
ReadOnlySpan<byte> responseBytes = /* received from DNS server */;
var reader = new DnsMessageReader(responseBytes);

// Check response status
if (reader.Header.ResponseCode != DnsResponseCode.NoError) { /* handle error */ }

// Skip questions (echo of our query)
for (int i = 0; i < reader.Header.QuestionCount; i++)
    reader.TryReadQuestion(out _);

// Read answer records
for (int i = 0; i < reader.Header.AnswerCount; i++)
{
    if (!reader.TryReadRecord(out DnsRecord record))
        break;

    switch (record.Type)
    {
        case DnsRecordType.A:
            record.TryParseARecord(out var a);
            Console.WriteLine($"{record.Name} -> {a.ToIPAddress()}, TTL={record.TimeToLive}s");
            break;
        case DnsRecordType.CNAME:
            record.TryParseCNameRecord(out var cname);
            Console.WriteLine($"{record.Name} -> CNAME {cname.CName}");
            break;
    }
}
```

## High-Level API: DnsResolver

### Overview

The high-level API provides an instance-based, async, TTL-aware DNS resolver. It handles transport (UDP with TCP fallback), retry logic, server failover, and hosts file lookup internally. On Windows, it delegates to `DnsQueryEx` for the common path. On Linux/macOS, it uses the low-level message primitives to communicate with the configured DNS server.

### Result Types

Result types are regular structs (heap-safe, usable across `await` boundaries). Each result carries a `DateTimeOffset ExpiresAt` computed from the wire TTL at the time the response was received.

```csharp
namespace System.Net;

public readonly struct DnsResolvedAddress
{
    public IPAddress Address { get; }
    public DateTimeOffset ExpiresAt { get; }
}

public readonly struct DnsResolvedService
{
    public string Target { get; }
    public ushort Port { get; }
    public ushort Priority { get; }
    public ushort Weight { get; }
    public DateTimeOffset ExpiresAt { get; }

    // Addresses from the additional section of the SRV response, if present.
    // Avoids a separate A/AAAA lookup when the server provides them inline.
    public DnsResolvedAddress[]? Addresses { get; }
}
```

### DnsResolver

```csharp
namespace System.Net;

public class DnsResolver : IAsyncDisposable, IDisposable
{
    // Uses system-configured DNS servers (resolv.conf / Windows registry).
    public DnsResolver();

    // Uses the provided options.
    public DnsResolver(DnsResolverOptions options);

    // High-level: hostname → addresses with TTL.
    // AddressFamily.Unspecified queries both A and AAAA.
    // Respects hosts file unless disabled in options.
    public Task<DnsResolvedAddress[]> ResolveAddressesAsync(
        string hostName,
        AddressFamily addressFamily = AddressFamily.Unspecified,
        CancellationToken cancellationToken = default);

    // High-level: SRV record lookup for service discovery.
    public Task<DnsResolvedService[]> ResolveServiceAsync(
        string serviceName,
        CancellationToken cancellationToken = default);

    // Low-level: arbitrary DNS query for any record type (class is always IN).
    // Returns the raw wire-format response for parsing with DnsMessageReader.
    // For non-IN class queries, use the low-level message primitives
    // (DnsMessageWriter/DnsMessageReader) to construct and send queries directly.
    public Task<DnsQueryResult> QueryAsync(
        string name,
        DnsRecordType type,
        CancellationToken cancellationToken = default);

    public void Dispose();
    public ValueTask DisposeAsync();
}
```

### DnsQueryResult

Bridges the high-level transport layer (retry, server failover, TCP fallback) with the low-level message parser. Returns the raw wire-format response so the user can parse it with `DnsMessageReader` for full access to all sections and record types.

```csharp
namespace System.Net;

public class DnsQueryResult : IDisposable
{
    // Response code from the header (note: only lower 4 bits;
    // full 12-bit RCODE requires parsing the OPT record if present).
    public DnsResponseCode ResponseCode { get; }
    public DnsHeaderFlags Flags { get; }

    // Full wire-format response. Parse with:
    //   var reader = new DnsMessageReader(result.ResponseMessage.Span);
    public ReadOnlyMemory<byte> ResponseMessage { get; }

    public void Dispose();
}
```

### DnsResolverOptions

```csharp
namespace System.Net;

public class DnsResolverOptions
{
    // DNS servers to query. If empty, uses system-configured servers.
    public IList<IPEndPoint> Servers { get; set; } = new List<IPEndPoint>();

    // Maximum number of retry attempts per server.
    // NOTE: Subject to open question #2 — may not be honored on Windows.
    public int MaxRetries { get; set; } = 2;

    // Timeout per individual query attempt.
    // NOTE: Subject to open question #2 — may not be honored on Windows.
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(3);

    // Whether to check the hosts file before querying DNS.
    public bool UseHostsFile { get; set; } = true;
}
```

### Open Questions

1. **Search domains**: Search domain expansion (`resolv.conf` `search` directive + `ndots` option) is critical for Kubernetes, where services are accessed by short names (e.g., `my-service` → `my-service.default.svc.cluster.local`). This is a client-side feature — the DNS server doesn't handle it. On Windows, `DnsQueryEx` applies system search domains automatically. On Linux/macOS, our stub resolver would need to implement the expansion logic itself. Questions to resolve:
   - Should `DnsResolverOptions` expose a `SearchDomains` override, or should the resolver always read them from system config (`resolv.conf`)?
   - Should `QueryAsync` (the low-level arbitrary query) also apply search domain expansion, or only the high-level convenience methods (`ResolveAddressesAsync`, `ResolveServiceAsync`)?

2. **Failover and timeout configuration**: Experimental testing shows that `DnsQueryEx` on Windows handles server failover and retries internally (~1s per-server timeout, ~12s total for 2 unreachable servers), with **no public API to control this behavior**. On Linux/macOS, our stub resolver would implement failover ourselves and could expose full control. This creates a platform consistency problem:
   - **Option A: Expose `MaxRetries` / `Timeout` options and only honor them on Linux/macOS.** This is honest but creates confusing platform-dependent behavior — the same settings would have different effects on different OSes.
   - **Option B: Do not expose retry/timeout options.** Accept the platform's default behavior on Windows and implement reasonable defaults on Linux/macOS to approximate Windows behavior. Simpler API, but limits advanced users.
   - **Option C: Bypass `DnsQueryEx` on Windows and implement our own failover on all platforms.** This gives full control but sacrifices integration with Windows DNS client features (cache, NRPT policy, system search domains).
   - **Option D: Expose options but document them as best-effort hints.** Settings are applied precisely on Linux/macOS and ignored (or approximated) on Windows. This matches how some .NET networking options already work across platforms.

### Alternative Design: Static API

An alternative to the instance-based `DnsResolver` is to expose the same methods as static methods accepting `DnsResolverOptions` as a parameter:

```csharp
public static class DnsResolver
{
    public static Task<DnsResolvedAddress[]> ResolveAddressesAsync(
        string hostName,
        DnsResolverOptions? options = null,
        CancellationToken cancellationToken = default);
    // ...
}
```

This would simplify one-off queries and could also enable replacing the implementation of existing `System.Net.Dns` static methods (e.g., `Dns.GetHostAddresses`) with the new resolver, addressing some of their current limitations (no TTL, synchronous-only on Linux) without requiring callers to manage a resolver instance.

However, static methods introduce challenges around resource management (socket reuse, connection pooling for TCP fallback) and testability (cannot be injected or mocked). The instance-based design is preferred as the primary API, with static convenience methods as a possible future addition.

## Future Work: EDNS0 (OPT Record) Support

EDNS0 (RFC 6891) extends DNS via a pseudo-record (OPT, type 41) placed in the additional section. It is practically required for modern DNS usage — without it, UDP responses are capped at 512 bytes, causing unnecessary TCP fallback. Support can be added incrementally on top of the current design:

- **Writer**: Add a `TryWriteOptRecord(ushort udpPayloadSize, ...)` method (or reintroduce a general `TryWriteResourceRecord`) to emit OPT in the additional section of requests.
- **Reader**: OPT records are already parseable as regular `DnsRecord`s, but their fields are repurposed (Class = UDP payload size, TTL = extended RCODE + version + flags). A `TryParseOptRecord` extension method would reinterpret these correctly.
- **Extended RCODE**: The response code is split across the header (lower 4 bits) and the OPT record's TTL field (upper 8 bits). The OPT accessor should expose the full 12-bit combined RCODE.
- **Fallback**: Some middleboxes drop EDNS0 queries. A robust resolver should retry without EDNS0 on timeout.
