# System.Net.NameResolution API Design

## Motivation

The existing `System.Net.Dns` class does not expose TTL (Time-To-Live) information from DNS responses. This forces consumers — most notably `SocketsHttpHandler` and the broader HTTP stack — to use conservative heuristics when deciding whether cached DNS results are still valid. In practice, this leads to premature disposal of HTTP connections in order to react to potential DNS-level changes (e.g., failover, load balancing rotation), even when the DNS records haven't actually changed. A TTL-aware API would allow consumers to know exactly when endpoint addresses should be rechecked, reducing unnecessary connection churn and improving performance.

Another motivation exposing more granular access to DNS records, currently, there is no API to retrieve TXT, MX, and many other record types.

## Goals

- **Expose TTL information** from DNS responses through high-level resolution APIs, enabling callers to make informed caching and connection lifetime decisions.
- **Support cross-platform operation**, accounting for differences in platform capabilities:
  - On **Windows**, OS-level APIs can return TTL information directly.
  - On **Linux/macOS**, the high-level TTL-aware API will be backed by a built-in stub resolver that communicates with the configured DNS server (from `/etc/resolv.conf`).
- **Respect existing platform resolution behavior** where possible, including:
  - Hosts file entries (`/etc/hosts`, `%SystemRoot%\System32\drivers\etc\hosts`).
  - Local stub resolvers such as `systemd-resolved` (by delegating to the configured nameserver, which may be `127.0.0.53`).
  - Search domains and other `resolv.conf` directives.
- **Provide a testable, configurable API** through an instance-based resolver class that supports dependency injection, custom DNS server configuration, and per-instance settings (timeouts, retry policy, etc.).
- **Implement a stub resolver only** — the built-in resolver will not perform recursive resolution. It assumes the target DNS server (typically a local or ISP recursive resolver) handles recursion.

## For discussion

- **Provide low-level DNS message APIs** For non-Windows platforms, we will need to implement reading/writing of DNS messages, so we may also decide to expose low-level primitives as public API to enable users more fine-grained control.

## Non-Goals

- **Full recursive resolver** — the implementation delegates recursion to the configured upstream DNS server.
- **DNSSEC validation** — the resolver may surface the AD (Authenticated Data) flag from responses, but will not perform its own DNSSEC validation.
- **DNS-over-HTTPS (DoH) / DNS-over-TLS (DoT)** — encrypted transport is out of scope for the initial design, though the architecture should not preclude future support.
- **mDNS / LLMNR** — multicast DNS and link-local multicast name resolution are out of scope.
- **Full `nsswitch.conf` implementation** — the resolver will handle hosts file lookup and DNS, but will not implement the full NSS plugin pipeline.

## Assumptions

- **Systemd resolver** - Linux systems with systemd-resolver run a stub listener at 127.0.0.53. Querries targeting this endpoint receive the same handling as gethostaddress and other glibc APIs including hostfiles, caching, DNSSEC, etc.

  - systemd-resolved is not universal, some distros don't have it at all, some distros don't enable it by default.
  - example distros without systemd-resolved: Alpine Linux, Gentoo
  - example distros with systemd-resolved disabled are Debian, RHEL, CentOS, SUSE, Oracle.
  - Servers generally don't use resolved and query upstream DNS server directly

## High-Level API: Static DNS APIs

The high-level API provides an async, TTL-aware DNS resolution using the OS-configured DNS server.

### Preferred design: separate methods for each type

```csharp
static class Dns
{
    // There are no conflicts with existing Dns methods. Most existing methods start with GetHost*

    // existing (obsolete) method
    // public static System.Net.IPHostEntry Resolve(string hostName);

    // Queries both A and AAAA, returns all addresses.
    public static Task<DnsResult<DnsAddressRecord>> ResolveAddressesAsync(
        string hostName, CancellationToken cancellationToken = default);

    // Overload to allow specifying only A or only AAAA records
    public static Task<DnsResult<DnsAddressRecord>> ResolveAddressesAsync(
        string hostName, AddressFamily addressFamily, CancellationToken cancellationToken = default);

    // SRV lookup. Collects additional-section A/AAAA records for each target.
    public static Task<DnsResult<DnsSrvRecord>> ResolveServiceAsync(
        string serviceName, CancellationToken cancellationToken = default);

    // MX lookup.
    public static Task<DnsResult<DnsMxRecord>> ResolveMxAsync(
        string name, CancellationToken cancellationToken = default);

    // TXT lookup. Each record's Strings are the character-strings decoded as UTF-8.
    public static Task<DnsResult<DnsTxtResult>> ResolveTxtAsync(
        string name, CancellationToken cancellationToken = default);

    // CNAME lookup.
    public static Task<DnsResult<DnsCNameResult>> ResolveCNameAsync(
        string name, CancellationToken cancellationToken = default);

    // PTR lookup (reverse DNS).
    // alternative: accept IPAddress instead of name
    public static Task<DnsResult<DnsPtrResult>> ResolvePtrAsync(
        string name, CancellationToken cancellationToken = default);

    // NS lookup.
    public static Task<DnsResult<DnsNsResult>> ResolveNsAsync(
        string name, CancellationToken cancellationToken = default);
}
```

Usage:

```csharp
// Simple address lookup (queries both A and AAAA)
DnsResult<DnsAddressRecord> addresses = await Dns.ResolveAddressesAsync("example.com");

// SRV lookup for service discovery (collects additional-section addresses)
DnsResult<DnsSrvRecord> services = await Dns.ResolveServiceAsync("_http._tcp.example.com");

// MX lookup
DnsResult<DnsMxRecord> mailServers = await Dns.ResolveMxAsync("example.com");

// TXT lookup
DnsResult<DnsTxtResult> txtRecords = await Dns.ResolveTxtAsync("example.com");

// PTR lookup (reverse DNS)
DnsResult<DnsPtrResult> ptr = await Dns.ResolvePtrAsync("1.0.0.10.in-addr.arpa");
// DnsResult<DnsPtrResult> ptr = await Dns.ResolvePtrAsync(IPAddress.Parse("1.0.0.10"));

// CNAME lookup
DnsResult<DnsCNameResult> cname = await Dns.ResolveCNameAsync("www.example.com");

// NS lookup
DnsResult<DnsNsResult> ns = await Dns.ResolveNsAsync("example.com");
```

There are more than 40 DNS record types, the list above is a selection of the most commonly used ones (?). The ability to read *any* existing record type as raw bytes is part of the low-level APIs later in the proposal.

### Result Wrapper

High-level methods return `DnsResult<T>`, a generic wrapper that carries the DNS response code alongside the resolved records. This allows callers to distinguish between:

- **Success**: `ResponseCode == NoError`, `Records` is non-empty
- **NODATA**: `ResponseCode == NoError`, `Records` is empty (name exists but has no records of the requested type)
- **NXDOMAIN**: `ResponseCode == NameError`, `Records` is empty (name does not exist)

```csharp
namespace System.Net;

public readonly struct DnsResult<T>
{
    public DnsResponseCode ResponseCode { get; }
    public ReadOnlyList<T> Records { get; }

    //
    // For negative responses (NXDOMAIN/NODATA), `NegativeCacheExpiresAt` is
    // populated from the SOA minimum TTL in the authority section (per RFC 2308
    // §5), enabling callers to cache negative results.
    //
    // Alternative name: NegativeCacheExpiration
    // Alternative: public int? NegativeCacheTtl { get; }
    public DateTimeOffset? NegativeCacheExpiresAt { get; }
}
```

### Record Types

Each record type is a regular struct (heap-safe, usable across `await` boundaries). All carry `DateTimeOffset ExpiresAt` computed from the wire TTL. Each type implements `IDnsRecord<TSelf>` with its own resolution strategy.

```csharp
namespace System.Net;

// Queries both A and AAAA, returns all addresses.
public readonly struct DnsAddressRecord : IDnsRecord<DnsAddressRecord>
{
    public IPAddress Address { get; }

    // Alternative name: Expiration
    // Alternative: public int Ttl { get; } (and same for all types below)
    public DateTimeOffset ExpiresAt { get; }
}

// Queries SRV, collects additional-section A/AAAA records for each target.
public readonly struct DnsSrvRecord : IDnsRecord<DnsSrvRecord>
{
    public string Target { get; }
    public ushort Port { get; }
    public ushort Priority { get; }
    public ushort Weight { get; }
    public DateTimeOffset ExpiresAt { get; }
    public DnsAddressRecord[]? Addresses { get; }
}

public readonly struct DnsMxRecord : IDnsRecord<DnsMxRecord>
{
    public string Exchange { get; }
    public ushort Preference { get; }
    public DateTimeOffset ExpiresAt { get; }
}

public readonly struct DnsTxtResult : IDnsRecord<DnsTxtResult>
{
    public string[] Strings { get; }
    public DateTimeOffset ExpiresAt { get; }
}

public readonly struct DnsCNameResult : IDnsRecord<DnsCNameResult>
{
    public string CanonicalName { get; }
    public DateTimeOffset ExpiresAt { get; }
}

public readonly struct DnsPtrResult : IDnsRecord<DnsPtrResult>
{
    public string Name { get; }
    public DateTimeOffset ExpiresAt { get; }
}

public readonly struct DnsNsResult : IDnsRecord<DnsNsResult>
{
    public string Name { get; }
    public DateTimeOffset ExpiresAt { get; }
}
```

### Alternative: Generic `Dns.ResolveAsync<T>` Design

The core idea is a single generic entry point where the type parameter `T` determines which DNS queries are sent and how the results are parsed:

```csharp
// Static API (preferred entry point)
public static class Dns
{
    static Task<DnsResult<T>> ResolveAsync<T>(string name, CancellationToken ct = default)
        where T : IDnsRecord<T>;

    // Overload to allow specifying only A or only AAAA records
    public static Task<DnsResult<DnsAddressRecord>> ResolveAddressesAsync(
        string hostName, AddressFamily addressFamily, CancellationToken cancellationToken = default);
}
```

Each result type `T` implements `IDnsRecord<T>`, which provides a **static abstract resolution strategy**. Rather than mapping `T` to a single DNS record type, each type owns its full parsing logic — it receives a query-sending delegate, sends whatever queries it needs, parses the responses, and returns the result.

```csharp
namespace System.Net;

// Delegate for sending a DNS query and receiving the raw response.
// Returns a rented buffer and its valid length. The caller must return the buffer to the pool.
public delegate Task<(byte[] Buffer, int Length)> DnsSendQueryAsync(
    string name, DnsRecordType type, CancellationToken cancellationToken);

public interface IDnsRecord<TSelf> where TSelf : IDnsRecord<TSelf>
{
    // Each type provides its own resolution strategy.
    // The delegate handles transport (UDP/TCP, retries, server failover).
    // The type handles query composition and response parsing.
    //
    // note: implementations will use explicit interface implementation, so
    //       this member will not be publicly visible as e.g. DnsAddressRecord.ResolveAsync(...)
    static abstract Task<DnsResult<TSelf>> ResolveAsync(
        string name,
        DnsSendQueryAsync sendQueryAsync,
        CancellationToken cancellationToken);
}
```

Usage:

```csharp
// Simple address lookup (queries both A and AAAA)
DnsResult<DnsAddressRecord> addresses = await Dns.ResolveAsync<DnsAddressRecord>("example.com");

// SRV lookup for service discovery (collects additional-section addresses)
DnsResult<DnsSrvRecord> services = await Dns.ResolveAsync<DnsSrvRecord>("_http._tcp.example.com");

// MX lookup
DnsResult<DnsMxRecord> mailServers = await Dns.ResolveAsync<DnsMxRecord>("example.com");

// TXT lookup
DnsResult<DnsTxtResult> txtRecords = await Dns.ResolveAsync<DnsTxtResult>("example.com");

// PTR lookup (reverse DNS)
DnsResult<DnsPtrResult> ptr = await Dns.ResolveAsync<DnsPtrResult>("1.0.0.10.in-addr.arpa");

// CNAME lookup
DnsResult<DnsCNameResult> cname = await Dns.ResolveAsync<DnsCNameResult>("www.example.com");

// NS lookup
DnsResult<DnsNsResult> ns = await Dns.ResolveAsync<DnsNsResult>("example.com");
```

## Configurable API: Instance-Based DnsResolver

For scenarios requiring custom configuration (specific DNS servers, timeout tuning, dependency injection), an instance-based `DnsResolver` can be also provided:

```csharp
namespace System.Net;

public class DnsResolver : IAsyncDisposable, IDisposable
{
    // uses default options (system-configured DNS server)
    public DnsResolver();

    public DnsResolver(DnsResolverOptions options);

    // Generic: resolve any supported record type.
    public Task<DnsResult<T>> ResolveAsync<T>(
        string name,
        CancellationToken cancellationToken = default)
        where T : IDnsRecord<T>;

    // or method-per-type alternative, same as static Dns methods

    public void Dispose();
    public ValueTask DisposeAsync();
}

public class DnsResolverOptions
{
    public IList<IPEndPoint> Servers { get; set; } = new List<IPEndPoint>();
    public int MaxRetries { get; set; } = 2;
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(3);
    // public bool UseHostsFile { get; set; } = true;

    // Possibly more config options coming in the future
}
```

### Open Questions

1. **Search domains**: Should `DnsResolverOptions` expose a `SearchDomains` override, or should the resolver always read from system config? Should `QueryAsync` also apply search domain expansion, or only `ResolveAsync<T>`?

2. **Failover and timeout configuration**: `DnsQueryEx` on Windows handles failover internally with no public API to control it, should we hardcode the behavior on Linux and remove the related options?

3. **Caching**: Should we implement caching of DNS responses, or leave the cache management to the users?

    - Internal cache: easier to use, more complex implementation (possibly requiring more DnsResolverOptions)
    - No cache: simple implementation, additional complexity for users, but may be more efficient (e.g. users will cache only results for one domain name on a class field and don't need hashtable-based cache)
    - Windows already performs caching on the API level
    - Linux can also be configured to cache at the systemd stub-resolver level at 127.0.0.53
    - Problem: cache invalidation on network changes? Hostfile monitoring?

4. **Hostfile handling**: Windows resolver and systemd stub-resolver already handle hostfiles. Is it really necessary to support hostfiles if user wants to point the DnsResolver to a custom DNS server?

5. **App-defined host-files**: Should applications be able to provide custom, hostfile-like mapping to support mocking for testing purposes?

    - Microsoft.Extensions.ServiceDiscovery - supports multiple sources for service discovery, including config files, DNS A/AAAA, DNS SRV, etc. => the problem already has a solution in external packages, do we need an in-box one?

## Low-Level API: DNS Message Primitives (Draft)

The low-level API provides non-allocating, type-safe primitives for constructing DNS query messages and parsing DNS response messages. These types operate over caller-provided `Span<byte>` / `ReadOnlySpan<byte>` buffers.

### Design Principles

- **`ref struct`-based**: Reader, writer, and related types like `DnsEncodedName` are `ref struct`s because they hold `Span<T>` references. This ensures stack-only usage and prevents accidental heap allocation.
- **`Try*` pattern**: All operations return `bool` to indicate success/failure (buffer too small, malformed data), rather than throwing exceptions. This is consistent with low-level .NET APIs.
- **Sequential cursor**: Both reader and writer maintain an internal position that advances with each operation. DNS messages are inherently sequential (header → questions → answers → authority → additional).
- **Lazy domain name resolution**: `DnsEncodedName` holds a reference to the full message buffer and resolves compression pointers on demand, avoiding intermediate copies.

### DnsQueryResult

Bridges the high-level transport layer (retry, server failover, TCP fallback) with the low-level message parser. Returns the raw wire-format response so the user can parse it with `DnsMessageReader` for full access to all sections and record types.

```csharp
namespace System.Net;

public class DnsQueryResult : IDisposable
{
    public DnsResponseCode ResponseCode { get; }
    public DnsHeaderFlags Flags { get; }
    public ReadOnlyMemory<byte> ResponseMessage { get; }
    public void Dispose();
}

public static class Dns
{
    public static Task<DnsQueryResult> ResolveAsync(DnsRecordType recordType, DnsRecordClass recordClass, string name, CancellationToken ct = default);
}
```

### DnsMessageReader

A ref struct that reads DNS messages from a buffer. Reads sequentially: header (parsed eagerly in TryCreate), then questions, then resource records (answers, authority, additional in order).

The caller uses `Header.QuestionCount`, `Header.AnswerCount`, `Header.AuthorityCount`, and `Header.AdditionalCount` to determine how many items to read and which section each record belongs to.

```csharp
namespace System.Net;

public ref struct DnsMessageReader
{
    // Attempts to create a reader. Parses the header eagerly.
    // Returns false if the buffer is too small for a valid header.
    public static bool TryCreate(ReadOnlySpan<byte> message, out DnsMessageReader reader);

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
public enum DnsHeaderFlags : byte
{
    None                = 0,
    AuthoritativeAnswer = 1 << 6,  // AA — wire bit 10
    Truncation          = 1 << 5,  // TC — wire bit 9
    RecursionDesired    = 1 << 4,  // RD — wire bit 8
    RecursionAvailable  = 1 << 3,  // RA — wire bit 7
    AuthenticData       = 1 << 1,  // AD — wire bit 5 (RFC 4035)
    CheckingDisabled    = 1 << 0,  // CD — wire bit 4 (RFC 4035)
}
```

### DnsMessageHeader

A mutable struct representing the fixed 12-byte DNS message header (RFC 1035 §4.1.1). Used by both reader and writer. Properties default to zero/false, so callers only need to set the fields relevant to their use case.

Wire format (each row is 16 bits):

```
                                 1  1  1  1  1  1
   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 |                      ID                         |
 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 |QR|   OpCode  |AA|TC|RD|RA| Z|AD|CD|   RCODE    |
 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 |                    QDCOUNT                      |
 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 |                    ANCOUNT                      |
 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 |                    NSCOUNT                      |
 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 |                    ARCOUNT                      |
 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```

This layout drives the enum sizing decisions:

- **`DnsOpCode : byte`** — 4-bit field (bits 1–4), fits in a byte.
- **`DnsResponseCode : ushort`** — 4-bit field (bits 12–15) in the base header, but EDNS0 extends it to 12 bits via the OPT record, so `ushort` provides room for future extension.
- **`DnsHeaderFlags : byte`** — 6 individual flag bits (AA, TC, RD, RA, AD, CD) packed into a `[Flags]` enum. Values are the wire bit positions shifted right by 4, so the enum fits in a `byte`. Encoding shifts left by 4 to restore wire positions; decoding masks and shifts right by 4.

```csharp
namespace System.Net;

public struct DnsMessageHeader
{
    public ushort Id { get; set; }
    public bool IsResponse { get; set; }              // QR bit
    public DnsOpCode OpCode { get; set; }
    public DnsHeaderFlags Flags { get; set; }
    public DnsResponseCode ResponseCode { get; set; } // RCODE
    public ushort QuestionCount { get; set; }         // QDCOUNT
    public ushort AnswerCount { get; set; }           // ANCOUNT
    public ushort AuthorityCount { get; set; }        // NSCOUNT
    public ushort AdditionalCount { get; set; }       // ARCOUNT
}
```

### DnsEncodedName

Represents a domain name in DNS wire format. Used by both the read path (names parsed from response messages) and the write path (names created from strings for query messages).

Internally holds `(ReadOnlySpan<byte> buffer, int offset)`. For names parsed from responses, `buffer` is the full message (needed to follow compression pointers per RFC 1035 §4.1.4). For names created from strings, `buffer` is a small caller-provided encode buffer with flat labels (no compression pointers). Label enumeration handles compression pointers transparently.

Internally, the type also tracks whether the wire encoding contains compression pointers (`_hasPointers`). This enables efficient serialization: names without pointers can be copied with a single `Span.CopyTo`, while names parsed from responses with compression pointers are expanded label-by-label only when needed.

Comparison is case-insensitive per DNS specification.

```csharp
namespace System.Net;

// Represents a strongly-typed, validated domain name
public readonly ref struct DnsEncodedName
{
    // Maximum wire-format size of any valid domain name
    // (including length prefixes and root label terminator).
    public const int MaxEncodedLength = 255;

    //
    // --- Write path: create from a dotted string ---
    //

    // Validates the name against RFC 1035 rules (label max 63 bytes, total max 253 chars,
    // valid characters) and encodes into wire format in the destination buffer.
    // Returns:
    //   Done          - success
    //   InvalidData   - name violates DNS rules
    //   DestinationTooSmall - destination buffer too small
    public static OperationStatus TryEncode(
        ReadOnlySpan<char> name,
        Span<byte> destination,
        out DnsEncodedName result,
        out int bytesWritten);

    //
    // --- Read path: parse from a wire-format buffer ---
    //

    // Parses a DNS name from a wire-format buffer at the given offset.
    // Validates that the name is well-formed (valid label lengths, no truncation).
    // The buffer is retained by the returned DnsEncodedName to support compression pointer resolution.
    // bytesConsumed is the number of bytes consumed at offset (not following compression pointers).
    public static bool TryParse(
        ReadOnlySpan<byte> buffer,
        int offset,
        out DnsEncodedName name,
        out int bytesConsumed);

    //
    // --- Shared: works identically for parsed and created names ---
    //

    // Decodes the domain name into the destination buffer as a dotted string.
    // Decodes punyencoding if applicable
    public bool TryDecode(Span<char> destination, out int charsWritten);

    // Compares this name to a dotted string representation (e.g., "example.com").
    // Case-insensitive. Does not allocate.
    // handles puny encoding transparently
    public bool Equals(ReadOnlySpan<char> name);

    // Enumerates the individual labels (e.g., "example" then "com").
    // Each label is a ReadOnlySpan<byte> of the raw ASCII bytes (no length prefix, no dot).
    // Follows compression pointers transparently.
    public DnsLabelEnumerator EnumerateLabels();

    // Convenience method. Allocates a string.
    public override string ToString();

    //
    // TODO: optional members below, may be useful in some cases
    //

    // Returns the character count of the decoded dotted string representation.
    // there is reasonable upper bound (256) that can be used when allocating space for the TryDecode method
    public int GetFormattedLength();

    // Copies the encoded representation to the target destination, expanding any compression pointers if
    // necessary
    // This method is already used internally to simplify DnsMessageWriter (accepts DnsEncodedName as parameter)
    public bool TryCopyEncodedTo(Span<byte> destination, out int bytesWritten)
}

// Duck-typed enumerator for foreach support (same pattern as Span<T>.Enumerator).
public ref struct DnsLabelEnumerator
{
    public ReadOnlySpan<byte> Current { get; }
    public bool MoveNext();
    public DnsLabelEnumerator GetEnumerator();
}
```

#### Validation

Both `TryParse` (read path) and `TryEncode` (write path) perform the same structural and content validation, ensuring that any successfully created `DnsEncodedName` can be safely enumerated, decoded, and round-tripped without further checks. The `DnsLabelEnumerator` trusts this up-front validation and uses only `Debug.Assert` internally.

**Structural rules (RFC 1035):**

- Each label must be 1–63 bytes (the zero-length root label terminates the name).
- The dotted ASCII form must not exceed 253 characters.
- The wire-format encoding must not exceed 255 bytes (`MaxEncodedLength`).
- The name must be properly terminated with a root label (zero byte).

**Label content rules (LDH + underscore):**

- Labels may only contain ASCII letters (`a-z`, `A-Z`), digits (`0-9`), hyphens (`-`), and underscores (`_`). Underscores are allowed for compatibility with SRV records (`_http._tcp`) and DKIM/DMARC (`_dmarc`, `_domainkey`).
- Labels must not start or end with a hyphen.
- Validation uses `SearchValues<byte>` with `IndexOfAnyExcept` for efficient character checking.

**Compression pointer rules (read path only):**

- Compression pointers (two high bits set, per RFC 1035 §4.1.4) must point strictly backwards in the buffer (`pointer < currentPosition`). Forward and self-referencing pointers are rejected to prevent infinite loops from malicious input.
- A maximum of 16 pointer hops is enforced to bound processing time.
- Reserved label type bytes (upper two bits = `01` or `10`) are rejected.

**ACE detection:**

- During validation, each label is checked for the `xn--` prefix (case-insensitive) to detect ACE/Punycode-encoded internationalized labels.
- The result is stored as an internal `_isAce` flag, allowing `TryDecode`, `GetFormattedLength`, and `ToString` to skip IDN processing for pure-ASCII names.

**IDN (write path):**

- If the input name contains non-ASCII characters, it is converted to ACE form via `IdnMapping.GetAscii()` before encoding. The ACE form is then validated with the same label content rules.

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
        DnsEncodedName name,
        DnsRecordType type,
        DnsRecordClass @class = DnsRecordClass.Internet);
}
```

### DnsQuestion

Represents a parsed question entry from the question section.

```csharp
namespace System.Net;

public readonly ref struct DnsQuestion
{
    public DnsEncodedName Name { get; }
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
    public DnsEncodedName Name { get; }
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
>
> ```csharp
> // Reads a domain name at the given byte offset within this record's RDATA.
> // Handles compression pointers using the underlying message context.
> public bool TryReadName(int rdataOffset, out DnsEncodedName name, out int bytesConsumed);
> ```
>
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
    public DnsEncodedName CName { get; }
}

public readonly ref struct DnsMxRecordData
{
    public ushort Preference { get; }
    public DnsEncodedName Exchange { get; }
}

public readonly ref struct DnsSrvRecordData
{
    public ushort Priority { get; }
    public ushort Weight { get; }
    public ushort Port { get; }
    public DnsEncodedName Target { get; }
}

public readonly ref struct DnsSoaRecordData
{
    public DnsEncodedName PrimaryNameServer { get; }
    public DnsEncodedName ResponsibleMailbox { get; }
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
    public DnsEncodedName Name { get; }
}

public readonly ref struct DnsNsRecordData
{
    public DnsEncodedName Name { get; }
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
Span<byte> nameBuffer = stackalloc byte[DnsEncodedName.MaxEncodedLength];
var status = DnsEncodedName.TryEncode("example.com", nameBuffer, out var name, out _);
if (status != OperationStatus.Done) { /* handle invalid name */ }

// Phase 2: Write the message
Span<byte> buffer = stackalloc byte[512];
var writer = new DnsMessageWriter(buffer);

var header = new DnsMessageHeader { Id = 0x1234, Flags = DnsHeaderFlags.RecursionDesired, QuestionCount = 1 };
writer.TryWriteHeader(in header);
writer.TryWriteQuestion(name, DnsRecordType.A);

ReadOnlySpan<byte> message = buffer[..writer.BytesWritten];
// Send 'message' over UDP to DNS server...
```

#### Parsing a DNS response

```csharp
ReadOnlySpan<byte> responseBytes = /* received from DNS server */;
DnsMessageReader.TryCreate(responseBytes, out var reader);

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

## Future Work: Alternative Transports (DoT / DoH / DoQ)

The initial implementation uses the classic DNS transport (UDP with TCP fallback on TC bit, RFC 1035 / 7766). Modern deployments increasingly use encrypted transports: DNS-over-TLS (DoT, RFC 7858), DNS-over-HTTPS (DoH, RFC 8484), and DNS-over-QUIC (DoQ, RFC 9250). The design accommodates them by introducing a transport abstraction.

### Transport Abstraction

Today the resolver's `SendQueryAsync` method takes a query (name + record type) and returns a raw response buffer. This is the natural cut point. We split it into an orchestration layer (retry, failover, UDP→TCP fallback, response validation) and a pluggable transport that only moves bytes:

```csharp
public abstract class DnsTransport : IAsyncDisposable
{
    // query is the fully-encoded DNS message. Returned buffer is rented from
    // ArrayPool; the caller returns it after use.
    public abstract Task<(byte[] Buffer, int Length)> SendQueryAsync(
        ReadOnlyMemory<byte> query, CancellationToken cancellationToken);

    public virtual ValueTask DisposeAsync() => default;

    // Built-in factories
    public static DnsTransport Udp(IPEndPoint server, TimeSpan timeout);
    public static DnsTransport Tcp(IPEndPoint server, TimeSpan timeout);
    public static DnsTransport Tls(IPEndPoint server, string host,
        SslClientAuthenticationOptions? tls = null);
    public static DnsTransport Https(Uri endpoint, HttpMessageHandler? handler = null);
    public static DnsTransport Quic(IPEndPoint server, string host);
}
```

`DnsResolverOptions` gains a transport hook, and `DnsResolver` becomes `IAsyncDisposable` so it can own the transport lifetime:

```csharp
public sealed class DnsResolver : IAsyncDisposable
{
    public DnsResolver(DnsResolverOptions options);
    public ValueTask DisposeAsync();
}

public class DnsResolverOptions
{
    // Existing options...
    public IList<IPEndPoint> Servers { get; set; } = new List<IPEndPoint>();

    // New: if set, overrides the default UDP+TCP-fallback transport built from Servers.
    // When null (default), the resolver uses classic UDP/TCP per-server.
    // Invoked at most once, lazily on first query. The resolver owns the
    // returned instance and disposes it in DnsResolver.DisposeAsync.
    public Func<DnsTransport>? TransportFactory { get; set; }
}
```

Because `IDnsRecord<T>.ResolveAsync` receives a transport-agnostic `DnsSendQueryAsync` delegate, **no record-type code changes** — DoT/DoH/DoQ are opaque to the parsing layer.

### Ownership and Lifetime

Ownership follows a single rule: **whoever constructs a disposable, disposes it.**

- **`TransportFactory` is invoked at most once, lazily, on the first query.** Eager construction in the resolver constructor would force a TLS handshake during construction, which is not async-safe.
- The resolver owns the transport it created via the factory and disposes it in `DnsResolver.DisposeAsync`.
- `DnsResolver.DisposeAsync` should wait for outstanding queries to drain before disposing the transport (same contract as `HttpClient`).
- A transport's own `DisposeAsync` must **only** dispose state it created itself. If a user's factory captures a pre-built `HttpClient` or `SslClientAuthenticationOptions` so they can be shared across resolvers, the transport wraps those without owning them (standard `HttpClient`-wrapper etiquette).
- The process-wide static path (`Dns.ResolveAsync<T>`) uses a framework-owned default resolver with the classic UDP+TCP transport. Users who need a custom transport must construct their own `DnsResolver` and dispose it.
- Multiple concurrent `ResolveAsync` calls on one resolver share the one transport — transport implementations must be thread-safe.

### Error Taxonomy

Transports signal failures by throwing one of three categories:

| Category | Examples | Retriable? |
|---|---|---|
| `OperationCanceledException` | caller cancelled | No — propagate immediately |
| `DnsTransportException` (new, wraps `SocketException`, `IOException`, HTTP 5xx, QUIC errors) | timeout, connection reset, transient network fault, malformed response (header unparseable) | **Yes** |
| Fatal exceptions | `AuthenticationException` (TLS cert failure), `ArgumentException`, `ObjectDisposedException` | No — indicate config / programmer error |

Anything else bubbling out of a transport is a bug in that transport.

Transports MAY internally retry **once** on stale-connection signals — TCP RST after idle, HTTP/2 GOAWAY, QUIC idle timeout — because the resolver cannot distinguish "stale pooled connection" from "server is dead". This is invisible to the resolver and does not count against `MaxRetries`. Transports MUST NOT retry on timeouts; timing is the resolver's budget to manage.

### Retry and Failover Rules

The resolver orchestrates retry. DNS queries are idempotent, so blind retry is safe.

| Signal | Resolver action |
|---|---|
| Per-attempt timeout | Count as retry, try next server (wrap-around), up to `MaxRetries` |
| `DnsTransportException` | Count as retry, try next server |
| Malformed response | Treat as transport error and retry |
| ID / question mismatch (UDP only) | Discard and keep reading within the same timeout window (does **not** count as a retry), up to a small cap |
| TC bit set (UDP only) | Transparent TCP fallback on the **same** server — does not count as a retry |
| RCODE `NoError` / `NxDomain` | Return as result (NXDOMAIN is a valid negative answer, cached per SOA TTL) |
| RCODE `ServFail` / `Refused` | Retry on next server; surface after exhausting `MaxRetries` |
| RCODE anything else | Surface to caller |
| `OperationCanceledException` | Propagate immediately |
| Fatal exceptions | Propagate immediately |

Notes:

- **Timeout budget**: `DnsResolverOptions.Timeout` is per-attempt, enforced by the resolver via a linked CTS passed to `SendQueryAsync`. Total worst-case wait ≈ `MaxRetries × Timeout`. We either document this or add an explicit `TotalTimeout`.
- **Transport-internal timeouts** (e.g., TLS handshake) must be ≤ the CTS deadline the transport receives; they never extend it.
- **Connection re-establishment**: if a pooled connection is broken, the transport transparently reopens on the next query (subject to the single stale-connection retry above). TLS/QUIC authentication failures are fatal and must not trigger reconnect loops.
- **Backoff**: no delay before the first retry; optional small fixed delay (e.g., 100 ms) between subsequent retries. No exponential — DNS deadlines are short enough. *Open question below.*
- **Cancellation isolation**: cancelling one query on a shared transport must not affect other in-flight queries on the same connection. Transports must use a per-call CTS, not a shared one.
- **Observability**: each retry, failover, and UDP→TCP fallback should emit an `EventSource` / `Activity` event. Out of scope for the first transport milestone, but the plumbing for it should be designed in up-front.

### Per-Transport Notes

| Transport | Wire format | Port | Reuses |
|---|---|---|---|
| UDP | bare message | 53 | — |
| TCP | 2-byte length prefix + message | 53 | — |
| **DoT** | identical to TCP, wrapped in `SslStream` | 853 | TCP framing |
| **DoH** | HTTP POST with `application/dns-message` body (or GET with base64url `dns=` parameter) | 443 | — (needs `HttpClient`) |
| **DoQ** | one message per QUIC stream, length-prefixed like TCP | 853 | TCP framing, `System.Net.Quic` |

- **DoT** is the cheapest increment — wrap the existing TCP send/receive logic in `SslStream`.
- **DoH** needs a `Uri`-based server identity rather than `IPEndPoint`, and reuses a shared `HttpClient` for HTTP/2 multiplexing.
- **DoQ** maps naturally onto QUIC streams (one query per stream), but depends on `System.Net.Quic`.
- For all three, there is **no TCP fallback path** — the transport carries arbitrary-size responses natively, so the orchestration layer must skip TC-bit handling when a non-UDP transport is in use.

### Connection Management

UDP opens a fresh socket per query — fine, since there is no handshake. DoT/DoH/DoQ must pool the underlying connection across queries; otherwise every query pays for a TLS handshake (~1 RTT) or worse. Each secure transport therefore owns state and is `IAsyncDisposable`:

- **DoT**: keep TCP+TLS connection open, pipeline queries with distinct IDs per RFC 7766.
- **DoH**: reuse `HttpClient`; HTTP/2 multiplexes concurrent queries on one connection.
- **DoQ**: keep one QUIC connection, open a new stream per query.

This is a key reason to make `DnsTransport` an instance type rather than a static helper or delegate.

### Server Identity

`IPEndPoint` is sufficient for UDP/TCP/DoQ (+ SNI hostname for the TLS/QUIC variants). DoH needs a `Uri`. The `DnsTransport` factory methods above absorb this asymmetry so that `DnsResolverOptions` does not need a polymorphic `DnsServer` type.

### Response Validation

The existing header/question-mirroring validation and ID matching remain applicable. Two adjustments:

- Truncation (TC bit) handling applies only to UDP; other transports ignore it.
- Query ID randomization is redundant over DoT/DoH/DoQ (the secure channel already provides integrity), but the ID must still round-trip so mismatched responses are rejected.

### Incremental Delivery Path

1. Refactor current UDP+TCP logic into `DnsTransport` subclasses behind the existing `SendQueryAsync`. Pure refactor, no API surface change.
2. Expose `DnsTransport` as public and add `DnsResolverOptions.TransportFactory`.
3. Ship `DnsTransport.Tls(...)` (reuses TCP framing).
4. Ship `DnsTransport.Https(...)`.
5. Ship `DnsTransport.Quic(...)` once `System.Net.Quic` is stable.

### Open Questions (Transport)

- Should `DnsResolverOptions` accept a list of transports for heterogeneous failover (e.g., DoH primary, DoT fallback), or is a single transport enough?
- Should we detect OS-level encrypted DNS (Windows 11 DoH via `DnsQueryEx`, systemd-resolved DoT) and prefer it, or always use our own stack when configured?
- Where do certificate validation callbacks / pinning live — on the transport factory, or in a shared `DnsResolverOptions.SslOptions`?

## Future Work: EDNS0 (OPT Record) Support

EDNS0 (RFC 6891) extends DNS via a pseudo-record (OPT, type 41) placed in the additional section. It is practically required for modern DNS usage — without it, UDP responses are capped at 512 bytes, causing unnecessary TCP fallback. Support can be added incrementally on top of the current design:

- **Writer**: Add a `TryWriteOptRecord(ushort udpPayloadSize, ...)` method (or reintroduce a general `TryWriteResourceRecord`) to emit OPT in the additional section of requests.
- **Reader**: OPT records are already parseable as regular `DnsRecord`s, but their fields are repurposed (Class = UDP payload size, TTL = extended RCODE + version + flags). A `TryParseOptRecord` extension method would reinterpret these correctly.
- **Extended RCODE**: The response code is split across the header (lower 4 bits) and the OPT record's TTL field (upper 8 bits). The OPT accessor should expose the full 12-bit combined RCODE.
- **Fallback**: Some middleboxes drop EDNS0 queries. A robust resolver should retry without EDNS0 on timeout.

## Internationalized Domain Names (IDN)

DNS wire format (RFC 1035) is limited to ASCII. Internationalized domain names (e.g., `münchen.de`, `例え.jp`) are supported via the IDNA 2008 standard (RFC 5891), which encodes Unicode labels using Punycode with the `xn--` ASCII-Compatible Encoding (ACE) prefix. For example, `münchen.de` becomes `xn--mnchen-3ya.de` on the wire.

### Approach

IDN conversion is handled transparently by `DnsEncodedName` using `System.Globalization.IdnMapping`:

- **Encoding** (`TryEncode`): When the input name contains non-ASCII characters, the entire name is converted to ACE form via `IdnMapping.GetAscii()` before wire encoding. Invalid Unicode input (e.g., lone surrogates) results in `OperationStatus.InvalidData`.
- **Decoding** (`TryDecode`, `ToString`): When the wire-format name contains ACE-encoded labels (detected by the `xn--` prefix), the decoded ASCII string is passed through `IdnMapping.GetUnicode()` to recover the original Unicode form. If IDN conversion fails (e.g., malformed ACE), the raw ASCII form is preserved.
- **Comparison** (`Equals`): When comparing against a Unicode string, the input is first converted to ACE form before case-insensitive ASCII comparison with the wire-format labels.

### Design Decisions

1. **Whole-name conversion**: `IdnMapping.GetAscii()` operates on the full dotted name, not individual labels. This simplifies the implementation and ensures consistent IDNA validation across all labels.
2. **Transparent round-trip**: `TryEncode("münchen.de", ...)` followed by `ToString()` returns `"münchen.de"` — the Unicode form is preserved through the ACE wire encoding.
3. **ACE pass-through**: Already-ACE names (e.g., `xn--mnchen-3ya.de`) are accepted by `TryEncode` and decoded to Unicode by `ToString()`. There is no double-encoding.
4. **Graceful fallback**: If `IdnMapping.GetUnicode()` fails during decoding, the raw ACE form is returned rather than throwing an exception.
5. **STD3 rules**: `IdnMapping` is configured with `UseStd3AsciiRules = true` to enforce hostname validity during IDN conversion. Note that `DnsEncodedName`'s own label validation is slightly more permissive than STD3 — it allows underscores for SRV/DKIM compatibility. The STD3 rules only apply to the IDN conversion step (i.e., names containing non-ASCII characters).

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
