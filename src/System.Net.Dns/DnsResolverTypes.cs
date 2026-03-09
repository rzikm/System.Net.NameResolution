using System.Buffers;
using System.Threading;

namespace System.Net;

/// <summary>
/// Delegate for sending a DNS query and receiving the raw response.
/// Returns a rented buffer and its valid length. The caller must return the buffer to the pool.
/// </summary>
public delegate Task<(byte[] Buffer, int Length)> DnsSendQueryAsync(
    string name, DnsRecordType type, CancellationToken cancellationToken);

/// <summary>
/// Constraint interface for DNS record types usable with <see cref="DnsResolver.ResolveAsync{T}"/>.
/// Each implementing type provides its own resolution strategy via <see cref="ResolveAsync"/>.
/// </summary>
public interface IDnsRecord<TSelf> where TSelf : IDnsRecord<TSelf>
{
    /// <summary>
    /// Resolves DNS records by sending queries via the provided delegate and
    /// parsing the responses. Each record type owns its full resolution strategy
    /// (e.g., DnsAddress queries both A and AAAA, DnsSrvRecord collects additional addresses).
    /// </summary>
    static abstract Task<DnsResult<TSelf>> ResolveAsync(
        string name,
        DnsSendQueryAsync sendQueryAsync,
        CancellationToken cancellationToken);
}

/// <summary>
/// Generic result type for high-level DNS resolution methods.
/// Carries the response code, resolved records, and negative cache information.
/// </summary>
public readonly struct DnsResult<T>
{
    /// <summary>
    /// The DNS response code. Use this to distinguish between:
    /// - NoError + non-empty Records = successful resolution
    /// - NoError + empty Records = NODATA (name exists but no records of requested type)
    /// - NameError + empty Records = NXDOMAIN (name does not exist)
    /// </summary>
    public DnsResponseCode ResponseCode { get; }

    /// <summary>Resolved records. Empty on error or NODATA.</summary>
    public T[] Records { get; }

    /// <summary>
    /// For negative responses (NXDOMAIN/NODATA), the expiration time derived from the
    /// SOA minimum TTL in the authority section. Callers can cache the negative result
    /// until this time. Null if no SOA was present or the response was successful.
    /// </summary>
    public DateTimeOffset? NegativeCacheExpiresAt { get; }

    public DnsResult(DnsResponseCode responseCode, T[] records, DateTimeOffset? negativeCacheExpiresAt = null)
    {
        ResponseCode = responseCode;
        Records = records;
        NegativeCacheExpiresAt = negativeCacheExpiresAt;
    }
}

/// <summary>
/// Address resolved from DNS with TTL-derived expiration.
/// </summary>
public readonly struct DnsAddress : IDnsRecord<DnsAddress>
{
    public IPAddress Address { get; }
    public DateTimeOffset ExpiresAt { get; }

    public DnsAddress(IPAddress address, DateTimeOffset expiresAt)
    {
        Address = address;
        ExpiresAt = expiresAt;
    }

    static async Task<DnsResult<DnsAddress>> IDnsRecord<DnsAddress>.ResolveAsync(
        string name, DnsSendQueryAsync sendQueryAsync, CancellationToken cancellationToken)
    {
        List<DnsAddress> results = new();
        DateTimeOffset now = DateTimeOffset.UtcNow;
        DnsResponseCode worstResponseCode = DnsResponseCode.NoError;
        DateTimeOffset? negativeCacheExpires = null;

        foreach (DnsRecordType type in (DnsRecordType[])[DnsRecordType.A, DnsRecordType.AAAA])
        {
            (byte[] responseBuf, int responseLength) = await sendQueryAsync(name, type, cancellationToken);
            try
            {
                (DnsResponseCode rcode, DateTimeOffset? negExpires) =
                    CollectAddresses(responseBuf.AsSpan(0, responseLength), now, results);
                if (rcode != DnsResponseCode.NoError && worstResponseCode == DnsResponseCode.NoError)
                {
                    worstResponseCode = rcode;
                    negativeCacheExpires = negExpires;
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(responseBuf);
            }
        }

        if (results.Count > 0)
        {
            return new DnsResult<DnsAddress>(DnsResponseCode.NoError, results.ToArray());
        }

        return new DnsResult<DnsAddress>(worstResponseCode, [], negativeCacheExpires);
    }

    private static (DnsResponseCode, DateTimeOffset?) CollectAddresses(
        ReadOnlySpan<byte> response, DateTimeOffset now, List<DnsAddress> results)
    {
        DnsMessageReader reader = DnsResolver.CreateReader(response);
        DnsResponseCode rcode = reader.Header.ResponseCode;

        if (rcode != DnsResponseCode.NoError)
        {
            DateTimeOffset? negExpires = DnsResolver.ExtractNegativeCacheTtl(response, now);
            return (rcode, negExpires);
        }

        DnsResolver.SkipQuestions(ref reader);

        for (int i = 0; i < reader.Header.AnswerCount; i++)
        {
            DnsRecord record = DnsResolver.ReadRecord(ref reader);

            if (record.TryParseARecord(out DnsARecordData a))
            {
                results.Add(new DnsAddress(
                    a.ToIPAddress(), now + TimeSpan.FromSeconds(record.TimeToLive)));
            }
            else if (record.TryParseAAAARecord(out DnsAAAARecordData aaaa))
            {
                results.Add(new DnsAddress(
                    aaaa.ToIPAddress(), now + TimeSpan.FromSeconds(record.TimeToLive)));
            }
        }

        return (DnsResponseCode.NoError, null);
    }
}

/// <summary>
/// SRV record resolved from DNS with TTL-derived expiration.
/// </summary>
public readonly struct DnsSrvRecord : IDnsRecord<DnsSrvRecord>
{
    public string Target { get; }
    public ushort Port { get; }
    public ushort Priority { get; }
    public ushort Weight { get; }
    public DateTimeOffset ExpiresAt { get; }

    /// <summary>
    /// Addresses from the additional section of the SRV response, if present.
    /// </summary>
    public DnsAddress[]? Addresses { get; }

    public DnsSrvRecord(string target, ushort port, ushort priority, ushort weight,
        DateTimeOffset expiresAt, DnsAddress[]? addresses = null)
    {
        Target = target;
        Port = port;
        Priority = priority;
        Weight = weight;
        ExpiresAt = expiresAt;
        Addresses = addresses;
    }

    static async Task<DnsResult<DnsSrvRecord>> IDnsRecord<DnsSrvRecord>.ResolveAsync(
        string name, DnsSendQueryAsync sendQueryAsync, CancellationToken cancellationToken)
    {
        (byte[] responseBuf, int responseLength) = await sendQueryAsync(name, DnsRecordType.SRV, cancellationToken);
        try
        {
            ReadOnlySpan<byte> responseSpan = responseBuf.AsSpan(0, responseLength);
            DnsMessageReader reader = DnsResolver.CreateReader(responseSpan);
            DateTimeOffset now = DateTimeOffset.UtcNow;

            if (reader.Header.ResponseCode != DnsResponseCode.NoError)
            {
                DateTimeOffset? negExpires = DnsResolver.ExtractNegativeCacheTtl(responseSpan, now);
                return new DnsResult<DnsSrvRecord>(reader.Header.ResponseCode, [], negExpires);
            }

            DnsResolver.SkipQuestions(ref reader);

            // Read answer records (SRV)
            List<(string Target, ushort Port, ushort Priority, ushort Weight, DateTimeOffset ExpiresAt)> srvRecords = new();

            for (int i = 0; i < reader.Header.AnswerCount; i++)
            {
                DnsRecord record = DnsResolver.ReadRecord(ref reader);
                if (record.TryParseSrvRecord(out DnsSrvRecordData srv))
                {
                    srvRecords.Add((srv.Target.ToString(), srv.Port, srv.Priority, srv.Weight,
                        now + TimeSpan.FromSeconds(record.TimeToLive)));
                }
            }

            DnsResolver.SkipRecords(ref reader, reader.Header.AuthorityCount);

            // Read additional section for addresses
            Dictionary<string, List<DnsAddress>> additionalAddresses = new(StringComparer.OrdinalIgnoreCase);
            for (int i = 0; i < reader.Header.AdditionalCount; i++)
            {
                DnsRecord record = DnsResolver.ReadRecord(ref reader);

                IPAddress? address = null;
                if (record.TryParseARecord(out DnsARecordData a))
                {
                    address = a.ToIPAddress();
                }
                else if (record.TryParseAAAARecord(out DnsAAAARecordData aaaa))
                {
                    address = aaaa.ToIPAddress();
                }

                if (address is not null)
                {
                    string recordName = record.Name.ToString();
                    if (!additionalAddresses.TryGetValue(recordName, out List<DnsAddress>? list))
                    {
                        list = new List<DnsAddress>();
                        additionalAddresses[recordName] = list;
                    }
                    list.Add(new DnsAddress(address, now + TimeSpan.FromSeconds(record.TimeToLive)));
                }
            }

            // Combine SRV records with their additional addresses
            List<DnsSrvRecord> services = new();
            foreach ((string target, ushort port, ushort priority, ushort weight, DateTimeOffset expiresAt) in srvRecords)
            {
                additionalAddresses.TryGetValue(target, out List<DnsAddress>? addrs);
                services.Add(new DnsSrvRecord(target, port, priority, weight, expiresAt,
                    addrs?.ToArray()));
            }

            return new DnsResult<DnsSrvRecord>(DnsResponseCode.NoError, services.ToArray());
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(responseBuf);
        }
    }
}

/// <summary>
/// MX record resolved from DNS with TTL-derived expiration.
/// </summary>
public readonly struct DnsMxRecord : IDnsRecord<DnsMxRecord>
{
    public string Exchange { get; }
    public ushort Preference { get; }
    public DateTimeOffset ExpiresAt { get; }

    public DnsMxRecord(string exchange, ushort preference, DateTimeOffset expiresAt)
    {
        Exchange = exchange;
        Preference = preference;
        ExpiresAt = expiresAt;
    }

    static async Task<DnsResult<DnsMxRecord>> IDnsRecord<DnsMxRecord>.ResolveAsync(
        string name, DnsSendQueryAsync sendQueryAsync, CancellationToken cancellationToken)
    {
        (byte[] responseBuf, int responseLength) = await sendQueryAsync(name, DnsRecordType.MX, cancellationToken);
        try
        {
            ReadOnlySpan<byte> responseSpan = responseBuf.AsSpan(0, responseLength);
            DnsMessageReader reader = DnsResolver.CreateReader(responseSpan);
            DateTimeOffset now = DateTimeOffset.UtcNow;

            if (reader.Header.ResponseCode != DnsResponseCode.NoError)
            {
                DateTimeOffset? negExpires = DnsResolver.ExtractNegativeCacheTtl(responseSpan, now);
                return new DnsResult<DnsMxRecord>(reader.Header.ResponseCode, [], negExpires);
            }

            DnsResolver.SkipQuestions(ref reader);

            List<DnsMxRecord> results = new();
            for (int i = 0; i < reader.Header.AnswerCount; i++)
            {
                DnsRecord record = DnsResolver.ReadRecord(ref reader);
                if (record.TryParseMxRecord(out DnsMxRecordData mx))
                {
                    results.Add(new DnsMxRecord(mx.Exchange.ToString(), mx.Preference,
                        now + TimeSpan.FromSeconds(record.TimeToLive)));
                }
            }

            return new DnsResult<DnsMxRecord>(DnsResponseCode.NoError, results.ToArray());
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(responseBuf);
        }
    }
}

/// <summary>
/// TXT record resolved from DNS with TTL-derived expiration.
/// </summary>
public readonly struct DnsTxtResult : IDnsRecord<DnsTxtResult>
{
    public string[] Strings { get; }
    public DateTimeOffset ExpiresAt { get; }

    public DnsTxtResult(string[] strings, DateTimeOffset expiresAt)
    {
        Strings = strings;
        ExpiresAt = expiresAt;
    }

    static async Task<DnsResult<DnsTxtResult>> IDnsRecord<DnsTxtResult>.ResolveAsync(
        string name, DnsSendQueryAsync sendQueryAsync, CancellationToken cancellationToken)
    {
        (byte[] responseBuf, int responseLength) = await sendQueryAsync(name, DnsRecordType.TXT, cancellationToken);
        try
        {
            ReadOnlySpan<byte> responseSpan = responseBuf.AsSpan(0, responseLength);
            DnsMessageReader reader = DnsResolver.CreateReader(responseSpan);
            DateTimeOffset now = DateTimeOffset.UtcNow;

            if (reader.Header.ResponseCode != DnsResponseCode.NoError)
            {
                DateTimeOffset? negExpires = DnsResolver.ExtractNegativeCacheTtl(responseSpan, now);
                return new DnsResult<DnsTxtResult>(reader.Header.ResponseCode, [], negExpires);
            }

            DnsResolver.SkipQuestions(ref reader);

            List<DnsTxtResult> results = new();
            for (int i = 0; i < reader.Header.AnswerCount; i++)
            {
                DnsRecord record = DnsResolver.ReadRecord(ref reader);
                if (record.TryParseTxtRecord(out DnsTxtRecordData txt))
                {
                    List<string> strings = new();
                    foreach (ReadOnlySpan<byte> s in txt.EnumerateStrings())
                    {
                        strings.Add(System.Text.Encoding.UTF8.GetString(s));
                    }
                    results.Add(new DnsTxtResult(strings.ToArray(),
                        now + TimeSpan.FromSeconds(record.TimeToLive)));
                }
            }

            return new DnsResult<DnsTxtResult>(DnsResponseCode.NoError, results.ToArray());
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(responseBuf);
        }
    }
}

/// <summary>
/// CNAME record resolved from DNS with TTL-derived expiration.
/// </summary>
public readonly struct DnsCNameResult : IDnsRecord<DnsCNameResult>
{
    public string CanonicalName { get; }
    public DateTimeOffset ExpiresAt { get; }

    public DnsCNameResult(string canonicalName, DateTimeOffset expiresAt)
    {
        CanonicalName = canonicalName;
        ExpiresAt = expiresAt;
    }

    static async Task<DnsResult<DnsCNameResult>> IDnsRecord<DnsCNameResult>.ResolveAsync(
        string name, DnsSendQueryAsync sendQueryAsync, CancellationToken cancellationToken)
    {
        (byte[] responseBuf, int responseLength) = await sendQueryAsync(name, DnsRecordType.CNAME, cancellationToken);
        try
        {
            ReadOnlySpan<byte> responseSpan = responseBuf.AsSpan(0, responseLength);
            DnsMessageReader reader = DnsResolver.CreateReader(responseSpan);
            DateTimeOffset now = DateTimeOffset.UtcNow;

            if (reader.Header.ResponseCode != DnsResponseCode.NoError)
            {
                DateTimeOffset? negExpires = DnsResolver.ExtractNegativeCacheTtl(responseSpan, now);
                return new DnsResult<DnsCNameResult>(reader.Header.ResponseCode, [], negExpires);
            }

            DnsResolver.SkipQuestions(ref reader);

            List<DnsCNameResult> results = new();
            for (int i = 0; i < reader.Header.AnswerCount; i++)
            {
                DnsRecord record = DnsResolver.ReadRecord(ref reader);
                if (record.TryParseCNameRecord(out DnsCNameRecordData cname))
                {
                    results.Add(new DnsCNameResult(cname.CName.ToString(),
                        now + TimeSpan.FromSeconds(record.TimeToLive)));
                }
            }

            return new DnsResult<DnsCNameResult>(DnsResponseCode.NoError, results.ToArray());
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(responseBuf);
        }
    }
}

/// <summary>
/// PTR record resolved from DNS with TTL-derived expiration.
/// </summary>
public readonly struct DnsPtrResult : IDnsRecord<DnsPtrResult>
{
    public string Name { get; }
    public DateTimeOffset ExpiresAt { get; }

    public DnsPtrResult(string name, DateTimeOffset expiresAt)
    {
        Name = name;
        ExpiresAt = expiresAt;
    }

    static async Task<DnsResult<DnsPtrResult>> IDnsRecord<DnsPtrResult>.ResolveAsync(
        string name, DnsSendQueryAsync sendQueryAsync, CancellationToken cancellationToken)
    {
        (byte[] responseBuf, int responseLength) = await sendQueryAsync(name, DnsRecordType.PTR, cancellationToken);
        try
        {
            ReadOnlySpan<byte> responseSpan = responseBuf.AsSpan(0, responseLength);
            DnsMessageReader reader = DnsResolver.CreateReader(responseSpan);
            DateTimeOffset now = DateTimeOffset.UtcNow;

            if (reader.Header.ResponseCode != DnsResponseCode.NoError)
            {
                DateTimeOffset? negExpires = DnsResolver.ExtractNegativeCacheTtl(responseSpan, now);
                return new DnsResult<DnsPtrResult>(reader.Header.ResponseCode, [], negExpires);
            }

            DnsResolver.SkipQuestions(ref reader);

            List<DnsPtrResult> results = new();
            for (int i = 0; i < reader.Header.AnswerCount; i++)
            {
                DnsRecord record = DnsResolver.ReadRecord(ref reader);
                if (record.TryParsePtrRecord(out DnsPtrRecordData ptr))
                {
                    results.Add(new DnsPtrResult(ptr.Name.ToString(),
                        now + TimeSpan.FromSeconds(record.TimeToLive)));
                }
            }

            return new DnsResult<DnsPtrResult>(DnsResponseCode.NoError, results.ToArray());
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(responseBuf);
        }
    }
}

/// <summary>
/// NS record resolved from DNS with TTL-derived expiration.
/// </summary>
public readonly struct DnsNsResult : IDnsRecord<DnsNsResult>
{
    public string Name { get; }
    public DateTimeOffset ExpiresAt { get; }

    public DnsNsResult(string name, DateTimeOffset expiresAt)
    {
        Name = name;
        ExpiresAt = expiresAt;
    }

    static async Task<DnsResult<DnsNsResult>> IDnsRecord<DnsNsResult>.ResolveAsync(
        string name, DnsSendQueryAsync sendQueryAsync, CancellationToken cancellationToken)
    {
        (byte[] responseBuf, int responseLength) = await sendQueryAsync(name, DnsRecordType.NS, cancellationToken);
        try
        {
            ReadOnlySpan<byte> responseSpan = responseBuf.AsSpan(0, responseLength);
            DnsMessageReader reader = DnsResolver.CreateReader(responseSpan);
            DateTimeOffset now = DateTimeOffset.UtcNow;

            if (reader.Header.ResponseCode != DnsResponseCode.NoError)
            {
                DateTimeOffset? negExpires = DnsResolver.ExtractNegativeCacheTtl(responseSpan, now);
                return new DnsResult<DnsNsResult>(reader.Header.ResponseCode, [], negExpires);
            }

            DnsResolver.SkipQuestions(ref reader);

            List<DnsNsResult> results = new();
            for (int i = 0; i < reader.Header.AnswerCount; i++)
            {
                DnsRecord record = DnsResolver.ReadRecord(ref reader);
                if (record.TryParseNsRecord(out DnsNsRecordData ns))
                {
                    results.Add(new DnsNsResult(ns.Name.ToString(),
                        now + TimeSpan.FromSeconds(record.TimeToLive)));
                }
            }

            return new DnsResult<DnsNsResult>(DnsResponseCode.NoError, results.ToArray());
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(responseBuf);
        }
    }
}

/// <summary>
/// Bridges the high-level transport with the low-level message parser.
/// Returns the raw wire-format response. Dispose to return the buffer to the pool.
/// </summary>
public sealed class DnsQueryResult : IDisposable
{
    public DnsResponseCode ResponseCode { get; }
    public DnsHeaderFlags Flags { get; }
    public ReadOnlyMemory<byte> ResponseMessage { get; }

    private byte[]? _pooledBuffer;

    internal DnsQueryResult(DnsResponseCode responseCode, DnsHeaderFlags flags,
        byte[] pooledBuffer, int length)
    {
        ResponseCode = responseCode;
        Flags = flags;
        _pooledBuffer = pooledBuffer;
        ResponseMessage = pooledBuffer.AsMemory(0, length);
    }

    public void Dispose()
    {
        byte[]? buf = Interlocked.Exchange(ref _pooledBuffer, null);
        if (buf != null)
        {
            ArrayPool<byte>.Shared.Return(buf);
        }
    }
}
