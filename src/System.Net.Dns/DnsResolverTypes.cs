using System.Buffers;

namespace System.Net;

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
public readonly struct DnsResolvedAddress
{
    public IPAddress Address { get; }
    public DateTimeOffset ExpiresAt { get; }

    public DnsResolvedAddress(IPAddress address, DateTimeOffset expiresAt)
    {
        Address = address;
        ExpiresAt = expiresAt;
    }
}

/// <summary>
/// SRV record resolved from DNS with TTL-derived expiration.
/// </summary>
public readonly struct DnsResolvedService
{
    public string Target { get; }
    public ushort Port { get; }
    public ushort Priority { get; }
    public ushort Weight { get; }
    public DateTimeOffset ExpiresAt { get; }

    /// <summary>
    /// Addresses from the additional section of the SRV response, if present.
    /// </summary>
    public DnsResolvedAddress[]? Addresses { get; }

    public DnsResolvedService(string target, ushort port, ushort priority, ushort weight,
        DateTimeOffset expiresAt, DnsResolvedAddress[]? addresses = null)
    {
        Target = target;
        Port = port;
        Priority = priority;
        Weight = weight;
        ExpiresAt = expiresAt;
        Addresses = addresses;
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
        byte[]? buf = _pooledBuffer;
        if (buf != null)
        {
            _pooledBuffer = null;
            ArrayPool<byte>.Shared.Return(buf);
        }
    }
}
