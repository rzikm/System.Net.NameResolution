namespace System.Net;

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
/// Returns the raw wire-format response.
/// </summary>
public sealed class DnsQueryResult : IDisposable
{
    public DnsResponseCode ResponseCode { get; }
    public DnsHeaderFlags Flags { get; }
    public ReadOnlyMemory<byte> ResponseMessage { get; }

    internal DnsQueryResult(DnsResponseCode responseCode, DnsHeaderFlags flags, byte[] responseMessage)
    {
        ResponseCode = responseCode;
        Flags = flags;
        ResponseMessage = responseMessage;
    }

    public void Dispose() { }
}
