using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;

namespace System.Net.Dns.Tests;

/// <summary>
/// A minimal in-process DNS server for testing. Listens on a loopback UDP port
/// and responds with preconfigured answers based on the query name and type.
/// </summary>
internal sealed class LoopbackDnsServer : IAsyncDisposable
{
    private readonly UdpClient _udp;
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _listenTask;
    private readonly Dictionary<(string Name, DnsRecordType Type), ResponseBuilder> _responses = new();

    public IPEndPoint EndPoint { get; }

    private LoopbackDnsServer(UdpClient udp, IPEndPoint endPoint)
    {
        _udp = udp;
        EndPoint = endPoint;
        _listenTask = ListenAsync(_cts.Token);
    }

    public static LoopbackDnsServer Start()
    {
        var udp = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var ep = (IPEndPoint)udp.Client.LocalEndPoint!;
        return new LoopbackDnsServer(udp, ep);
    }

    /// <summary>
    /// Registers a response to be returned for the given query name and type.
    /// </summary>
    public void AddResponse(string name, DnsRecordType type, ResponseBuilder builder)
    {
        _responses[(name.ToLowerInvariant(), type)] = builder;
    }

    /// <summary>
    /// Convenience: adds an A record response.
    /// </summary>
    public void AddARecord(string name, IPAddress address, uint ttl = 300)
    {
        AddResponse(name, DnsRecordType.A, (queryId, qName) =>
            BuildSimpleResponse(queryId, qName, DnsRecordType.A, address.GetAddressBytes(), ttl));
    }

    /// <summary>
    /// Convenience: adds an AAAA record response.
    /// </summary>
    public void AddAAAARecord(string name, IPAddress address, uint ttl = 300)
    {
        AddResponse(name, DnsRecordType.AAAA, (queryId, qName) =>
            BuildSimpleResponse(queryId, qName, DnsRecordType.AAAA, address.GetAddressBytes(), ttl));
    }

    /// <summary>
    /// Convenience: adds an NXDOMAIN response.
    /// </summary>
    public void AddNxDomain(string name, DnsRecordType type)
    {
        AddResponse(name, type, (queryId, qName) =>
            BuildErrorResponse(queryId, qName, type, DnsResponseCode.NameError));
    }

    /// <summary>
    /// Convenience: adds a custom response builder for full control.
    /// </summary>
    public delegate byte[] ResponseBuilder(ushort queryId, byte[] questionName);

    private async Task ListenAsync(CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                var result = await _udp.ReceiveAsync(ct);
                var query = result.Buffer;
                var remote = result.RemoteEndPoint;

                byte[] response = ProcessQuery(query);
                await _udp.SendAsync(response, remote, ct);
            }
        }
        catch (OperationCanceledException) { }
        catch (ObjectDisposedException) { }
    }

    private byte[] ProcessQuery(byte[] query)
    {
        if (query.Length < 12)
            return [];

        ushort queryId = BinaryPrimitives.ReadUInt16BigEndian(query);
        ushort qdCount = BinaryPrimitives.ReadUInt16BigEndian(query.AsSpan(4));

        if (qdCount < 1)
            return BuildErrorResponse(queryId, [], 0, DnsResponseCode.FormatError);

        // Parse the question name and type from the raw query
        int pos = 12;
        int nameStart = pos;

        // Skip past the name
        while (pos < query.Length)
        {
            byte b = query[pos];
            if (b == 0) { pos++; break; }
            if ((b & 0xC0) == 0xC0) { pos += 2; break; }
            pos += 1 + b;
        }

        byte[] questionName = query[nameStart..pos];

        if (pos + 4 > query.Length)
            return BuildErrorResponse(queryId, questionName, 0, DnsResponseCode.FormatError);

        var qType = (DnsRecordType)BinaryPrimitives.ReadUInt16BigEndian(query.AsSpan(pos));

        // Decode the name for lookup
        var dnsName = new DnsName(query, nameStart);
        string nameStr = dnsName.ToString();

        if (_responses.TryGetValue((nameStr.ToLowerInvariant(), qType), out var builder))
            return builder(queryId, questionName);

        // Default: NXDOMAIN
        return BuildErrorResponse(queryId, questionName, qType, DnsResponseCode.NameError);
    }

    internal static byte[] BuildSimpleResponse(ushort queryId, byte[] questionName,
        DnsRecordType type, byte[] rdata, uint ttl)
    {
        using var ms = new MemoryStream();
        // Header
        WriteUInt16BE(ms, queryId);
        WriteUInt16BE(ms, 0x8180); // QR=1, RD=1, RA=1
        WriteUInt16BE(ms, 1); // QDCOUNT
        WriteUInt16BE(ms, 1); // ANCOUNT
        WriteUInt16BE(ms, 0); // NSCOUNT
        WriteUInt16BE(ms, 0); // ARCOUNT

        // Question echo
        ms.Write(questionName);
        WriteUInt16BE(ms, (ushort)type);
        WriteUInt16BE(ms, 1); // CLASS=IN

        // Answer with compression pointer to offset 12 (question name)
        ms.WriteByte(0xC0);
        ms.WriteByte(0x0C);
        WriteUInt16BE(ms, (ushort)type);
        WriteUInt16BE(ms, 1); // CLASS=IN
        WriteUInt32BE(ms, ttl);
        WriteUInt16BE(ms, (ushort)rdata.Length);
        ms.Write(rdata);

        return ms.ToArray();
    }

    internal static byte[] BuildErrorResponse(ushort queryId, byte[] questionName,
        DnsRecordType type, DnsResponseCode rcode)
    {
        using var ms = new MemoryStream();
        // Header: QR=1, RD=1, RA=1, RCODE
        ushort flags = (ushort)(0x8180 | (ushort)rcode);
        WriteUInt16BE(ms, queryId);
        WriteUInt16BE(ms, flags);
        WriteUInt16BE(ms, (ushort)(questionName.Length > 0 ? 1 : 0)); // QDCOUNT
        WriteUInt16BE(ms, 0); // ANCOUNT
        WriteUInt16BE(ms, 0); // NSCOUNT
        WriteUInt16BE(ms, 0); // ARCOUNT

        if (questionName.Length > 0)
        {
            ms.Write(questionName);
            WriteUInt16BE(ms, (ushort)type);
            WriteUInt16BE(ms, 1); // CLASS=IN
        }

        return ms.ToArray();
    }

    private static void WriteUInt16BE(MemoryStream ms, ushort value)
    {
        ms.WriteByte((byte)(value >> 8));
        ms.WriteByte((byte)(value & 0xFF));
    }

    private static void WriteUInt32BE(MemoryStream ms, uint value)
    {
        ms.WriteByte((byte)(value >> 24));
        ms.WriteByte((byte)((value >> 16) & 0xFF));
        ms.WriteByte((byte)((value >> 8) & 0xFF));
        ms.WriteByte((byte)(value & 0xFF));
    }

    public async ValueTask DisposeAsync()
    {
        _cts.Cancel();
        _udp.Dispose();
        try { await _listenTask; } catch { }
        _cts.Dispose();
    }
}
