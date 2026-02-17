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
    private readonly TcpListener _tcp;
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _udpListenTask;
    private readonly Task _tcpListenTask;
    private readonly Dictionary<(string Name, DnsRecordType Type), ResponseBuilder> _responses = new();
    private int _requestCount;

    public IPEndPoint EndPoint { get; }

    /// <summary>Number of requests received so far.</summary>
    public int RequestCount => _requestCount;

    /// <summary>Number of TCP requests received.</summary>
    public int TcpRequestCount { get; private set; }

    private LoopbackDnsServer(UdpClient udp, TcpListener tcp, IPEndPoint endPoint)
    {
        _udp = udp;
        _tcp = tcp;
        EndPoint = endPoint;
        _udpListenTask = ListenUdpAsync(_cts.Token);
        _tcpListenTask = ListenTcpAsync(_cts.Token);
    }

    public static LoopbackDnsServer Start()
    {
        UdpClient udp = new(new IPEndPoint(IPAddress.Loopback, 0));
        IPEndPoint ep = (IPEndPoint)udp.Client.LocalEndPoint!;
        // Listen on TCP on the same port
        TcpListener tcp = new(IPAddress.Loopback, ep.Port);
        tcp.Start();
        return new LoopbackDnsServer(udp, tcp, ep);
    }

    /// <summary>
    /// Registers a response to be returned for the given query name and type.
    /// </summary>
    public void AddResponse(string name, DnsRecordType type, ResponseBuilder builder)
    {
        _responses[(name.ToLowerInvariant(), type)] = builder;
    }

    /// <summary>
    /// Registers a response using the fluent <see cref="DnsResponseBuilder"/>.
    /// The configure callback receives a pre-seeded builder and should return the configured builder.
    /// </summary>
    public void AddResponse(string name, DnsRecordType type, Func<DnsResponseBuilder, DnsResponseBuilder> configure)
    {
        _responses[(name.ToLowerInvariant(), type)] = (queryId, qName, _) =>
            configure(DnsResponseBuilder.For(queryId, qName, type)).Build();
    }

    /// <summary>
    /// Adds a response that sends raw bytes (for testing malformed responses).
    /// The factory receives the query transaction ID.
    /// </summary>
    public void AddRawResponse(string name, DnsRecordType type, Func<ushort, byte[]> rawFactory)
    {
        AddResponse(name, type, (queryId, _, _) => rawFactory(queryId));
    }

    /// <summary>
    /// Delegate for full control over response construction.
    /// </summary>
    public delegate byte[] ResponseBuilder(ushort queryId, byte[] questionName, bool isTcp);

    /// <summary>
    /// Builds an NXDOMAIN response with SOA in authority, but the SOA RDATA is truncated.
    /// This must be built manually since the builder writes well-formed records,
    /// so we patch the RDLENGTH after building.
    /// </summary>
    internal static byte[] BuildNxDomainWithTruncatedSoa(ushort queryId, byte[] questionName,
        DnsRecordType type)
    {
        byte[] response = DnsResponseBuilder.For(queryId, questionName, type)
            .ResponseCode(DnsResponseCode.NameError)
            .Authority("test", DnsRecordType.SOA, new byte[4], 60)
            .Build();

        // Patch the RDLENGTH to claim 50 bytes instead of the actual 4
        int rdLengthOffset = response.Length - 4 - 2; // back past rdata(4) and rdlength(2)
        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(rdLengthOffset), 50);

        return response;
    }

    internal static byte[] EncodeName(string name)
    {
        Span<byte> buf = stackalloc byte[DnsEncodedName.MaxEncodedLength];
        DnsEncodedName.TryEncode(name, buf, out _, out int written);
        return buf[..written].ToArray();
    }

    private async Task ListenUdpAsync(CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                UdpReceiveResult result = await _udp.ReceiveAsync(ct);
                byte[] query = result.Buffer;
                IPEndPoint remote = result.RemoteEndPoint;
                Interlocked.Increment(ref _requestCount);

                byte[] response = ProcessQuery(query);
                if (response.Length > 0)
                {
                    await _udp.SendAsync(response, remote, ct);
                }
            }
        }
        catch (OperationCanceledException) { }
        catch (ObjectDisposedException) { }
    }

    private async Task ListenTcpAsync(CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                TcpClient client = await _tcp.AcceptTcpClientAsync(ct);
                // Handle each client in a fire-and-forget task
                _ = HandleTcpClientAsync(client, ct);
            }
        }
        catch (OperationCanceledException) { }
        catch (ObjectDisposedException) { }
    }

    private async Task HandleTcpClientAsync(TcpClient client, CancellationToken ct)
    {
        try
        {
            using (client)
            {
                NetworkStream stream = client.GetStream();

                // Read 2-byte length prefix
                byte[] lengthBuf = new byte[2];
                int read = 0;
                while (read < 2)
                {
                    int n = await stream.ReadAsync(lengthBuf.AsMemory(read, 2 - read), ct);
                    if (n == 0)
                    {
                        return;
                    }
                    read += n;
                }

                int queryLength = BinaryPrimitives.ReadUInt16BigEndian(lengthBuf);
                byte[] query = new byte[queryLength];
                read = 0;
                while (read < queryLength)
                {
                    int n = await stream.ReadAsync(query.AsMemory(read, queryLength - read), ct);
                    if (n == 0)
                    {
                        return;
                    }
                    read += n;
                }

                Interlocked.Increment(ref _requestCount);
                TcpRequestCount++;

                byte[] response = ProcessQuery(query, isTcp: true);
                if (response.Length > 0)
                {
                    // Write 2-byte length prefix + response
                    byte[] responseLengthBuf = new byte[2];
                    BinaryPrimitives.WriteUInt16BigEndian(responseLengthBuf, (ushort)response.Length);
                    await stream.WriteAsync(responseLengthBuf, ct);
                    await stream.WriteAsync(response, ct);
                }
            }
        }
        catch (OperationCanceledException) { }
        catch (ObjectDisposedException) { }
        catch (IOException) { }
    }

    private byte[] ProcessQuery(byte[] query, bool isTcp = false)
    {
        if (query.Length < 12)
            return [];

        ushort queryId = BinaryPrimitives.ReadUInt16BigEndian(query);
        ushort qdCount = BinaryPrimitives.ReadUInt16BigEndian(query.AsSpan(4));

        if (qdCount < 1)
        {
            return DnsResponseBuilder.For(queryId, [], 0)
                .ResponseCode(DnsResponseCode.FormatError)
                .SkipQuestion()
                .Build();
        }

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
        {
            return DnsResponseBuilder.For(queryId, questionName, 0)
                .ResponseCode(DnsResponseCode.FormatError)
                .Build();
        }

        DnsRecordType qType = (DnsRecordType)BinaryPrimitives.ReadUInt16BigEndian(query.AsSpan(pos));

        // Decode the name for lookup
        DnsEncodedName.TryParse(query, nameStart, out DnsEncodedName encodedName, out _);
        string nameStr = encodedName.ToString();

        if (_responses.TryGetValue((nameStr.ToLowerInvariant(), qType), out var builder))
        {
            return builder(queryId, questionName, isTcp);
        }

        // Default: NXDOMAIN
        return DnsResponseBuilder.For(queryId, questionName, qType)
            .ResponseCode(DnsResponseCode.NameError)
            .Build();
    }

    public async ValueTask DisposeAsync()
    {
        _cts.Cancel();
        _udp.Dispose();
        _tcp.Stop();
        try { await _udpListenTask; } catch { }
        try { await _tcpListenTask; } catch { }
        _cts.Dispose();
    }
}
