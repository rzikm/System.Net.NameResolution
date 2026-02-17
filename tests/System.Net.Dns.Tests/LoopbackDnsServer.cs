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
    /// Convenience: adds an A record response.
    /// </summary>
    public void AddARecord(string name, IPAddress address, uint ttl = 300)
    {
        AddResponse(name, DnsRecordType.A, (queryId, qName, _) =>
            BuildSimpleResponse(queryId, qName, DnsRecordType.A, address.GetAddressBytes(), ttl));
    }

    /// <summary>
    /// Convenience: adds an AAAA record response.
    /// </summary>
    public void AddAAAARecord(string name, IPAddress address, uint ttl = 300)
    {
        AddResponse(name, DnsRecordType.AAAA, (queryId, qName, _) =>
            BuildSimpleResponse(queryId, qName, DnsRecordType.AAAA, address.GetAddressBytes(), ttl));
    }

    /// <summary>
    /// Convenience: adds an NXDOMAIN response.
    /// </summary>
    public void AddNxDomain(string name, DnsRecordType type)
    {
        AddResponse(name, type, (queryId, qName, _) =>
            BuildErrorResponse(queryId, qName, type, DnsResponseCode.NameError));
    }

    /// <summary>
    /// Convenience: adds a CNAME + A response (alias chain).
    /// </summary>
    public void AddCNameAndARecord(string name, string cname, IPAddress address, uint ttl = 300)
    {
        AddResponse(name, DnsRecordType.A, (queryId, qName, _) =>
            BuildCNameAndAResponse(queryId, qName, cname, address, ttl));
    }

    /// <summary>
    /// Adds a response that drops the packet (no reply), causing a timeout.
    /// </summary>
    public void AddDrop(string name, DnsRecordType type)
    {
        AddResponse(name, type, (_, _, _) => []);
    }

    /// <summary>
    /// Adds a truncated A record response (TC bit set, no answer records).
    /// The resolver should retry over TCP, where the full response is returned.
    /// </summary>
    public void AddTruncatedARecord(string name, IPAddress address, uint ttl = 300)
    {
        AddResponse(name, DnsRecordType.A, (queryId, qName, isTcp) =>
            isTcp
                ? BuildSimpleResponse(queryId, qName, DnsRecordType.A, address.GetAddressBytes(), ttl)
                : BuildTruncatedResponse(queryId, qName, DnsRecordType.A));
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
    /// Adds a ServerFailure response.
    /// </summary>
    public void AddServerFailure(string name, DnsRecordType type)
    {
        AddResponse(name, type, (queryId, qName, _) =>
            BuildErrorResponse(queryId, qName, type, DnsResponseCode.ServerFailure));
    }

    /// <summary>
    /// Adds a NODATA response (NoError with zero answers, SOA in authority section).
    /// </summary>
    public void AddNoData(string name, DnsRecordType type, string soaName = "test", uint soaMinTtl = 60)
    {
        AddResponse(name, type, (queryId, qName, _) =>
            BuildResponseWithSoa(queryId, qName, type, DnsResponseCode.NoError, soaName, soaMinTtl));
    }

    /// <summary>
    /// Adds an NXDOMAIN response with a SOA record in the authority section.
    /// </summary>
    public void AddNxDomainWithSoa(string name, DnsRecordType type, string soaName = "test", uint soaMinTtl = 60)
    {
        AddResponse(name, type, (queryId, qName, _) =>
            BuildResponseWithSoa(queryId, qName, type, DnsResponseCode.NameError, soaName, soaMinTtl));
    }

    /// <summary>
    /// Convenience: adds SRV records with optional additional A/AAAA records.
    /// </summary>
    public void AddSrvRecords(string name, (string Target, ushort Port, ushort Priority, ushort Weight, uint Ttl, IPAddress[]? Addresses)[] entries)
    {
        AddResponse(name, DnsRecordType.SRV, (queryId, qName, _) =>
            BuildSrvResponse(queryId, qName, entries));
    }

    /// <summary>
    /// Convenience: adds a custom response builder for full control.
    /// </summary>
    public delegate byte[] ResponseBuilder(ushort queryId, byte[] questionName, bool isTcp);

    // --- Response builders using product primitives ---

    private static DnsEncodedName ParseName(byte[] nameBytes)
    {
        DnsEncodedName.TryParse(nameBytes, 0, out DnsEncodedName name, out _);
        return name;
    }

    /// <summary>
    /// Writes a resource record (name + type + class + TTL + RDLENGTH + RDATA) into the buffer
    /// at the position indicated by <paramref name="writer"/>'s BytesWritten, then advances the writer
    /// by writing an equivalent number of padding bytes via TryWriteQuestion is not possible...
    /// Instead, writes directly into the buffer after the writer's current position.
    /// </summary>
    private static void WriteRecord(Span<byte> buf, ref int offset, scoped DnsEncodedName name,
        DnsRecordType type, uint ttl, ReadOnlySpan<byte> rdata, DnsRecordClass @class = DnsRecordClass.Internet)
    {
        // Write name (flat, expanding compression pointers)
        foreach (ReadOnlySpan<byte> label in name.EnumerateLabels())
        {
            buf[offset++] = (byte)label.Length;
            label.CopyTo(buf[offset..]);
            offset += label.Length;
        }
        buf[offset++] = 0; // root label

        BinaryPrimitives.WriteUInt16BigEndian(buf[offset..], (ushort)type);
        BinaryPrimitives.WriteUInt16BigEndian(buf[(offset + 2)..], (ushort)@class);
        BinaryPrimitives.WriteUInt32BigEndian(buf[(offset + 4)..], ttl);
        BinaryPrimitives.WriteUInt16BigEndian(buf[(offset + 8)..], (ushort)rdata.Length);
        offset += 10;

        rdata.CopyTo(buf[offset..]);
        offset += rdata.Length;
    }

    internal static byte[] BuildSimpleResponse(ushort queryId, byte[] questionName,
        DnsRecordType type, byte[] rdata, uint ttl)
    {
        DnsEncodedName qName = ParseName(questionName);
        Span<byte> buf = stackalloc byte[512];
        DnsMessageWriter writer = new(buf);

        writer.TryWriteHeader(ResponseHeader(queryId, questionCount: 1, answerCount: 1));
        writer.TryWriteQuestion(qName, type);

        int offset = writer.BytesWritten;
        WriteRecord(buf, ref offset, qName, type, ttl, rdata);

        return buf[..offset].ToArray();
    }

    internal static byte[] BuildTruncatedResponse(ushort queryId, byte[] questionName, DnsRecordType type)
    {
        DnsEncodedName qName = ParseName(questionName);
        Span<byte> buf = stackalloc byte[512];
        DnsMessageWriter writer = new(buf);

        writer.TryWriteHeader(ResponseHeader(queryId, flags: DnsHeaderFlags.Truncation, questionCount: 1));
        writer.TryWriteQuestion(qName, type);

        return buf[..writer.BytesWritten].ToArray();
    }

    internal static byte[] BuildErrorResponse(ushort queryId, byte[] questionName,
        DnsRecordType type, DnsResponseCode rcode)
    {
        DnsEncodedName qName = ParseName(questionName);
        Span<byte> buf = stackalloc byte[512];
        DnsMessageWriter writer = new(buf);

        ushort questionCount = (ushort)(questionName.Length > 0 ? 1 : 0);
        writer.TryWriteHeader(ResponseHeader(queryId, rcode: rcode, questionCount: questionCount));

        if (questionName.Length > 0)
        {
            writer.TryWriteQuestion(qName, type);
        }

        return buf[..writer.BytesWritten].ToArray();
    }

    private static byte[] BuildCNameAndAResponse(ushort queryId, byte[] questionName,
        string cname, IPAddress address, uint ttl)
    {
        DnsRecordType addrType = address.AddressFamily == AddressFamily.InterNetworkV6
            ? DnsRecordType.AAAA : DnsRecordType.A;

        DnsEncodedName qName = ParseName(questionName);
        byte[] cnameEncoded = EncodeName(cname);
        DnsEncodedName cnameName = ParseName(cnameEncoded);

        Span<byte> buf = stackalloc byte[512];
        DnsMessageWriter writer = new(buf);

        writer.TryWriteHeader(ResponseHeader(queryId, questionCount: 1, answerCount: 2));
        writer.TryWriteQuestion(qName, addrType);

        int offset = writer.BytesWritten;
        WriteRecord(buf, ref offset, qName, DnsRecordType.CNAME, ttl, cnameEncoded);
        WriteRecord(buf, ref offset, cnameName, addrType, ttl, address.GetAddressBytes());

        return buf[..offset].ToArray();
    }

    private static byte[] BuildResponseWithSoa(ushort queryId, byte[] questionName,
        DnsRecordType type, DnsResponseCode rcode, string soaName, uint soaMinTtl)
    {
        DnsEncodedName qName = ParseName(questionName);
        byte[] soaNameEncoded = EncodeName(soaName);
        DnsEncodedName soaDnsName = ParseName(soaNameEncoded);

        // Build SOA RDATA: mname, rname, serial, refresh, retry, expire, minimum
        byte[] mname = EncodeName("ns." + soaName);
        byte[] rname = EncodeName("admin." + soaName);
        Span<byte> soaRdata = stackalloc byte[mname.Length + rname.Length + 20];
        mname.CopyTo(soaRdata);
        rname.CopyTo(soaRdata[mname.Length..]);
        int fixedStart = mname.Length + rname.Length;
        BinaryPrimitives.WriteUInt32BigEndian(soaRdata[fixedStart..], 2024010101); // serial
        BinaryPrimitives.WriteUInt32BigEndian(soaRdata[(fixedStart + 4)..], 3600); // refresh
        BinaryPrimitives.WriteUInt32BigEndian(soaRdata[(fixedStart + 8)..], 900); // retry
        BinaryPrimitives.WriteUInt32BigEndian(soaRdata[(fixedStart + 12)..], 604800); // expire
        BinaryPrimitives.WriteUInt32BigEndian(soaRdata[(fixedStart + 16)..], soaMinTtl); // minimum

        Span<byte> buf = stackalloc byte[512];
        DnsMessageWriter writer = new(buf);

        writer.TryWriteHeader(ResponseHeader(queryId, rcode: rcode, questionCount: 1, authorityCount: 1));
        writer.TryWriteQuestion(qName, type);

        int offset = writer.BytesWritten;
        WriteRecord(buf, ref offset, soaDnsName, DnsRecordType.SOA, soaMinTtl, soaRdata);

        return buf[..offset].ToArray();
    }

    private static byte[] BuildSrvResponse(ushort queryId, byte[] questionName,
        (string Target, ushort Port, ushort Priority, ushort Weight, uint Ttl, IPAddress[]? Addresses)[] entries)
    {
        DnsEncodedName qName = ParseName(questionName);

        int additionalCount = 0;
        foreach (var e in entries)
        {
            if (e.Addresses != null)
            {
                additionalCount += e.Addresses.Length;
            }
        }

        Span<byte> buf = stackalloc byte[2048];
        DnsMessageWriter writer = new(buf);

        writer.TryWriteHeader(ResponseHeader(queryId,
            questionCount: 1,
            answerCount: (ushort)entries.Length,
            additionalCount: (ushort)additionalCount));
        writer.TryWriteQuestion(qName, DnsRecordType.SRV);

        int offset = writer.BytesWritten;

        // SRV answer records
        foreach (var e in entries)
        {
            byte[] targetBytes = EncodeName(e.Target);
            byte[] srvRdata = new byte[6 + targetBytes.Length];
            BinaryPrimitives.WriteUInt16BigEndian(srvRdata, e.Priority);
            BinaryPrimitives.WriteUInt16BigEndian(srvRdata.AsSpan(2), e.Weight);
            BinaryPrimitives.WriteUInt16BigEndian(srvRdata.AsSpan(4), e.Port);
            targetBytes.CopyTo(srvRdata.AsSpan(6));

            WriteRecord(buf, ref offset, qName, DnsRecordType.SRV, e.Ttl, srvRdata);
        }

        // Additional section: A/AAAA records for targets
        foreach (var e in entries)
        {
            if (e.Addresses == null)
            {
                continue;
            }

            byte[] targetBytes = EncodeName(e.Target);
            DnsEncodedName targetName = ParseName(targetBytes);
            foreach (IPAddress addr in e.Addresses)
            {
                DnsRecordType addrType = addr.AddressFamily == AddressFamily.InterNetworkV6
                    ? DnsRecordType.AAAA : DnsRecordType.A;
                WriteRecord(buf, ref offset, targetName, addrType, e.Ttl, addr.GetAddressBytes());
            }
        }

        return buf[..offset].ToArray();
    }

    /// <summary>
    /// Builds a response with a valid header and question echo, but with ANCOUNT set
    /// to a value higher than the actual number of answer records in the body.
    /// </summary>
    internal static byte[] BuildResponseWithMissingAnswers(ushort queryId, byte[] questionName,
        DnsRecordType type, ushort claimedAnswerCount)
    {
        DnsEncodedName qName = ParseName(questionName);
        Span<byte> buf = stackalloc byte[512];
        DnsMessageWriter writer = new(buf);

        writer.TryWriteHeader(ResponseHeader(queryId, questionCount: 1, answerCount: claimedAnswerCount));
        writer.TryWriteQuestion(qName, type);

        return buf[..writer.BytesWritten].ToArray();
    }

    /// <summary>
    /// Builds a response where the question section claims QDCOUNT questions
    /// but the body does not contain any question data beyond the header.
    /// </summary>
    internal static byte[] BuildResponseWithMissingQuestions(ushort queryId, ushort claimedQuestionCount)
    {
        Span<byte> buf = stackalloc byte[512];
        DnsMessageWriter writer = new(buf);

        writer.TryWriteHeader(ResponseHeader(queryId, questionCount: claimedQuestionCount));

        return buf[..writer.BytesWritten].ToArray();
    }

    /// <summary>
    /// Builds a response with valid question and answer, but with NSCOUNT set higher
    /// than actual authority records present (zero).
    /// </summary>
    internal static byte[] BuildResponseWithMissingAuthority(ushort queryId, byte[] questionName,
        DnsRecordType type, byte[] rdata, uint ttl, ushort claimedAuthorityCount)
    {
        DnsEncodedName qName = ParseName(questionName);
        Span<byte> buf = stackalloc byte[512];
        DnsMessageWriter writer = new(buf);

        writer.TryWriteHeader(ResponseHeader(queryId, questionCount: 1, answerCount: 1, authorityCount: claimedAuthorityCount));
        writer.TryWriteQuestion(qName, type);

        int offset = writer.BytesWritten;
        WriteRecord(buf, ref offset, qName, type, ttl, rdata);

        return buf[..offset].ToArray();
    }

    /// <summary>
    /// Builds an NXDOMAIN response with SOA in authority, but the SOA RDATA is truncated.
    /// This must be built manually since the writer doesn't support writing malformed records.
    /// </summary>
    internal static byte[] BuildNxDomainWithTruncatedSoa(ushort queryId, byte[] questionName,
        DnsRecordType type)
    {
        DnsEncodedName qName = ParseName(questionName);
        byte[] soaNameBytes = EncodeName("test");
        DnsEncodedName soaName = ParseName(soaNameBytes);

        Span<byte> buf = stackalloc byte[512];
        DnsMessageWriter writer = new(buf);

        writer.TryWriteHeader(ResponseHeader(queryId, rcode: DnsResponseCode.NameError, questionCount: 1, authorityCount: 1));
        writer.TryWriteQuestion(qName, type);

        // Write a SOA record with RDLENGTH claiming 50 bytes but only 4 bytes of actual data.
        // We write the record fields manually with a mismatched RDLENGTH.
        int offset = writer.BytesWritten;
        WriteRecord(buf, ref offset, soaName, DnsRecordType.SOA, 60, new byte[4]);

        // Patch the RDLENGTH to claim 50 bytes instead of the actual 4
        int rdLengthOffset = offset - 4 - 2; // back past rdata(4) and rdlength(2)
        BinaryPrimitives.WriteUInt16BigEndian(buf[rdLengthOffset..], 50);

        return buf[..offset].ToArray();
    }

    /// <summary>
    /// Creates a standard response header with common defaults (QR=1, RD=1, RA=1).
    /// </summary>
    private static DnsMessageHeader ResponseHeader(
        ushort id,
        DnsResponseCode rcode = DnsResponseCode.NoError,
        DnsHeaderFlags flags = default,
        ushort questionCount = 0,
        ushort answerCount = 0,
        ushort authorityCount = 0,
        ushort additionalCount = 0)
    {
        return new DnsMessageHeader
        {
            Id = id,
            IsResponse = true,
            Flags = DnsHeaderFlags.RecursionDesired | DnsHeaderFlags.RecursionAvailable | flags,
            ResponseCode = rcode,
            QuestionCount = questionCount,
            AnswerCount = answerCount,
            AuthorityCount = authorityCount,
            AdditionalCount = additionalCount,
        };
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

        DnsRecordType qType = (DnsRecordType)BinaryPrimitives.ReadUInt16BigEndian(query.AsSpan(pos));

        // Decode the name for lookup
        DnsEncodedName.TryParse(query, nameStart, out DnsEncodedName encodedName, out _);
        string nameStr = encodedName.ToString();

        if (_responses.TryGetValue((nameStr.ToLowerInvariant(), qType), out var builder))
            return builder(queryId, questionName, isTcp);

        // Default: NXDOMAIN
        return BuildErrorResponse(queryId, questionName, qType, DnsResponseCode.NameError);
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
