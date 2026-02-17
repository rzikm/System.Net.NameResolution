using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Net.Sockets;
using System.Security.Cryptography;

namespace System.Net;

/// <summary>
/// TTL-aware DNS resolver. Sends queries over UDP to configured servers
/// and parses responses using the low-level DNS message primitives.
/// </summary>
public class DnsResolver : IAsyncDisposable, IDisposable
{
    // Max UDP DNS message size (without EDNS0)
    private const int MaxUdpResponseSize = 512;

    // Initial buffer size for TCP responses; resized based on the 2-byte length prefix
    private const int InitialTcpBufferSize = 1024;

    private readonly DnsResolverOptions _options;
    private volatile bool _disposed;

    public DnsResolver() : this(new DnsResolverOptions()) { }

    public DnsResolver(DnsResolverOptions options)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
    }

    /// <summary>
    /// Resolves hostname to addresses with TTL information.
    /// AddressFamily.Unspecified queries both A and AAAA.
    /// </summary>
    public async Task<DnsResult<DnsResolvedAddress>> ResolveAddressesAsync(
        string hostName,
        AddressFamily addressFamily = AddressFamily.Unspecified,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentException.ThrowIfNullOrEmpty(hostName);

        List<DnsResolvedAddress> results = new();
        DateTimeOffset now = DateTimeOffset.UtcNow;
        DnsResponseCode worstResponseCode = DnsResponseCode.NoError;
        DateTimeOffset? negativeCacheExpires = null;

        if (addressFamily is AddressFamily.Unspecified or AddressFamily.InterNetwork)
        {
            (DnsResponseCode rcode, DateTimeOffset? negExpires) =
                await QueryAndCollectAddressesAsync(hostName, DnsRecordType.A, now, results, cancellationToken);
            if (rcode != DnsResponseCode.NoError)
            {
                worstResponseCode = rcode;
                negativeCacheExpires = negExpires;
            }
        }

        if (addressFamily is AddressFamily.Unspecified or AddressFamily.InterNetworkV6)
        {
            (DnsResponseCode rcode, DateTimeOffset? negExpires) =
                await QueryAndCollectAddressesAsync(hostName, DnsRecordType.AAAA, now, results, cancellationToken);
            if (rcode != DnsResponseCode.NoError && worstResponseCode == DnsResponseCode.NoError)
            {
                worstResponseCode = rcode;
                negativeCacheExpires = negExpires;
            }
        }

        if (results.Count > 0)
        {
            return new DnsResult<DnsResolvedAddress>(DnsResponseCode.NoError, results.ToArray());
        }

        return new DnsResult<DnsResolvedAddress>(worstResponseCode, [], negativeCacheExpires);
    }

    private async Task<(DnsResponseCode, DateTimeOffset?)> QueryAndCollectAddressesAsync(
        string hostName, DnsRecordType type, DateTimeOffset now,
        List<DnsResolvedAddress> results, CancellationToken ct)
    {
        (byte[] responseBuf, int responseLength) = await SendQueryAsync(hostName, type, ct);
        try
        {
            return CollectAddresses(responseBuf.AsSpan(0, responseLength), now, results);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(responseBuf);
        }
    }

    /// <summary>
    /// Resolves SRV records for service discovery.
    /// </summary>
    public async Task<DnsResult<DnsResolvedService>> ResolveServiceAsync(
        string serviceName,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentException.ThrowIfNullOrEmpty(serviceName);

        (byte[] responseBuf, int responseLength) = await SendQueryAsync(serviceName, DnsRecordType.SRV, cancellationToken);
        try
        {
            ReadOnlySpan<byte> responseSpan = responseBuf.AsSpan(0, responseLength);
            DnsMessageReader reader = CreateReader(responseSpan);
            DateTimeOffset now = DateTimeOffset.UtcNow;

            if (reader.Header.ResponseCode != DnsResponseCode.NoError)
            {
                DateTimeOffset? negExpires = ExtractNegativeCacheTtl(responseSpan, now);
                return new DnsResult<DnsResolvedService>(reader.Header.ResponseCode, [], negExpires);
            }

            SkipQuestions(ref reader);

            List<DnsResolvedService> services = new();
            Dictionary<string, List<DnsResolvedAddress>> additionalAddresses = new(StringComparer.OrdinalIgnoreCase);

            // Read answer records (SRV)
            List<(string Target, ushort Port, ushort Priority, ushort Weight, DateTimeOffset ExpiresAt)> srvRecords = new();

            for (int i = 0; i < reader.Header.AnswerCount; i++)
            {
                DnsRecord record = ReadRecord(ref reader);
                if (record.TryParseSrvRecord(out DnsSrvRecordData srv))
                {
                    srvRecords.Add((srv.Target.ToString(), srv.Port, srv.Priority, srv.Weight,
                        now + TimeSpan.FromSeconds(record.TimeToLive)));
                }
            }

            SkipRecords(ref reader, reader.Header.AuthorityCount);

            // Read additional section for addresses
            for (int i = 0; i < reader.Header.AdditionalCount; i++)
            {
                DnsRecord record = ReadRecord(ref reader);

                IPAddress? address = null;
                if (record.TryParseARecord(out DnsARecordData a))
                {
                    address = a.ToIPAddress();
                }
                else if (record.TryParseAAAARecord(out DnsAAAARecordData aaaa))
                {
                    address = aaaa.ToIPAddress();
                }

                if (address != null)
                {
                    string recordName = record.Name.ToString();
                    if (!additionalAddresses.TryGetValue(recordName, out List<DnsResolvedAddress>? list))
                    {
                        list = new List<DnsResolvedAddress>();
                        additionalAddresses[recordName] = list;
                    }
                    list.Add(new DnsResolvedAddress(address, now + TimeSpan.FromSeconds(record.TimeToLive)));
                }
            }

            // Combine SRV records with their additional addresses
            foreach ((string target, ushort port, ushort priority, ushort weight, DateTimeOffset expiresAt) in srvRecords)
            {
                additionalAddresses.TryGetValue(target, out List<DnsResolvedAddress>? addrs);
                services.Add(new DnsResolvedService(target, port, priority, weight, expiresAt,
                    addrs?.ToArray()));
            }

            return new DnsResult<DnsResolvedService>(DnsResponseCode.NoError, services.ToArray());
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(responseBuf);
        }
    }

    /// <summary>
    /// Sends an arbitrary DNS query and returns the raw response.
    /// The caller must dispose the returned DnsQueryResult to return the buffer to the pool.
    /// </summary>
    public async Task<DnsQueryResult> QueryAsync(
        string name,
        DnsRecordType type,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentException.ThrowIfNullOrEmpty(name);

        (byte[] responseBuf, int responseLength) = await SendQueryAsync(name, type, cancellationToken);
        try
        {
            DnsMessageReader reader = CreateReader(responseBuf.AsSpan(0, responseLength));
            DnsQueryResult result = new DnsQueryResult(reader.Header.ResponseCode, reader.Header.Flags, responseBuf, responseLength);
            return result;
        }
        catch
        {
            ArrayPool<byte>.Shared.Return(responseBuf);
            throw;
        }
    }

    /// <summary>
    /// Sends a DNS query, validates the response, and handles TCP fallback if the
    /// response is truncated (TC bit). Returns the response buffer (rented from ArrayPool)
    /// and the number of valid bytes. The caller must return the buffer to the pool.
    /// </summary>
    private async Task<(byte[] Buffer, int Length)> SendQueryAsync(
        string name, DnsRecordType type, CancellationToken ct)
    {
        IReadOnlyList<IPEndPoint> servers = GetServers();
        Debug.Assert(servers.Count > 0, "GetServers should return at least one server.");

        byte[] queryBytes = ArrayPool<byte>.Shared.Rent(MaxUdpResponseSize);
        try
        {
            ushort queryId = (ushort)RandomNumberGenerator.GetInt32(ushort.MaxValue + 1);
            int queryLength = WriteDnsRequestMessage(queryId, name, type, queryBytes);
            ReadOnlyMemory<byte> query = queryBytes.AsMemory(0, queryLength);

            byte[] responseBuffer = ArrayPool<byte>.Shared.Rent(MaxUdpResponseSize);
            Exception? lastException = null;

            foreach (IPEndPoint server in servers)
            {
                for (int attempt = 0; attempt <= _options.MaxRetries; attempt++)
                {
                    try
                    {
                        int responseLength = await SendUdpQueryAsync(query, server, responseBuffer, ct);

                        ResponseValidation validation = ValidateResponse(
                            responseBuffer.AsSpan(0, responseLength), queryId, name, type,
                            out Exception? validationError);

                        if (validation == ResponseValidation.Retry)
                        {
                            continue;
                        }

                        if (validation == ResponseValidation.RetryWithError)
                        {
                            lastException = validationError;
                            continue;
                        }

                        if (validation == ResponseValidation.TcpFallback)
                        {
                            (byte[]? tcpBuffer, int tcpLength, Exception? tcpError) =
                                await TryTcpFallbackAsync(query, server, ct);

                            if (tcpBuffer != null)
                            {
                                ArrayPool<byte>.Shared.Return(responseBuffer);
                                return (tcpBuffer, tcpLength);
                            }

                            lastException = tcpError;
                            continue;
                        }

                        return (responseBuffer, responseLength);
                    }
                    catch (OperationCanceledException) when (ct.IsCancellationRequested)
                    {
                        throw;
                    }
                    catch (OperationCanceledException)
                    {
                        lastException = new TimeoutException("DNS query timed out.");
                    }
                    catch (Exception ex)
                    {
                        lastException = ex;
                    }
                }
            }

            ArrayPool<byte>.Shared.Return(responseBuffer);

            if (lastException is TimeoutException)
            {
                throw lastException;
            }

            throw new InvalidOperationException("All DNS servers failed.", lastException);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(queryBytes);
        }
    }

    private enum ResponseValidation
    {
        Ok,
        Retry,
        RetryWithError,
        TcpFallback,
    }

    /// <summary>
    /// Validates a UDP DNS response. Returns the validation result indicating
    /// whether the response is acceptable, should be retried, or needs TCP fallback.
    /// On RetryWithError, <paramref name="error"/> contains the specific exception.
    /// </summary>
    private static ResponseValidation ValidateResponse(
        ReadOnlySpan<byte> response, ushort expectedId, string expectedName, DnsRecordType expectedType,
        out Exception? error)
    {
        error = null;

        if (!DnsMessageHeader.TryRead(response, out DnsMessageHeader header))
        {
            error = new InvalidDataException("DNS response too short to contain a valid header.");
            return ResponseValidation.RetryWithError;
        }

        if (!header.IsResponse)
        {
            error = new InvalidDataException("DNS response has QR=0 (not a response).");
            return ResponseValidation.RetryWithError;
        }

        if (header.Id != expectedId)
        {
            return ResponseValidation.Retry;
        }

        if (!ValidateResponseQuestion(response, header, expectedName, expectedType))
        {
            error = new InvalidDataException("DNS response question does not match the query.");
            return ResponseValidation.RetryWithError;
        }

        if (header.ResponseCode == DnsResponseCode.ServerFailure)
        {
            error = new InvalidOperationException($"DNS server returned {header.ResponseCode}");
            return ResponseValidation.RetryWithError;
        }

        if (header.Flags.HasFlag(DnsHeaderFlags.Truncation))
        {
            return ResponseValidation.TcpFallback;
        }

        return ResponseValidation.Ok;
    }

    /// <summary>
    /// Attempts to resend the query over TCP. Returns the buffer and length on success,
    /// or null buffer with the exception on failure.
    /// </summary>
    private async Task<(byte[]? Buffer, int Length, Exception? Error)> TryTcpFallbackAsync(
        ReadOnlyMemory<byte> query, IPEndPoint server, CancellationToken ct)
    {
        try
        {
            (byte[] tcpBuffer, int tcpLength) = await SendTcpQueryAsync(query, server, ct);
            return (tcpBuffer, tcpLength, null);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            return (null, 0, new TimeoutException("DNS TCP query timed out."));
        }
        catch (Exception ex)
        {
            return (null, 0, ex);
        }
    }

    private int WriteDnsRequestMessage(ushort queryId, string name, DnsRecordType type, Span<byte> destination)
    {
        // Build query message on the stack
        Span<byte> dnsNameBuffer = stackalloc byte[DnsEncodedName.MaxEncodedLength];
        OperationStatus status = DnsEncodedName.TryEncode(name, dnsNameBuffer, out DnsEncodedName encodedName, out int nameBytesWritten);
        if (status == OperationStatus.InvalidData)
        {
            throw new ArgumentException($"Invalid DNS name: '{name}'", nameof(name));
        }

        Debug.Assert(status == OperationStatus.Done);

        DnsMessageWriter writer = new DnsMessageWriter(destination);
        writer.TryWriteHeader(new DnsMessageHeader { Id = queryId, Flags = DnsHeaderFlags.RecursionDesired, QuestionCount = 1 });
        writer.TryWriteQuestion(encodedName, type);
        return writer.BytesWritten;
    }

    /// <summary>
    /// Sends a UDP query and writes the response into <paramref name="responseBuffer"/>.
    /// Returns the number of bytes received.
    /// </summary>
    private async Task<int> SendUdpQueryAsync(
        ReadOnlyMemory<byte> query, IPEndPoint server,
        byte[] responseBuffer, CancellationToken ct)
    {
        using Socket socket = new Socket(server.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        using CancellationTokenSource timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeoutCts.CancelAfter(_options.Timeout);

        await socket.SendToAsync(query, SocketFlags.None, server, timeoutCts.Token);
        SocketReceiveFromResult result = await socket.ReceiveFromAsync(
            responseBuffer, SocketFlags.None, server, timeoutCts.Token);
        return result.ReceivedBytes;
    }

    /// <summary>
    /// Sends a DNS query over TCP (RFC 1035 §4.2.2). TCP messages are prefixed
    /// with a 2-byte big-endian length field. Returns a rented buffer and the number
    /// of valid response bytes. The caller must return the buffer to the pool.
    /// </summary>
    private async Task<(byte[] Buffer, int Length)> SendTcpQueryAsync(
        ReadOnlyMemory<byte> query, IPEndPoint server, CancellationToken ct)
    {
        using Socket socket = new Socket(server.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        using CancellationTokenSource timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeoutCts.CancelAfter(_options.Timeout);

        await socket.ConnectAsync(server, timeoutCts.Token);

        // Send: 2-byte length prefix + query
        byte[] tmpBuffer = ArrayPool<byte>.Shared.Rent(InitialTcpBufferSize);
        int responseLength;
        try
        {
            BinaryPrimitives.WriteUInt16BigEndian(tmpBuffer, (ushort)query.Length);
            await socket.SendAsync(tmpBuffer.AsMemory(0, 2), SocketFlags.None, timeoutCts.Token);
            await socket.SendAsync(query, SocketFlags.None, timeoutCts.Token);

            // Receive: 2-byte length prefix
            await ReceiveExactAsync(socket, tmpBuffer.AsMemory(0, 2), timeoutCts.Token);
            responseLength = BinaryPrimitives.ReadUInt16BigEndian(tmpBuffer);

            if (responseLength > tmpBuffer.Length)
            {
                ArrayPool<byte>.Shared.Return(tmpBuffer);
                tmpBuffer = ArrayPool<byte>.Shared.Rent(responseLength);
            }

            await ReceiveExactAsync(socket, tmpBuffer.AsMemory(0, responseLength), timeoutCts.Token);
        }
        catch
        {
            ArrayPool<byte>.Shared.Return(tmpBuffer);
            throw;
        }

        return (tmpBuffer, responseLength);
    }

    /// <summary>
    /// Reads exactly <paramref name="buffer"/>.Length bytes from the socket.
    /// TCP may deliver data in multiple segments; this loops until all bytes are received.
    /// </summary>
    private static async Task ReceiveExactAsync(Socket socket, Memory<byte> buffer, CancellationToken ct)
    {
        int totalReceived = 0;
        while (totalReceived < buffer.Length)
        {
            int received = await socket.ReceiveAsync(buffer[totalReceived..], SocketFlags.None, ct);
            if (received == 0)
            {
                ThrowMalformedResponse();
            }
            totalReceived += received;
        }
    }

    private IReadOnlyList<IPEndPoint> GetServers()
    {
        if (_options.Servers.Count > 0)
        {
            return (IReadOnlyList<IPEndPoint>)_options.Servers;
        }

        // Fallback: use system DNS — for now just return the loopback as placeholder.
        // A real implementation would parse resolv.conf on Linux or use
        // GetNetworkParams on Windows.
        return [new IPEndPoint(IPAddress.Loopback, 53)];
    }

    private static (DnsResponseCode, DateTimeOffset?) CollectAddresses(
        ReadOnlySpan<byte> response, DateTimeOffset now, List<DnsResolvedAddress> results)
    {
        DnsMessageReader reader = CreateReader(response);
        DnsResponseCode rcode = reader.Header.ResponseCode;

        if (rcode != DnsResponseCode.NoError)
        {
            DateTimeOffset? negExpires = ExtractNegativeCacheTtl(response, now);
            return (rcode, negExpires);
        }

        SkipQuestions(ref reader);

        for (int i = 0; i < reader.Header.AnswerCount; i++)
        {
            DnsRecord record = ReadRecord(ref reader);

            if (record.TryParseARecord(out DnsARecordData a))
            {
                results.Add(new DnsResolvedAddress(
                    a.ToIPAddress(), now + TimeSpan.FromSeconds(record.TimeToLive)));
            }
            else if (record.TryParseAAAARecord(out DnsAAAARecordData aaaa))
            {
                results.Add(new DnsResolvedAddress(
                    aaaa.ToIPAddress(), now + TimeSpan.FromSeconds(record.TimeToLive)));
            }
        }

        return (DnsResponseCode.NoError, null);
    }

    /// <summary>
    /// Extracts the negative cache TTL from the SOA record in the authority section.
    /// Per RFC 2308, the negative cache TTL is the minimum of the SOA TTL and the SOA MINIMUM field.
    /// </summary>
    private static DateTimeOffset? ExtractNegativeCacheTtl(ReadOnlySpan<byte> response, DateTimeOffset now)
    {
        DnsMessageReader reader = CreateReader(response);

        SkipQuestions(ref reader);
        SkipRecords(ref reader, reader.Header.AnswerCount);

        for (int i = 0; i < reader.Header.AuthorityCount; i++)
        {
            DnsRecord record = ReadRecord(ref reader);
            if (record.TryParseSoaRecord(out DnsSoaRecordData soa))
            {
                // RFC 2308 §5: negative cache TTL = min(SOA record TTL, SOA MINIMUM field)
                uint negativeTtl = Math.Min(record.TimeToLive, soa.MinimumTtl);
                return now + TimeSpan.FromSeconds(negativeTtl);
            }
        }

        return null;
    }

    /// <summary>
    /// Validates that the response contains exactly one question matching the query name and type.
    /// </summary>
    private static bool ValidateResponseQuestion(
        ReadOnlySpan<byte> response, DnsMessageHeader header, string expectedName, DnsRecordType expectedType)
    {
        if (header.QuestionCount != 1)
        {
            return false;
        }

        DnsMessageReader.TryCreate(response, out DnsMessageReader reader);
        if (!reader.TryReadQuestion(out DnsQuestion question))
        {
            return false;
        }

        return question.Type == expectedType && question.Name.Equals(expectedName);
    }

    [DoesNotReturn]
    private static void ThrowMalformedResponse() =>
        throw new InvalidDataException("Malformed DNS response.");

    private static DnsMessageReader CreateReader(ReadOnlySpan<byte> response)
    {
        if (!DnsMessageReader.TryCreate(response, out DnsMessageReader reader))
        {
            ThrowMalformedResponse();
        }
        return reader;
    }

    private static void SkipQuestions(ref DnsMessageReader reader)
    {
        for (int i = 0; i < reader.Header.QuestionCount; i++)
        {
            if (!reader.TryReadQuestion(out _))
            {
                ThrowMalformedResponse();
            }
        }
    }

    private static DnsRecord ReadRecord(ref DnsMessageReader reader)
    {
        if (!reader.TryReadRecord(out DnsRecord record))
        {
            ThrowMalformedResponse();
        }
        return record;
    }

    private static void SkipRecords(ref DnsMessageReader reader, int count)
    {
        for (int i = 0; i < count; i++)
        {
            if (!reader.TryReadRecord(out _))
            {
                ThrowMalformedResponse();
            }
        }
    }

    public void Dispose()
    {
        _disposed = true;
    }

    public ValueTask DisposeAsync()
    {
        _disposed = true;
        return ValueTask.CompletedTask;
    }
}
