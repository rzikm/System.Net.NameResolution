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
    /// Resolves DNS records of type <typeparamref name="T"/> for the given name.
    /// Each record type provides its own resolution strategy via <see cref="IDnsRecord{T}"/>.
    /// </summary>
    public Task<DnsResult<T>> ResolveAsync<T>(
        string name,
        CancellationToken cancellationToken = default)
        where T : IDnsRecord<T>
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentException.ThrowIfNullOrEmpty(name);

        return T.ResolveAsync(name, SendQueryAsync, cancellationToken);
    }

    /// <summary>
    /// Resolves hostname to addresses with TTL information.
    /// Convenience wrapper for <see cref="ResolveAsync{T}"/> with <see cref="DnsAddress"/>.
    /// </summary>
    public Task<DnsResult<DnsAddress>> ResolveAddressesAsync(
        string hostName,
        CancellationToken cancellationToken = default)
    {
        return ResolveAsync<DnsAddress>(hostName, cancellationToken);
    }

    /// <summary>
    /// Resolves SRV records for service discovery.
    /// Convenience wrapper for <see cref="ResolveAsync{T}"/> with <see cref="DnsSrvRecord"/>.
    /// </summary>
    public Task<DnsResult<DnsSrvRecord>> ResolveServiceAsync(
        string serviceName,
        CancellationToken cancellationToken = default)
    {
        return ResolveAsync<DnsSrvRecord>(serviceName, cancellationToken);
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

    /// <summary>
    /// Extracts the negative cache TTL from the SOA record in the authority section.
    /// Per RFC 2308, the negative cache TTL is the minimum of the SOA TTL and the SOA MINIMUM field.
    /// </summary>
    internal static DateTimeOffset? ExtractNegativeCacheTtl(ReadOnlySpan<byte> response, DateTimeOffset now)
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
    internal static void ThrowMalformedResponse() =>
        throw new InvalidDataException("Malformed DNS response.");

    internal static DnsMessageReader CreateReader(ReadOnlySpan<byte> response)
    {
        if (!DnsMessageReader.TryCreate(response, out DnsMessageReader reader))
        {
            ThrowMalformedResponse();
        }
        return reader;
    }

    internal static void SkipQuestions(ref DnsMessageReader reader)
    {
        for (int i = 0; i < reader.Header.QuestionCount; i++)
        {
            if (!reader.TryReadQuestion(out _))
            {
                ThrowMalformedResponse();
            }
        }
    }

    internal static DnsRecord ReadRecord(ref DnsMessageReader reader)
    {
        if (!reader.TryReadRecord(out DnsRecord record))
        {
            ThrowMalformedResponse();
        }
        return record;
    }

    internal static void SkipRecords(ref DnsMessageReader reader, int count)
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
