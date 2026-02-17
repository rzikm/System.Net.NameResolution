using System.Buffers;
using System.IO;
using System.Net.Sockets;

namespace System.Net;

/// <summary>
/// TTL-aware DNS resolver. Sends queries over UDP to configured servers
/// and parses responses using the low-level DNS message primitives.
/// </summary>
public class DnsResolver : IAsyncDisposable, IDisposable
{
    // Max UDP DNS message size (without EDNS0)
    private const int MaxUdpResponseSize = 512;

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

        byte[] responseBuf = ArrayPool<byte>.Shared.Rent(MaxUdpResponseSize);
        try
        {
            if (addressFamily is AddressFamily.Unspecified or AddressFamily.InterNetwork)
            {
                int responseLength = await SendQueryAsync(hostName, DnsRecordType.A, responseBuf, cancellationToken);
                (DnsResponseCode rcode, DateTimeOffset? negExpires) = CollectAddresses(responseBuf.AsSpan(0, responseLength), now, results);
                if (rcode != DnsResponseCode.NoError)
                {
                    worstResponseCode = rcode;
                    negativeCacheExpires = negExpires;
                }
            }

            if (addressFamily is AddressFamily.Unspecified or AddressFamily.InterNetworkV6)
            {
                int responseLength = await SendQueryAsync(hostName, DnsRecordType.AAAA, responseBuf, cancellationToken);
                (DnsResponseCode rcode, DateTimeOffset? negExpires) = CollectAddresses(responseBuf.AsSpan(0, responseLength), now, results);
                if (rcode != DnsResponseCode.NoError && worstResponseCode == DnsResponseCode.NoError)
                {
                    worstResponseCode = rcode;
                    negativeCacheExpires = negExpires;
                }
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(responseBuf);
        }

        // If we got any addresses, treat as success regardless of individual query codes
        // (e.g., A succeeds but AAAA returns NODATA for Unspecified)
        if (results.Count > 0)
        {
            return new DnsResult<DnsResolvedAddress>(DnsResponseCode.NoError, results.ToArray());
        }

        return new DnsResult<DnsResolvedAddress>(worstResponseCode, [], negativeCacheExpires);
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

        byte[] responseBuf = ArrayPool<byte>.Shared.Rent(MaxUdpResponseSize);
        try
        {
            int responseLength = await SendQueryAsync(serviceName, DnsRecordType.SRV, responseBuf, cancellationToken);
            ReadOnlySpan<byte> responseSpan = responseBuf.AsSpan(0, responseLength);
            if (!DnsMessageReader.TryCreate(responseSpan, out DnsMessageReader reader))
            {
                throw new InvalidDataException("DNS response too small for header.");
            }
            DateTimeOffset now = DateTimeOffset.UtcNow;

            if (reader.Header.ResponseCode != DnsResponseCode.NoError)
            {
                DateTimeOffset? negExpires = ExtractNegativeCacheTtl(responseSpan, now);
                return new DnsResult<DnsResolvedService>(reader.Header.ResponseCode, [], negExpires);
            }

            // Skip questions
            for (int i = 0; i < reader.Header.QuestionCount; i++)
            {
                reader.TryReadQuestion(out _);
            }

            List<DnsResolvedService> services = new();
            Dictionary<string, List<DnsResolvedAddress>> additionalAddresses = new(StringComparer.OrdinalIgnoreCase);

            // Read answer records (SRV)
            List<(string Target, ushort Port, ushort Priority, ushort Weight, DateTimeOffset ExpiresAt)> srvRecords = new();

            for (int i = 0; i < reader.Header.AnswerCount; i++)
            {
                if (!reader.TryReadRecord(out DnsRecord record))
                {
                    break;
                }
                if (record.TryParseSrvRecord(out DnsSrvRecordData srv))
                {
                    srvRecords.Add((srv.Target.ToString(), srv.Port, srv.Priority, srv.Weight,
                        now + TimeSpan.FromSeconds(record.TimeToLive)));
                }
            }

            // Skip authority
            for (int i = 0; i < reader.Header.AuthorityCount; i++)
            {
                reader.TryReadRecord(out _);
            }

            // Read additional section for addresses
            for (int i = 0; i < reader.Header.AdditionalCount; i++)
            {
                if (!reader.TryReadRecord(out DnsRecord record))
                {
                    break;
                }
                if (record.TryParseARecord(out DnsARecordData a))
                {
                    string name = record.Name.ToString();
                    if (!additionalAddresses.ContainsKey(name))
                    {
                        additionalAddresses[name] = new List<DnsResolvedAddress>();
                    }
                    additionalAddresses[name].Add(new DnsResolvedAddress(
                        a.ToIPAddress(), now + TimeSpan.FromSeconds(record.TimeToLive)));
                }
                else if (record.TryParseAAAARecord(out DnsAAAARecordData aaaa))
                {
                    string name = record.Name.ToString();
                    if (!additionalAddresses.ContainsKey(name))
                    {
                        additionalAddresses[name] = new List<DnsResolvedAddress>();
                    }
                    additionalAddresses[name].Add(new DnsResolvedAddress(
                        aaaa.ToIPAddress(), now + TimeSpan.FromSeconds(record.TimeToLive)));
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

        byte[] responseBuf = ArrayPool<byte>.Shared.Rent(MaxUdpResponseSize);
        bool success = false;
        try
        {
            int responseLength = await SendQueryAsync(name, type, responseBuf, cancellationToken);
            if (!DnsMessageReader.TryCreate(responseBuf.AsSpan(0, responseLength), out DnsMessageReader reader))
            {
                throw new InvalidDataException("DNS response too small for header.");
            }
            DnsQueryResult result = new DnsQueryResult(reader.Header.ResponseCode, reader.Header.Flags, responseBuf, responseLength);
            success = true;
            return result;
        }
        finally
        {
            if (!success)
            {
                ArrayPool<byte>.Shared.Return(responseBuf);
            }
        }
    }

    /// <summary>
    /// Sends a DNS query, writes the validated response into <paramref name="responseBuffer"/>,
    /// and returns the number of bytes written. Handles retries and server failover.
    /// </summary>
    private async Task<int> SendQueryAsync(string name, DnsRecordType type,
        byte[] responseBuffer, CancellationToken ct)
    {
        // Build query message on the stack
        Span<byte> nameBuf = stackalloc byte[DnsEncodedName.MaxEncodedLength];
        OperationStatus status = DnsEncodedName.TryEncode(name, nameBuf, out DnsEncodedName encodedName, out _);
        if (status != OperationStatus.Done)
        {
            throw new ArgumentException($"Invalid DNS name: '{name}'", nameof(name));
        }

        Span<byte> querySpan = stackalloc byte[MaxUdpResponseSize];
        DnsMessageWriter writer = new DnsMessageWriter(querySpan);
        ushort queryId = (ushort)Random.Shared.Next(0, ushort.MaxValue + 1);
        writer.TryWriteHeader(new DnsMessageHeader { Id = queryId, Flags = DnsHeaderFlags.RecursionDesired, QuestionCount = 1 });
        writer.TryWriteQuestion(encodedName, type);

        // Copy to a heap buffer for async send (can't use stackalloc across await)
        byte[] queryBytes = ArrayPool<byte>.Shared.Rent(writer.BytesWritten);
        querySpan[..writer.BytesWritten].CopyTo(queryBytes);
        int queryLength = writer.BytesWritten;

        IReadOnlyList<IPEndPoint> servers = GetServers();
        if (servers.Count == 0)
        {
            ArrayPool<byte>.Shared.Return(queryBytes);
            throw new InvalidOperationException("No DNS servers configured.");
        }

        Exception? lastException = null;

        try
        {
            foreach (IPEndPoint server in servers)
            {
                for (int attempt = 0; attempt <= _options.MaxRetries; attempt++)
                {
                    try
                    {
                        int responseLength = await SendUdpQueryAsync(
                            queryBytes.AsMemory(0, queryLength), server, responseBuffer, ct);

                        // Validate response is a well-formed DNS message
                        if (!DnsMessageHeader.TryRead(responseBuffer.AsSpan(0, responseLength), out DnsMessageHeader header))
                        {
                            lastException = new InvalidDataException("DNS response too short to contain a valid header.");
                            continue;
                        }

                        if (!header.IsResponse)
                        {
                            lastException = new InvalidDataException("DNS response has QR=0 (not a response).");
                            continue;
                        }

                        if (header.Id != queryId)
                        {
                            continue; // ignore mismatched response, retry
                        }

                        // Validate response echoes back the same question
                        if (!ValidateResponseQuestion(responseBuffer.AsSpan(0, responseLength), header, name, type))
                        {
                            lastException = new InvalidDataException("DNS response question does not match the query.");
                            continue;
                        }

                        if (header.ResponseCode == DnsResponseCode.ServerFailure)
                        {
                            lastException = new InvalidOperationException($"DNS server returned {header.ResponseCode}");
                            continue;
                        }

                        return responseLength;
                    }
                    catch (OperationCanceledException) when (ct.IsCancellationRequested)
                    {
                        throw;
                    }
                    catch (OperationCanceledException)
                    {
                        // Per-attempt timeout (not user cancellation)
                        lastException = new TimeoutException("DNS query timed out.");
                    }
                    catch (Exception ex)
                    {
                        lastException = ex;
                    }
                }
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(queryBytes);
        }

        if (lastException is TimeoutException)
        {
            throw lastException;
        }

        throw new InvalidOperationException("All DNS servers failed.", lastException);
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
        if (!DnsMessageReader.TryCreate(response, out DnsMessageReader reader))
        {
            return (DnsResponseCode.ServerFailure, null);
        }
        DnsResponseCode rcode = reader.Header.ResponseCode;

        if (rcode != DnsResponseCode.NoError)
        {
            DateTimeOffset? negExpires = ExtractNegativeCacheTtl(response, now);
            return (rcode, negExpires);
        }

        for (int i = 0; i < reader.Header.QuestionCount; i++)
        {
            reader.TryReadQuestion(out _);
        }

        for (int i = 0; i < reader.Header.AnswerCount; i++)
        {
            if (!reader.TryReadRecord(out DnsRecord record))
            {
                break;
            }

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
        if (!DnsMessageReader.TryCreate(response, out DnsMessageReader reader))
        {
            return null;
        }

        for (int i = 0; i < reader.Header.QuestionCount; i++)
        {
            reader.TryReadQuestion(out _);
        }
        for (int i = 0; i < reader.Header.AnswerCount; i++)
        {
            reader.TryReadRecord(out _);
        }

        for (int i = 0; i < reader.Header.AuthorityCount; i++)
        {
            if (!reader.TryReadRecord(out DnsRecord record))
            {
                break;
            }
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
