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

        var results = new List<DnsResolvedAddress>();
        var now = DateTimeOffset.UtcNow;
        DnsResponseCode worstResponseCode = DnsResponseCode.NoError;
        DateTimeOffset? negativeCacheExpires = null;

        if (addressFamily is AddressFamily.Unspecified or AddressFamily.InterNetwork)
        {
            var (response, responseLength) = await SendQueryAsync(hostName, DnsRecordType.A, cancellationToken);
            try
            {
                var (rcode, negExpires) = CollectAddresses(response.AsSpan(0, responseLength), now, results);
                if (rcode != DnsResponseCode.NoError)
                {
                    worstResponseCode = rcode;
                    negativeCacheExpires = negExpires;
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(response);
            }
        }

        if (addressFamily is AddressFamily.Unspecified or AddressFamily.InterNetworkV6)
        {
            var (response, responseLength) = await SendQueryAsync(hostName, DnsRecordType.AAAA, cancellationToken);
            try
            {
                var (rcode, negExpires) = CollectAddresses(response.AsSpan(0, responseLength), now, results);
                if (rcode != DnsResponseCode.NoError && worstResponseCode == DnsResponseCode.NoError)
                {
                    worstResponseCode = rcode;
                    negativeCacheExpires = negExpires;
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(response);
            }
        }

        // If we got any addresses, treat as success regardless of individual query codes
        // (e.g., A succeeds but AAAA returns NODATA for Unspecified)
        if (results.Count > 0)
            return new DnsResult<DnsResolvedAddress>(DnsResponseCode.NoError, results.ToArray());

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

        var (response, responseLength) = await SendQueryAsync(serviceName, DnsRecordType.SRV, cancellationToken);
        try
        {
            var responseSpan = response.AsSpan(0, responseLength);
            var reader = new DnsMessageReader(responseSpan);
            var now = DateTimeOffset.UtcNow;

            if (reader.Header.ResponseCode != DnsResponseCode.NoError)
            {
                var negExpires = ExtractNegativeCacheTtl(responseSpan, now);
                return new DnsResult<DnsResolvedService>(reader.Header.ResponseCode, [], negExpires);
            }

            // Skip questions
            for (int i = 0; i < reader.Header.QuestionCount; i++)
                reader.TryReadQuestion(out _);

            var services = new List<DnsResolvedService>();
            var additionalAddresses = new Dictionary<string, List<DnsResolvedAddress>>(StringComparer.OrdinalIgnoreCase);

            // Read answer records (SRV)
            var srvRecords = new List<(string Target, ushort Port, ushort Priority, ushort Weight, DateTimeOffset ExpiresAt)>();

            for (int i = 0; i < reader.Header.AnswerCount; i++)
            {
                if (!reader.TryReadRecord(out var record)) break;
                if (record.TryParseSrvRecord(out var srv))
                {
                    srvRecords.Add((srv.Target.ToString(), srv.Port, srv.Priority, srv.Weight,
                        now + TimeSpan.FromSeconds(record.TimeToLive)));
                }
            }

            // Skip authority
            for (int i = 0; i < reader.Header.AuthorityCount; i++)
                reader.TryReadRecord(out _);

            // Read additional section for addresses
            for (int i = 0; i < reader.Header.AdditionalCount; i++)
            {
                if (!reader.TryReadRecord(out var record)) break;
                if (record.TryParseARecord(out var a))
                {
                    string name = record.Name.ToString();
                    if (!additionalAddresses.ContainsKey(name))
                        additionalAddresses[name] = new List<DnsResolvedAddress>();
                    additionalAddresses[name].Add(new DnsResolvedAddress(
                        a.ToIPAddress(), now + TimeSpan.FromSeconds(record.TimeToLive)));
                }
                else if (record.TryParseAAAARecord(out var aaaa))
                {
                    string name = record.Name.ToString();
                    if (!additionalAddresses.ContainsKey(name))
                        additionalAddresses[name] = new List<DnsResolvedAddress>();
                    additionalAddresses[name].Add(new DnsResolvedAddress(
                        aaaa.ToIPAddress(), now + TimeSpan.FromSeconds(record.TimeToLive)));
                }
            }

            // Combine SRV records with their additional addresses
            foreach (var (target, port, priority, weight, expiresAt) in srvRecords)
            {
                additionalAddresses.TryGetValue(target, out var addrs);
                services.Add(new DnsResolvedService(target, port, priority, weight, expiresAt,
                    addrs?.ToArray()));
            }

            return new DnsResult<DnsResolvedService>(DnsResponseCode.NoError, services.ToArray());
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(response);
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

        var (response, responseLength) = await SendQueryAsync(name, type, cancellationToken);
        var reader = new DnsMessageReader(response.AsSpan(0, responseLength));

        return new DnsQueryResult(reader.Header.ResponseCode, reader.Header.Flags, response, responseLength);
    }

    /// <summary>
    /// Returns a pooled buffer containing the response and its actual length.
    /// The caller must return the buffer to ArrayPool&lt;byte&gt;.Shared when done.
    /// </summary>
    private async Task<(byte[] Buffer, int Length)> SendQueryAsync(string name, DnsRecordType type, CancellationToken ct)
    {
        // Build query message on the stack
        Span<byte> nameBuf = stackalloc byte[DnsName.MaxEncodedLength];
        var status = DnsName.TryCreate(name, nameBuf, out var dnsName, out _);
        if (status != OperationStatus.Done)
            throw new ArgumentException($"Invalid DNS name: '{name}'", nameof(name));

        Span<byte> querySpan = stackalloc byte[512];
        var writer = new DnsMessageWriter(querySpan);
        ushort queryId = (ushort)Random.Shared.Next(0, ushort.MaxValue + 1);
        writer.TryWriteHeader(DnsMessageHeader.CreateStandardQuery(queryId));
        writer.TryWriteQuestion(dnsName, type);

        // Copy to a heap buffer for async send (can't use stackalloc across await)
        byte[] queryBytes = ArrayPool<byte>.Shared.Rent(writer.BytesWritten);
        querySpan[..writer.BytesWritten].CopyTo(queryBytes);
        int queryLength = writer.BytesWritten;

        var servers = GetServers();
        if (servers.Count == 0)
        {
            ArrayPool<byte>.Shared.Return(queryBytes);
            throw new InvalidOperationException("No DNS servers configured.");
        }

        Exception? lastException = null;

        try
        {
            foreach (var server in servers)
            {
                for (int attempt = 0; attempt <= _options.MaxRetries; attempt++)
                {
                    try
                    {
                        var (response, responseLength) = await SendUdpQueryAsync(
                            queryBytes.AsMemory(0, queryLength), server, ct);

                        // Validate response is a well-formed DNS message
                        if (!DnsMessageHeader.TryRead(response.AsSpan(0, responseLength), out var header))
                        {
                            ArrayPool<byte>.Shared.Return(response);
                            lastException = new InvalidDataException("DNS response too short to contain a valid header.");
                            continue;
                        }

                        // Must be a response (QR=1), not a query
                        if (!header.IsResponse)
                        {
                            ArrayPool<byte>.Shared.Return(response);
                            lastException = new InvalidDataException("DNS response has QR=0 (not a response).");
                            continue;
                        }

                        // Validate transaction ID matches
                        if (header.Id != queryId)
                        {
                            ArrayPool<byte>.Shared.Return(response);
                            continue;
                        }

                        // Check for retriable server errors
                        if (header.ResponseCode == DnsResponseCode.ServerFailure)
                        {
                            ArrayPool<byte>.Shared.Return(response);
                            lastException = new InvalidOperationException($"DNS server returned {header.ResponseCode}");
                            continue;
                        }

                        return (response, responseLength);
                    }
                    catch (OperationCanceledException) when (ct.IsCancellationRequested)
                    {
                        throw;
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

        throw new InvalidOperationException("All DNS servers failed.", lastException);
    }

    private async Task<(byte[] Buffer, int Length)> SendUdpQueryAsync(
        ReadOnlyMemory<byte> query, IPEndPoint server, CancellationToken ct)
    {
        using var udp = new UdpClient(server.AddressFamily);
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeoutCts.CancelAfter(_options.Timeout);

        await udp.SendAsync(query, server, timeoutCts.Token);
        var result = await udp.ReceiveAsync(timeoutCts.Token);

        // Copy into a pooled buffer
        byte[] pooled = ArrayPool<byte>.Shared.Rent(result.Buffer.Length);
        result.Buffer.CopyTo(pooled, 0);
        return (pooled, result.Buffer.Length);
    }

    private IReadOnlyList<IPEndPoint> GetServers()
    {
        if (_options.Servers.Count > 0)
            return (IReadOnlyList<IPEndPoint>)_options.Servers;

        // Fallback: use system DNS — for now just return the loopback as placeholder.
        // A real implementation would parse resolv.conf on Linux or use
        // GetNetworkParams on Windows.
        return [new IPEndPoint(IPAddress.Loopback, 53)];
    }

    private static (DnsResponseCode, DateTimeOffset?) CollectAddresses(
        ReadOnlySpan<byte> response, DateTimeOffset now, List<DnsResolvedAddress> results)
    {
        var reader = new DnsMessageReader(response);
        var rcode = reader.Header.ResponseCode;

        if (rcode != DnsResponseCode.NoError)
        {
            var negExpires = ExtractNegativeCacheTtl(response, now);
            return (rcode, negExpires);
        }

        for (int i = 0; i < reader.Header.QuestionCount; i++)
            reader.TryReadQuestion(out _);

        for (int i = 0; i < reader.Header.AnswerCount; i++)
        {
            if (!reader.TryReadRecord(out var record)) break;

            if (record.TryParseARecord(out var a))
            {
                results.Add(new DnsResolvedAddress(
                    a.ToIPAddress(), now + TimeSpan.FromSeconds(record.TimeToLive)));
            }
            else if (record.TryParseAAAARecord(out var aaaa))
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
        var reader = new DnsMessageReader(response);

        for (int i = 0; i < reader.Header.QuestionCount; i++)
            reader.TryReadQuestion(out _);
        for (int i = 0; i < reader.Header.AnswerCount; i++)
            reader.TryReadRecord(out _);

        for (int i = 0; i < reader.Header.AuthorityCount; i++)
        {
            if (!reader.TryReadRecord(out var record)) break;
            if (record.TryParseSoaRecord(out var soa))
            {
                // RFC 2308 §5: negative cache TTL = min(SOA record TTL, SOA MINIMUM field)
                uint negativeTtl = Math.Min(record.TimeToLive, soa.MinimumTtl);
                return now + TimeSpan.FromSeconds(negativeTtl);
            }
        }

        return null;
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
