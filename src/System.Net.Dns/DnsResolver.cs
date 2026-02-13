using System.Buffers;
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
    public async Task<DnsResolvedAddress[]> ResolveAddressesAsync(
        string hostName,
        AddressFamily addressFamily = AddressFamily.Unspecified,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentException.ThrowIfNullOrEmpty(hostName);

        var results = new List<DnsResolvedAddress>();
        var now = DateTimeOffset.UtcNow;

        if (addressFamily is AddressFamily.Unspecified or AddressFamily.InterNetwork)
        {
            var response = await SendQueryAsync(hostName, DnsRecordType.A, cancellationToken);
            CollectAddresses(response, now, results);
        }

        if (addressFamily is AddressFamily.Unspecified or AddressFamily.InterNetworkV6)
        {
            var response = await SendQueryAsync(hostName, DnsRecordType.AAAA, cancellationToken);
            CollectAddresses(response, now, results);
        }

        return results.ToArray();
    }

    /// <summary>
    /// Resolves SRV records for service discovery.
    /// </summary>
    public async Task<DnsResolvedService[]> ResolveServiceAsync(
        string serviceName,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentException.ThrowIfNullOrEmpty(serviceName);

        var response = await SendQueryAsync(serviceName, DnsRecordType.SRV, cancellationToken);
        var reader = new DnsMessageReader(response);
        var now = DateTimeOffset.UtcNow;

        // Skip questions
        for (int i = 0; i < reader.Header.QuestionCount; i++)
            reader.TryReadQuestion(out _);

        var services = new List<DnsResolvedService>();
        var additionalAddresses = new Dictionary<string, List<DnsResolvedAddress>>(StringComparer.OrdinalIgnoreCase);

        // Read answer records (SRV)
        int totalRecords = reader.Header.AnswerCount + reader.Header.AuthorityCount + reader.Header.AdditionalCount;
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

        return services.ToArray();
    }

    /// <summary>
    /// Sends an arbitrary DNS query and returns the raw response.
    /// </summary>
    public async Task<DnsQueryResult> QueryAsync(
        string name,
        DnsRecordType type,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentException.ThrowIfNullOrEmpty(name);

        var response = await SendQueryAsync(name, type, cancellationToken);
        var reader = new DnsMessageReader(response);

        return new DnsQueryResult(reader.Header.ResponseCode, reader.Header.Flags, response);
    }

    private async Task<byte[]> SendQueryAsync(string name, DnsRecordType type, CancellationToken ct)
    {
        // Build query message
        byte[] queryBytes = BuildQuery(name, type);
        ushort queryId = System.Buffers.Binary.BinaryPrimitives.ReadUInt16BigEndian(queryBytes);

        var servers = GetServers();
        if (servers.Count == 0)
            throw new InvalidOperationException("No DNS servers configured.");

        Exception? lastException = null;

        foreach (var server in servers)
        {
            for (int attempt = 0; attempt <= _options.MaxRetries; attempt++)
            {
                try
                {
                    byte[] response = await SendUdpQueryAsync(queryBytes, server, ct);

                    // Validate transaction ID matches
                    if (response.Length >= 2)
                    {
                        ushort responseId = System.Buffers.Binary.BinaryPrimitives.ReadUInt16BigEndian(response);
                        if (responseId != queryId)
                            continue; // ignore mismatched response, retry
                    }

                    // Check for retriable server errors
                    if (response.Length >= 4)
                    {
                        var rcode = (DnsResponseCode)(response[3] & 0xF);
                        if (rcode == DnsResponseCode.ServerFailure)
                        {
                            lastException = new InvalidOperationException($"DNS server returned {rcode}");
                            continue; // retry
                        }
                    }

                    return response;
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

        throw new InvalidOperationException("All DNS servers failed.", lastException);
    }

    private async Task<byte[]> SendUdpQueryAsync(byte[] query, IPEndPoint server, CancellationToken ct)
    {
        using var udp = new UdpClient(server.AddressFamily);
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeoutCts.CancelAfter(_options.Timeout);

        await udp.SendAsync(query, server, timeoutCts.Token);
        var result = await udp.ReceiveAsync(timeoutCts.Token);
        return result.Buffer;
    }

    private static byte[] BuildQuery(string name, DnsRecordType type)
    {
        Span<byte> nameBuf = stackalloc byte[DnsName.MaxEncodedLength];
        var status = DnsName.TryCreate(name, nameBuf, out var dnsName, out _);
        if (status != OperationStatus.Done)
            throw new ArgumentException($"Invalid DNS name: '{name}'", nameof(name));

        Span<byte> buffer = stackalloc byte[512];
        var writer = new DnsMessageWriter(buffer);

        ushort id = (ushort)Random.Shared.Next(0, ushort.MaxValue + 1);
        writer.TryWriteHeader(DnsMessageHeader.CreateStandardQuery(id));
        writer.TryWriteQuestion(dnsName, type);

        return buffer[..writer.BytesWritten].ToArray();
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

    private static void CollectAddresses(byte[] response, DateTimeOffset now, List<DnsResolvedAddress> results)
    {
        var reader = new DnsMessageReader(response);
        if (reader.Header.ResponseCode != DnsResponseCode.NoError)
            return;

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
