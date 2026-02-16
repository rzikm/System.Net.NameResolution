using System.Net;
using System.Net.Sockets;

namespace System.Net.Dns.Tests;

public class DnsResolverEdgeCaseTests : IAsyncLifetime
{
    private LoopbackDnsServer _server = null!;
    private DnsResolver _resolver = null!;

    public async Task InitializeAsync()
    {
        _server = LoopbackDnsServer.Start();

        // CNAME + A record in same response
        _server.AddCNameAndARecord("alias.test", "real.test", IPAddress.Parse("10.0.0.99"));

        // Server failure
        _server.AddServerFailure("fail.test", DnsRecordType.A);

        // Drop (no response → timeout)
        _server.AddDrop("timeout.test", DnsRecordType.A);

        // Malformed: response too short (only 4 bytes)
        _server.AddRawResponse("truncated.test", DnsRecordType.A, id => [(byte)(id >> 8), (byte)id, 0x81, 0x80]);

        // Malformed: response with QR=0 (looks like a query, not a response)
        _server.AddRawResponse("notresponse.test", DnsRecordType.A, id =>
        {
            // Valid 12-byte header but QR=0
            var buf = new byte[12];
            buf[0] = (byte)(id >> 8);
            buf[1] = (byte)id;
            // flags = 0x0100 (RD=1, QR=0)
            buf[2] = 0x01;
            buf[3] = 0x00;
            return buf;
        });

        _resolver = new DnsResolver(new DnsResolverOptions
        {
            Servers = [_server.EndPoint],
            Timeout = TimeSpan.FromMilliseconds(500),
            MaxRetries = 0,
        });

        await Task.CompletedTask;
    }

    public async Task DisposeAsync()
    {
        await _resolver.DisposeAsync();
        await _server.DisposeAsync();
    }

    // --- Cancellation ---

    [Fact]
    public async Task PreCanceledToken_Throws()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => _resolver.ResolveAddressesAsync("alias.test", cancellationToken: cts.Token));
    }

    [Fact]
    public async Task CancellationDuringRequest_Throws()
    {
        // Configure a server that drops packets → the resolver will wait for timeout
        // Cancel before the timeout fires
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(50));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => _resolver.ResolveAddressesAsync("timeout.test", cancellationToken: cts.Token));
    }

    // --- CNAME following ---

    [Fact]
    public async Task ResolveAddresses_CNameAndARecord_ReturnsAddress()
    {
        // The server returns CNAME + A in the same response.
        // Our CollectAddresses picks up the A record from the answer section.
        var result = await _resolver.ResolveAddressesAsync("alias.test", AddressFamily.InterNetwork);

        Assert.Equal(DnsResponseCode.NoError, result.ResponseCode);
        Assert.Single(result.Records);
        Assert.Equal("10.0.0.99", result.Records[0].Address.ToString());
    }

    // --- Timeout / Server Failure ---

    [Fact]
    public async Task Timeout_ThrowsInvalidOperation()
    {
        // Server drops the packet, timeout fires → all servers failed
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => _resolver.ResolveAddressesAsync("timeout.test", AddressFamily.InterNetwork));
    }

    [Fact]
    public async Task ServerFailure_ThrowsInvalidOperation()
    {
        // ServerFailure response code → treated as error
        // With MaxRetries=0, single attempt fails → all servers failed
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => _resolver.ResolveAddressesAsync("fail.test", AddressFamily.InterNetwork));
    }

    // --- Malformed responses ---

    [Fact]
    public async Task TruncatedResponse_ThrowsWithInvalidDataInner()
    {
        // Response is only 4 bytes — too short for a DNS header
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => _resolver.ResolveAddressesAsync("truncated.test", AddressFamily.InterNetwork));
        Assert.IsType<InvalidDataException>(ex.InnerException);
    }

    [Fact]
    public async Task NonResponseMessage_ThrowsWithInvalidDataInner()
    {
        // Response has QR=0 — not a valid DNS response
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => _resolver.ResolveAddressesAsync("notresponse.test", AddressFamily.InterNetwork));
        Assert.IsType<InvalidDataException>(ex.InnerException);
    }
}

public class DnsResolverRetryTests : IAsyncLifetime
{
    private LoopbackDnsServer _primary = null!;
    private LoopbackDnsServer _secondary = null!;

    public async Task InitializeAsync()
    {
        _primary = LoopbackDnsServer.Start();
        _secondary = LoopbackDnsServer.Start();
        await Task.CompletedTask;
    }

    public async Task DisposeAsync()
    {
        await _primary.DisposeAsync();
        await _secondary.DisposeAsync();
    }

    [Fact]
    public async Task Retry_EventualSuccess()
    {
        int callCount = 0;
        _primary.AddResponse("retry.test", DnsRecordType.A, (queryId, qName) =>
        {
            callCount++;
            if (callCount < 3)
                return LoopbackDnsServer.BuildErrorResponse(queryId, qName, DnsRecordType.A, DnsResponseCode.ServerFailure);
            return LoopbackDnsServer.BuildSimpleResponse(queryId, qName, DnsRecordType.A, [10, 0, 0, 1], 60);
        });

        await using var resolver = new DnsResolver(new DnsResolverOptions
        {
            Servers = [_primary.EndPoint],
            MaxRetries = 3,
            Timeout = TimeSpan.FromSeconds(2),
        });

        var result = await resolver.ResolveAddressesAsync("retry.test", AddressFamily.InterNetwork);
        Assert.Single(result.Records);
        Assert.Equal("10.0.0.1", result.Records[0].Address.ToString());
        Assert.Equal(3, callCount);
    }

    [Fact]
    public async Task NameError_NoRetry()
    {
        _primary.AddNxDomain("nxdomain.test", DnsRecordType.A);

        await using var resolver = new DnsResolver(new DnsResolverOptions
        {
            Servers = [_primary.EndPoint],
            MaxRetries = 3,
            Timeout = TimeSpan.FromSeconds(2),
        });

        var result = await resolver.ResolveAddressesAsync("nxdomain.test", AddressFamily.InterNetwork);
        Assert.Equal(DnsResponseCode.NameError, result.ResponseCode);
        Assert.Empty(result.Records);
        // With NXDOMAIN, only 1 request should have been made (no retries)
        Assert.Equal(1, _primary.RequestCount);
    }

    [Fact]
    public async Task Failover_PrimaryDrops_SecondarySucceeds()
    {
        _primary.AddDrop("failover.test", DnsRecordType.A);
        _secondary.AddARecord("failover.test", IPAddress.Parse("10.0.0.2"));

        await using var resolver = new DnsResolver(new DnsResolverOptions
        {
            Servers = [_primary.EndPoint, _secondary.EndPoint],
            MaxRetries = 0,
            Timeout = TimeSpan.FromMilliseconds(200),
        });

        var result = await resolver.ResolveAddressesAsync("failover.test", AddressFamily.InterNetwork);
        Assert.Single(result.Records);
        Assert.Equal("10.0.0.2", result.Records[0].Address.ToString());
    }

    [Fact]
    public async Task Failover_PrimaryServerFailure_SecondarySucceeds()
    {
        _primary.AddServerFailure("failover2.test", DnsRecordType.A);
        _secondary.AddARecord("failover2.test", IPAddress.Parse("10.0.0.3"));

        await using var resolver = new DnsResolver(new DnsResolverOptions
        {
            Servers = [_primary.EndPoint, _secondary.EndPoint],
            MaxRetries = 0,
            Timeout = TimeSpan.FromSeconds(2),
        });

        var result = await resolver.ResolveAddressesAsync("failover2.test", AddressFamily.InterNetwork);
        Assert.Single(result.Records);
        Assert.Equal("10.0.0.3", result.Records[0].Address.ToString());
    }

    [Fact]
    public async Task Retry_MalformedThenSuccess()
    {
        int callCount = 0;
        _primary.AddResponse("malformed-retry.test", DnsRecordType.A, (queryId, qName) =>
        {
            callCount++;
            if (callCount < 2)
            {
                // Return a truncated response (too short for header)
                return [(byte)(queryId >> 8), (byte)queryId, 0x81, 0x80];
            }
            return LoopbackDnsServer.BuildSimpleResponse(queryId, qName, DnsRecordType.A, [10, 0, 0, 5], 60);
        });

        await using var resolver = new DnsResolver(new DnsResolverOptions
        {
            Servers = [_primary.EndPoint],
            MaxRetries = 2,
            Timeout = TimeSpan.FromSeconds(2),
        });

        var result = await resolver.ResolveAddressesAsync("malformed-retry.test", AddressFamily.InterNetwork);
        Assert.Single(result.Records);
        Assert.Equal("10.0.0.5", result.Records[0].Address.ToString());
        Assert.Equal(2, callCount);
    }
}
