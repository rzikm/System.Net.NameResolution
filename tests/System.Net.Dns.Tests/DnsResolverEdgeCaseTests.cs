using System.Net;
using System.Net.Sockets;
using System.Threading;

namespace System.Net.Dns.Tests;

public class DnsResolverEdgeCaseTests : IAsyncLifetime
{
    private LoopbackDnsServer _server = null!;
    private DnsResolver _resolver = null!;

    public async Task InitializeAsync()
    {
        _server = LoopbackDnsServer.Start();

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
        using CancellationTokenSource cts = new();
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => _resolver.ResolveAddressesAsync("alias.test", cancellationToken: cts.Token));
    }

    [Fact]
    public async Task CancellationDuringUdpRequest_Throws()
    {
        // Server accepts the UDP query but holds the response.
        // We cancel the resolver while it waits for the UDP response.
        using SemaphoreSlim udpReceived = new(0, 1);
        using ManualResetEventSlim serverCanContinue = new(false);
        using CancellationTokenSource cts = new();

        await using LoopbackDnsServer server = LoopbackDnsServer.Start();
        server.AddResponse("cancel-udp.test", DnsRecordType.A, (queryId, qName, _) =>
        {
            udpReceived.Release();
            serverCanContinue.Wait(TimeSpan.FromSeconds(10));
            return DnsResponseBuilder.For(queryId, qName, DnsRecordType.A)
                .Answer([10, 0, 0, 1], ttl: 60)
                .Build();
        });

        using DnsResolver resolver = new DnsResolver(new DnsResolverOptions
        {
            Servers = [server.EndPoint],
            Timeout = TimeSpan.FromSeconds(30),
            MaxRetries = 0,
        });

        Task resolveTask = resolver.ResolveAddressesAsync("cancel-udp.test", AddressFamily.InterNetwork, cts.Token);

        await udpReceived.WaitAsync(TimeSpan.FromSeconds(5));

        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => resolveTask);

        serverCanContinue.Set();
    }

    [Fact]
    public async Task CancellationDuringTcpFallback_Throws()
    {
        // Server returns TC=1 on UDP. On TCP, the server accepts but holds the
        // response until we signal. We cancel the resolver while it waits for TCP data.
        using SemaphoreSlim tcpReceived = new(0, 1);
        using ManualResetEventSlim serverCanContinue = new(false);
        using CancellationTokenSource cts = new();

        await using LoopbackDnsServer server = LoopbackDnsServer.Start();
        server.AddResponse("cancel-tcp.test", DnsRecordType.A, (queryId, qName, isTcp) =>
        {
            if (isTcp)
            {
                tcpReceived.Release();
                // Block until test signals (after cancelling the resolver)
                serverCanContinue.Wait(TimeSpan.FromSeconds(10));
                return DnsResponseBuilder.For(queryId, qName, DnsRecordType.A)
                    .Answer([10, 0, 0, 1], ttl: 60)
                    .Build();
            }
            return DnsResponseBuilder.For(queryId, qName, DnsRecordType.A)
                .Truncated()
                .Build();
        });

        using DnsResolver resolver = new DnsResolver(new DnsResolverOptions
        {
            Servers = [server.EndPoint],
            Timeout = TimeSpan.FromSeconds(30),
            MaxRetries = 0,
        });

        Task resolveTask = resolver.ResolveAddressesAsync("cancel-tcp.test", AddressFamily.InterNetwork, cts.Token);

        // Wait until the server has received the TCP query
        await tcpReceived.WaitAsync(TimeSpan.FromSeconds(5));

        // Now cancel — the resolver is blocked on ReceiveExactAsync
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => resolveTask);

        // Unblock the server handler so dispose completes quickly
        serverCanContinue.Set();
    }

    [Fact]
    public async Task TimeoutDuringTcpFallback_ThrowsTimeoutException()
    {
        // Server returns TC=1 on UDP. On TCP, the server accepts but never
        // sends a response, so the resolver's internal timeout fires.
        using SemaphoreSlim tcpReceived = new(0, 1);
        using ManualResetEventSlim serverCanContinue = new(false);

        await using LoopbackDnsServer server = LoopbackDnsServer.Start();
        server.AddResponse("tcp-timeout.test", DnsRecordType.A, (queryId, qName, isTcp) =>
        {
            if (isTcp)
            {
                tcpReceived.Release();
                // Block until test finishes — simulates an unresponsive TCP server
                serverCanContinue.Wait(TimeSpan.FromSeconds(10));
                return DnsResponseBuilder.For(queryId, qName, DnsRecordType.A)
                    .Answer([10, 0, 0, 1], ttl: 60)
                    .Build();
            }
            return DnsResponseBuilder.For(queryId, qName, DnsRecordType.A)
                .Truncated()
                .Build();
        });

        using DnsResolver resolver = new DnsResolver(new DnsResolverOptions
        {
            Servers = [server.EndPoint],
            Timeout = TimeSpan.FromMilliseconds(200),
            MaxRetries = 0,
        });

        await Assert.ThrowsAsync<TimeoutException>(
            () => resolver.ResolveAddressesAsync("tcp-timeout.test", AddressFamily.InterNetwork));

        // Unblock the server handler so dispose completes quickly
        serverCanContinue.Set();
    }

    // --- CNAME following ---

    [Fact]
    public async Task ResolveAddresses_CNameAndARecord_ReturnsAddress()
    {
        byte[] cnameEncoded = LoopbackDnsServer.EncodeName("real.test");
        _server.AddResponse("alias.test", DnsRecordType.A, (queryId, qName, _) =>
            DnsResponseBuilder.For(queryId, qName, DnsRecordType.A)
                .Answer(DnsRecordType.CNAME, cnameEncoded, ttl: 300)
                .Answer("real.test", DnsRecordType.A, [10, 0, 0, 99], ttl: 300)
                .Build());

        DnsResult<DnsResolvedAddress> result = await _resolver.ResolveAddressesAsync("alias.test", AddressFamily.InterNetwork);

        Assert.Equal(DnsResponseCode.NoError, result.ResponseCode);
        Assert.Single(result.Records);
        Assert.Equal("10.0.0.99", result.Records[0].Address.ToString());
    }

    // --- Timeout / Server Failure ---

    [Fact]
    public async Task Timeout_ThrowsTimeoutException()
    {
        _server.AddResponse("timeout.test", DnsRecordType.A, (_, _, _) => []);

        // Server drops the packet, timeout fires → TimeoutException
        await Assert.ThrowsAsync<TimeoutException>(
            () => _resolver.ResolveAddressesAsync("timeout.test", AddressFamily.InterNetwork));
    }

    [Fact]
    public async Task ServerFailure_ThrowsInvalidOperation()
    {
        _server.AddResponse("fail.test", DnsRecordType.A, b => b.ResponseCode(DnsResponseCode.ServerFailure));

        // ServerFailure response code → treated as error
        // With MaxRetries=0, single attempt fails → all servers failed
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => _resolver.ResolveAddressesAsync("fail.test", AddressFamily.InterNetwork));
    }

    // --- Malformed responses ---

    [Fact]
    public async Task TruncatedResponse_ThrowsWithInvalidDataInner()
    {
        _server.AddRawResponse("truncated.test", DnsRecordType.A, id => [(byte)(id >> 8), (byte)id, 0x81, 0x80]);

        // Response is only 4 bytes — too short for a DNS header
        InvalidOperationException ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => _resolver.ResolveAddressesAsync("truncated.test", AddressFamily.InterNetwork));
        Assert.IsType<InvalidDataException>(ex.InnerException);
    }

    [Fact]
    public async Task NonResponseMessage_ThrowsWithInvalidDataInner()
    {
        _server.AddRawResponse("notresponse.test", DnsRecordType.A, id =>
        {
            // Valid 12-byte header but QR=0
            byte[] buf = new byte[12];
            buf[0] = (byte)(id >> 8);
            buf[1] = (byte)id;
            // flags = 0x0100 (RD=1, QR=0)
            buf[2] = 0x01;
            buf[3] = 0x00;
            return buf;
        });

        // Response has QR=0 — not a valid DNS response
        InvalidOperationException ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => _resolver.ResolveAddressesAsync("notresponse.test", AddressFamily.InterNetwork));
        Assert.IsType<InvalidDataException>(ex.InnerException);
    }

    [Fact]
    public async Task WrongQuestionName_ThrowsWithInvalidDataInner()
    {
        _server.AddRawResponse("wrongquestion.test", DnsRecordType.A, id =>
            DnsResponseBuilder.For(id, LoopbackDnsServer.EncodeName("other.test"), DnsRecordType.A)
                .Answer([10, 0, 0, 1], ttl: 60)
                .Build());

        // Response echoes back a different question name than what was queried
        InvalidOperationException ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => _resolver.ResolveAddressesAsync("wrongquestion.test", AddressFamily.InterNetwork));
        Assert.IsType<InvalidDataException>(ex.InnerException);
    }

    // --- Malformed response bodies (valid header but corrupted record sections) ---

    [Fact]
    public async Task MalformedAnswerRecords_ThrowsInvalidDataException()
    {
        // Header says ANCOUNT=2 but no answer records are present after the question
        _server.AddResponse("malformed-answers.test", DnsRecordType.A, (queryId, qName, _) =>
            DnsResponseBuilder.For(queryId, qName, DnsRecordType.A)
                .OverrideAnswerCount(2)
                .Build());

        await Assert.ThrowsAsync<InvalidDataException>(
            () => _resolver.ResolveAddressesAsync("malformed-answers.test", AddressFamily.InterNetwork));
    }

    [Fact]
    public async Task MalformedQuestionSection_ThrowsInvalidOperationException()
    {
        // Header says QDCOUNT=2 but no question body follows the 12-byte header.
        // This fails during response validation (question doesn't match), so we get
        // InvalidOperationException wrapping InvalidDataException.
        _server.AddRawResponse("malformed-questions.test", DnsRecordType.A, id =>
            DnsResponseBuilder.For(id, [], DnsRecordType.A)
                .OverrideQuestionCount(2)
                .SkipQuestion()
                .Build());

        InvalidOperationException ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => _resolver.ResolveAddressesAsync("malformed-questions.test", AddressFamily.InterNetwork));
        Assert.IsType<InvalidDataException>(ex.InnerException);
    }

    [Fact]
    public async Task MalformedSrvAnswerRecords_ThrowsInvalidDataException()
    {
        // Header says ANCOUNT=1 but no answer record data present after question
        _server.AddResponse("malformed-srv.test", DnsRecordType.SRV, (queryId, qName, _) =>
            DnsResponseBuilder.For(queryId, qName, DnsRecordType.SRV)
                .OverrideAnswerCount(1)
                .Build());

        await Assert.ThrowsAsync<InvalidDataException>(
            () => _resolver.ResolveServiceAsync("malformed-srv.test"));
    }

    [Fact]
    public async Task MalformedAuthoritySection_ThrowsInvalidDataException()
    {
        // Valid answer, but NSCOUNT claims authority records that aren't there.
        // ResolveServiceAsync reads the authority section, so this tests that path.
        _server.AddResponse("malformed-auth.test", DnsRecordType.SRV, (queryId, qName, _) =>
            DnsResponseBuilder.For(queryId, qName, DnsRecordType.SRV)
                .Answer(new byte[] { 0, 0, 0, 0, 0x00, 0x50, 3, (byte)'s', (byte)'v', (byte)'c', 4, (byte)'t', (byte)'e', (byte)'s', (byte)'t', 0 }, ttl: 300)
                .OverrideAuthorityCount(1)
                .Build());

        await Assert.ThrowsAsync<InvalidDataException>(
            () => _resolver.ResolveServiceAsync("malformed-auth.test"));
    }

    [Fact]
    public async Task NxDomainWithTruncatedSoa_ThrowsInvalidDataException()
    {
        // NXDOMAIN response with a SOA record that has RDLENGTH > actual data.
        // The reader should fail to parse the authority record.
        _server.AddRawResponse("malformed-soa.test", DnsRecordType.A, id =>
            LoopbackDnsServer.BuildNxDomainWithTruncatedSoa(id,
                LoopbackDnsServer.EncodeName("malformed-soa.test"), DnsRecordType.A));

        await Assert.ThrowsAsync<InvalidDataException>(
            () => _resolver.ResolveAddressesAsync("malformed-soa.test", AddressFamily.InterNetwork));
    }

    [Fact]
    public async Task MalformedAdditionalSection_ThrowsInvalidDataException()
    {
        // Build a response with ARCOUNT > 0 but no additional records.
        // ResolveServiceAsync reads the additional section.
        _server.AddResponse("malformed-additional.test", DnsRecordType.SRV, (queryId, qName, _) =>
            DnsResponseBuilder.For(queryId, qName, DnsRecordType.SRV)
                .OverrideAdditionalCount(1)
                .Build());

        await Assert.ThrowsAsync<InvalidDataException>(
            () => _resolver.ResolveServiceAsync("malformed-additional.test"));
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
        _primary.AddResponse("retry.test", DnsRecordType.A, (queryId, qName, _) =>
        {
            callCount++;
            if (callCount < 3)
            {
                return DnsResponseBuilder.For(queryId, qName, DnsRecordType.A)
                    .ResponseCode(DnsResponseCode.ServerFailure)
                    .Build();
            }
            return DnsResponseBuilder.For(queryId, qName, DnsRecordType.A)
                .Answer([10, 0, 0, 1], ttl: 60)
                .Build();
        });

        await using DnsResolver resolver = new(new DnsResolverOptions
        {
            Servers = [_primary.EndPoint],
            MaxRetries = 3,
            Timeout = TimeSpan.FromSeconds(2),
        });

        DnsResult<DnsResolvedAddress> result = await resolver.ResolveAddressesAsync("retry.test", AddressFamily.InterNetwork);
        Assert.Single(result.Records);
        Assert.Equal("10.0.0.1", result.Records[0].Address.ToString());
        Assert.Equal(3, callCount);
    }

    [Fact]
    public async Task NameError_NoRetry()
    {
        _primary.AddResponse("nxdomain.test", DnsRecordType.A, b => b.ResponseCode(DnsResponseCode.NameError));

        await using DnsResolver resolver = new(new DnsResolverOptions
        {
            Servers = [_primary.EndPoint],
            MaxRetries = 3,
            Timeout = TimeSpan.FromSeconds(2),
        });

        DnsResult<DnsResolvedAddress> result = await resolver.ResolveAddressesAsync("nxdomain.test", AddressFamily.InterNetwork);
        Assert.Equal(DnsResponseCode.NameError, result.ResponseCode);
        Assert.Empty(result.Records);
        // With NXDOMAIN, only 1 request should have been made (no retries)
        Assert.Equal(1, _primary.RequestCount);
    }

    [Fact]
    public async Task Failover_PrimaryDrops_SecondarySucceeds()
    {
        _primary.AddResponse("failover.test", DnsRecordType.A, (_, _, _) => []);
        _secondary.AddResponse("failover.test", DnsRecordType.A, b => b.Answer([10, 0, 0, 2]));

        await using DnsResolver resolver = new(new DnsResolverOptions
        {
            Servers = [_primary.EndPoint, _secondary.EndPoint],
            MaxRetries = 0,
            Timeout = TimeSpan.FromMilliseconds(200),
        });

        DnsResult<DnsResolvedAddress> result = await resolver.ResolveAddressesAsync("failover.test", AddressFamily.InterNetwork);
        Assert.Single(result.Records);
        Assert.Equal("10.0.0.2", result.Records[0].Address.ToString());
    }

    [Fact]
    public async Task Failover_PrimaryServerFailure_SecondarySucceeds()
    {
        _primary.AddResponse("failover2.test", DnsRecordType.A, b => b.ResponseCode(DnsResponseCode.ServerFailure));
        _secondary.AddResponse("failover2.test", DnsRecordType.A, b => b.Answer([10, 0, 0, 3]));

        await using DnsResolver resolver = new(new DnsResolverOptions
        {
            Servers = [_primary.EndPoint, _secondary.EndPoint],
            MaxRetries = 0,
            Timeout = TimeSpan.FromSeconds(2),
        });

        DnsResult<DnsResolvedAddress> result = await resolver.ResolveAddressesAsync("failover2.test", AddressFamily.InterNetwork);
        Assert.Single(result.Records);
        Assert.Equal("10.0.0.3", result.Records[0].Address.ToString());
    }

    [Fact]
    public async Task Retry_MalformedThenSuccess()
    {
        int callCount = 0;
        _primary.AddResponse("malformed-retry.test", DnsRecordType.A, (queryId, qName, _) =>
        {
            callCount++;
            if (callCount < 2)
            {
                // Return a truncated response (too short for header)
                return [(byte)(queryId >> 8), (byte)queryId, 0x81, 0x80];
            }
            return DnsResponseBuilder.For(queryId, qName, DnsRecordType.A)
                .Answer([10, 0, 0, 5], ttl: 60)
                .Build();
        });

        await using DnsResolver resolver = new(new DnsResolverOptions
        {
            Servers = [_primary.EndPoint],
            MaxRetries = 2,
            Timeout = TimeSpan.FromSeconds(2),
        });

        DnsResult<DnsResolvedAddress> result = await resolver.ResolveAddressesAsync("malformed-retry.test", AddressFamily.InterNetwork);
        Assert.Single(result.Records);
        Assert.Equal("10.0.0.5", result.Records[0].Address.ToString());
        Assert.Equal(2, callCount);
    }

    [Fact]
    public async Task TcpFallback_WhenTruncated_ResolvesOverTcp()
    {
        await using LoopbackDnsServer server = LoopbackDnsServer.Start();
        server.AddResponse("tcpfallback.test", DnsRecordType.A, (queryId, qName, isTcp) =>
            isTcp
                ? DnsResponseBuilder.For(queryId, qName, DnsRecordType.A).Answer([10, 0, 0, 42]).Build()
                : DnsResponseBuilder.For(queryId, qName, DnsRecordType.A).Truncated().Build());

        using DnsResolver resolver = new DnsResolver(new DnsResolverOptions
        {
            Servers = [server.EndPoint],
            Timeout = TimeSpan.FromSeconds(5),
        });

        DnsResult<DnsResolvedAddress> result = await resolver.ResolveAddressesAsync(
            "tcpfallback.test", AddressFamily.InterNetwork);

        Assert.Equal(DnsResponseCode.NoError, result.ResponseCode);
        Assert.Single(result.Records);
        Assert.Equal(IPAddress.Parse("10.0.0.42"), result.Records[0].Address);
        Assert.True(server.TcpRequestCount > 0, "Expected at least one TCP request");
    }

    [Fact]
    public async Task TcpFallback_TcpDropsConnection_FailsOverToNextServer()
    {
        // Primary returns TC=1 on UDP and drops TCP connection (empty response)
        _primary.AddResponse("tcpdrop.test", DnsRecordType.A, (queryId, qName, isTcp) =>
            isTcp
                ? [] // drop TCP connection
                : DnsResponseBuilder.For(queryId, qName, DnsRecordType.A)
                    .Truncated()
                    .Build());

        _secondary.AddResponse("tcpdrop.test", DnsRecordType.A, b => b.Answer([10, 0, 0, 2]));

        await using DnsResolver resolver = new(new DnsResolverOptions
        {
            Servers = [_primary.EndPoint, _secondary.EndPoint],
            MaxRetries = 0,
            Timeout = TimeSpan.FromSeconds(2),
        });

        DnsResult<DnsResolvedAddress> result = await resolver.ResolveAddressesAsync("tcpdrop.test", AddressFamily.InterNetwork);
        Assert.Single(result.Records);
        Assert.Equal("10.0.0.2", result.Records[0].Address.ToString());
    }

    [Fact]
    public async Task TcpFallback_TcpFails_RetriesOnSameServer()
    {
        int udpCount = 0;
        // First UDP: TC=1, TCP drops. Second UDP: normal response.
        _primary.AddResponse("tcpretry.test", DnsRecordType.A, (queryId, qName, isTcp) =>
        {
            if (isTcp)
            {
                return []; // drop TCP
            }
            udpCount++;
            if (udpCount == 1)
            {
                return DnsResponseBuilder.For(queryId, qName, DnsRecordType.A)
                    .Truncated()
                    .Build();
            }
            return DnsResponseBuilder.For(queryId, qName, DnsRecordType.A)
                .Answer([10, 0, 0, 1], ttl: 60)
                .Build();
        });

        await using DnsResolver resolver = new(new DnsResolverOptions
        {
            Servers = [_primary.EndPoint],
            MaxRetries = 2,
            Timeout = TimeSpan.FromSeconds(2),
        });

        DnsResult<DnsResolvedAddress> result = await resolver.ResolveAddressesAsync("tcpretry.test", AddressFamily.InterNetwork);
        Assert.Single(result.Records);
        Assert.Equal("10.0.0.1", result.Records[0].Address.ToString());
        Assert.Equal(2, udpCount);
    }

    [Fact]
    public async Task TcpFallback_LargeResponse_ResolvesCorrectly()
    {
        // Build a response larger than InitialTcpBufferSize (1024 bytes)
        // by adding many A records to the answer section
        int recordCount = 100; // 100 A records × ~16 bytes each > 1024
        _primary.AddResponse("large-tcp.test", DnsRecordType.A, (queryId, qName, isTcp) =>
        {
            if (!isTcp)
            {
                return DnsResponseBuilder.For(queryId, qName, DnsRecordType.A)
                    .Truncated()
                    .Build();
            }

            // Build a large response with many A records
            DnsResponseBuilder builder = DnsResponseBuilder.For(queryId, qName, DnsRecordType.A);
            for (int i = 0; i < recordCount; i++)
            {
                builder = builder.Answer([10, 0, (byte)(i / 256), (byte)(i % 256)]);
            }

            return builder.Build();
        });

        await using DnsResolver resolver = new(new DnsResolverOptions
        {
            Servers = [_primary.EndPoint],
            Timeout = TimeSpan.FromSeconds(5),
        });

        DnsResult<DnsResolvedAddress> result = await resolver.ResolveAddressesAsync("large-tcp.test", AddressFamily.InterNetwork);
        Assert.Equal(recordCount, result.Records.Length);
        Assert.True(_primary.TcpRequestCount > 0, "Expected at least one TCP request");
    }

    [Fact]
    public async Task TcpFallback_AllServersFail_ThrowsInvalidOperation()
    {
        // Both servers return TC=1 on UDP and drop TCP
        _primary.AddResponse("allfail-tcp.test", DnsRecordType.A, (queryId, qName, isTcp) =>
            isTcp ? [] : DnsResponseBuilder.For(queryId, qName, DnsRecordType.A).Truncated().Build());
        _secondary.AddResponse("allfail-tcp.test", DnsRecordType.A, (queryId, qName, isTcp) =>
            isTcp ? [] : DnsResponseBuilder.For(queryId, qName, DnsRecordType.A).Truncated().Build());

        await using DnsResolver resolver = new(new DnsResolverOptions
        {
            Servers = [_primary.EndPoint, _secondary.EndPoint],
            MaxRetries = 0,
            Timeout = TimeSpan.FromSeconds(2),
        });

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => resolver.ResolveAddressesAsync("allfail-tcp.test", AddressFamily.InterNetwork));
    }
}
