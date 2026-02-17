using System.Net;
using System.Net.Sockets;

namespace System.Net.Dns.Tests;

public class DnsResolverTests : IAsyncLifetime
{
    private LoopbackDnsServer _server = null!;
    private DnsResolver _resolver = null!;

    public async Task InitializeAsync()
    {
        _server = LoopbackDnsServer.Start();
        _server.AddARecord("host.test", IPAddress.Parse("10.0.0.1"), ttl: 120);
        _server.AddAAAARecord("host.test", IPAddress.Parse("fd00::1"), ttl: 60);
        _server.AddARecord("v4only.test", IPAddress.Parse("10.0.0.2"), ttl: 300);
        _server.AddNxDomain("v4only.test", DnsRecordType.AAAA);
        _server.AddNxDomainWithSoa("missing.test", DnsRecordType.A, soaMinTtl: 120);

        // NODATA: name exists (has A) but no AAAA
        _server.AddARecord("noaaaa.test", IPAddress.Parse("10.0.0.3"), ttl: 300);
        _server.AddNoData("noaaaa.test", DnsRecordType.AAAA, soaMinTtl: 30);

        _server.AddSrvRecords("_http._tcp.svc.test",
        [
            ("node1.test", 8080, 10, 100, 120, [IPAddress.Parse("10.0.0.10")]),
            ("node2.test", 8081, 20, 50, 120, [IPAddress.Parse("10.0.0.11"), IPAddress.Parse("fd00::11")]),
        ]);

        _server.AddSrvRecords("_noadd._tcp.svc.test",
        [
            ("noaddr.test", 9090, 10, 100, 60, null),
        ]);

        _resolver = new DnsResolver(new DnsResolverOptions
        {
            Servers = [_server.EndPoint],
            Timeout = TimeSpan.FromSeconds(2),
            MaxRetries = 0,
        });

        await Task.CompletedTask;
    }

    public async Task DisposeAsync()
    {
        await _resolver.DisposeAsync();
        await _server.DisposeAsync();
    }

    [Fact]
    public async Task ResolveAddresses_Unspecified_ReturnsBothV4AndV6()
    {
        DnsResult<DnsResolvedAddress> result = await _resolver.ResolveAddressesAsync("host.test");

        Assert.Equal(DnsResponseCode.NoError, result.ResponseCode);
        Assert.Equal(2, result.Records.Length);
        Assert.Contains(result.Records, a => a.Address.ToString() == "10.0.0.1");
        Assert.Contains(result.Records, a => a.Address.ToString() == "fd00::1");
    }

    [Fact]
    public async Task ResolveAddresses_IPv4Only()
    {
        DnsResult<DnsResolvedAddress> result = await _resolver.ResolveAddressesAsync("host.test", AddressFamily.InterNetwork);

        Assert.Single(result.Records);
        Assert.Equal("10.0.0.1", result.Records[0].Address.ToString());
    }

    [Fact]
    public async Task ResolveAddresses_IPv6Only()
    {
        DnsResult<DnsResolvedAddress> result = await _resolver.ResolveAddressesAsync("host.test", AddressFamily.InterNetworkV6);

        Assert.Single(result.Records);
        Assert.Equal("fd00::1", result.Records[0].Address.ToString());
    }

    [Fact]
    public async Task ResolveAddresses_V4OnlyHost_ReturnsOnlyV4()
    {
        DnsResult<DnsResolvedAddress> result = await _resolver.ResolveAddressesAsync("v4only.test");

        // A succeeds, AAAA returns NXDOMAIN — but since we got addresses, overall is success
        Assert.Equal(DnsResponseCode.NoError, result.ResponseCode);
        Assert.Single(result.Records);
        Assert.Equal("10.0.0.2", result.Records[0].Address.ToString());
    }

    [Fact]
    public async Task ResolveAddresses_Nxdomain_ReturnsNameError()
    {
        DnsResult<DnsResolvedAddress> result = await _resolver.ResolveAddressesAsync("missing.test");

        Assert.Equal(DnsResponseCode.NameError, result.ResponseCode);
        Assert.Empty(result.Records);
    }

    [Fact]
    public async Task ResolveAddresses_Nxdomain_HasNegativeCacheTtl()
    {
        DateTimeOffset before = DateTimeOffset.UtcNow;
        DnsResult<DnsResolvedAddress> result = await _resolver.ResolveAddressesAsync("missing.test", AddressFamily.InterNetwork);
        DateTimeOffset after = DateTimeOffset.UtcNow;

        Assert.Equal(DnsResponseCode.NameError, result.ResponseCode);
        Assert.NotNull(result.NegativeCacheExpiresAt);
        // SOA minimum TTL is 120s
        Assert.True(result.NegativeCacheExpiresAt >= before + TimeSpan.FromSeconds(119));
        Assert.True(result.NegativeCacheExpiresAt <= after + TimeSpan.FromSeconds(121));
    }

    [Fact]
    public async Task ResolveAddresses_NoData_ReturnsNoErrorWithEmptyRecords()
    {
        // noaaaa.test exists (has A record) but has no AAAA → NODATA
        DnsResult<DnsResolvedAddress> result = await _resolver.ResolveAddressesAsync("noaaaa.test", AddressFamily.InterNetworkV6);

        Assert.Equal(DnsResponseCode.NoError, result.ResponseCode);
        Assert.Empty(result.Records);
    }

    [Fact]
    public async Task ResolveAddresses_NoData_Vs_Nxdomain_Distinguishable()
    {
        // NODATA: name exists, no records of requested type → NoError + empty
        DnsResult<DnsResolvedAddress> nodata = await _resolver.ResolveAddressesAsync("noaaaa.test", AddressFamily.InterNetworkV6);
        Assert.Equal(DnsResponseCode.NoError, nodata.ResponseCode);
        Assert.Empty(nodata.Records);

        // NXDOMAIN: name doesn't exist → NameError + empty
        DnsResult<DnsResolvedAddress> nxdomain = await _resolver.ResolveAddressesAsync("missing.test", AddressFamily.InterNetwork);
        Assert.Equal(DnsResponseCode.NameError, nxdomain.ResponseCode);
        Assert.Empty(nxdomain.Records);

        // They are distinguishable via ResponseCode
        Assert.NotEqual(nodata.ResponseCode, nxdomain.ResponseCode);
    }

    [Fact]
    public async Task ResolveAddresses_HasExpiration()
    {
        DateTimeOffset before = DateTimeOffset.UtcNow;
        DnsResult<DnsResolvedAddress> result = await _resolver.ResolveAddressesAsync("host.test", AddressFamily.InterNetwork);
        DateTimeOffset after = DateTimeOffset.UtcNow;

        Assert.Single(result.Records);
        // TTL is 120s, so ExpiresAt should be ~120s from now
        Assert.True(result.Records[0].ExpiresAt >= before + TimeSpan.FromSeconds(119));
        Assert.True(result.Records[0].ExpiresAt <= after + TimeSpan.FromSeconds(121));
    }

    [Fact]
    public async Task ResolveService_ReturnsSrvRecords()
    {
        DnsResult<DnsResolvedService> result = await _resolver.ResolveServiceAsync("_http._tcp.svc.test");

        Assert.Equal(DnsResponseCode.NoError, result.ResponseCode);
        Assert.Equal(2, result.Records.Length);

        DnsResolvedService s1 = Assert.Single(result.Records, s => s.Target == "node1.test");
        Assert.Equal(8080, s1.Port);
        Assert.Equal(10, s1.Priority);
        Assert.Equal(100, s1.Weight);

        DnsResolvedService s2 = Assert.Single(result.Records, s => s.Target == "node2.test");
        Assert.Equal(8081, s2.Port);
        Assert.Equal(20, s2.Priority);
    }

    [Fact]
    public async Task ResolveService_IncludesAdditionalAddresses()
    {
        DnsResult<DnsResolvedService> result = await _resolver.ResolveServiceAsync("_http._tcp.svc.test");

        DnsResolvedService s1 = Assert.Single(result.Records, s => s.Target == "node1.test");
        Assert.NotNull(s1.Addresses);
        Assert.Single(s1.Addresses);
        Assert.Equal("10.0.0.10", s1.Addresses[0].Address.ToString());

        DnsResolvedService s2 = Assert.Single(result.Records, s => s.Target == "node2.test");
        Assert.NotNull(s2.Addresses);
        Assert.Equal(2, s2.Addresses.Length);
    }

    [Fact]
    public async Task ResolveService_NoAdditionalAddresses()
    {
        DnsResult<DnsResolvedService> result = await _resolver.ResolveServiceAsync("_noadd._tcp.svc.test");

        Assert.Single(result.Records);
        Assert.Equal("noaddr.test", result.Records[0].Target);
        Assert.Null(result.Records[0].Addresses);
    }

    [Fact]
    public async Task QueryAsync_ReturnsRawResponse()
    {
        using DnsQueryResult result = await _resolver.QueryAsync("host.test", DnsRecordType.A);

        Assert.Equal(DnsResponseCode.NoError, result.ResponseCode);
        Assert.True(result.Flags.HasFlag(DnsHeaderFlags.RecursionAvailable));

        // Parse the raw response
        DnsMessageReader.TryCreate(result.ResponseMessage.Span, out var reader);
        Assert.Equal(1, reader.Header.AnswerCount);

        reader.TryReadQuestion(out _);
        reader.TryReadRecord(out var record);
        Assert.True(record.TryParseARecord(out var a));
        Assert.Equal("10.0.0.1", a.ToIPAddress().ToString());
    }

    [Fact]
    public async Task QueryAsync_Nxdomain_ReturnsErrorCode()
    {
        using DnsQueryResult result = await _resolver.QueryAsync("missing.test", DnsRecordType.A);
        Assert.Equal(DnsResponseCode.NameError, result.ResponseCode);
    }

    [Fact]
    public async Task Disposed_Throws()
    {
        DnsResolver resolver = new(new DnsResolverOptions { Servers = [_server.EndPoint] });
        await resolver.DisposeAsync();

        await Assert.ThrowsAsync<ObjectDisposedException>(
            () => resolver.ResolveAddressesAsync("host.test"));
    }

    [Fact]
    public async Task InvalidName_Throws()
    {
        await Assert.ThrowsAsync<ArgumentException>(
            () => _resolver.ResolveAddressesAsync(""));
    }
}
