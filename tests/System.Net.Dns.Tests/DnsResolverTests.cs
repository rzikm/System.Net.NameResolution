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
        _server.AddNxDomain("missing.test", DnsRecordType.A);

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
        var addresses = await _resolver.ResolveAddressesAsync("host.test");

        Assert.Equal(2, addresses.Length);
        Assert.Contains(addresses, a => a.Address.ToString() == "10.0.0.1");
        Assert.Contains(addresses, a => a.Address.ToString() == "fd00::1");
    }

    [Fact]
    public async Task ResolveAddresses_IPv4Only()
    {
        var addresses = await _resolver.ResolveAddressesAsync("host.test", AddressFamily.InterNetwork);

        Assert.Single(addresses);
        Assert.Equal("10.0.0.1", addresses[0].Address.ToString());
    }

    [Fact]
    public async Task ResolveAddresses_IPv6Only()
    {
        var addresses = await _resolver.ResolveAddressesAsync("host.test", AddressFamily.InterNetworkV6);

        Assert.Single(addresses);
        Assert.Equal("fd00::1", addresses[0].Address.ToString());
    }

    [Fact]
    public async Task ResolveAddresses_V4OnlyHost_ReturnsOnlyV4()
    {
        var addresses = await _resolver.ResolveAddressesAsync("v4only.test");

        Assert.Single(addresses);
        Assert.Equal("10.0.0.2", addresses[0].Address.ToString());
    }

    [Fact]
    public async Task ResolveAddresses_Nxdomain_ReturnsEmpty()
    {
        var addresses = await _resolver.ResolveAddressesAsync("missing.test");
        Assert.Empty(addresses);
    }

    [Fact]
    public async Task ResolveAddresses_HasExpiration()
    {
        var before = DateTimeOffset.UtcNow;
        var addresses = await _resolver.ResolveAddressesAsync("host.test", AddressFamily.InterNetwork);
        var after = DateTimeOffset.UtcNow;

        Assert.Single(addresses);
        // TTL is 120s, so ExpiresAt should be ~120s from now
        Assert.True(addresses[0].ExpiresAt >= before + TimeSpan.FromSeconds(119));
        Assert.True(addresses[0].ExpiresAt <= after + TimeSpan.FromSeconds(121));
    }

    [Fact]
    public async Task ResolveService_ReturnsSrvRecords()
    {
        var services = await _resolver.ResolveServiceAsync("_http._tcp.svc.test");

        Assert.Equal(2, services.Length);

        var s1 = Assert.Single(services, s => s.Target == "node1.test");
        Assert.Equal(8080, s1.Port);
        Assert.Equal(10, s1.Priority);
        Assert.Equal(100, s1.Weight);

        var s2 = Assert.Single(services, s => s.Target == "node2.test");
        Assert.Equal(8081, s2.Port);
        Assert.Equal(20, s2.Priority);
    }

    [Fact]
    public async Task ResolveService_IncludesAdditionalAddresses()
    {
        var services = await _resolver.ResolveServiceAsync("_http._tcp.svc.test");

        var s1 = Assert.Single(services, s => s.Target == "node1.test");
        Assert.NotNull(s1.Addresses);
        Assert.Single(s1.Addresses);
        Assert.Equal("10.0.0.10", s1.Addresses[0].Address.ToString());

        var s2 = Assert.Single(services, s => s.Target == "node2.test");
        Assert.NotNull(s2.Addresses);
        Assert.Equal(2, s2.Addresses.Length);
    }

    [Fact]
    public async Task ResolveService_NoAdditionalAddresses()
    {
        var services = await _resolver.ResolveServiceAsync("_noadd._tcp.svc.test");

        Assert.Single(services);
        Assert.Equal("noaddr.test", services[0].Target);
        Assert.Null(services[0].Addresses);
    }

    [Fact]
    public async Task QueryAsync_ReturnsRawResponse()
    {
        using var result = await _resolver.QueryAsync("host.test", DnsRecordType.A);

        Assert.Equal(DnsResponseCode.NoError, result.ResponseCode);
        Assert.True(result.Flags.HasFlag(DnsHeaderFlags.RecursionAvailable));

        // Parse the raw response
        var reader = new DnsMessageReader(result.ResponseMessage.Span);
        Assert.Equal(1, reader.Header.AnswerCount);

        reader.TryReadQuestion(out _);
        reader.TryReadRecord(out var record);
        Assert.True(record.TryParseARecord(out var a));
        Assert.Equal("10.0.0.1", a.ToIPAddress().ToString());
    }

    [Fact]
    public async Task QueryAsync_Nxdomain_ReturnsErrorCode()
    {
        using var result = await _resolver.QueryAsync("missing.test", DnsRecordType.A);
        Assert.Equal(DnsResponseCode.NameError, result.ResponseCode);
    }

    [Fact]
    public async Task Disposed_Throws()
    {
        var resolver = new DnsResolver(new DnsResolverOptions { Servers = [_server.EndPoint] });
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
