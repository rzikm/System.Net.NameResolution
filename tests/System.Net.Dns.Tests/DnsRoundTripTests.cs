using System.Buffers;
using System.Net;
using System.Net.Sockets;

namespace System.Net.Dns.Tests;

public class DnsRoundTripTests : IAsyncLifetime
{
    private LoopbackDnsServer _server = null!;

    public async Task InitializeAsync()
    {
        _server = LoopbackDnsServer.Start();
        _server.AddARecord("roundtrip.test", IPAddress.Parse("10.20.30.40"), ttl: 120);
        _server.AddAAAARecord("roundtrip.test", IPAddress.Parse("::1"), ttl: 60);
        _server.AddNxDomain("nonexistent.test", DnsRecordType.A);
        await Task.CompletedTask;
    }

    public async Task DisposeAsync() => await _server.DisposeAsync();

    private async Task<byte[]> SendQueryAsync(byte[] query)
    {
        using var udp = new UdpClient();
        await udp.SendAsync(query, _server.EndPoint);
        var result = await udp.ReceiveAsync();
        return result.Buffer;
    }

    [Fact]
    public async Task ARecord_RoundTrip()
    {
        byte[] query = BuildQuery(0x1001, "roundtrip.test", DnsRecordType.A);
        byte[] response = await SendQueryAsync(query);

        // Parse response
        DnsMessageReader.TryCreate(response, out var reader);
        Assert.Equal(0x1001, reader.Header.Id);
        Assert.True(reader.Header.IsResponse);
        Assert.Equal(DnsResponseCode.NoError, reader.Header.ResponseCode);
        Assert.Equal(1, reader.Header.AnswerCount);

        reader.TryReadQuestion(out var q);
        Assert.True(q.Name.Equals("roundtrip.test"));
        Assert.Equal(DnsRecordType.A, q.Type);

        reader.TryReadRecord(out var record);
        Assert.Equal(DnsRecordType.A, record.Type);
        Assert.Equal(120u, record.TimeToLive);

        Assert.True(record.TryParseARecord(out var a));
        Assert.Equal("10.20.30.40", a.ToIPAddress().ToString());
    }

    [Fact]
    public async Task AAAARecord_RoundTrip()
    {
        byte[] query = BuildQuery(0x1002, "roundtrip.test", DnsRecordType.AAAA);
        byte[] response = await SendQueryAsync(query);

        DnsMessageReader.TryCreate(response, out var reader);
        Assert.Equal(DnsResponseCode.NoError, reader.Header.ResponseCode);
        reader.TryReadQuestion(out _);
        reader.TryReadRecord(out var record);

        Assert.True(record.TryParseAAAARecord(out var aaaa));
        Assert.Equal("::1", aaaa.ToIPAddress().ToString());
    }

    [Fact]
    public async Task Nxdomain_RoundTrip()
    {
        byte[] query = BuildQuery(0x1003, "nonexistent.test", DnsRecordType.A);
        byte[] response = await SendQueryAsync(query);

        DnsMessageReader.TryCreate(response, out var reader);
        Assert.Equal(DnsResponseCode.NameError, reader.Header.ResponseCode);
        Assert.Equal(0, reader.Header.AnswerCount);
    }

    [Fact]
    public async Task UnregisteredName_ReturnsNxdomain()
    {
        byte[] query = BuildQuery(0x1004, "unknown.test", DnsRecordType.A);
        byte[] response = await SendQueryAsync(query);

        DnsMessageReader.TryCreate(response, out var reader);
        Assert.Equal(DnsResponseCode.NameError, reader.Header.ResponseCode);
    }

    [Fact]
    public async Task QueryId_EchoedCorrectly()
    {
        // Send multiple queries with different IDs
        for (ushort id = 100; id < 103; id++)
        {
            byte[] query = BuildQuery(id, "roundtrip.test", DnsRecordType.A);
            byte[] response = await SendQueryAsync(query);
            DnsMessageReader.TryCreate(response, out var reader);
            Assert.Equal(id, reader.Header.Id);
        }
    }

    private static byte[] BuildQuery(ushort id, string name, DnsRecordType type)
    {
        Span<byte> nameBuf = stackalloc byte[DnsEncodedName.MaxEncodedLength];
        DnsEncodedName.TryEncode(name, nameBuf, out var encodedName, out _);

        Span<byte> queryBuf = stackalloc byte[512];
        var writer = new DnsMessageWriter(queryBuf);
        writer.TryWriteHeader(DnsMessageHeader.CreateStandardQuery(id: id));
        writer.TryWriteQuestion(encodedName, type);
        return queryBuf[..writer.BytesWritten].ToArray();
    }
}
