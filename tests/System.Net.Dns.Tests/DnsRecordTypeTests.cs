using System.Buffers.Binary;
using System.Net;
using System.Text;

namespace System.Net.Dns.Tests;

public class DnsRecordTypeTests
{
    // Helper: builds a minimal DNS response with a single answer record.
    // The question is "q.test" and the answer name uses a pointer to it.
    private static byte[] BuildResponse(DnsRecordType type, byte[] rdata, uint ttl = 300)
    {
        // Question name: q.test = \x01q\x04test\x00 (8 bytes)
        byte[] questionName = [0x01, (byte)'q', 0x04, (byte)'t', (byte)'e', (byte)'s', (byte)'t', 0x00];

        using MemoryStream ms = new();
        BinaryWriter bw = new(ms);

        // Header (12 bytes)
        bw.Write((byte)0x00); bw.Write((byte)0x01); // ID=1
        bw.Write((byte)0x81); bw.Write((byte)0x80); // QR=1, RD=1, RA=1
        bw.Write((byte)0x00); bw.Write((byte)0x01); // QDCOUNT=1
        bw.Write((byte)0x00); bw.Write((byte)0x01); // ANCOUNT=1
        bw.Write((byte)0x00); bw.Write((byte)0x00); // NSCOUNT=0
        bw.Write((byte)0x00); bw.Write((byte)0x00); // ARCOUNT=0

        // Question section
        bw.Write(questionName);
        bw.Write(BinaryPrimitives.ReverseEndianness((ushort)type));
        bw.Write(BinaryPrimitives.ReverseEndianness((ushort)1)); // CLASS=IN

        // Answer: pointer to offset 12 (question name)
        bw.Write((byte)0xC0); bw.Write((byte)0x0C);
        bw.Write(BinaryPrimitives.ReverseEndianness((ushort)type));
        bw.Write(BinaryPrimitives.ReverseEndianness((ushort)1)); // CLASS=IN
        bw.Write(BinaryPrimitives.ReverseEndianness(ttl));
        bw.Write(BinaryPrimitives.ReverseEndianness((ushort)rdata.Length));
        bw.Write(rdata);

        return ms.ToArray();
    }

    private static DnsRecord GetAnswerRecord(byte[] response)
    {
        DnsMessageReader.TryCreate(response, out var reader);
        reader.TryReadQuestion(out _);
        reader.TryReadRecord(out var record);
        return record;
    }

    [Fact]
    public void ARecord_ParsesCorrectly()
    {
        byte[] rdata = [192, 168, 1, 1];
        DnsRecord record = GetAnswerRecord(BuildResponse(DnsRecordType.A, rdata));

        Assert.True(record.TryParseARecord(out var a));
        Assert.Equal(rdata, a.AddressBytes.ToArray());

        IPAddress ip = a.ToIPAddress();
        Assert.Equal("192.168.1.1", ip.ToString());
    }

    [Fact]
    public void AAAARecord_ParsesCorrectly()
    {
        // ::1 in 16 bytes
        byte[] rdata = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        DnsRecord record = GetAnswerRecord(BuildResponse(DnsRecordType.AAAA, rdata));

        Assert.True(record.TryParseAAAARecord(out var aaaa));
        Assert.Equal(rdata, aaaa.AddressBytes.ToArray());
        Assert.Equal("::1", aaaa.ToIPAddress().ToString());
    }

    [Fact]
    public void CNameRecord_ParsesCorrectly()
    {
        // RDATA: target.test = \x06target\x04test\x00
        byte[] rdata = [0x06, (byte)'t', (byte)'a', (byte)'r', (byte)'g', (byte)'e', (byte)'t',
                        0x04, (byte)'t', (byte)'e', (byte)'s', (byte)'t', 0x00];
        DnsRecord record = GetAnswerRecord(BuildResponse(DnsRecordType.CNAME, rdata));

        Assert.True(record.TryParseCNameRecord(out var cname));
        Assert.True(cname.CName.Equals("target.test"));
    }

    [Fact]
    public void MxRecord_ParsesCorrectly()
    {
        // RDATA: preference=10, exchange=mail.test
        byte[] rdata = [0x00, 0x0A, // preference=10
                        0x04, (byte)'m', (byte)'a', (byte)'i', (byte)'l',
                        0x04, (byte)'t', (byte)'e', (byte)'s', (byte)'t', 0x00];
        DnsRecord record = GetAnswerRecord(BuildResponse(DnsRecordType.MX, rdata));

        Assert.True(record.TryParseMxRecord(out var mx));
        Assert.Equal(10, mx.Preference);
        Assert.True(mx.Exchange.Equals("mail.test"));
    }

    [Fact]
    public void SrvRecord_ParsesCorrectly()
    {
        // RDATA: priority=10, weight=20, port=8080, target=srv.test
        byte[] rdata = [0x00, 0x0A, // priority=10
                        0x00, 0x14, // weight=20
                        0x1F, 0x90, // port=8080
                        0x03, (byte)'s', (byte)'r', (byte)'v',
                        0x04, (byte)'t', (byte)'e', (byte)'s', (byte)'t', 0x00];
        DnsRecord record = GetAnswerRecord(BuildResponse(DnsRecordType.SRV, rdata));

        Assert.True(record.TryParseSrvRecord(out var srv));
        Assert.Equal(10, srv.Priority);
        Assert.Equal(20, srv.Weight);
        Assert.Equal(8080, srv.Port);
        Assert.True(srv.Target.Equals("srv.test"));
    }

    [Fact]
    public void TxtRecord_SingleString()
    {
        byte[] rdata = [0x05, (byte)'h', (byte)'e', (byte)'l', (byte)'l', (byte)'o'];
        DnsRecord record = GetAnswerRecord(BuildResponse(DnsRecordType.TXT, rdata));

        Assert.True(record.TryParseTxtRecord(out var txt));

        List<string> strings = new();
        foreach (ReadOnlySpan<byte> s in txt.EnumerateStrings())
            strings.Add(Encoding.ASCII.GetString(s));

        Assert.Equal(["hello"], strings);
    }

    [Fact]
    public void TxtRecord_MultipleStrings()
    {
        byte[] rdata = [0x03, (byte)'a', (byte)'b', (byte)'c',
                        0x02, (byte)'d', (byte)'e'];
        DnsRecord record = GetAnswerRecord(BuildResponse(DnsRecordType.TXT, rdata));

        Assert.True(record.TryParseTxtRecord(out var txt));

        List<string> strings = new();
        foreach (ReadOnlySpan<byte> s in txt.EnumerateStrings())
            strings.Add(Encoding.ASCII.GetString(s));

        Assert.Equal(["abc", "de"], strings);
    }

    [Fact]
    public void PtrRecord_ParsesCorrectly()
    {
        // RDATA: host.test
        byte[] rdata = [0x04, (byte)'h', (byte)'o', (byte)'s', (byte)'t',
                        0x04, (byte)'t', (byte)'e', (byte)'s', (byte)'t', 0x00];
        DnsRecord record = GetAnswerRecord(BuildResponse(DnsRecordType.PTR, rdata));

        Assert.True(record.TryParsePtrRecord(out var ptr));
        Assert.True(ptr.Name.Equals("host.test"));
    }

    [Fact]
    public void NsRecord_ParsesCorrectly()
    {
        // RDATA: ns1.test
        byte[] rdata = [0x03, (byte)'n', (byte)'s', (byte)'1',
                        0x04, (byte)'t', (byte)'e', (byte)'s', (byte)'t', 0x00];
        DnsRecord record = GetAnswerRecord(BuildResponse(DnsRecordType.NS, rdata));

        Assert.True(record.TryParseNsRecord(out var ns));
        Assert.True(ns.Name.Equals("ns1.test"));
    }

    [Fact]
    public void SoaRecord_ParsesCorrectly()
    {
        // RDATA: mname=ns.test, rname=admin.test, serial=2024010101, refresh=3600, retry=900, expire=604800, minimum=86400
        byte[] mname = [0x02, (byte)'n', (byte)'s', 0x04, (byte)'t', (byte)'e', (byte)'s', (byte)'t', 0x00];
        byte[] rname = [0x05, (byte)'a', (byte)'d', (byte)'m', (byte)'i', (byte)'n', 0x04, (byte)'t', (byte)'e', (byte)'s', (byte)'t', 0x00];
        byte[] fixedFields = new byte[20];
        BinaryPrimitives.WriteUInt32BigEndian(fixedFields.AsSpan(0), 2024010101);
        BinaryPrimitives.WriteUInt32BigEndian(fixedFields.AsSpan(4), 3600);
        BinaryPrimitives.WriteUInt32BigEndian(fixedFields.AsSpan(8), 900);
        BinaryPrimitives.WriteUInt32BigEndian(fixedFields.AsSpan(12), 604800);
        BinaryPrimitives.WriteUInt32BigEndian(fixedFields.AsSpan(16), 86400);

        byte[] rdata = [.. mname, .. rname, .. fixedFields];
        DnsRecord record = GetAnswerRecord(BuildResponse(DnsRecordType.SOA, rdata));

        Assert.True(record.TryParseSoaRecord(out var soa));
        Assert.True(soa.PrimaryNameServer.Equals("ns.test"));
        Assert.True(soa.ResponsibleMailbox.Equals("admin.test"));
        Assert.Equal(2024010101u, soa.SerialNumber);
        Assert.Equal(3600u, soa.RefreshInterval);
        Assert.Equal(900u, soa.RetryInterval);
        Assert.Equal(604800u, soa.ExpireLimit);
        Assert.Equal(86400u, soa.MinimumTtl);
    }

    [Theory]
    [InlineData(DnsRecordType.A)]
    [InlineData(DnsRecordType.AAAA)]
    [InlineData(DnsRecordType.CNAME)]
    [InlineData(DnsRecordType.MX)]
    [InlineData(DnsRecordType.SRV)]
    [InlineData(DnsRecordType.TXT)]
    [InlineData(DnsRecordType.PTR)]
    [InlineData(DnsRecordType.NS)]
    public void TypeMismatch_ReturnsFalse(DnsRecordType actualType)
    {
        // Use a valid A record, but try to parse as every other type
        byte[] rdata = [192, 168, 1, 1];
        DnsRecord record = GetAnswerRecord(BuildResponse(actualType, rdata));

        // Try parsing as each type — only the matching one should succeed
        if (actualType != DnsRecordType.A) Assert.False(record.TryParseARecord(out _));
        if (actualType != DnsRecordType.AAAA) Assert.False(record.TryParseAAAARecord(out _));
        if (actualType != DnsRecordType.CNAME) Assert.False(record.TryParseCNameRecord(out _));
        if (actualType != DnsRecordType.MX) Assert.False(record.TryParseMxRecord(out _));
        if (actualType != DnsRecordType.SRV) Assert.False(record.TryParseSrvRecord(out _));
        if (actualType != DnsRecordType.TXT) Assert.False(record.TryParseTxtRecord(out _));
        if (actualType != DnsRecordType.PTR) Assert.False(record.TryParsePtrRecord(out _));
        if (actualType != DnsRecordType.NS) Assert.False(record.TryParseNsRecord(out _));
    }

    [Fact]
    public void CNameRecord_WithCompressionPointer()
    {
        // Build a response where the CNAME RDATA uses a compression pointer
        // back to the question name ("q.test")
        byte[] rdata = [0xC0, 0x0C]; // pointer to offset 12 = question name
        DnsRecord record = GetAnswerRecord(BuildResponse(DnsRecordType.CNAME, rdata));

        Assert.True(record.TryParseCNameRecord(out var cname));
        Assert.True(cname.CName.Equals("q.test"));
    }
}
