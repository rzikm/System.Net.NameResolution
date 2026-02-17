using System.Net;

namespace System.Net.Dns.Tests;

public class DnsMessageHeaderTests
{
    [Fact]
    public void StandardQuery_SetsDefaults()
    {
        var header = new DnsMessageHeader { Id = 0x1234, Flags = DnsHeaderFlags.RecursionDesired, QuestionCount = 1 };

        Assert.Equal(0x1234, header.Id);
        Assert.False(header.IsResponse);
        Assert.Equal(DnsOpCode.Query, header.OpCode);
        Assert.Equal(DnsHeaderFlags.RecursionDesired, header.Flags);
        Assert.Equal(DnsResponseCode.NoError, header.ResponseCode);
        Assert.Equal(1, header.QuestionCount);
        Assert.Equal(0, header.AnswerCount);
        Assert.Equal(0, header.AuthorityCount);
        Assert.Equal(0, header.AdditionalCount);
    }

    [Fact]
    public void RoundTrip_StandardQuery()
    {
        var original = new DnsMessageHeader { Id = 0xABCD, Flags = DnsHeaderFlags.RecursionDesired, QuestionCount = 2 };
        Span<byte> buffer = stackalloc byte[DnsMessageHeader.Size];

        Assert.True(original.TryWrite(buffer));
        Assert.True(DnsMessageHeader.TryRead(buffer, out var parsed));

        Assert.Equal(original.Id, parsed.Id);
        Assert.Equal(original.IsResponse, parsed.IsResponse);
        Assert.Equal(original.OpCode, parsed.OpCode);
        Assert.Equal(original.Flags, parsed.Flags);
        Assert.Equal(original.ResponseCode, parsed.ResponseCode);
        Assert.Equal(original.QuestionCount, parsed.QuestionCount);
        Assert.Equal(original.AnswerCount, parsed.AnswerCount);
        Assert.Equal(original.AuthorityCount, parsed.AuthorityCount);
        Assert.Equal(original.AdditionalCount, parsed.AdditionalCount);
    }

    [Fact]
    public void RoundTrip_ResponseWithAllFlags()
    {
        var flags = DnsHeaderFlags.AuthoritativeAnswer | DnsHeaderFlags.RecursionDesired
            | DnsHeaderFlags.RecursionAvailable | DnsHeaderFlags.AuthenticData;

        var original = new DnsMessageHeader
        {
            Id = 0x5678,
            IsResponse = true,
            Flags = flags,
            QuestionCount = 1,
            AnswerCount = 3,
            AuthorityCount = 1,
            AdditionalCount = 2,
        };

        Span<byte> buffer = stackalloc byte[DnsMessageHeader.Size];
        Assert.True(original.TryWrite(buffer));
        Assert.True(DnsMessageHeader.TryRead(buffer, out var parsed));

        Assert.True(parsed.IsResponse);
        Assert.Equal(flags, parsed.Flags);
        Assert.Equal(3, parsed.AnswerCount);
        Assert.Equal(1, parsed.AuthorityCount);
        Assert.Equal(2, parsed.AdditionalCount);
    }

    [Fact]
    public void RoundTrip_AllResponseCodes()
    {
        foreach (DnsResponseCode rcode in Enum.GetValues<DnsResponseCode>())
        {
            var original = new DnsMessageHeader { IsResponse = true, ResponseCode = rcode };

            Span<byte> buffer = stackalloc byte[DnsMessageHeader.Size];
            Assert.True(original.TryWrite(buffer));
            Assert.True(DnsMessageHeader.TryRead(buffer, out var parsed));
            Assert.Equal(rcode, parsed.ResponseCode);
        }
    }

    [Fact]
    public void RoundTrip_OpCodes()
    {
        foreach (DnsOpCode opcode in Enum.GetValues<DnsOpCode>())
        {
            var original = new DnsMessageHeader { OpCode = opcode };

            Span<byte> buffer = stackalloc byte[DnsMessageHeader.Size];
            Assert.True(original.TryWrite(buffer));
            Assert.True(DnsMessageHeader.TryRead(buffer, out var parsed));
            Assert.Equal(opcode, parsed.OpCode);
        }
    }

    [Fact]
    public void TryWrite_BufferTooSmall_ReturnsFalse()
    {
        var header = new DnsMessageHeader { Id = 1, Flags = DnsHeaderFlags.RecursionDesired, QuestionCount = 1 };
        Span<byte> buffer = stackalloc byte[11]; // one byte short
        Assert.False(header.TryWrite(buffer));
    }

    [Fact]
    public void TryRead_BufferTooSmall_ReturnsFalse()
    {
        Span<byte> buffer = stackalloc byte[11];
        Assert.False(DnsMessageHeader.TryRead(buffer, out _));
    }

    [Fact]
    public void WireFormat_KnownBytes()
    {
        // Hand-crafted standard query: ID=0x1234, RD=1, QDCOUNT=1
        // Flags word: 0x0100 (RD bit at position 8)
        byte[] expected = [
            0x12, 0x34, // ID
            0x01, 0x00, // Flags: RD=1
            0x00, 0x01, // QDCOUNT=1
            0x00, 0x00, // ANCOUNT=0
            0x00, 0x00, // NSCOUNT=0
            0x00, 0x00, // ARCOUNT=0
        ];

        var header = new DnsMessageHeader { Id = 0x1234, Flags = DnsHeaderFlags.RecursionDesired, QuestionCount = 1 };
        Span<byte> buffer = stackalloc byte[DnsMessageHeader.Size];
        Assert.True(header.TryWrite(buffer));
        Assert.True(buffer.SequenceEqual(expected));
    }

    [Fact]
    public void WireFormat_ResponseWithFlags()
    {
        // Response: QR=1, AA=1, RD=1, RA=1, RCODE=0
        // Flags word: 1_0000_1_0_1_1_0_0_0_0000 = 0x8580
        byte[] expected = [
            0x00, 0x01, // ID
            0x85, 0x80, // QR=1, AA=1, RD=1, RA=1
            0x00, 0x01, // QDCOUNT=1
            0x00, 0x02, // ANCOUNT=2
            0x00, 0x00, // NSCOUNT=0
            0x00, 0x00, // ARCOUNT=0
        ];

        var header = new DnsMessageHeader
        {
            Id = 1,
            IsResponse = true,
            Flags = DnsHeaderFlags.AuthoritativeAnswer | DnsHeaderFlags.RecursionDesired
                | DnsHeaderFlags.RecursionAvailable,
            QuestionCount = 1,
            AnswerCount = 2,
        };

        Span<byte> buffer = stackalloc byte[DnsMessageHeader.Size];
        Assert.True(header.TryWrite(buffer));
        Assert.True(buffer.SequenceEqual(expected));
    }
}
