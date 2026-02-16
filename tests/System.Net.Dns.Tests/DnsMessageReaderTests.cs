using System.Buffers;
using System.Diagnostics;
using System.Net;

namespace System.Net.Dns.Tests;

public class DnsMessageReaderTests
{
    // A complete DNS response for "example.com" A query:
    // Header: ID=0x1234, QR=1, RD=1, RA=1, QDCOUNT=1, ANCOUNT=1
    // Question: example.com IN A
    // Answer: example.com A 93.184.216.34 TTL=300
    // The answer name uses a compression pointer to offset 12 (the question name)
    private static readonly byte[] ExampleComAResponse =
    [
        // Header (12 bytes)
        0x12, 0x34,  // ID
        0x81, 0x80,  // Flags: QR=1, RD=1, RA=1
        0x00, 0x01,  // QDCOUNT=1
        0x00, 0x01,  // ANCOUNT=1
        0x00, 0x00,  // NSCOUNT=0
        0x00, 0x00,  // ARCOUNT=0

        // Question section:
        // example.com IN A
        0x07, (byte)'e', (byte)'x', (byte)'a', (byte)'m', (byte)'p', (byte)'l', (byte)'e',
        0x03, (byte)'c', (byte)'o', (byte)'m', 0x00,
        0x00, 0x01,  // QTYPE = A
        0x00, 0x01,  // QCLASS = IN

        // Answer section:
        // example.com (compression pointer to offset 12) A IN TTL=300 RDATA=93.184.216.34
        0xC0, 0x0C,  // Name: pointer to offset 12
        0x00, 0x01,  // TYPE = A
        0x00, 0x01,  // CLASS = IN
        0x00, 0x00, 0x01, 0x2C,  // TTL = 300
        0x00, 0x04,  // RDLENGTH = 4
        0x5D, 0xB8, 0xD8, 0x22,  // RDATA: 93.184.216.34
    ];

    [Fact]
    public void ParseHeader_CorrectFields()
    {
        var reader = new DnsMessageReader(ExampleComAResponse);

        Assert.Equal(0x1234, reader.Header.Id);
        Assert.True(reader.Header.IsResponse);
        Assert.Equal(DnsOpCode.Query, reader.Header.OpCode);
        Assert.True(reader.Header.Flags.HasFlag(DnsHeaderFlags.RecursionDesired));
        Assert.True(reader.Header.Flags.HasFlag(DnsHeaderFlags.RecursionAvailable));
        Assert.Equal(DnsResponseCode.NoError, reader.Header.ResponseCode);
        Assert.Equal(1, reader.Header.QuestionCount);
        Assert.Equal(1, reader.Header.AnswerCount);
        Assert.Equal(0, reader.Header.AuthorityCount);
        Assert.Equal(0, reader.Header.AdditionalCount);
    }

    [Fact]
    public void ParseQuestion_CorrectFields()
    {
        var reader = new DnsMessageReader(ExampleComAResponse);

        Assert.True(reader.TryReadQuestion(out var question));
        Assert.True(question.Name.Equals("example.com"));
        Assert.Equal(DnsRecordType.A, question.Type);
        Assert.Equal(DnsRecordClass.Internet, question.Class);
    }

    [Fact]
    public void ParseAnswer_ARecord()
    {
        var reader = new DnsMessageReader(ExampleComAResponse);

        // Skip question
        Assert.True(reader.TryReadQuestion(out _));

        // Read answer
        Assert.True(reader.TryReadRecord(out var record));
        Assert.True(record.Name.Equals("example.com"));
        Assert.Equal(DnsRecordType.A, record.Type);
        Assert.Equal(DnsRecordClass.Internet, record.Class);
        Assert.Equal(300u, record.TimeToLive);
        Assert.Equal(4, record.Data.Length);
        Assert.Equal(new byte[] { 0x5D, 0xB8, 0xD8, 0x22 }, record.Data.ToArray());
    }

    [Fact]
    public void ParseAnswer_NameUsesCompressionPointer()
    {
        var reader = new DnsMessageReader(ExampleComAResponse);
        reader.TryReadQuestion(out _);
        reader.TryReadRecord(out var record);

        // The answer name is a compression pointer to offset 12 (the question name)
        Assert.True(record.Name.Equals("example.com"));
        Assert.Equal("example.com", record.Name.ToString());
    }

    // Response with multiple answers: example.com CNAME + A
    private static readonly byte[] CnameAndAResponse =
    [
        // Header
        0x00, 0x01,  // ID=1
        0x81, 0x80,  // QR=1, RD=1, RA=1
        0x00, 0x01,  // QDCOUNT=1
        0x00, 0x02,  // ANCOUNT=2
        0x00, 0x00,  // NSCOUNT=0
        0x00, 0x00,  // ARCOUNT=0

        // Question: www.example.com A IN
        0x03, (byte)'w', (byte)'w', (byte)'w',
        0x07, (byte)'e', (byte)'x', (byte)'a', (byte)'m', (byte)'p', (byte)'l', (byte)'e',
        0x03, (byte)'c', (byte)'o', (byte)'m', 0x00,
        0x00, 0x01,  // QTYPE = A
        0x00, 0x01,  // QCLASS = IN

        // Answer 1: www.example.com CNAME example.com
        0xC0, 0x0C,  // pointer to offset 12 (www.example.com)
        0x00, 0x05,  // TYPE = CNAME
        0x00, 0x01,  // CLASS = IN
        0x00, 0x00, 0x00, 0x3C,  // TTL = 60
        0x00, 0x02,  // RDLENGTH = 2
        0xC0, 0x10,  // RDATA: pointer to offset 16 (example.com)

        // Answer 2: example.com A 93.184.216.34
        0xC0, 0x10,  // pointer to offset 16 (example.com)
        0x00, 0x01,  // TYPE = A
        0x00, 0x01,  // CLASS = IN
        0x00, 0x00, 0x01, 0x2C,  // TTL = 300
        0x00, 0x04,  // RDLENGTH = 4
        0x5D, 0xB8, 0xD8, 0x22,  // 93.184.216.34
    ];

    [Fact]
    public void ParseMultipleAnswers_CnameAndA()
    {
        var reader = new DnsMessageReader(CnameAndAResponse);

        // Skip question
        Assert.True(reader.TryReadQuestion(out var q));
        Assert.True(q.Name.Equals("www.example.com"));

        // CNAME answer
        Assert.True(reader.TryReadRecord(out var cname));
        Assert.Equal(DnsRecordType.CNAME, cname.Type);
        Assert.Equal(60u, cname.TimeToLive);
        Assert.True(cname.Name.Equals("www.example.com"));

        // The CNAME RDATA contains a compression pointer to "example.com"
        var cnameTarget = new DnsName(cname.Message, cname.DataOffset);
        Assert.True(cnameTarget.Equals("example.com"));

        // A answer
        Assert.True(reader.TryReadRecord(out var a));
        Assert.Equal(DnsRecordType.A, a.Type);
        Assert.True(a.Name.Equals("example.com"));
        Assert.Equal(300u, a.TimeToLive);
    }

    // NXDOMAIN response
    private static readonly byte[] NxdomainResponse =
    [
        // Header: QR=1, RD=1, RA=1, RCODE=3 (NXDOMAIN)
        0x00, 0x02,  // ID=2
        0x81, 0x83,  // QR=1, RD=1, RA=1, RCODE=3
        0x00, 0x01,  // QDCOUNT=1
        0x00, 0x00,  // ANCOUNT=0
        0x00, 0x00,  // NSCOUNT=0
        0x00, 0x00,  // ARCOUNT=0

        // Question: nonexistent.example.com A IN
        0x0B, (byte)'n', (byte)'o', (byte)'n', (byte)'e', (byte)'x', (byte)'i',
              (byte)'s', (byte)'t', (byte)'e', (byte)'n', (byte)'t',
        0x07, (byte)'e', (byte)'x', (byte)'a', (byte)'m', (byte)'p', (byte)'l', (byte)'e',
        0x03, (byte)'c', (byte)'o', (byte)'m', 0x00,
        0x00, 0x01,  // QTYPE = A
        0x00, 0x01,  // QCLASS = IN
    ];

    [Fact]
    public void ParseNxdomain_ResponseCode()
    {
        var reader = new DnsMessageReader(NxdomainResponse);

        Assert.Equal(DnsResponseCode.NameError, reader.Header.ResponseCode);
        Assert.Equal(0, reader.Header.AnswerCount);

        Assert.True(reader.TryReadQuestion(out var q));
        Assert.True(q.Name.Equals("nonexistent.example.com"));

        // No records to read
        Assert.False(reader.TryReadRecord(out _));
    }

    [Fact]
    public void Constructor_TooSmallBuffer_Throws()
    {
        Assert.Throws<ArgumentException>(() => new DnsMessageReader(new byte[11]));
    }

    [Fact]
    public void TryReadRecord_TruncatedRdata_ReturnsFalse()
    {
        // Take the valid response and truncate the RDATA
        byte[] truncated = ExampleComAResponse[..^2]; // cut off last 2 bytes of RDATA
        var reader = new DnsMessageReader(truncated);
        reader.TryReadQuestion(out _);
        Assert.False(reader.TryReadRecord(out _));
    }

    [Fact]
    public void TryReadQuestion_MalformedLabelLength_ReturnsFalse()
    {
        // Craft a message where the question name has a label length extending past buffer
        byte[] malformed =
        [
            0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // header
            0xFF, // label length = 255, but no data follows
        ];
        var reader = new DnsMessageReader(malformed);
        Assert.False(reader.TryReadQuestion(out _));
    }

    [Fact]
    public void TryReadRecord_InvalidCompressionPointer_ReturnsFalse()
    {
        // Craft a message where a record name has a compression pointer to an out-of-bounds offset
        byte[] malformed =
        [
            0x00, 0x01, 0x81, 0x80, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, // header: ANCOUNT=1
            0xC0, 0xFF, // compression pointer to offset 255, way beyond buffer
            0x00, 0x01, // TYPE=A
            0x00, 0x01, // CLASS=IN
            0x00, 0x00, 0x00, 0x3C, // TTL=60
            0x00, 0x04, // RDLENGTH=4
            0x01, 0x02, 0x03, 0x04, // RDATA
        ];
        var reader = new DnsMessageReader(malformed);
        // The record can be read structurally (pointer is just 2 bytes to skip)
        Assert.True(reader.TryReadRecord(out var record));
        // But the name's labels cannot be enumerated
        var enumerator = record.Name.EnumerateLabels();
        Assert.False(enumerator.MoveNext());
    }

    [Fact]
    public void RoundTrip_WriteThenRead()
    {
        // Build a query with the writer, then parse it with the reader
        Span<byte> buffer = stackalloc byte[512];
        var writer = new DnsMessageWriter(buffer);

        var header = DnsMessageHeader.CreateStandardQuery(id: 0xBEEF, questionCount: 2);
        writer.TryWriteHeader(in header);

        Span<byte> nameBuf = stackalloc byte[DnsName.MaxEncodedLength];
        DnsName.TryCreate("example.com", nameBuf, out var name1, out _);
        writer.TryWriteQuestion(name1, DnsRecordType.A);

        DnsName.TryCreate("example.org", nameBuf, out var name2, out _);
        writer.TryWriteQuestion(name2, DnsRecordType.AAAA);

        // Now parse
        var reader = new DnsMessageReader(buffer[..writer.BytesWritten]);
        Assert.Equal(0xBEEF, reader.Header.Id);
        Assert.False(reader.Header.IsResponse);
        Assert.Equal(2, reader.Header.QuestionCount);

        Assert.True(reader.TryReadQuestion(out var q1));
        Assert.True(q1.Name.Equals("example.com"));
        Assert.Equal(DnsRecordType.A, q1.Type);

        Assert.True(reader.TryReadQuestion(out var q2));
        Assert.True(q2.Name.Equals("example.org"));
        Assert.Equal(DnsRecordType.AAAA, q2.Type);
    }

    [Fact]
    public void CompressionPointerLoop_DoesNotHang()
    {
        // Message with a compression pointer that loops back, creating a cycle.
        // The reader must terminate rather than loop indefinitely.
        byte[] data = [0x12, 0x34, 0x81, 0x80, 0x3f, 0x0, 0x1, 0x1, 0x1, 0x0, 0x0, 0x0,
                       0x0, 0x63, 0x6f, 0x2b, 0x0, 0x1, 0x0, 0x1, 0xc, 0xc0, 0x0, 0x0,
                       0x0, 0x1, 0x2c, 0x0, 0x4, 0xa, 0x0, 0x0, 0x91, 0x1];

        Stopwatch sw = Stopwatch.StartNew();
        DnsMessageReader reader = new DnsMessageReader(data);
        for (int i = 0; i < reader.Header.QuestionCount && i < 32; i++)
        {
            if (!reader.TryReadQuestion(out DnsQuestion q))
            {
                break;
            }
            q.Name.ToString();
            q.Name.Equals("example.com");
        }
        int total = reader.Header.AnswerCount + reader.Header.AuthorityCount + reader.Header.AdditionalCount;
        for (int i = 0; i < total && i < 64; i++)
        {
            if (!reader.TryReadRecord(out DnsRecord r))
            {
                break;
            }
            r.Name.ToString();
            r.TryParseSoaRecord(out _);
        }
        sw.Stop();
        Assert.True(sw.ElapsedMilliseconds < 1000, $"Took {sw.ElapsedMilliseconds}ms");
    }
}
