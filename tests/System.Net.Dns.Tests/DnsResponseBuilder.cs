using System.Buffers.Binary;
using System.Net;

namespace System.Net.Dns.Tests;

/// <summary>
/// Fluent builder for constructing DNS response byte arrays in tests.
/// Makes it easy to see at the callsite what type of response is being built.
/// </summary>
internal class DnsResponseBuilder
{
    private readonly ushort _queryId;
    private readonly byte[] _questionName;
    private readonly DnsRecordType _questionType;

    private DnsResponseCode _rcode;
    private DnsHeaderFlags _extraFlags;

    // Section records: (ownerName, type, ttl, rdata)
    // null ownerName means "use question name"
    private List<(byte[]? OwnerName, DnsRecordType Type, uint Ttl, byte[] Rdata)>? _answers;
    private List<(byte[]? OwnerName, DnsRecordType Type, uint Ttl, byte[] Rdata)>? _authority;
    private List<(byte[]? OwnerName, DnsRecordType Type, uint Ttl, byte[] Rdata)>? _additional;

    // Section count overrides for malformed responses (-1 = use actual count)
    private int _questionCountOverride = -1;
    private int _answerCountOverride = -1;
    private int _authorityCountOverride = -1;
    private int _additionalCountOverride = -1;

    private bool _skipQuestion;

    private DnsResponseBuilder(ushort queryId, byte[] questionName, DnsRecordType questionType)
    {
        _queryId = queryId;
        _questionName = questionName;
        _questionType = questionType;
    }

    /// <summary>
    /// Creates a new response builder for the given query.
    /// </summary>
    public static DnsResponseBuilder For(ushort queryId, byte[] questionName, DnsRecordType questionType)
    {
        return new DnsResponseBuilder(queryId, questionName, questionType);
    }

    /// <summary>
    /// Sets the response code.
    /// </summary>
    public DnsResponseBuilder ResponseCode(DnsResponseCode rcode)
    {
        _rcode = rcode;
        return this;
    }

    /// <summary>
    /// Sets the Truncation (TC) flag and omits all records.
    /// </summary>
    public DnsResponseBuilder Truncated()
    {
        _extraFlags |= DnsHeaderFlags.Truncation;
        return this;
    }

    /// <summary>
    /// Adds an answer record using the question name as owner.
    /// </summary>
    public DnsResponseBuilder Answer(byte[] rdata, uint ttl = 300)
    {
        return Answer(_questionType, rdata, ttl);
    }

    /// <summary>
    /// Adds an answer record using the question name as owner, with explicit type.
    /// </summary>
    public DnsResponseBuilder Answer(DnsRecordType type, byte[] rdata, uint ttl = 300)
    {
        _answers ??= new();
        _answers.Add((null, type, ttl, rdata));
        return this;
    }

    /// <summary>
    /// Adds an answer record with a different owner name.
    /// </summary>
    public DnsResponseBuilder Answer(string ownerName, DnsRecordType type, byte[] rdata, uint ttl = 300)
    {
        _answers ??= new();
        _answers.Add((EncodeName(ownerName), type, ttl, rdata));
        return this;
    }

    /// <summary>
    /// Adds an authority record.
    /// </summary>
    public DnsResponseBuilder Authority(string ownerName, DnsRecordType type, byte[] rdata, uint ttl = 60)
    {
        _authority ??= new();
        _authority.Add((EncodeName(ownerName), type, ttl, rdata));
        return this;
    }

    /// <summary>
    /// Adds an additional record.
    /// </summary>
    public DnsResponseBuilder Additional(string ownerName, DnsRecordType type, byte[] rdata, uint ttl = 300)
    {
        _additional ??= new();
        _additional.Add((EncodeName(ownerName), type, ttl, rdata));
        return this;
    }

    /// <summary>
    /// Overrides the QDCOUNT in the header (for malformed responses).
    /// </summary>
    public DnsResponseBuilder OverrideQuestionCount(ushort count)
    {
        _questionCountOverride = count;
        return this;
    }

    /// <summary>
    /// Overrides the ANCOUNT in the header (for malformed responses).
    /// </summary>
    public DnsResponseBuilder OverrideAnswerCount(ushort count)
    {
        _answerCountOverride = count;
        return this;
    }

    /// <summary>
    /// Overrides the NSCOUNT in the header (for malformed responses).
    /// </summary>
    public DnsResponseBuilder OverrideAuthorityCount(ushort count)
    {
        _authorityCountOverride = count;
        return this;
    }

    /// <summary>
    /// Overrides the ARCOUNT in the header (for malformed responses).
    /// </summary>
    public DnsResponseBuilder OverrideAdditionalCount(ushort count)
    {
        _additionalCountOverride = count;
        return this;
    }

    /// <summary>
    /// Omits the question section from the response body (header-only for malformed responses).
    /// </summary>
    public DnsResponseBuilder SkipQuestion()
    {
        _skipQuestion = true;
        return this;
    }

    /// <summary>
    /// Builds the DNS response as a byte array.
    /// </summary>
    public byte[] Build()
    {
        int answerCount = _answers?.Count ?? 0;
        int authorityCount = _authority?.Count ?? 0;
        int additionalCount = _additional?.Count ?? 0;
        bool writeQuestion = !_skipQuestion && _questionName.Length > 0;

        DnsMessageHeader header = new()
        {
            Id = _queryId,
            IsResponse = true,
            Flags = DnsHeaderFlags.RecursionDesired | DnsHeaderFlags.RecursionAvailable | _extraFlags,
            ResponseCode = _rcode,
            QuestionCount = (ushort)(_questionCountOverride >= 0 ? _questionCountOverride : (writeQuestion ? 1 : 0)),
            AnswerCount = (ushort)(_answerCountOverride >= 0 ? _answerCountOverride : answerCount),
            AuthorityCount = (ushort)(_authorityCountOverride >= 0 ? _authorityCountOverride : authorityCount),
            AdditionalCount = (ushort)(_additionalCountOverride >= 0 ? _additionalCountOverride : additionalCount),
        };

        Span<byte> buf = stackalloc byte[4096];
        DnsMessageWriter writer = new(buf);
        writer.TryWriteHeader(in header);

        DnsEncodedName qName = ParseName(_questionName);
        if (writeQuestion)
        {
            writer.TryWriteQuestion(qName, _questionType);
        }

        int offset = writer.BytesWritten;

        WriteSection(buf, ref offset, _answers, qName);
        WriteSection(buf, ref offset, _authority, qName);
        WriteSection(buf, ref offset, _additional, qName);

        return buf[..offset].ToArray();
    }

    private static void WriteSection(Span<byte> buf, ref int offset,
        List<(byte[]? OwnerName, DnsRecordType Type, uint Ttl, byte[] Rdata)>? records,
        scoped DnsEncodedName defaultName)
    {
        if (records == null)
        {
            return;
        }

        foreach (var (ownerName, type, ttl, rdata) in records)
        {
            DnsEncodedName name = ownerName != null ? ParseName(ownerName) : defaultName;
            WriteRecord(buf, ref offset, name, type, ttl, rdata);
        }
    }

    private static DnsEncodedName ParseName(byte[] nameBytes)
    {
        DnsEncodedName.TryParse(nameBytes, 0, out DnsEncodedName name, out _);
        return name;
    }

    private static byte[] EncodeName(string name)
    {
        Span<byte> buf = stackalloc byte[DnsEncodedName.MaxEncodedLength];
        DnsEncodedName.TryEncode(name, buf, out _, out int written);
        return buf[..written].ToArray();
    }

    private static void WriteRecord(Span<byte> buf, ref int offset, scoped DnsEncodedName name,
        DnsRecordType type, uint ttl, ReadOnlySpan<byte> rdata, DnsRecordClass @class = DnsRecordClass.Internet)
    {
        foreach (ReadOnlySpan<byte> label in name.EnumerateLabels())
        {
            buf[offset++] = (byte)label.Length;
            label.CopyTo(buf[offset..]);
            offset += label.Length;
        }
        buf[offset++] = 0; // root label

        BinaryPrimitives.WriteUInt16BigEndian(buf[offset..], (ushort)type);
        BinaryPrimitives.WriteUInt16BigEndian(buf[(offset + 2)..], (ushort)@class);
        BinaryPrimitives.WriteUInt32BigEndian(buf[(offset + 4)..], ttl);
        BinaryPrimitives.WriteUInt16BigEndian(buf[(offset + 8)..], (ushort)rdata.Length);
        offset += 10;

        rdata.CopyTo(buf[offset..]);
        offset += rdata.Length;
    }

    /// <summary>
    /// Builds SOA RDATA from the given parameters.
    /// </summary>
    internal static byte[] BuildSoaRdata(string soaName, uint minTtl)
    {
        byte[] mname = EncodeName("ns." + soaName);
        byte[] rname = EncodeName("admin." + soaName);
        byte[] rdata = new byte[mname.Length + rname.Length + 20];
        mname.CopyTo(rdata, 0);
        rname.CopyTo(rdata, mname.Length);
        int fixedStart = mname.Length + rname.Length;
        BinaryPrimitives.WriteUInt32BigEndian(rdata.AsSpan(fixedStart), 2024010101);     // serial
        BinaryPrimitives.WriteUInt32BigEndian(rdata.AsSpan(fixedStart + 4), 3600);       // refresh
        BinaryPrimitives.WriteUInt32BigEndian(rdata.AsSpan(fixedStart + 8), 900);        // retry
        BinaryPrimitives.WriteUInt32BigEndian(rdata.AsSpan(fixedStart + 12), 604800);    // expire
        BinaryPrimitives.WriteUInt32BigEndian(rdata.AsSpan(fixedStart + 16), minTtl);    // minimum
        return rdata;
    }

    /// <summary>
    /// Builds SRV RDATA from the given parameters.
    /// </summary>
    internal static byte[] BuildSrvRdata(ushort priority, ushort weight, ushort port, string target)
    {
        byte[] targetBytes = EncodeName(target);
        byte[] rdata = new byte[6 + targetBytes.Length];
        BinaryPrimitives.WriteUInt16BigEndian(rdata, priority);
        BinaryPrimitives.WriteUInt16BigEndian(rdata.AsSpan(2), weight);
        BinaryPrimitives.WriteUInt16BigEndian(rdata.AsSpan(4), port);
        targetBytes.CopyTo(rdata, 6);
        return rdata;
    }
}
