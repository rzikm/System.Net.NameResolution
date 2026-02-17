using System.Buffers.Binary;

namespace System.Net;

/// <summary>
/// Represents a parsed question entry from the question section.
/// </summary>
public readonly ref struct DnsQuestion
{
    public DnsEncodedName Name { get; }
    public DnsRecordType Type { get; }
    public DnsRecordClass Class { get; }

    internal DnsQuestion(DnsEncodedName name, DnsRecordType type, DnsRecordClass @class)
    {
        Name = name;
        Type = type;
        Class = @class;
    }
}

/// <summary>
/// Represents a parsed resource record from any section (answer, authority, additional).
/// </summary>
public readonly ref struct DnsRecord
{
    public DnsEncodedName Name { get; }
    public DnsRecordType Type { get; }
    public DnsRecordClass Class { get; }
    public uint TimeToLive { get; }

    /// <summary>Raw RDATA bytes.</summary>
    public ReadOnlySpan<byte> Data { get; }

    /// <summary>The full DNS message buffer, for resolving compression pointers in RDATA.</summary>
    public ReadOnlySpan<byte> Message { get; }

    /// <summary>Offset of Data within Message.</summary>
    public int DataOffset { get; }

    internal DnsRecord(DnsEncodedName name, DnsRecordType type, DnsRecordClass @class,
        uint ttl, ReadOnlySpan<byte> data, ReadOnlySpan<byte> message, int dataOffset)
    {
        Name = name;
        Type = type;
        Class = @class;
        TimeToLive = ttl;
        Data = data;
        Message = message;
        DataOffset = dataOffset;
    }
}

/// <summary>
/// Reads DNS messages from a buffer. Parses sequentially: header, questions, resource records.
/// </summary>
public ref struct DnsMessageReader
{
    private readonly ReadOnlySpan<byte> _message;
    private int _pos;

    public DnsMessageHeader Header { get; }

    private DnsMessageReader(ReadOnlySpan<byte> message, DnsMessageHeader header)
    {
        _message = message;
        _pos = DnsMessageHeader.Size;
        Header = header;
    }

    /// <summary>
    /// Attempts to create a reader over a DNS message. Parses the header eagerly.
    /// Returns false if the buffer is too small for a valid header.
    /// </summary>
    public static bool TryCreate(ReadOnlySpan<byte> message, out DnsMessageReader reader)
    {
        reader = default;

        if (!DnsMessageHeader.TryRead(message, out DnsMessageHeader header))
        {
            return false;
        }

        reader = new DnsMessageReader(message, header);
        return true;
    }

    /// <summary>
    /// Reads the next question from the message.
    /// </summary>
    public bool TryReadQuestion(out DnsQuestion question)
    {
        question = default;

        if (_pos >= _message.Length)
        {
            return false;
        }

        // Read name
        if (!DnsEncodedName.TryParse(_message, _pos, out DnsEncodedName name, out int nameWireLen))
        {
            return false; // malformed name
        }
        _pos += nameWireLen;

        // Read QTYPE (2) + QCLASS (2) = 4 bytes
        if (_pos + 4 > _message.Length)
        {
            return false;
        }

        DnsRecordType type = (DnsRecordType)BinaryPrimitives.ReadUInt16BigEndian(_message[_pos..]);
        _pos += 2;
        DnsRecordClass @class = (DnsRecordClass)BinaryPrimitives.ReadUInt16BigEndian(_message[_pos..]);
        _pos += 2;

        question = new DnsQuestion(name, type, @class);
        return true;
    }

    /// <summary>
    /// Reads the next resource record from the message.
    /// </summary>
    public bool TryReadRecord(out DnsRecord record)
    {
        record = default;

        if (_pos >= _message.Length)
        {
            return false;
        }

        // Read name
        if (!DnsEncodedName.TryParse(_message, _pos, out DnsEncodedName name, out int nameWireLen))
        {
            return false; // malformed name
        }
        _pos += nameWireLen;

        // Read TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2) = 10 bytes
        if (_pos + 10 > _message.Length)
        {
            return false;
        }

        DnsRecordType type = (DnsRecordType)BinaryPrimitives.ReadUInt16BigEndian(_message[_pos..]);
        _pos += 2;
        DnsRecordClass @class = (DnsRecordClass)BinaryPrimitives.ReadUInt16BigEndian(_message[_pos..]);
        _pos += 2;
        uint ttl = BinaryPrimitives.ReadUInt32BigEndian(_message[_pos..]);
        _pos += 4;
        ushort rdLength = BinaryPrimitives.ReadUInt16BigEndian(_message[_pos..]);
        _pos += 2;

        int dataOffset = _pos;
        if (dataOffset + rdLength > _message.Length)
        {
            return false;
        }

        ReadOnlySpan<byte> data = _message.Slice(dataOffset, rdLength);
        _pos += rdLength;

        record = new DnsRecord(name, type, @class, ttl, data, _message, dataOffset);
        return true;
    }
}
