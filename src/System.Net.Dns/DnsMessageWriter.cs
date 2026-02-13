namespace System.Net;

/// <summary>
/// Writes DNS query messages into a caller-provided buffer.
/// Only supports writing request messages (header + questions).
/// </summary>
public ref struct DnsMessageWriter
{
    private readonly Span<byte> _destination;
    private int _bytesWritten;

    public DnsMessageWriter(Span<byte> destination)
    {
        _destination = destination;
        _bytesWritten = 0;
    }

    public int BytesWritten => _bytesWritten;

    /// <summary>
    /// Writes the 12-byte message header at the current position.
    /// </summary>
    public bool TryWriteHeader(in DnsMessageHeader header)
    {
        if (!header.TryWrite(_destination[_bytesWritten..]))
            return false;
        _bytesWritten += DnsMessageHeader.Size;
        return true;
    }

    /// <summary>
    /// Writes a question entry: encoded domain name + type + class.
    /// </summary>
    public bool TryWriteQuestion(
        DnsName name,
        DnsRecordType type,
        DnsRecordClass @class = DnsRecordClass.Internet)
    {
        int nameLen = name.GetWireLength();
        int needed = nameLen + 4; // name + 2 bytes type + 2 bytes class

        if (_bytesWritten + needed > _destination.Length)
            return false;

        // Copy the encoded name bytes
        name.Buffer.Slice(name.Offset, nameLen).CopyTo(_destination[_bytesWritten..]);
        _bytesWritten += nameLen;

        // Write type (big-endian)
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(
            _destination[_bytesWritten..], (ushort)type);
        _bytesWritten += 2;

        // Write class (big-endian)
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(
            _destination[_bytesWritten..], (ushort)@class);
        _bytesWritten += 2;

        return true;
    }
}
