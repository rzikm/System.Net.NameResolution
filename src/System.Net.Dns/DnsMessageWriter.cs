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
        {
            return false;
        }
        _bytesWritten += DnsMessageHeader.Size;
        return true;
    }

    /// <summary>
    /// Writes a question entry: encoded domain name + type + class.
    /// Expands compression pointers if present (safe for names from responses).
    /// </summary>
    public bool TryWriteQuestion(
        DnsName name,
        DnsRecordType type,
        DnsRecordClass @class = DnsRecordClass.Internet)
    {
        // Calculate the flat encoded size by enumerating labels
        int nameLen = 1; // root label terminator
        foreach (ReadOnlySpan<byte> label in name.EnumerateLabels())
        {
            nameLen += 1 + label.Length; // length prefix + label bytes
        }

        int needed = nameLen + 4; // name + 2 bytes type + 2 bytes class
        if (_bytesWritten + needed > _destination.Length)
        {
            return false;
        }

        // Write the name label by label (expands any compression pointers)
        foreach (ReadOnlySpan<byte> label in name.EnumerateLabels())
        {
            _destination[_bytesWritten] = (byte)label.Length;
            _bytesWritten++;
            label.CopyTo(_destination[_bytesWritten..]);
            _bytesWritten += label.Length;
        }
        _destination[_bytesWritten] = 0; // root label
        _bytesWritten++;

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
