using System.Diagnostics;

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
        scoped DnsEncodedName name,
        DnsRecordType type,
        DnsRecordClass @class = DnsRecordClass.Internet)
    {
        // Write the name, expanding any compression pointers
        if (!name.TryCopyEncodedTo(_destination[_bytesWritten..], out int nameWritten))
        {
            return false;
        }

        // Check remaining space for type (2) + class (2)
        if (_bytesWritten + nameWritten + 4 > _destination.Length)
        {
            return false;
        }
        _bytesWritten += nameWritten;

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
