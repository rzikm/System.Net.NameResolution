using System.Buffers;

namespace System.Net;

/// <summary>
/// Represents a domain name in DNS wire format (RFC 1035 §4.1.4).
/// Works for both read path (response with compression pointers) and write path (flat encoded).
/// </summary>
public readonly ref struct DnsName
{
    /// <summary>
    /// Maximum wire-format size of any valid domain name
    /// (including length prefixes and root label terminator).
    /// </summary>
    public const int MaxEncodedLength = 255;

    // The buffer containing the encoded name. For names parsed from responses,
    // this is the full message (needed to follow compression pointers).
    // For names created via TryCreate, this is the flat encoded buffer.
    private readonly ReadOnlySpan<byte> _buffer;

    // Offset within _buffer where this name starts.
    private readonly int _offset;

    internal DnsName(ReadOnlySpan<byte> buffer, int offset)
    {
        _buffer = buffer;
        _offset = offset;
    }

    /// <summary>
    /// Gets the underlying buffer (for internal use by reader/writer).
    /// </summary>
    internal ReadOnlySpan<byte> Buffer => _buffer;

    /// <summary>
    /// Gets the offset within the buffer where this name starts.
    /// </summary>
    internal int Offset => _offset;

    /// <summary>
    /// Validates a domain name and encodes it into wire format.
    /// </summary>
    public static OperationStatus TryCreate(
        ReadOnlySpan<char> name,
        Span<byte> destination,
        out DnsName result,
        out int bytesWritten)
    {
        result = default;
        bytesWritten = 0;

        // Handle root name "." or empty string
        if (name.Length == 0 || (name.Length == 1 && name[0] == '.'))
        {
            if (destination.Length < 1)
                return OperationStatus.DestinationTooSmall;
            destination[0] = 0; // root label
            bytesWritten = 1;
            result = new DnsName(destination[..1], 0);
            return OperationStatus.Done;
        }

        // Strip trailing dot if present (FQDN notation)
        if (name[^1] == '.')
            name = name[..^1];

        int pos = 0;
        int nameIdx = 0;

        while (nameIdx < name.Length)
        {
            // Find end of current label
            int dotIdx = name[nameIdx..].IndexOf('.');
            int labelEnd = dotIdx >= 0 ? nameIdx + dotIdx : name.Length;
            int labelLen = labelEnd - nameIdx;

            if (labelLen == 0)
                return OperationStatus.InvalidData; // consecutive dots
            if (labelLen > 63)
                return OperationStatus.InvalidData; // label too long

            // Check total length so far
            int needed = pos + 1 + labelLen + 1; // length byte + label + at least root terminator
            if (needed > MaxEncodedLength)
                return OperationStatus.InvalidData; // name too long

            if (pos + 1 + labelLen > destination.Length)
                return OperationStatus.DestinationTooSmall;

            // Write length prefix
            destination[pos] = (byte)labelLen;
            pos++;

            // Write label bytes (ASCII only)
            for (int i = 0; i < labelLen; i++)
            {
                char c = name[nameIdx + i];
                if (c > 127)
                    return OperationStatus.InvalidData;
                // Allow letters, digits, hyphens per RFC 1035 §2.3.1
                // We're lenient: allow any ASCII printable except '.'
                destination[pos + i] = (byte)c;
            }
            pos += labelLen;

            nameIdx = labelEnd + 1; // skip the dot
            if (dotIdx < 0) break; // no more labels
        }

        // Write root label terminator
        if (pos >= destination.Length)
            return OperationStatus.DestinationTooSmall;
        destination[pos] = 0;
        pos++;

        bytesWritten = pos;
        result = new DnsName(destination[..pos], 0);
        return OperationStatus.Done;
    }

    /// <summary>
    /// Compares this name to a dotted string representation. Case-insensitive.
    /// </summary>
    public bool Equals(ReadOnlySpan<char> name)
    {
        // Strip trailing dot from the comparison name
        if (name.Length > 0 && name[^1] == '.')
            name = name[..^1];

        var enumerator = EnumerateLabels();
        int nameIdx = 0;

        while (enumerator.MoveNext())
        {
            var label = enumerator.Current;

            if (nameIdx > 0)
            {
                // Expect a dot separator
                if (nameIdx >= name.Length || name[nameIdx] != '.')
                    return false;
                nameIdx++;
            }

            if (nameIdx + label.Length > name.Length)
                return false;

            // Case-insensitive compare of label bytes vs name chars
            for (int i = 0; i < label.Length; i++)
            {
                char c = name[nameIdx + i];
                if (c > 127) return false;
                if (!AsciiEqualsIgnoreCase((byte)c, label[i]))
                    return false;
            }
            nameIdx += label.Length;
        }

        return nameIdx == name.Length;
    }

    /// <summary>
    /// Decodes the domain name into the destination buffer as a dotted string.
    /// </summary>
    public bool TryFormat(Span<char> destination, out int charsWritten)
    {
        charsWritten = 0;
        var enumerator = EnumerateLabels();
        bool first = true;

        while (enumerator.MoveNext())
        {
            var label = enumerator.Current;

            if (!first)
            {
                if (charsWritten >= destination.Length)
                    return false;
                destination[charsWritten] = '.';
                charsWritten++;
            }
            first = false;

            if (charsWritten + label.Length > destination.Length)
                return false;

            for (int i = 0; i < label.Length; i++)
                destination[charsWritten + i] = (char)label[i];
            charsWritten += label.Length;
        }

        // Root name produces empty string — that's fine
        return true;
    }

    /// <summary>
    /// Returns the character count of the decoded dotted string representation.
    /// </summary>
    public int GetFormattedLength()
    {
        int length = 0;
        var enumerator = EnumerateLabels();
        bool first = true;

        while (enumerator.MoveNext())
        {
            if (!first) length++; // dot separator
            first = false;
            length += enumerator.Current.Length;
        }
        return length;
    }

    /// <summary>
    /// Enumerates the individual labels of this domain name.
    /// Follows compression pointers transparently.
    /// </summary>
    public DnsLabelEnumerator EnumerateLabels() => new DnsLabelEnumerator(_buffer, _offset);

    public override string ToString()
    {
        int len = GetFormattedLength();
        if (len == 0) return ".";
        Span<char> chars = len <= 256 ? stackalloc char[len] : new char[len];
        TryFormat(chars, out _);
        return new string(chars);
    }

    /// <summary>
    /// Gets the number of bytes consumed by this name in the buffer,
    /// accounting for compression pointers. Used by the reader to advance past a name.
    /// </summary>
    internal int GetWireLength()
    {
        int pos = _offset;
        while (pos < _buffer.Length)
        {
            byte b = _buffer[pos];
            if (b == 0) return pos + 1 - _offset; // root label
            if ((b & 0xC0) == 0xC0) return pos + 2 - _offset; // compression pointer
            if (pos + 1 + b > _buffer.Length) break; // malformed: label extends past buffer
            pos += 1 + b; // skip label
        }
        return -1; // malformed name
    }

    private static bool AsciiEqualsIgnoreCase(byte a, byte b)
    {
        if (a == b) return true;
        // Normalize to uppercase and compare
        if (a >= (byte)'a' && a <= (byte)'z') a -= 32;
        if (b >= (byte)'a' && b <= (byte)'z') b -= 32;
        return a == b;
    }
}

/// <summary>
/// Enumerates labels of a DNS name, following compression pointers.
/// </summary>
public ref struct DnsLabelEnumerator
{
    private readonly ReadOnlySpan<byte> _buffer;
    private int _pos;
    private ReadOnlySpan<byte> _current;

    internal DnsLabelEnumerator(ReadOnlySpan<byte> buffer, int offset)
    {
        _buffer = buffer;
        _pos = offset;
        _current = default;
    }

    public ReadOnlySpan<byte> Current => _current;

    public bool MoveNext()
    {
        const int MaxPointerHops = 128; // prevent infinite loops
        int hops = 0;

        while (_pos < _buffer.Length)
        {
            byte b = _buffer[_pos];

            if (b == 0)
            {
                // Root label — end of name
                _pos = _buffer.Length; // mark as exhausted
                return false;
            }

            if ((b & 0xC0) == 0xC0)
            {
                // Compression pointer: 2 bytes, upper 2 bits are 11
                if (_pos + 1 >= _buffer.Length) return false;
                int pointer = ((b & 0x3F) << 8) | _buffer[_pos + 1];
                if (pointer >= _buffer.Length) return false; // invalid pointer target
                _pos = pointer;
                if (++hops > MaxPointerHops) return false; // loop protection
                continue;
            }

            // Regular label
            int labelLen = b;
            _pos++;
            if (_pos + labelLen > _buffer.Length) return false;
            _current = _buffer.Slice(_pos, labelLen);
            _pos += labelLen;
            return true;
        }
        return false;
    }

    public DnsLabelEnumerator GetEnumerator() => this;
}
