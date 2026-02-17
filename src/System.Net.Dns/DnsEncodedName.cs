using System.Buffers;
using System.Globalization;

namespace System.Net;

/// <summary>
/// Represents a domain name in DNS wire format (RFC 1035 §4.1.4).
/// Works for both read path (response with compression pointers) and write path (flat encoded).
/// </summary>
public readonly ref struct DnsEncodedName
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

    internal DnsEncodedName(ReadOnlySpan<byte> buffer, int offset)
    {
        _buffer = buffer;
        _offset = offset;
    }

    /// <summary>
    /// Attempts to parse a DNS name from a wire-format buffer at the given offset.
    /// Validates that the name is well-formed (valid label lengths, no truncation).
    /// The <paramref name="buffer"/> is retained by the returned <see cref="DnsEncodedName"/>
    /// to support compression pointer resolution.
    /// </summary>
    /// <param name="buffer">The buffer containing the encoded name.</param>
    /// <param name="offset">The byte offset within <paramref name="buffer"/> where the name starts.</param>
    /// <param name="name">On success, receives the parsed name.</param>
    /// <param name="bytesConsumed">On success, receives the number of bytes consumed from the buffer
    /// at <paramref name="offset"/> (not following compression pointers).</param>
    /// <returns><c>true</c> if the name was successfully parsed; <c>false</c> if the data is malformed.</returns>
    public static bool TryParse(ReadOnlySpan<byte> buffer, int offset, out DnsEncodedName name, out int bytesConsumed)
    {
        name = default;
        bytesConsumed = 0;

        if (offset < 0 || offset >= buffer.Length)
        {
            return false;
        }

        DnsEncodedName candidate = new DnsEncodedName(buffer, offset);
        int wireLen = candidate.GetWireLength();
        if (wireLen < 0)
        {
            return false;
        }

        name = candidate;
        bytesConsumed = wireLen;
        return true;
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
    public static OperationStatus TryEncode(
        ReadOnlySpan<char> name,
        Span<byte> destination,
        out DnsEncodedName result,
        out int bytesWritten)
    {
        result = default;
        bytesWritten = 0;

        // Handle root name "." or empty string
        if (name.Length == 0 || (name.Length == 1 && name[0] == '.'))
        {
            if (destination.Length < 1)
            {
                return OperationStatus.DestinationTooSmall;
            }
            destination[0] = 0; // root label
            bytesWritten = 1;
            result = new DnsEncodedName(destination[..1], 0);
            return OperationStatus.Done;
        }

        // If the name contains non-ASCII characters, convert to ACE (Punycode) form
        // per RFC 5891 (IDNA 2008) before wire encoding.
        // TODO: Switch to span-based IdnMapping.TryGetAscii when available (.NET 11+)
        string? aceName = null;
        if (ContainsNonAscii(name))
        {
            try
            {
                aceName = s_idnMapping.GetAscii(name.ToString());
            }
            catch (ArgumentException)
            {
                return OperationStatus.InvalidData;
            }
            name = aceName;
        }

        // Strip trailing dot if present (FQDN notation),
        // but only if it doesn't create an empty label (e.g., "vp.." should remain invalid)
        if (name[^1] == '.' && (name.Length < 2 || name[^2] != '.'))
        {
            name = name[..^1];
        }

        int pos = 0;
        int nameIdx = 0;

        while (nameIdx < name.Length)
        {
            // Find end of current label
            int dotIdx = name[nameIdx..].IndexOf('.');
            int labelEnd = dotIdx >= 0 ? nameIdx + dotIdx : name.Length;
            int labelLen = labelEnd - nameIdx;

            if (labelLen == 0)
            {
                return OperationStatus.InvalidData; // consecutive dots
            }
            if (labelLen > 63)
            {
                return OperationStatus.InvalidData; // label too long
            }

            // Check total length so far
            int needed = pos + 1 + labelLen + 1; // length byte + label + at least root terminator
            if (needed > MaxEncodedLength)
            {
                return OperationStatus.InvalidData; // name too long
            }

            if (pos + 1 + labelLen > destination.Length)
            {
                return OperationStatus.DestinationTooSmall;
            }

            // Write length prefix
            destination[pos] = (byte)labelLen;
            pos++;

            // Write label bytes (ASCII only after IDN conversion)
            for (int i = 0; i < labelLen; i++)
            {
                char c = name[nameIdx + i];
                if (c > 127)
                {
                    return OperationStatus.InvalidData;
                }
                destination[pos + i] = (byte)c;
            }
            pos += labelLen;

            nameIdx = labelEnd + 1; // skip the dot
            if (dotIdx < 0) break; // no more labels
        }

        // Write root label terminator
        if (pos >= destination.Length)
        {
            return OperationStatus.DestinationTooSmall;
        }
        destination[pos] = 0;
        pos++;

        bytesWritten = pos;
        result = new DnsEncodedName(destination[..pos], 0);
        return OperationStatus.Done;
    }

    private static readonly IdnMapping s_idnMapping = new IdnMapping { AllowUnassigned = false, UseStd3AsciiRules = true };

    private static bool ContainsNonAscii(ReadOnlySpan<char> text)
    {
        for (int i = 0; i < text.Length; i++)
        {
            if (text[i] > 127)
            {
                return true;
            }
        }
        return false;
    }

    /// <summary>
    /// Compares this name to a dotted string representation. Case-insensitive.
    /// Non-ASCII (Unicode) names are converted to ACE form before comparison.
    /// </summary>
    public bool Equals(ReadOnlySpan<char> name)
    {
        // If the name contains non-ASCII characters, convert to ACE for comparison
        // TODO: Switch to span-based IdnMapping.TryGetAscii when available (.NET 11+)
        string? aceName = null;
        if (ContainsNonAscii(name))
        {
            try
            {
                aceName = s_idnMapping.GetAscii(name.ToString());
            }
            catch (ArgumentException)
            {
                return false;
            }
            name = aceName;
        }

        // Strip trailing dot from the comparison name
        if (name.Length > 0 && name[^1] == '.')
        {
            name = name[..^1];
        }

        DnsLabelEnumerator enumerator = EnumerateLabels();
        int nameIdx = 0;

        while (enumerator.MoveNext())
        {
            ReadOnlySpan<byte> label = enumerator.Current;

            if (nameIdx > 0)
            {
                // Expect a dot separator
                if (nameIdx >= name.Length || name[nameIdx] != '.')
                {
                    return false;
                }
                nameIdx++;
            }

            if (nameIdx + label.Length > name.Length)
            {
                return false;
            }

            // Case-insensitive compare of label bytes vs name chars
            for (int i = 0; i < label.Length; i++)
            {
                char c = name[nameIdx + i];
                if (c > 127)
                {
                    return false;
                }
                if (!AsciiEqualsIgnoreCase((byte)c, label[i]))
                {
                    return false;
                }
            }
            nameIdx += label.Length;
        }

        return nameIdx == name.Length;
    }

    /// <summary>
    /// Decodes the domain name into the destination buffer as a dotted string.
    /// ACE-encoded labels (starting with "xn--") are converted back to Unicode.
    /// </summary>
    public bool TryDecode(Span<char> destination, out int charsWritten)
    {
        charsWritten = 0;
        DnsLabelEnumerator enumerator = EnumerateLabels();
        bool first = true;
        bool hasAce = false;

        while (enumerator.MoveNext())
        {
            ReadOnlySpan<byte> label = enumerator.Current;

            if (!first)
            {
                if (charsWritten >= destination.Length)
                {
                    return false;
                }
                destination[charsWritten] = '.';
                charsWritten++;
            }
            first = false;

            if (charsWritten + label.Length > destination.Length)
            {
                return false;
            }

            for (int i = 0; i < label.Length; i++)
            {
                destination[charsWritten + i] = (char)label[i];
            }

            if (!hasAce && IsAceLabel(label))
            {
                hasAce = true;
            }

            charsWritten += label.Length;
        }

        // If any label was ACE-encoded, try to convert the whole name to Unicode
        // TODO: Switch to span-based IdnMapping.TryGetUnicode when available (.NET 11+)
        if (hasAce)
        {
            try
            {
                string unicode = s_idnMapping.GetUnicode(new string(destination[..charsWritten]));
                if (unicode.Length <= destination.Length)
                {
                    unicode.AsSpan().CopyTo(destination);
                    charsWritten = unicode.Length;
                }
                // If the Unicode form doesn't fit, keep the ACE form
            }
            catch (ArgumentException)
            {
                // If IDN conversion fails, keep the raw ACE form
            }
        }

        // Root name produces empty string — that's fine
        return true;
    }

    private static bool IsAceLabel(ReadOnlySpan<byte> label)
    {
        return label.Length >= 4 &&
               (label[0] == (byte)'x' || label[0] == (byte)'X') &&
               (label[1] == (byte)'n' || label[1] == (byte)'N') &&
               label[2] == (byte)'-' &&
               label[3] == (byte)'-';
    }

    /// <summary>
    /// Returns the character count of the decoded dotted string representation.
    /// For names containing ACE-encoded labels, this returns the length of the Unicode form.
    /// </summary>
    public int GetFormattedLength()
    {
        int length = 0;
        DnsLabelEnumerator enumerator = EnumerateLabels();
        bool first = true;
        bool hasAce = false;

        while (enumerator.MoveNext())
        {
            if (!first)
            {
                length++; // dot separator
            }
            first = false;

            if (!hasAce && IsAceLabel(enumerator.Current))
            {
                hasAce = true;
            }

            length += enumerator.Current.Length;
        }

        if (hasAce)
        {
            // Need to compute actual Unicode length
            // TODO: Switch to span-based IdnMapping.TryGetUnicode when available (.NET 11+)
            Span<char> chars = length <= 256 ? stackalloc char[256] : new char[length];
            TryDecodeAscii(chars, out int asciiWritten);
            try
            {
                string unicode = s_idnMapping.GetUnicode(new string(chars[..asciiWritten]));
                return unicode.Length;
            }
            catch (ArgumentException)
            {
                // Fall back to ACE length
            }
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
        // First get the ASCII form
        int asciiLen = GetAsciiFormattedLength();
        if (asciiLen == 0)
        {
            return ".";
        }
        Span<char> chars = asciiLen <= 256 ? stackalloc char[asciiLen] : new char[asciiLen];
        TryDecodeAscii(chars, out int written);

        // Try to convert ACE labels to Unicode
        // TODO: Switch to span-based IdnMapping.TryGetUnicode when available (.NET 11+)
        string ascii = new string(chars[..written]);
        try
        {
            return s_idnMapping.GetUnicode(ascii);
        }
        catch (ArgumentException)
        {
            return ascii;
        }
    }

    /// <summary>
    /// Gets the ASCII (non-IDN-decoded) formatted length.
    /// </summary>
    private int GetAsciiFormattedLength()
    {
        int length = 0;
        DnsLabelEnumerator enumerator = EnumerateLabels();
        bool first = true;

        while (enumerator.MoveNext())
        {
            if (!first)
            {
                length++; // dot separator
            }
            first = false;
            length += enumerator.Current.Length;
        }
        return length;
    }

    /// <summary>
    /// Decodes the domain name as raw ASCII without IDN conversion.
    /// </summary>
    private bool TryDecodeAscii(Span<char> destination, out int charsWritten)
    {
        charsWritten = 0;
        DnsLabelEnumerator enumerator = EnumerateLabels();
        bool first = true;

        while (enumerator.MoveNext())
        {
            ReadOnlySpan<byte> label = enumerator.Current;

            if (!first)
            {
                if (charsWritten >= destination.Length)
                {
                    return false;
                }
                destination[charsWritten] = '.';
                charsWritten++;
            }
            first = false;

            if (charsWritten + label.Length > destination.Length)
            {
                return false;
            }

            for (int i = 0; i < label.Length; i++)
            {
                destination[charsWritten + i] = (char)label[i];
            }
            charsWritten += label.Length;
        }

        return true;
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
            if (b == 0)
            {
                return pos + 1 - _offset; // root label
            }
            if ((b & 0xC0) == 0xC0)
            {
                if (pos + 1 >= _buffer.Length)
                {
                    break; // truncated pointer
                }
                return pos + 2 - _offset; // compression pointer
            }
            if (b > 63)
            {
                break; // label too long per RFC 1035
            }
            if (pos + 1 + b > _buffer.Length)
            {
                break; // malformed: label extends past buffer
            }
            pos += 1 + b; // skip label
        }
        return -1; // malformed name
    }

    private static bool AsciiEqualsIgnoreCase(byte a, byte b)
    {
        if (a == b)
        {
            return true;
        }
        // Normalize to uppercase and compare
        if (a >= (byte)'a' && a <= (byte)'z')
        {
            a -= 32;
        }
        if (b >= (byte)'a' && b <= (byte)'z')
        {
            b -= 32;
        }
        return a == b;
    }
}

/// <summary>
/// Enumerates labels of a DNS name, following compression pointers.
/// </summary>
public ref struct DnsLabelEnumerator
{
    private const int MaxPointerHops = 16; // prevent infinite loops from malformed compression pointers

    private readonly ReadOnlySpan<byte> _buffer;
    private int _pos;
    private int _hops;
    private ReadOnlySpan<byte> _current;

    internal DnsLabelEnumerator(ReadOnlySpan<byte> buffer, int offset)
    {
        _buffer = buffer;
        _pos = offset;
        _hops = 0;
        _current = default;
    }

    public ReadOnlySpan<byte> Current => _current;

    public bool MoveNext()
    {
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
                if (_pos + 1 >= _buffer.Length)
                {
                    return false;
                }
                int pointer = ((b & 0x3F) << 8) | _buffer[_pos + 1];
                if (pointer >= _pos)
                {
                    return false; // only backwards jumps allowed
                }
                _pos = pointer;
                if (++_hops > MaxPointerHops)
                {
                    return false; // loop protection
                }
                continue;
            }

            // Regular label
            int labelLen = b;
            if (labelLen > 63)
            {
                return false; // label too long per RFC 1035
            }
            _pos++;
            if (_pos + labelLen > _buffer.Length)
            {
                return false;
            }
            _current = _buffer.Slice(_pos, labelLen);
            _pos += labelLen;
            return true;
        }
        return false;
    }

    public DnsLabelEnumerator GetEnumerator() => this;
}
