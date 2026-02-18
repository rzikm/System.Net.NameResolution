using System.Buffers;
using System.Diagnostics;
using System.Globalization;
using System.Text;

namespace System.Net;

/// <summary>
/// Represents a domain name in DNS wire format (RFC 1035 §4.1.4).
/// Works for both read path (response with compression pointers) and write path (flat encoded).
/// </summary>
public readonly ref struct DnsEncodedName
{
    private static readonly IdnMapping s_idnMapping = new IdnMapping { AllowUnassigned = false, UseStd3AsciiRules = true };

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

    // Whether any label is ACE-encoded (starts with "xn--"), indicating IDN/Punycode.
    private readonly bool _isAce;

    internal DnsEncodedName(ReadOnlySpan<byte> buffer, int offset, bool isAce = false)
    {
        _buffer = buffer;
        _offset = offset;
        _isAce = isAce;
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

        if (!ValidateName(buffer, offset, out int wireLen, out _, out bool isAce))
        {
            return false;
        }

        name = new DnsEncodedName(buffer, offset, isAce);
        bytesConsumed = wireLen;
        return true;
    }

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
        if (!Ascii.IsValid(name))
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
        if (name[^1] == '.')
        {
            name = name[..^1];
        }

        // Wire format length: each '.' becomes a length byte, plus one leading length byte and trailing root label
        int wireLen = name.Length + 2;
        if (wireLen > MaxEncodedLength)
        {
            return OperationStatus.InvalidData; // name too long
        }
        if (wireLen > destination.Length)
        {
            return OperationStatus.DestinationTooSmall;
        }

        // Copy the ASCII name at offset 1, so dots land where length prefixes will go
        OperationStatus asciiStatus = Ascii.FromUtf16(name, destination.Slice(1, name.Length), out _);
        Debug.Assert(asciiStatus == OperationStatus.Done);

        // Walk through and replace dots with label lengths, validate labels along the way
        // The bytes are at destination[1..wireLen-1], with dots at positions where '.' was in the name
        Span<byte> body = destination.Slice(1, name.Length);
        int labelStart = 0;
        bool isAce = aceName != null;
        while (true)
        {
            int dotIdx = body[labelStart..].IndexOf((byte)'.');
            int labelLen = dotIdx >= 0 ? dotIdx : body.Length - labelStart;

            Span<byte> label = body.Slice(labelStart, labelLen);
            if (!IsValidLabel(label))
            {
                return OperationStatus.InvalidData;
            }

            if (!isAce && labelLen >= 4)
            {
                isAce = IsAceLabel(label);
            }

            // Overwrite the dot (or the leading slot at destination[0]) with the label length
            destination[labelStart] = (byte)labelLen;

            if (dotIdx < 0)
            {
                break;
            }

            labelStart += labelLen + 1;
        }

        // Write root (empty) label
        destination[wireLen - 1] = 0;

        bytesWritten = wireLen;
        result = new DnsEncodedName(destination[..wireLen], 0, isAce);
        return OperationStatus.Done;
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
        if (!Ascii.IsValid(name))
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

            if (!Ascii.EqualsIgnoreCase(label, name.Slice(nameIdx, label.Length)))
            {
                return false;
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

            Ascii.ToUtf16(label, destination.Slice(charsWritten, label.Length), out _);

            charsWritten += label.Length;
        }

        if (charsWritten == 0)
        {
            // Root name produces "." in dotted form
            if (destination.Length < 1)
            {
                return false;
            }
            destination[0] = '.';
            charsWritten = 1;
            return true;
        }

        // If any label was ACE-encoded, try to convert the whole name to Unicode
        // TODO: Switch to span-based IdnMapping.TryGetUnicode when available (.NET 11+)
        if (_isAce)
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
               Ascii.EqualsIgnoreCase(label[..4], "xn--"u8);
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

        if (_isAce)
        {
            // If the name contains ACE labels, we need to compute the length of the Unicode form.
            // This is an approximation since some Unicode characters may be multiple UTF-16 code units,
            // but it's sufficient for sizing buffers for TryDecode.
            Span<char> chars = stackalloc char[256];
            bool success = TryDecode(chars, out int charsWritten);
            Debug.Assert(success);
            return charsWritten;
        }

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
    /// Enumerates the individual labels of this domain name.
    /// Follows compression pointers transparently.
    /// </summary>
    public DnsLabelEnumerator EnumerateLabels() => new DnsLabelEnumerator(_buffer, _offset);

    public override string ToString()
    {
        Span<char> chars = stackalloc char[256];
        bool success = TryDecode(chars, out int charsWritten);
        Debug.Assert(success);
        return new string(chars[..charsWritten]);
    }

    /// <summary>
    /// Validates the name and computes the wire-format byte count, the dotted ASCII
    /// string length, and whether any label is ACE-encoded, all in a single pass.
    /// Returns <c>false</c> if the name is malformed or exceeds RFC 1035 limits.
    /// </summary>
    private static bool ValidateName(ReadOnlySpan<byte> buffer, int offset,
        out int wireLength, out int formattedLength, out bool isAce)
    {
        wireLength = 0;
        formattedLength = 0;
        isAce = false;

        int pos = offset;
        bool foundWireEnd = false;
        int hops = 0;

        while (pos < buffer.Length)
        {
            byte b = buffer[pos];

            if (b == 0)
            {
                // Root label — end of name
                if (!foundWireEnd)
                {
                    wireLength = pos + 1 - offset;
                }
                return true;
            }

            if ((b & 0xC0) == 0xC0)
            {
                // Compression pointer
                if (pos + 1 >= buffer.Length)
                {
                    return false; // truncated pointer
                }

                if (!foundWireEnd)
                {
                    wireLength = pos + 2 - offset;
                    foundWireEnd = true;
                }

                int pointer = ((b & 0x3F) << 8) | buffer[pos + 1];
                if (pointer >= pos)
                {
                    return false; // only backwards jumps allowed
                }
                pos = pointer;

                if (++hops > 16)
                {
                    return false; // too many pointer hops
                }
                continue;
            }

            if ((b & 0xC0) != 0x00)
            {
                return false; // one of the upper 2 bits are nonzero, invalid as per RFC 1035
            }
            Debug.Assert(b <= 63); // enforced by condition above

            if (pos + 1 + b > buffer.Length)
            {
                return false; // label extends past buffer
            }

            // Account for dot separator in formatted length
            formattedLength += formattedLength > 0 ? b + 1 : b;
            if (formattedLength > 253)
            {
                return false; // RFC 1035: max 253 characters in dotted form
            }

            // Check for ACE label ("xn--" prefix)
            ReadOnlySpan<byte> label = buffer.Slice(pos + 1, b);
            if (!isAce && b >= 4)
            {
                isAce = IsAceLabel(label);
            }

            // Validate label contents: LDH + underscore, no leading/trailing hyphens
            if (!IsValidLabel(label))
            {
                return false;
            }

            pos += 1 + b; // skip length byte + label
        }

        return false; // ran off the end of buffer without finding root label
    }

    private static readonly SearchValues<byte> s_ldhBytes =
        SearchValues.Create("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"u8);

    /// <summary>
    /// Validates that a label has valid length (1-63), contains only LDH (Letters, Digits,
    /// Hyphens) characters and underscores (for SRV, DKIM, etc.), and does not start or
    /// end with a hyphen.
    /// </summary>
    private static bool IsValidLabel(ReadOnlySpan<byte> label)
    {
        return label.Length > 0 &&
               label.Length <= 63 &&
               label[0] != (byte)'-' &&
               label[^1] != (byte)'-' &&
               label.IndexOfAnyExcept(s_ldhBytes) < 0;
    }
}

/// <summary>
/// Enumerates labels of a DNS name, following compression pointers.
/// The name must have been validated by <see cref="DnsEncodedName.TryParse"/>
/// or <see cref="DnsEncodedName.TryEncode"/> before enumeration.
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
        byte b = _buffer[_pos];

        while ((b & 0xC0) == 0xC0)
        {
            // Compression pointer: follow it
            Debug.Assert(_pos + 1 < _buffer.Length, "Truncated compression pointer");
            int pointer = ((b & 0x3F) << 8) | _buffer[_pos + 1];
            Debug.Assert(pointer < _pos, "Forward or self-referencing compression pointer");
            _pos = pointer;
            b = _buffer[_pos];
        }

        if (b == 0)
        {
            // end, root label
            return false;
        }

        // Regular label
        Debug.Assert(b <= 63, "Invalid label length byte");
        int labelLen = b;
        _pos++;
        Debug.Assert(_pos + labelLen <= _buffer.Length, "Label extends past buffer");
        _current = _buffer.Slice(_pos, labelLen);
        _pos += labelLen;
        return true;
    }

    public DnsLabelEnumerator GetEnumerator() => this;
}
