using System.Buffers;
using System.Net;
using System.Text;

namespace System.Net.Dns.Tests;

public class DnsEncodedNameTests
{
    [Theory]
    [InlineData("example.com", new byte[] { 7, (byte)'e', (byte)'x', (byte)'a', (byte)'m', (byte)'p', (byte)'l', (byte)'e', 3, (byte)'c', (byte)'o', (byte)'m', 0 })]
    [InlineData("a.b", new byte[] { 1, (byte)'a', 1, (byte)'b', 0 })]
    public void TryCreate_ValidName_ProducesExpectedBytes(string name, byte[] expected)
    {
        Span<byte> buffer = stackalloc byte[DnsEncodedName.MaxEncodedLength];
        OperationStatus status = DnsEncodedName.TryEncode(name, buffer, out _, out int bytesWritten);

        Assert.Equal(OperationStatus.Done, status);
        Assert.Equal(expected.Length, bytesWritten);
        Assert.True(buffer[..bytesWritten].SequenceEqual(expected));
    }

    [Theory]
    [InlineData("")]    // empty → root
    [InlineData(".")]   // explicit root
    public void TryCreate_Root_ProducesSingleZeroByte(string name)
    {
        Span<byte> buffer = stackalloc byte[DnsEncodedName.MaxEncodedLength];
        OperationStatus status = DnsEncodedName.TryEncode(name, buffer, out _, out int bytesWritten);

        Assert.Equal(OperationStatus.Done, status);
        Assert.Equal(1, bytesWritten);
        Assert.Equal(0, buffer[0]);
    }

    [Fact]
    public void TryCreate_TrailingDot_SameAsWithout()
    {
        Span<byte> buf1 = stackalloc byte[DnsEncodedName.MaxEncodedLength];
        Span<byte> buf2 = stackalloc byte[DnsEncodedName.MaxEncodedLength];

        DnsEncodedName.TryEncode("example.com", buf1, out _, out int len1);
        DnsEncodedName.TryEncode("example.com.", buf2, out _, out int len2);

        Assert.Equal(len1, len2);
        Assert.True(buf1[..len1].SequenceEqual(buf2[..len2]));
    }

    [Fact]
    public void TryCreate_LabelTooLong_ReturnsInvalidData()
    {
        string longLabel = new string('a', 64) + ".com"; // 64 > 63 max
        Span<byte> buffer = stackalloc byte[DnsEncodedName.MaxEncodedLength];
        OperationStatus status = DnsEncodedName.TryEncode(longLabel, buffer, out _, out _);
        Assert.Equal(OperationStatus.InvalidData, status);
    }

    [Fact]
    public void TryCreate_MaxLengthLabel_Succeeds()
    {
        string maxLabel = new string('a', 63) + ".com";
        Span<byte> buffer = stackalloc byte[DnsEncodedName.MaxEncodedLength];
        OperationStatus status = DnsEncodedName.TryEncode(maxLabel, buffer, out _, out _);
        Assert.Equal(OperationStatus.Done, status);
    }

    [Fact]
    public void TryCreate_ConsecutiveDots_ReturnsInvalidData()
    {
        Span<byte> buffer = stackalloc byte[DnsEncodedName.MaxEncodedLength];
        OperationStatus status = DnsEncodedName.TryEncode("example..com", buffer, out _, out _);
        Assert.Equal(OperationStatus.InvalidData, status);
    }

    [Fact]
    public void TryCreate_NameTooLong_ReturnsInvalidData()
    {
        // Build a name that exceeds 255 wire-format bytes
        // Each "a." label takes 3 bytes (1 length + 1 char + will get a dot separator)
        // 63 labels of "aaa" = 63 * (1+3) + 1 root = 253 bytes — just fits
        // Add one more to overflow
        string name = string.Join(".", Enumerable.Repeat("aaaa", 64));
        Span<byte> buffer = stackalloc byte[512]; // oversized buffer
        OperationStatus status = DnsEncodedName.TryEncode(name, buffer, out _, out _);
        Assert.Equal(OperationStatus.InvalidData, status);
    }

    [Fact]
    public void TryCreate_DestinationTooSmall_ReturnsDestinationTooSmall()
    {
        Span<byte> buffer = stackalloc byte[5]; // too small for "example.com"
        OperationStatus status = DnsEncodedName.TryEncode("example.com", buffer, out _, out _);
        Assert.Equal(OperationStatus.DestinationTooSmall, status);
    }

    [Theory]
    [InlineData("example.com", "example.com", true)]
    [InlineData("example.com", "EXAMPLE.COM", true)]
    [InlineData("example.com", "Example.Com", true)]
    [InlineData("example.com", "example.com.", true)]  // trailing dot ignored
    [InlineData("example.com", "example.org", false)]
    [InlineData("example.com", "example", false)]
    [InlineData("a.b.c", "a.b.c", true)]
    [InlineData("a.b.c", "a.b", false)]
    public void Equals_CaseInsensitiveComparison(string create, string compare, bool expected)
    {
        Span<byte> buffer = stackalloc byte[DnsEncodedName.MaxEncodedLength];
        DnsEncodedName.TryEncode(create, buffer, out var name, out _);
        Assert.Equal(expected, name.Equals(compare));
    }

    [Fact]
    public void TryDecode_ProducesDottedString()
    {
        Span<byte> nameBuffer = stackalloc byte[DnsEncodedName.MaxEncodedLength];
        DnsEncodedName.TryEncode("example.com", nameBuffer, out var name, out _);

        Span<char> chars = stackalloc char[64];
        Assert.True(name.TryDecode(chars, out int written));
        Assert.Equal("example.com", new string(chars[..written]));
    }

    [Fact]
    public void TryDecode_Root_ProducesEmptyString()
    {
        Span<byte> nameBuffer = stackalloc byte[DnsEncodedName.MaxEncodedLength];
        DnsEncodedName.TryEncode(".", nameBuffer, out var name, out _);

        Span<char> chars = stackalloc char[64];
        Assert.True(name.TryDecode(chars, out int written));
        Assert.Equal(0, written);
    }

    [Fact]
    public void TryDecode_DestinationTooSmall_ReturnsFalse()
    {
        Span<byte> nameBuffer = stackalloc byte[DnsEncodedName.MaxEncodedLength];
        DnsEncodedName.TryEncode("example.com", nameBuffer, out var name, out _);

        Span<char> chars = stackalloc char[5]; // too small
        Assert.False(name.TryDecode(chars, out _));
    }

    [Fact]
    public void GetFormattedLength_ReturnsCorrectLength()
    {
        Span<byte> nameBuffer = stackalloc byte[DnsEncodedName.MaxEncodedLength];
        DnsEncodedName.TryEncode("example.com", nameBuffer, out var name, out _);
        Assert.Equal("example.com".Length, name.GetFormattedLength());
    }

    [Fact]
    public void ToString_ReturnsFormattedName()
    {
        Span<byte> nameBuffer = stackalloc byte[DnsEncodedName.MaxEncodedLength];
        DnsEncodedName.TryEncode("example.com", nameBuffer, out var name, out _);
        Assert.Equal("example.com", name.ToString());
    }

    [Fact]
    public void ToString_Root_ReturnsDot()
    {
        Span<byte> nameBuffer = stackalloc byte[DnsEncodedName.MaxEncodedLength];
        DnsEncodedName.TryEncode(".", nameBuffer, out var name, out _);
        Assert.Equal(".", name.ToString());
    }

    [Fact]
    public void EnumerateLabels_ReturnsAllLabels()
    {
        Span<byte> nameBuffer = stackalloc byte[DnsEncodedName.MaxEncodedLength];
        DnsEncodedName.TryEncode("a.bb.ccc", nameBuffer, out var name, out _);

        List<string> labels = new();
        foreach (ReadOnlySpan<byte> label in name.EnumerateLabels())
            labels.Add(Encoding.ASCII.GetString(label));

        Assert.Equal(["a", "bb", "ccc"], labels);
    }

    [Fact]
    public void EnumerateLabels_Root_ReturnsNoLabels()
    {
        Span<byte> nameBuffer = stackalloc byte[DnsEncodedName.MaxEncodedLength];
        DnsEncodedName.TryEncode(".", nameBuffer, out var name, out _);

        List<string> labels = new();
        foreach (ReadOnlySpan<byte> label in name.EnumerateLabels())
            labels.Add(Encoding.ASCII.GetString(label));

        Assert.Empty(labels);
    }

    [Fact]
    public void CompressionPointer_FollowedCorrectly()
    {
        // Simulate a DNS message where a name uses a compression pointer:
        // Offset 0: \x07example\x03com\x00  (example.com, 13 bytes)
        // Offset 13: \x03www\xC0\x00        (www + pointer to offset 0 = www.example.com)
        byte[] message =
        [
            7, (byte)'e', (byte)'x', (byte)'a', (byte)'m', (byte)'p', (byte)'l', (byte)'e',
            3, (byte)'c', (byte)'o', (byte)'m', 0,
            3, (byte)'w', (byte)'w', (byte)'w', 0xC0, 0x00
        ];

        DnsEncodedName name = new(message, 13);
        Assert.True(name.Equals("www.example.com"));
        Assert.Equal("www.example.com", name.ToString());
    }

    [Fact]
    public void CompressionPointer_MidName()
    {
        // Offset 0: \x03com\x00  (com, 5 bytes)
        // Offset 5: \x03foo\xC0\x00  (foo + pointer to offset 0 = foo.com)
        byte[] message =
        [
            3, (byte)'c', (byte)'o', (byte)'m', 0,
            3, (byte)'f', (byte)'o', (byte)'o', 0xC0, 0x00
        ];

        DnsEncodedName name = new(message, 5);
        Assert.True(name.Equals("foo.com"));
    }

    [Fact]
    public void GetWireLength_FlatName()
    {
        Span<byte> buffer = stackalloc byte[DnsEncodedName.MaxEncodedLength];
        DnsEncodedName.TryEncode("example.com", buffer, out var name, out int bytesWritten);
        Assert.Equal(bytesWritten, name.GetWireLength());
    }

    [Fact]
    public void GetWireLength_WithCompressionPointer()
    {
        // Name at offset 13: \x03www\xC0\x00  — 6 bytes wire length (1+3 label + 2 pointer)
        byte[] message =
        [
            7, (byte)'e', (byte)'x', (byte)'a', (byte)'m', (byte)'p', (byte)'l', (byte)'e',
            3, (byte)'c', (byte)'o', (byte)'m', 0,
            3, (byte)'w', (byte)'w', (byte)'w', 0xC0, 0x00
        ];

        DnsEncodedName name = new(message, 13);
        Assert.Equal(6, name.GetWireLength());
    }

    [Fact]
    public void CompressionPointer_SelfReferencing_StopsEnumeration()
    {
        // Pointer at offset 0 that points to itself
        byte[] message = [0xC0, 0x00];
        DnsEncodedName name = new(message, 0);
        // Should not infinite-loop; max hop limit kicks in
        List<string> labels = new();
        foreach (ReadOnlySpan<byte> label in name.EnumerateLabels())
            labels.Add(Encoding.ASCII.GetString(label));
        // Enumerator returns false after max hops
        Assert.Empty(labels);
    }

    [Fact]
    public void CompressionPointer_ForwardPointer_HandledByMaxHops()
    {
        // Pointer at offset 0 that points forward to offset 2 (past itself, but within buffer)
        // Offset 2 has another pointer back to offset 0 → loop
        byte[] message = [0xC0, 0x02, 0xC0, 0x00];
        DnsEncodedName name = new(message, 0);
        List<string> labels = new();
        foreach (ReadOnlySpan<byte> label in name.EnumerateLabels())
            labels.Add(Encoding.ASCII.GetString(label));
        Assert.Empty(labels);
    }

    [Fact]
    public void CompressionPointer_ChainedPointers_StopsAtMaxHops()
    {
        // Multiple pointers chaining: offset 0 → offset 2 → offset 4 → root
        byte[] message = [0xC0, 0x02, 0xC0, 0x04, 0x01, (byte)'a', 0x00];
        DnsEncodedName name = new(message, 0);
        Assert.True(name.Equals("a"));
    }

    [Fact]
    public void CompressionPointer_OutOfBounds_ReturnsFalse()
    {
        // Pointer to offset 0xFF, far beyond the 4-byte buffer
        byte[] message = [0xC0, 0xFF, 0x00, 0x00];
        DnsEncodedName name = new(message, 0);
        DnsLabelEnumerator enumerator = name.EnumerateLabels();
        Assert.False(enumerator.MoveNext());
    }

    [Fact]
    public void TryCreate_TrailingDoubleDot_ReturnsInvalidData()
    {
        Span<byte> nameBuf = stackalloc byte[DnsEncodedName.MaxEncodedLength];
        OperationStatus status = DnsEncodedName.TryEncode("vp..", nameBuf, out _, out _);
        Assert.Equal(OperationStatus.InvalidData, status);
    }

    [Fact]
    public void TryCreate_NullCharsAndConsecutiveDots_ReturnsInvalidData()
    {
        Span<char> nameChars = ['\0', '\0', '\0', '\0', 'p', '.', '.'];
        Span<byte> nameBuf = stackalloc byte[DnsEncodedName.MaxEncodedLength];
        OperationStatus status = DnsEncodedName.TryEncode(nameChars, nameBuf, out _, out _);
        Assert.Equal(OperationStatus.InvalidData, status);
    }

    [Fact]
    public void TryParse_ValidRootName_Succeeds()
    {
        byte[] buffer = [0x00];
        Assert.True(DnsEncodedName.TryParse(buffer, 0, out DnsEncodedName name, out int consumed));
        Assert.Equal(1, consumed);
        Assert.Equal(".", name.ToString());
    }

    [Fact]
    public void TryParse_ValidFlatName_Succeeds()
    {
        byte[] buffer = [3, (byte)'w', (byte)'w', (byte)'w', 7, (byte)'e', (byte)'x', (byte)'a', (byte)'m', (byte)'p', (byte)'l', (byte)'e', 3, (byte)'c', (byte)'o', (byte)'m', 0];
        Assert.True(DnsEncodedName.TryParse(buffer, 0, out DnsEncodedName name, out int consumed));
        Assert.Equal(buffer.Length, consumed);
        Assert.Equal("www.example.com", name.ToString());
    }

    [Fact]
    public void TryParse_AtOffset_Succeeds()
    {
        // "com" starts at offset 12 in a typical message; simulate with padding
        byte[] buffer = new byte[5 + 3 + 3 + 1]; // 5 bytes padding + 3-label "com" + root
        buffer[5] = 3;
        buffer[6] = (byte)'c';
        buffer[7] = (byte)'o';
        buffer[8] = (byte)'m';
        buffer[9] = 0;
        Assert.True(DnsEncodedName.TryParse(buffer, 5, out DnsEncodedName name, out int consumed));
        Assert.Equal(5, consumed);
        Assert.Equal("com", name.ToString());
    }

    [Fact]
    public void TryParse_WithCompressionPointer_Succeeds()
    {
        // Buffer: "com\0" at offset 0, then a pointer to offset 0 at offset 4
        byte[] buffer = [3, (byte)'c', (byte)'o', (byte)'m', 0, 0xC0, 0x00];
        Assert.True(DnsEncodedName.TryParse(buffer, 5, out DnsEncodedName name, out int consumed));
        Assert.Equal(2, consumed); // compression pointer is 2 bytes
        Assert.Equal("com", name.ToString());
    }

    [Fact]
    public void TryParse_Truncated_ReturnsFalse()
    {
        // Label says length 5 but buffer only has 3 more bytes
        byte[] buffer = [5, (byte)'a', (byte)'b'];
        Assert.False(DnsEncodedName.TryParse(buffer, 0, out _, out _));
    }

    [Fact]
    public void TryParse_LabelTooLong_ReturnsFalse()
    {
        // Label length byte > 63 and not a pointer (0x40..0xBF range)
        byte[] buffer = [0x50, 0x00];
        Assert.False(DnsEncodedName.TryParse(buffer, 0, out _, out _));
    }

    [Fact]
    public void TryParse_NegativeOffset_ReturnsFalse()
    {
        byte[] buffer = [0x00];
        Assert.False(DnsEncodedName.TryParse(buffer, -1, out _, out _));
    }

    [Fact]
    public void TryParse_OffsetBeyondBuffer_ReturnsFalse()
    {
        byte[] buffer = [0x00];
        Assert.False(DnsEncodedName.TryParse(buffer, 5, out _, out _));
    }

    [Fact]
    public void TryParse_EmptyBuffer_ReturnsFalse()
    {
        Assert.False(DnsEncodedName.TryParse(ReadOnlySpan<byte>.Empty, 0, out _, out _));
    }
}
