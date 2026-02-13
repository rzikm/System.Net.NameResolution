using System.Buffers;
using System.Net;
using System.Text;

namespace System.Net.Dns.Tests;

public class DnsNameTests
{
    [Theory]
    [InlineData("example.com", new byte[] { 7, (byte)'e', (byte)'x', (byte)'a', (byte)'m', (byte)'p', (byte)'l', (byte)'e', 3, (byte)'c', (byte)'o', (byte)'m', 0 })]
    [InlineData("a.b", new byte[] { 1, (byte)'a', 1, (byte)'b', 0 })]
    public void TryCreate_ValidName_ProducesExpectedBytes(string name, byte[] expected)
    {
        Span<byte> buffer = stackalloc byte[DnsName.MaxEncodedLength];
        var status = DnsName.TryCreate(name, buffer, out _, out int bytesWritten);

        Assert.Equal(OperationStatus.Done, status);
        Assert.Equal(expected.Length, bytesWritten);
        Assert.True(buffer[..bytesWritten].SequenceEqual(expected));
    }

    [Theory]
    [InlineData("")]    // empty → root
    [InlineData(".")]   // explicit root
    public void TryCreate_Root_ProducesSingleZeroByte(string name)
    {
        Span<byte> buffer = stackalloc byte[DnsName.MaxEncodedLength];
        var status = DnsName.TryCreate(name, buffer, out _, out int bytesWritten);

        Assert.Equal(OperationStatus.Done, status);
        Assert.Equal(1, bytesWritten);
        Assert.Equal(0, buffer[0]);
    }

    [Fact]
    public void TryCreate_TrailingDot_SameAsWithout()
    {
        Span<byte> buf1 = stackalloc byte[DnsName.MaxEncodedLength];
        Span<byte> buf2 = stackalloc byte[DnsName.MaxEncodedLength];

        DnsName.TryCreate("example.com", buf1, out _, out int len1);
        DnsName.TryCreate("example.com.", buf2, out _, out int len2);

        Assert.Equal(len1, len2);
        Assert.True(buf1[..len1].SequenceEqual(buf2[..len2]));
    }

    [Fact]
    public void TryCreate_LabelTooLong_ReturnsInvalidData()
    {
        string longLabel = new string('a', 64) + ".com"; // 64 > 63 max
        Span<byte> buffer = stackalloc byte[DnsName.MaxEncodedLength];
        var status = DnsName.TryCreate(longLabel, buffer, out _, out _);
        Assert.Equal(OperationStatus.InvalidData, status);
    }

    [Fact]
    public void TryCreate_MaxLengthLabel_Succeeds()
    {
        string maxLabel = new string('a', 63) + ".com";
        Span<byte> buffer = stackalloc byte[DnsName.MaxEncodedLength];
        var status = DnsName.TryCreate(maxLabel, buffer, out _, out _);
        Assert.Equal(OperationStatus.Done, status);
    }

    [Fact]
    public void TryCreate_ConsecutiveDots_ReturnsInvalidData()
    {
        Span<byte> buffer = stackalloc byte[DnsName.MaxEncodedLength];
        var status = DnsName.TryCreate("example..com", buffer, out _, out _);
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
        var status = DnsName.TryCreate(name, buffer, out _, out _);
        Assert.Equal(OperationStatus.InvalidData, status);
    }

    [Fact]
    public void TryCreate_DestinationTooSmall_ReturnsDestinationTooSmall()
    {
        Span<byte> buffer = stackalloc byte[5]; // too small for "example.com"
        var status = DnsName.TryCreate("example.com", buffer, out _, out _);
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
        Span<byte> buffer = stackalloc byte[DnsName.MaxEncodedLength];
        DnsName.TryCreate(create, buffer, out var name, out _);
        Assert.Equal(expected, name.Equals(compare));
    }

    [Fact]
    public void TryFormat_ProducesDottedString()
    {
        Span<byte> nameBuffer = stackalloc byte[DnsName.MaxEncodedLength];
        DnsName.TryCreate("example.com", nameBuffer, out var name, out _);

        Span<char> chars = stackalloc char[64];
        Assert.True(name.TryFormat(chars, out int written));
        Assert.Equal("example.com", new string(chars[..written]));
    }

    [Fact]
    public void TryFormat_Root_ProducesEmptyString()
    {
        Span<byte> nameBuffer = stackalloc byte[DnsName.MaxEncodedLength];
        DnsName.TryCreate(".", nameBuffer, out var name, out _);

        Span<char> chars = stackalloc char[64];
        Assert.True(name.TryFormat(chars, out int written));
        Assert.Equal(0, written);
    }

    [Fact]
    public void TryFormat_DestinationTooSmall_ReturnsFalse()
    {
        Span<byte> nameBuffer = stackalloc byte[DnsName.MaxEncodedLength];
        DnsName.TryCreate("example.com", nameBuffer, out var name, out _);

        Span<char> chars = stackalloc char[5]; // too small
        Assert.False(name.TryFormat(chars, out _));
    }

    [Fact]
    public void GetFormattedLength_ReturnsCorrectLength()
    {
        Span<byte> nameBuffer = stackalloc byte[DnsName.MaxEncodedLength];
        DnsName.TryCreate("example.com", nameBuffer, out var name, out _);
        Assert.Equal("example.com".Length, name.GetFormattedLength());
    }

    [Fact]
    public void ToString_ReturnsFormattedName()
    {
        Span<byte> nameBuffer = stackalloc byte[DnsName.MaxEncodedLength];
        DnsName.TryCreate("example.com", nameBuffer, out var name, out _);
        Assert.Equal("example.com", name.ToString());
    }

    [Fact]
    public void ToString_Root_ReturnsDot()
    {
        Span<byte> nameBuffer = stackalloc byte[DnsName.MaxEncodedLength];
        DnsName.TryCreate(".", nameBuffer, out var name, out _);
        Assert.Equal(".", name.ToString());
    }

    [Fact]
    public void EnumerateLabels_ReturnsAllLabels()
    {
        Span<byte> nameBuffer = stackalloc byte[DnsName.MaxEncodedLength];
        DnsName.TryCreate("a.bb.ccc", nameBuffer, out var name, out _);

        var labels = new List<string>();
        foreach (var label in name.EnumerateLabels())
            labels.Add(Encoding.ASCII.GetString(label));

        Assert.Equal(["a", "bb", "ccc"], labels);
    }

    [Fact]
    public void EnumerateLabels_Root_ReturnsNoLabels()
    {
        Span<byte> nameBuffer = stackalloc byte[DnsName.MaxEncodedLength];
        DnsName.TryCreate(".", nameBuffer, out var name, out _);

        var labels = new List<string>();
        foreach (var label in name.EnumerateLabels())
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

        var name = new DnsName(message, 13);
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

        var name = new DnsName(message, 5);
        Assert.True(name.Equals("foo.com"));
    }

    [Fact]
    public void GetWireLength_FlatName()
    {
        Span<byte> buffer = stackalloc byte[DnsName.MaxEncodedLength];
        DnsName.TryCreate("example.com", buffer, out var name, out int bytesWritten);
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

        var name = new DnsName(message, 13);
        Assert.Equal(6, name.GetWireLength());
    }
}
