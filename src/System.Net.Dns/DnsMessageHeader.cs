using System.Buffers.Binary;

namespace System.Net;

/// <summary>
/// Represents the fixed 12-byte DNS message header (RFC 1035 §4.1.1).
/// </summary>
public readonly struct DnsMessageHeader
{
    public ushort Id { get; }
    public bool IsResponse { get; }
    public DnsOpCode OpCode { get; }
    public DnsHeaderFlags Flags { get; }
    public DnsResponseCode ResponseCode { get; }
    public ushort QuestionCount { get; }
    public ushort AnswerCount { get; }
    public ushort AuthorityCount { get; }
    public ushort AdditionalCount { get; }

    public DnsMessageHeader(
        ushort id, bool isResponse, DnsOpCode opCode,
        DnsHeaderFlags flags, DnsResponseCode responseCode,
        ushort questionCount, ushort answerCount,
        ushort authorityCount, ushort additionalCount)
    {
        Id = id;
        IsResponse = isResponse;
        OpCode = opCode;
        Flags = flags;
        ResponseCode = responseCode;
        QuestionCount = questionCount;
        AnswerCount = answerCount;
        AuthorityCount = authorityCount;
        AdditionalCount = additionalCount;
    }

    public static DnsMessageHeader CreateStandardQuery(
        ushort id,
        ushort questionCount = 1,
        DnsHeaderFlags flags = DnsHeaderFlags.RecursionDesired)
    {
        return new DnsMessageHeader(
            id, isResponse: false, DnsOpCode.Query,
            flags, DnsResponseCode.NoError,
            questionCount, answerCount: 0,
            authorityCount: 0, additionalCount: 0);
    }

    /// <summary>
    /// Size of the DNS header in bytes.
    /// </summary>
    internal const int Size = 12;

    /// <summary>
    /// Writes this header into the destination buffer in wire format.
    /// </summary>
    internal bool TryWrite(Span<byte> destination)
    {
        if (destination.Length < Size)
        {
            return false;
        }

        BinaryPrimitives.WriteUInt16BigEndian(destination, Id);
        BinaryPrimitives.WriteUInt16BigEndian(destination[2..], EncodeFlagsWord());
        BinaryPrimitives.WriteUInt16BigEndian(destination[4..], QuestionCount);
        BinaryPrimitives.WriteUInt16BigEndian(destination[6..], AnswerCount);
        BinaryPrimitives.WriteUInt16BigEndian(destination[8..], AuthorityCount);
        BinaryPrimitives.WriteUInt16BigEndian(destination[10..], AdditionalCount);
        return true;
    }

    /// <summary>
    /// Reads a header from the source buffer in wire format.
    /// </summary>
    internal static bool TryRead(ReadOnlySpan<byte> source, out DnsMessageHeader header)
    {
        header = default;
        if (source.Length < Size)
        {
            return false;
        }

        ushort id = BinaryPrimitives.ReadUInt16BigEndian(source);
        ushort flagsWord = BinaryPrimitives.ReadUInt16BigEndian(source[2..]);
        ushort qdCount = BinaryPrimitives.ReadUInt16BigEndian(source[4..]);
        ushort anCount = BinaryPrimitives.ReadUInt16BigEndian(source[6..]);
        ushort nsCount = BinaryPrimitives.ReadUInt16BigEndian(source[8..]);
        ushort arCount = BinaryPrimitives.ReadUInt16BigEndian(source[10..]);

        DecodeFlagsWord(flagsWord, out bool isResponse, out DnsOpCode opCode,
            out DnsHeaderFlags flags, out DnsResponseCode responseCode);

        header = new DnsMessageHeader(id, isResponse, opCode, flags, responseCode,
            qdCount, anCount, nsCount, arCount);
        return true;
    }

    // RFC 1035 §4.1.1 wire format of the flags word (bytes 2-3):
    //
    //   Bit:  15 14 13 12 11 10  9  8  7  6  5  4  3  2  1  0
    //         QR |  OpCode | AA TC RD RA  Z AD CD |   RCODE   |
    //
    // QR (1 bit)     - Query/Response
    // OpCode (4 bits) - Operation code
    // AA (1 bit)     - Authoritative Answer
    // TC (1 bit)     - Truncation
    // RD (1 bit)     - Recursion Desired
    // RA (1 bit)     - Recursion Available
    // Z  (1 bit)     - Reserved (must be zero)
    // AD (1 bit)     - Authentic Data (RFC 4035)
    // CD (1 bit)     - Checking Disabled (RFC 4035)
    // RCODE (4 bits) - Response code

    private ushort EncodeFlagsWord()
    {
        ushort word = 0;

        if (IsResponse)
        {
            word |= 1 << 15;
        }

        word |= (ushort)(((int)OpCode & 0xF) << 11);

        if (Flags.HasFlag(DnsHeaderFlags.AuthoritativeAnswer))
        {
            word |= 1 << 10;
        }
        if (Flags.HasFlag(DnsHeaderFlags.Truncation))
        {
            word |= 1 << 9;
        }
        if (Flags.HasFlag(DnsHeaderFlags.RecursionDesired))
        {
            word |= 1 << 8;
        }
        if (Flags.HasFlag(DnsHeaderFlags.RecursionAvailable))
        {
            word |= 1 << 7;
        }
        if (Flags.HasFlag(DnsHeaderFlags.AuthenticData))
        {
            word |= 1 << 5;
        }
        if (Flags.HasFlag(DnsHeaderFlags.CheckingDisabled))
        {
            word |= 1 << 4;
        }

        word |= (ushort)((int)ResponseCode & 0xF);

        return word;
    }

    private static void DecodeFlagsWord(ushort word,
        out bool isResponse, out DnsOpCode opCode,
        out DnsHeaderFlags flags, out DnsResponseCode responseCode)
    {
        isResponse = (word & (1 << 15)) != 0;
        opCode = (DnsOpCode)((word >> 11) & 0xF);
        responseCode = (DnsResponseCode)(word & 0xF);

        flags = DnsHeaderFlags.None;
        if ((word & (1 << 10)) != 0)
        {
            flags |= DnsHeaderFlags.AuthoritativeAnswer;
        }
        if ((word & (1 << 9)) != 0)
        {
            flags |= DnsHeaderFlags.Truncation;
        }
        if ((word & (1 << 8)) != 0)
        {
            flags |= DnsHeaderFlags.RecursionDesired;
        }
        if ((word & (1 << 7)) != 0)
        {
            flags |= DnsHeaderFlags.RecursionAvailable;
        }
        if ((word & (1 << 5)) != 0)
        {
            flags |= DnsHeaderFlags.AuthenticData;
        }
        if ((word & (1 << 4)) != 0)
        {
            flags |= DnsHeaderFlags.CheckingDisabled;
        }
    }
}
