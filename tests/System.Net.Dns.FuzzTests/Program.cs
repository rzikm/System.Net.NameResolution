using System.Buffers;
using System.Net;
using SharpFuzz;

// Select fuzz target via first argument.
// Usage: dotnet run -- <target>
// Targets: reader, name, writer, roundtrip, generate-seeds

string target = args.Length > 0 ? args[0] : "reader";

switch (target)
{
    case "reader":
        Fuzzer.LibFuzzer.Run(FuzzTargets.Reader);
        break;
    case "name":
        Fuzzer.LibFuzzer.Run(FuzzTargets.Name);
        break;
    case "writer":
        Fuzzer.LibFuzzer.Run(FuzzTargets.Writer);
        break;
    case "roundtrip":
        Fuzzer.LibFuzzer.Run(FuzzTargets.RoundTrip);
        break;
    case "generate-seeds":
        SeedGenerator.Generate();
        break;
    default:
        Console.Error.WriteLine($"Unknown target: {target}");
        Console.Error.WriteLine("Available targets: reader, name, writer, roundtrip, generate-seeds");
        return 1;
}

return 0;

/// <summary>
/// Fuzz target methods for SharpFuzz. Each method takes a ReadOnlySpan&lt;byte&gt;
/// of fuzzer-generated input and exercises the DNS public APIs.
/// The contract: no input should cause an unhandled exception, hang, or
/// out-of-bounds access. All failures must be graceful.
/// </summary>
static class FuzzTargets
{
    /// <summary>
    /// Fuzzes the full DNS message reader pipeline: header, questions,
    /// resource records, and all typed record parsers.
    /// </summary>
    public static void Reader(ReadOnlySpan<byte> data)
    {
        DnsMessageReader reader;
        try
        {
            reader = new DnsMessageReader(data);
        }
        catch (ArgumentException)
        {
            return;
        }

        for (int i = 0; i < reader.Header.QuestionCount && i < 32; i++)
        {
            if (!reader.TryReadQuestion(out DnsQuestion question))
            {
                break;
            }
            // ToString() internally calls GetFormattedLength() + TryDecode()
            question.Name.ToString();
            question.Name.Equals("example.com");
        }

        int totalRecords = reader.Header.AnswerCount +
                           reader.Header.AuthorityCount +
                           reader.Header.AdditionalCount;
        for (int i = 0; i < totalRecords && i < 64; i++)
        {
            if (!reader.TryReadRecord(out DnsRecord record))
            {
                break;
            }

            // Exercise name via public methods
            record.Name.ToString();
            record.Name.Equals("test.example.com");

            // Exercise all typed record parsers
            record.TryParseARecord(out _);
            record.TryParseAAAARecord(out _);
            record.TryParseCNameRecord(out _);
            record.TryParseMxRecord(out _);
            record.TryParseSrvRecord(out _);
            record.TryParseSoaRecord(out _);
            record.TryParseTxtRecord(out _);
            record.TryParsePtrRecord(out _);
            record.TryParseNsRecord(out _);

            // If typed parse succeeded, exercise the parsed data
            if (record.TryParseSrvRecord(out DnsSrvRecordData srv))
            {
                srv.Target.ToString();
            }
            if (record.TryParseSoaRecord(out DnsSoaRecordData soa))
            {
                soa.PrimaryNameServer.ToString();
                soa.ResponsibleMailbox.ToString();
            }
            if (record.TryParseMxRecord(out DnsMxRecordData mx))
            {
                mx.Exchange.ToString();
            }
            if (record.TryParseCNameRecord(out DnsCNameRecordData cname))
            {
                cname.CName.ToString();
            }
            if (record.TryParseTxtRecord(out DnsTxtRecordData txt))
            {
                foreach (ReadOnlySpan<byte> s in txt.EnumerateStrings())
                {
                    _ = s.Length;
                }
            }
        }
    }

    /// <summary>
    /// Fuzzes DnsEncodedName creation from arbitrary strings via TryCreate,
    /// then exercises all public name methods.
    /// </summary>
    public static void Name(ReadOnlySpan<byte> data)
    {
        if (data.Length < 2)
        {
            return;
        }

        byte selector = data[0];
        ReadOnlySpan<byte> payload = data[1..];

        if (selector % 2 == 0)
        {
            // Exercise TryParse: treat payload as wire-format message buffer
            int offset = payload[0] % payload.Length;
            if (DnsEncodedName.TryParse(payload, offset, out DnsEncodedName name, out int bytesConsumed))
            {
                name.ToString();
                name.GetFormattedLength();
                name.Equals("example.com");

                foreach (ReadOnlySpan<byte> label in name.EnumerateLabels())
                {
                    _ = label.Length;
                }
            }
        }
        else
        {
            // Exercise TryCreate: treat payload as characters for name creation
            Span<char> chars = stackalloc char[payload.Length];
            for (int i = 0; i < payload.Length; i++)
            {
                chars[i] = (char)payload[i];
            }

            Span<byte> dest = stackalloc byte[DnsEncodedName.MaxEncodedLength];
            OperationStatus status = DnsEncodedName.TryEncode(chars, dest, out DnsEncodedName name, out int written);

            if (status == OperationStatus.Done && written > 0)
            {
                name.ToString();
                name.GetFormattedLength();
                name.Equals(new string(chars));

                foreach (ReadOnlySpan<byte> label in name.EnumerateLabels())
                {
                    _ = label.Length;
                }

                // Also write the name into a message and read it back
                Span<byte> msgBuf = stackalloc byte[512];
                DnsMessageWriter writer = new DnsMessageWriter(msgBuf);
                writer.TryWriteHeader(DnsMessageHeader.CreateStandardQuery(0x0001));
                writer.TryWriteQuestion(name, DnsRecordType.A);

                if (writer.BytesWritten >= 12)
                {
                    DnsMessageReader reader = new DnsMessageReader(msgBuf[..writer.BytesWritten]);
                    if (reader.TryReadQuestion(out DnsQuestion q))
                    {
                        q.Name.ToString();
                        q.Name.Equals(chars);
                    }
                }
            }
        }
    }

    /// <summary>
    /// Fuzzes DnsMessageWriter with random names and record types.
    /// Input provides the name string and type to write.
    /// </summary>
    public static void Writer(ReadOnlySpan<byte> data)
    {
        if (data.Length < 3)
        {
            return;
        }

        // First 2 bytes = record type, rest = name
        ushort type = (ushort)(data[0] << 8 | data[1]);
        ReadOnlySpan<byte> nameBytes = data[2..];

        Span<char> nameChars = new char[nameBytes.Length];
        for (int i = 0; i < nameBytes.Length; i++)
        {
            nameChars[i] = (char)nameBytes[i];
        }

        Span<byte> nameBuf = new byte[DnsEncodedName.MaxEncodedLength];
        OperationStatus status = DnsEncodedName.TryEncode(nameChars, nameBuf, out DnsEncodedName encodedName, out _);
        if (status != OperationStatus.Done)
        {
            return;
        }

        // Write into various buffer sizes to test boundary conditions
        for (int size = 0; size <= 512; size += 64)
        {
            Span<byte> writeDest = new byte[size];
            DnsMessageWriter writer = new DnsMessageWriter(writeDest);
            writer.TryWriteHeader(DnsMessageHeader.CreateStandardQuery(0x1234));
            writer.TryWriteQuestion(encodedName, (DnsRecordType)type);
        }

        // Full-size write and read back
        Span<byte> fullDest = new byte[512];
        DnsMessageWriter fullWriter = new DnsMessageWriter(fullDest);
        if (fullWriter.TryWriteHeader(DnsMessageHeader.CreateStandardQuery(0x5678)) &&
            fullWriter.TryWriteQuestion(encodedName, (DnsRecordType)type))
        {
            try
            {
                DnsMessageReader reader = new DnsMessageReader(fullDest[..fullWriter.BytesWritten]);
                reader.TryReadQuestion(out _);
            }
            catch (ArgumentException)
            {
                // Expected for very short output
            }
        }
    }

    /// <summary>
    /// Fuzzes a write-then-read round-trip: creates a query from fuzzer input,
    /// then parses the written bytes back through the reader and verifies consistency.
    /// </summary>
    public static void RoundTrip(ReadOnlySpan<byte> data)
    {
        if (data.Length < 3)
        {
            return;
        }

        ushort id = (ushort)(data[0] << 8 | data[1]);
        ReadOnlySpan<byte> nameBytes = data[2..];

        Span<char> nameChars = stackalloc char[nameBytes.Length];
        for (int i = 0; i < nameBytes.Length; i++)
        {
            nameChars[i] = (char)nameBytes[i];
        }

        Span<byte> nameBuf = stackalloc byte[DnsEncodedName.MaxEncodedLength];
        OperationStatus status = DnsEncodedName.TryEncode(nameChars, nameBuf, out DnsEncodedName encodedName, out _);
        if (status != OperationStatus.Done)
        {
            return;
        }

        // Write a query
        Span<byte> msgBuf = stackalloc byte[512];
        DnsMessageWriter writer = new DnsMessageWriter(msgBuf);
        if (!writer.TryWriteHeader(DnsMessageHeader.CreateStandardQuery(id)))
        {
            return;
        }
        if (!writer.TryWriteQuestion(encodedName, DnsRecordType.A))
        {
            return;
        }

        // Read it back
        ReadOnlySpan<byte> written = msgBuf[..writer.BytesWritten];
        DnsMessageReader reader = new DnsMessageReader(written);

        if (reader.Header.Id != id)
        {
            throw new Exception($"Round-trip ID mismatch: wrote {id}, read {reader.Header.Id}");
        }

        if (reader.TryReadQuestion(out DnsQuestion question))
        {
            // Compare via ToString() to normalize (TryCreate strips trailing dots)
            string writtenName = encodedName.ToString();
            string readName = question.Name.ToString();
            if (!writtenName.Equals(readName, StringComparison.OrdinalIgnoreCase))
            {
                throw new Exception($"Round-trip name mismatch: wrote '{writtenName}', read '{readName}'");
            }
            if (question.Type != DnsRecordType.A)
            {
                throw new Exception("Round-trip type mismatch");
            }
        }
        else
        {
            throw new Exception("Failed to read back written question");
        }
    }
}

static class SeedGenerator
{
    public static void Generate()
    {
        string corpusDir = Path.Combine(AppContext.BaseDirectory, "..", "..", "corpus");

        GenerateReaderSeeds(Path.Combine(corpusDir, "reader"));
        GenerateNameSeeds(Path.Combine(corpusDir, "name"));
        GenerateWriterSeeds(Path.Combine(corpusDir, "writer"));
        GenerateRoundTripSeeds(Path.Combine(corpusDir, "roundtrip"));

        Console.WriteLine($"Seeds generated in {Path.GetFullPath(corpusDir)}");
    }

    private static void GenerateReaderSeeds(string dir)
    {
        WriteFile(dir, "a_response.bin", BuildResponse("example.com", 1, [10, 0, 0, 1]));
        WriteFile(dir, "nxdomain.bin", BuildErrorResponse("missing.test", 1, 3));

        // Minimal valid 12-byte response header
        byte[] minResponse = new byte[12];
        minResponse[2] = 0x80;
        WriteFile(dir, "minimal_response.bin", minResponse);
    }

    private static void GenerateNameSeeds(string dir)
    {
        WriteFile(dir, "simple.bin", "example.com"u8.ToArray());
        WriteFile(dir, "subdomain.bin", "www.example.com"u8.ToArray());
        WriteFile(dir, "root.bin", "."u8.ToArray());
        WriteFile(dir, "trailing_dot.bin", "example.com."u8.ToArray());
        WriteFile(dir, "long_labels.bin",
            "abcdefghijklmnopqrstuvwxyz.abcdefghijklmnopqrstuvwxyz.example.com"u8.ToArray());
    }

    private static void GenerateWriterSeeds(string dir)
    {
        // Type A (0x0001) + "test.com"
        byte[] seed = new byte[2 + "test.com"u8.Length];
        seed[0] = 0; seed[1] = 1;
        "test.com"u8.CopyTo(seed.AsSpan(2));
        WriteFile(dir, "a_query.bin", seed);

        // Type AAAA (0x001C) + "ipv6.example.com"
        byte[] seed2 = new byte[2 + "ipv6.example.com"u8.Length];
        seed2[0] = 0; seed2[1] = 28;
        "ipv6.example.com"u8.CopyTo(seed2.AsSpan(2));
        WriteFile(dir, "aaaa_query.bin", seed2);
    }

    private static void GenerateRoundTripSeeds(string dir)
    {
        // ID + name
        byte[] seed = new byte[2 + "example.com"u8.Length];
        seed[0] = 0x12; seed[1] = 0x34;
        "example.com"u8.CopyTo(seed.AsSpan(2));
        WriteFile(dir, "example.bin", seed);

        byte[] seed2 = new byte[2 + "test"u8.Length];
        seed2[0] = 0xAB; seed2[1] = 0xCD;
        "test"u8.CopyTo(seed2.AsSpan(2));
        WriteFile(dir, "single_label.bin", seed2);
    }

    private static byte[] BuildResponse(string name, ushort type, byte[] rdata)
    {
        using MemoryStream ms = new();
        W16(ms, 0x1234); W16(ms, 0x8180);
        W16(ms, 1); W16(ms, 1); W16(ms, 0); W16(ms, 0);
        ms.Write(EncodeName(name));
        W16(ms, type); W16(ms, 1);
        ms.Write([0xC0, 0x0C]);
        W16(ms, type); W16(ms, 1);
        W16(ms, 0); W16(ms, 300);
        W16(ms, (ushort)rdata.Length);
        ms.Write(rdata);
        return ms.ToArray();
    }

    private static byte[] BuildErrorResponse(string name, ushort type, ushort rcode)
    {
        using MemoryStream ms = new();
        W16(ms, 0x1234); W16(ms, (ushort)(0x8180 | rcode));
        W16(ms, 1); W16(ms, 0); W16(ms, 0); W16(ms, 0);
        ms.Write(EncodeName(name));
        W16(ms, type); W16(ms, 1);
        return ms.ToArray();
    }

    private static byte[] EncodeName(string name)
    {
        Span<byte> buf = stackalloc byte[DnsEncodedName.MaxEncodedLength];
        DnsEncodedName.TryEncode(name, buf, out _, out int written);
        return buf[..written].ToArray();
    }

    private static void W16(MemoryStream ms, ushort v)
    {
        ms.WriteByte((byte)(v >> 8));
        ms.WriteByte((byte)(v & 0xFF));
    }

    private static void WriteFile(string dir, string name, byte[] data)
    {
        Directory.CreateDirectory(dir);
        File.WriteAllBytes(Path.Combine(dir, name), data);
    }
}
