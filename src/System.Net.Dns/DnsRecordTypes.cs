using System.Buffers.Binary;
using System.Net.Sockets;

namespace System.Net;

// --- Typed record data readonly ref structs ---

public readonly ref struct DnsARecordData
{
    public ReadOnlySpan<byte> AddressBytes { get; }

    internal DnsARecordData(ReadOnlySpan<byte> addressBytes)
    {
        AddressBytes = addressBytes;
    }

    public IPAddress ToIPAddress() => new IPAddress(AddressBytes);
}

public readonly ref struct DnsAAAARecordData
{
    public ReadOnlySpan<byte> AddressBytes { get; }

    internal DnsAAAARecordData(ReadOnlySpan<byte> addressBytes)
    {
        AddressBytes = addressBytes;
    }

    public IPAddress ToIPAddress() => new IPAddress(AddressBytes);
}

public readonly ref struct DnsCNameRecordData
{
    public DnsName CName { get; }

    internal DnsCNameRecordData(DnsName cname)
    {
        CName = cname;
    }
}

public readonly ref struct DnsMxRecordData
{
    public ushort Preference { get; }
    public DnsName Exchange { get; }

    internal DnsMxRecordData(ushort preference, DnsName exchange)
    {
        Preference = preference;
        Exchange = exchange;
    }
}

public readonly ref struct DnsSrvRecordData
{
    public ushort Priority { get; }
    public ushort Weight { get; }
    public ushort Port { get; }
    public DnsName Target { get; }

    internal DnsSrvRecordData(ushort priority, ushort weight, ushort port, DnsName target)
    {
        Priority = priority;
        Weight = weight;
        Port = port;
        Target = target;
    }
}

public readonly ref struct DnsSoaRecordData
{
    public DnsName PrimaryNameServer { get; }
    public DnsName ResponsibleMailbox { get; }
    public uint SerialNumber { get; }
    public uint RefreshInterval { get; }
    public uint RetryInterval { get; }
    public uint ExpireLimit { get; }
    public uint MinimumTtl { get; }

    internal DnsSoaRecordData(DnsName primaryNameServer, DnsName responsibleMailbox,
        uint serialNumber, uint refreshInterval, uint retryInterval,
        uint expireLimit, uint minimumTtl)
    {
        PrimaryNameServer = primaryNameServer;
        ResponsibleMailbox = responsibleMailbox;
        SerialNumber = serialNumber;
        RefreshInterval = refreshInterval;
        RetryInterval = retryInterval;
        ExpireLimit = expireLimit;
        MinimumTtl = minimumTtl;
    }
}

public readonly ref struct DnsTxtRecordData
{
    private readonly ReadOnlySpan<byte> _data;

    internal DnsTxtRecordData(ReadOnlySpan<byte> data)
    {
        _data = data;
    }

    public DnsTxtEnumerator EnumerateStrings() => new DnsTxtEnumerator(_data);
}

public ref struct DnsTxtEnumerator
{
    private ReadOnlySpan<byte> _remaining;
    private ReadOnlySpan<byte> _current;

    internal DnsTxtEnumerator(ReadOnlySpan<byte> data)
    {
        _remaining = data;
        _current = default;
    }

    public ReadOnlySpan<byte> Current => _current;

    public bool MoveNext()
    {
        if (_remaining.Length == 0)
            return false;

        int len = _remaining[0];
        if (1 + len > _remaining.Length)
            return false;

        _current = _remaining.Slice(1, len);
        _remaining = _remaining[(1 + len)..];
        return true;
    }

    public DnsTxtEnumerator GetEnumerator() => this;
}

public readonly ref struct DnsPtrRecordData
{
    public DnsName Name { get; }

    internal DnsPtrRecordData(DnsName name)
    {
        Name = name;
    }
}

public readonly ref struct DnsNsRecordData
{
    public DnsName Name { get; }

    internal DnsNsRecordData(DnsName name)
    {
        Name = name;
    }
}

// --- Extension methods ---

public static class DnsRecordExtensions
{
    public static bool TryParseARecord(this DnsRecord record, out DnsARecordData result)
    {
        result = default;
        if (record.Type != DnsRecordType.A || record.Data.Length != 4)
            return false;
        result = new DnsARecordData(record.Data);
        return true;
    }

    public static bool TryParseAAAARecord(this DnsRecord record, out DnsAAAARecordData result)
    {
        result = default;
        if (record.Type != DnsRecordType.AAAA || record.Data.Length != 16)
            return false;
        result = new DnsAAAARecordData(record.Data);
        return true;
    }

    public static bool TryParseCNameRecord(this DnsRecord record, out DnsCNameRecordData result)
    {
        result = default;
        if (record.Type != DnsRecordType.CNAME || record.Data.Length == 0)
            return false;
        result = new DnsCNameRecordData(new DnsName(record.Message, record.DataOffset));
        return true;
    }

    public static bool TryParseMxRecord(this DnsRecord record, out DnsMxRecordData result)
    {
        result = default;
        if (record.Type != DnsRecordType.MX || record.Data.Length < 3)
            return false;
        ushort preference = BinaryPrimitives.ReadUInt16BigEndian(record.Data);
        var exchange = new DnsName(record.Message, record.DataOffset + 2);
        result = new DnsMxRecordData(preference, exchange);
        return true;
    }

    public static bool TryParseSrvRecord(this DnsRecord record, out DnsSrvRecordData result)
    {
        result = default;
        if (record.Type != DnsRecordType.SRV || record.Data.Length < 7)
            return false;
        ushort priority = BinaryPrimitives.ReadUInt16BigEndian(record.Data);
        ushort weight = BinaryPrimitives.ReadUInt16BigEndian(record.Data[2..]);
        ushort port = BinaryPrimitives.ReadUInt16BigEndian(record.Data[4..]);
        var target = new DnsName(record.Message, record.DataOffset + 6);
        result = new DnsSrvRecordData(priority, weight, port, target);
        return true;
    }

    public static bool TryParseSoaRecord(this DnsRecord record, out DnsSoaRecordData result)
    {
        result = default;
        if (record.Type != DnsRecordType.SOA || record.Data.Length < 22)
            return false;

        var mname = new DnsName(record.Message, record.DataOffset);
        int mnameLen = mname.GetWireLength();

        int rnameOffset = record.DataOffset + mnameLen;
        if (rnameOffset >= record.Message.Length)
            return false;
        var rname = new DnsName(record.Message, rnameOffset);
        int rnameLen = rname.GetWireLength();

        int fixedStart = rnameOffset + rnameLen - record.DataOffset;
        if (fixedStart + 20 > record.Data.Length)
            return false;

        var fixedData = record.Data[fixedStart..];
        result = new DnsSoaRecordData(mname, rname,
            BinaryPrimitives.ReadUInt32BigEndian(fixedData),
            BinaryPrimitives.ReadUInt32BigEndian(fixedData[4..]),
            BinaryPrimitives.ReadUInt32BigEndian(fixedData[8..]),
            BinaryPrimitives.ReadUInt32BigEndian(fixedData[12..]),
            BinaryPrimitives.ReadUInt32BigEndian(fixedData[16..]));
        return true;
    }

    public static bool TryParseTxtRecord(this DnsRecord record, out DnsTxtRecordData result)
    {
        result = default;
        if (record.Type != DnsRecordType.TXT || record.Data.Length == 0)
            return false;
        result = new DnsTxtRecordData(record.Data);
        return true;
    }

    public static bool TryParsePtrRecord(this DnsRecord record, out DnsPtrRecordData result)
    {
        result = default;
        if (record.Type != DnsRecordType.PTR || record.Data.Length == 0)
            return false;
        result = new DnsPtrRecordData(new DnsName(record.Message, record.DataOffset));
        return true;
    }

    public static bool TryParseNsRecord(this DnsRecord record, out DnsNsRecordData result)
    {
        result = default;
        if (record.Type != DnsRecordType.NS || record.Data.Length == 0)
            return false;
        result = new DnsNsRecordData(new DnsName(record.Message, record.DataOffset));
        return true;
    }
}
