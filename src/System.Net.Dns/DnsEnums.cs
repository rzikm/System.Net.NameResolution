namespace System.Net;

public enum DnsRecordType : ushort
{
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    PTR = 12,
    MX = 15,
    TXT = 16,
    AAAA = 28,
    SRV = 33,
    NAPTR = 35,
    OPT = 41,
    SVCB = 64,
    HTTPS = 65,
}

public enum DnsRecordClass : ushort
{
    Internet = 1,
    Chaos = 3,
    Hesiod = 4,
    Any = 255,
}

public enum DnsResponseCode : ushort
{
    NoError = 0,
    FormatError = 1,
    ServerFailure = 2,
    NameError = 3,        // NXDOMAIN
    NotImplemented = 4,
    Refused = 5,
}

public enum DnsOpCode : byte
{
    Query = 0,
    InverseQuery = 1,
    Status = 2,
    Notify = 4,
    Update = 5,
}

[Flags]
public enum DnsHeaderFlags : ushort
{
    None = 0,
    AuthoritativeAnswer = 1 << 0,  // AA
    Truncation = 1 << 1,           // TC
    RecursionDesired = 1 << 2,     // RD
    RecursionAvailable = 1 << 3,   // RA
    AuthenticData = 1 << 4,        // AD (RFC 4035)
    CheckingDisabled = 1 << 5,     // CD (RFC 4035)
}
