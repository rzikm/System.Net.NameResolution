// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace System.Net.NameResolution.Resolver;

public struct DnsResourceRecord
{
    public EncodedDomainName Name { get; }
    public QueryType Type { get; }
    public QueryClass Class { get; }
    public int Ttl { get; }
    public ReadOnlyMemory<byte> Data { get; }

    public DnsResourceRecord(EncodedDomainName name, QueryType type, QueryClass @class, int ttl, ReadOnlyMemory<byte> data)
    {
        Name = name;
        Type = type;
        Class = @class;
        Ttl = ttl;
        Data = data;
    }
}
