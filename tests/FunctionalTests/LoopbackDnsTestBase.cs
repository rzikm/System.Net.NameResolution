// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Globalization;
using System.Text;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using Xunit.Abstractions;

namespace System.Net.NameResolution.Resolver.Tests;

public abstract class LoopbackDnsTestBase : IDisposable
{
    protected readonly ITestOutputHelper Output;

    internal LoopbackDnsServer DnsServer { get; }
    private readonly Lazy<DnsResolver> _resolverLazy;
    internal DnsResolver Resolver => _resolverLazy.Value;
    internal DnsResolverOptions Options { get; }
    protected readonly FakeTimeProvider TimeProvider;

    public LoopbackDnsTestBase(ITestOutputHelper output)
    {
        Output = output;
        DnsServer = new();
        TimeProvider = new();
        Options = new()
        {
            Servers = [DnsServer.DnsEndPoint],
            Timeout = TimeSpan.FromSeconds(5),
            MaxAttempts = 1,
        };
        _resolverLazy = new(InitializeResolver);
    }

    DnsResolver InitializeResolver()
    {
        var resolver = new DnsResolver(TimeProvider, NullLogger<DnsResolver>.Instance, Options);
        return resolver;
    }

    public void Dispose()
    {
        DnsServer.Dispose();
    }
}
