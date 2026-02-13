namespace System.Net;

public class DnsResolverOptions
{
    /// <summary>
    /// DNS servers to query. If empty, uses system-configured servers.
    /// </summary>
    public IList<IPEndPoint> Servers { get; set; } = new List<IPEndPoint>();

    /// <summary>
    /// Maximum number of retry attempts per server.
    /// NOTE: Subject to open design question — may not be honored on all platforms.
    /// </summary>
    public int MaxRetries { get; set; } = 2;

    /// <summary>
    /// Timeout per individual query attempt.
    /// NOTE: Subject to open design question — may not be honored on all platforms.
    /// </summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(3);

    /// <summary>
    /// Whether to check the hosts file before querying DNS.
    /// </summary>
    public bool UseHostsFile { get; set; } = true;
}
