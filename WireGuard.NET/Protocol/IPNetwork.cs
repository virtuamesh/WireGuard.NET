using System.Net;

namespace WireGuard.NET.Protocol;

/// <summary>
/// An IPv4 or IPv6 network in CIDR notation; the element type of a peer's
/// AllowedIPs list.
/// </summary>
public class IPNetwork
{
    /// <summary>
    /// The network (base) address of the range.
    /// </summary>
    public IPAddress Address { get; set; } = IPAddress.None;

    /// <summary>
    /// The CIDR prefix length of the range: 0–32 for IPv4 networks, 0–128 for IPv6.
    /// </summary>
    public int PrefixLength { get; set; }
}
