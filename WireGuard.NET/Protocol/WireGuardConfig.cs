using System.Net;

namespace WireGuard.NET.Protocol;

/// <summary>
/// Static configuration for a WireGuard interface: the local node's private key,
/// tunnel addressing and the list of configured peers.
/// </summary>
public class WireGuardConfig
{
    /// <summary>
    /// The local node's 32-byte X25519 private key used for all handshakes.
    /// </summary>
    public byte[] PrivateKey { get; set; } = Array.Empty<byte>();

    /// <summary>
    /// The public key corresponding to <see cref="PrivateKey"/> when already known;
    /// <c>null</c> otherwise (the handshake layer derives it from the private key
    /// itself).
    /// </summary>
    public byte[]? PublicKey { get; set; }

    /// <summary>
    /// The local UDP port the WireGuard socket listens on; 0 (the default) lets the
    /// operating system choose an ephemeral port.
    /// </summary>
    public int ListenPort { get; set; } = 0;

    /// <summary>
    /// The MTU of the tunnel interface. The default (1420) leaves headroom for the
    /// outer IPv4 + UDP + WireGuard headers so tunneled packets are not fragmented.
    /// </summary>
    public int Mtu { get; set; } = 1420;

    /// <summary>
    /// The tunnel's IPv4 address; <c>null</c> when IPv4 is not used.
    /// </summary>
    public IPAddress? Address { get; set; }

    /// <summary>
    /// The CIDR prefix length of the IPv4 address (the network mask); the default is
    /// a single-host /32.
    /// </summary>
    public int AddressPrefixLength { get; set; } = 32;

    /// <summary>
    /// The tunnel's IPv6 address; <c>null</c> when IPv6 is not used.
    /// </summary>
    public IPAddress? AddressV6 { get; set; }

    /// <summary>
    /// The CIDR prefix length of the IPv6 address; the default is /64.
    /// </summary>
    public int AddressV6PrefixLength { get; set; } = 64;

    /// <summary>
    /// The peers configured on this interface.
    /// </summary>
    public List<PeerConfig> Peers { get; set; } = [];
}
