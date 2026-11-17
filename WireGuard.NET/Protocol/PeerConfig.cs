using System.Net;

namespace WireGuard.NET.Protocol;

/// <summary>
/// Static configuration for a single WireGuard peer — the local node's view of one
/// remote tunnel participant.
/// </summary>
public class PeerConfig
{
    /// <summary>
    /// The peer's 32-byte X25519 public key that identifies it for handshakes.
    /// </summary>
    public byte[] PublicKey { get; set; } = Array.Empty<byte>();

    /// <summary>
    /// Optional 32-byte preshared key (PSK) mixed into the Noise handshake for extra
    /// hardening; <c>null</c> when this peer uses no PSK.
    /// </summary>
    public byte[]? PresharedKey { get; set; }

    /// <summary>
    /// The CIDR networks routed to this peer (AllowedIPs). Packets whose destination
    /// address falls inside one of these networks are sent to this peer.
    /// </summary>
    public List<IPNetwork> AllowedIPs { get; set; } = [];

    /// <summary>
    /// The peer's UDP endpoint (address and port) used to initiate handshakes;
    /// <c>null</c> when the endpoint is learned dynamically (e.g. a roaming peer
    /// that initiates contact itself).
    /// </summary>
    public IPEndPoint? Endpoint { get; set; }

    /// <summary>
    /// Persistent keepalive interval in seconds. When greater than zero, an empty
    /// transport data packet is sent at this interval to keep NAT mappings alive.
    /// Zero (the default) disables keepalives.
    /// </summary>
    public int PersistentKeepalive { get; set; } = 0;
}
