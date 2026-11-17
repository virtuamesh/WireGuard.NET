namespace WireGuard.NET;

/// <summary>
/// Represents the runtime status of a single WireGuard peer.
/// </summary>
public class PeerStatus
{
    /// <summary>Gets or sets the Base64-encoded public key of the peer.</summary>
    public string PublicKey { get; set; } = string.Empty;

    /// <summary>Gets or sets the peer's last known transport endpoint, or <c>null</c> if no endpoint is known.</summary>
    public string? Endpoint { get; set; }

    /// <summary>Gets or sets the time of the last successful handshake with the peer.</summary>
    public DateTime LastHandshake { get; set; }

    /// <summary>Gets or sets the total number of bytes received from the peer.</summary>
    public ulong RxBytes { get; set; }

    /// <summary>Gets or sets the total number of bytes transmitted to the peer.</summary>
    public ulong TxBytes { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether traffic for this peer is currently relayed
    /// through DERP. When <c>true</c>, higher layers may use it as a trigger to verify and
    /// upgrade the connection to a direct path.
    /// </summary>
    public bool IsDerpConnected { get; set; }
}
