namespace WireGuard.NET;

/// <summary>
/// Represents a point-in-time snapshot of a WireGuard device's runtime state,
/// including its running state, identity, listen port, and per-peer status.
/// </summary>
public class DeviceStatus
{
    /// <summary>Gets or sets a value indicating whether the device is currently running.</summary>
    public bool IsRunning { get; set; }

    /// <summary>Gets or sets the Base64-encoded public key of the device.</summary>
    public string PublicKey { get; set; } = string.Empty;

    /// <summary>Gets or sets the local UDP port the device is bound to.</summary>
    public int ListenPort { get; set; }

    /// <summary>Gets or sets the runtime status of every configured peer.</summary>
    public List<PeerStatus> Peers { get; set; } = [];
}
