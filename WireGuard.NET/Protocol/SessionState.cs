namespace WireGuard.NET.Protocol;

/// <summary>
/// Lifecycle state of a peer's handshake/transport session.
/// </summary>
public enum SessionState
{
    /// <summary>
    /// No handshake in progress; the session carries no usable keys.
    /// </summary>
    Idle,

    /// <summary>
    /// We created and sent a handshake initiation and are awaiting the peer's response.
    /// </summary>
    Initiating,

    /// <summary>
    /// We processed the peer's initiation and sent our response; transport keys are
    /// derived and await confirmation by first data traffic.
    /// </summary>
    Responding,

    /// <summary>
    /// The handshake completed on both sides; transport data packets can be exchanged.
    /// </summary>
    Established
}
