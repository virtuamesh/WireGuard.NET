using WireGuard.NET.Protocol.Noise;

namespace WireGuard.NET.Protocol;

/// <summary>
/// Mutable session state for one peer: handshake progress, derived transport keys,
/// session indices and traffic statistics. Instances are owned by
/// <see cref="WireGuardSession"/> and are not internally synchronized — field access
/// is coordinated by the owning session's internal lock.
/// </summary>
public class PeerSession
{
    /// <summary>
    /// The peer's 32-byte X25519 public key this session is keyed to.
    /// </summary>
    public byte[] PublicKey { get; set; } = Array.Empty<byte>();

    /// <summary>
    /// The Noise handshake state while a handshake is in flight; <c>null</c> once the
    /// handshake state has been disposed (after completion) or when the session was
    /// cleared.
    /// </summary>
    public NoiseHandshakeState? HandshakeState { get; set; }

    /// <summary>
    /// The current lifecycle state of the session (handshake progress).
    /// </summary>
    public SessionState State { get; set; }

    /// <summary>
    /// The 32-byte transport send key (ChaCha20Poly1305 key used to encrypt outbound
    /// data packets); <c>null</c> until key derivation completes.
    /// </summary>
    public byte[]? SendKey { get; set; }

    /// <summary>
    /// The 32-byte transport receive key used to decrypt inbound data packets;
    /// <c>null</c> until key derivation completes.
    /// </summary>
    public byte[]? RecvKey { get; set; }

    /// <summary>
    /// Our locally generated 4-byte session index for this handshake.
    /// </summary>
    public uint LocalIndex { get; set; }

    /// <summary>
    /// The peer's 4-byte session index observed in its handshake messages.
    /// </summary>
    public uint RemoteIndex { get; set; }

    /// <summary>
    /// The UTC time the current handshake was created or completed.
    /// </summary>
    public DateTime HandshakeTime { get; set; }

    /// <summary>
    /// Cumulative plaintext bytes received in this session.
    /// </summary>
    public ulong RxBytes { get; set; }

    /// <summary>
    /// Cumulative plaintext bytes sent in this session.
    /// </summary>
    public ulong TxBytes { get; set; }
}
