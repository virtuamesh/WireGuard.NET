using System.Net;
using WireGuard.NET.Protocol.Noise;

namespace WireGuard.NET.Protocol;

/// <summary>
/// Tracks the handshake and session lifecycle for all peers of one interface: it owns
/// the <see cref="WireGuardHandshake"/> engine built from the local private key and
/// maps each peer's 32-byte public key to its <see cref="PeerSession"/>, with an
/// additional lookup by local session index.
/// All members are thread-safe: a single internal lock guards the session dictionary
/// and every mutation applied to the stored sessions.
/// </summary>
public class WireGuardSession
{
    private static readonly ByteArrayComparer _comparer = new();
    private readonly WireGuardConfig _config;
    private readonly WireGuardHandshake _handshake;
    private readonly Dictionary<byte[], PeerSession> _peerSessions = new(_comparer);
    private readonly object _lock = new();

    /// <summary>
    /// Creates the session manager for the given configuration. The local private key
    /// (<paramref name="config"/>.PrivateKey, 32 bytes) is used for all handshakes.
    /// </summary>
    /// <param name="config">The interface configuration carrying the local private key.</param>
    public WireGuardSession(WireGuardConfig config)
    {
        _config = config;
        _handshake = new WireGuardHandshake(config.PrivateKey);
    }

    /// <summary>
    /// Builds a handshake initiation message for the given peer and records a pending
    /// <see cref="PeerSession"/> in the <see cref="SessionState.Initiating"/> state.
    /// </summary>
    /// <param name="peerPublicKey">The peer's 32-byte X25519 public key.</param>
    /// <returns>
    /// A tuple of:
    /// <c>message</c> — the 148-byte initiation message ready to send (header + Noise
    /// payload + MAC1 + MAC2);
    /// <c>handshakeState</c> — the Noise state that must be passed to
    /// <see cref="ProcessResponse"/> when the peer replies;
    /// <c>localIndex</c> — the random 31-bit session index generated for this handshake.
    /// </returns>
    public (byte[] message, NoiseHandshakeState handshakeState, uint localIndex) CreateInitiation(byte[] peerPublicKey)
    {
        var (message, state, localIndex) = _handshake.CreateInitiation(peerPublicKey);

        lock (_lock)
        {
            _peerSessions[peerPublicKey] = new PeerSession
            {
                PublicKey = peerPublicKey,
                HandshakeState = state,
                LocalIndex = localIndex,
                State = SessionState.Initiating
            };
        }

        return (message, state, localIndex);
    }

    /// <summary>
    /// Processes an inbound handshake initiation as the responder: authenticates it
    /// against the known peer public keys, creates the response message, derives the
    /// transport keys and records a <see cref="PeerSession"/> in the
    /// <see cref="SessionState.Responding"/> state.
    /// </summary>
    /// <param name="message">The raw 148-byte initiation message (WireGuard type 1).</param>
    /// <param name="knownPeerPublicKeys">
    /// Candidate peer public keys (32 bytes each) used to identify the initiator;
    /// required by the Noise_IKpsk2 responder, which tries each candidate until one
    /// authenticates.
    /// </param>
    /// <returns>
    /// A tuple of:
    /// <c>response</c> — the 92-byte response message to send back;
    /// <c>senderIndex</c> — the initiator's session index;
    /// <c>localIndex</c> — our freshly generated session index;
    /// <c>peerPublicKey</c> — the matched initiator's public key (non-null on success);
    /// <c>state</c> — the Noise handshake state of the matched peer;
    /// <c>sendKey</c> / <c>recvKey</c> — the derived 32-byte transport keys.
    /// </returns>
    /// <exception cref="System.Security.Cryptography.CryptographicException">
    /// Thrown by the handshake layer when MAC1 validation fails or no known peer
    /// authenticates; in that case no session is recorded.
    /// </exception>
    public (byte[] response, uint senderIndex, uint localIndex, byte[] peerPublicKey, NoiseHandshakeState state, byte[] sendKey, byte[] recvKey) ProcessInitiation(byte[] message, IEnumerable<byte[]>? knownPeerPublicKeys = null)
    {
        var (state, senderIndex, peerPublicKey, response, localIndex, sendKey, recvKey) = _handshake.ProcessInitiation(message, knownPeerPublicKeys);

        lock (_lock)
        {
            if (peerPublicKey != null)
            {
                _peerSessions[peerPublicKey] = new PeerSession
                {
                    PublicKey = peerPublicKey,
                    HandshakeState = state,
                    LocalIndex = localIndex,
                    RemoteIndex = senderIndex,
                    SendKey = sendKey,
                    RecvKey = recvKey,
                    State = SessionState.Responding,
                    HandshakeTime = DateTime.UtcNow
                };
            }
        }

        return (response, senderIndex, localIndex, peerPublicKey!, state, sendKey, recvKey);
    }

    /// <summary>
    /// Processes an inbound handshake response as the initiator, completing the
    /// handshake: derives the transport keys and promotes the peer's pending session to
    /// <see cref="SessionState.Established"/>. The derived keys are returned even when
    /// no pending session exists for the peer (in which case no state is updated).
    /// </summary>
    /// <param name="peerPublicKey">The peer's 32-byte public key whose pending session to complete.</param>
    /// <param name="message">The raw 92-byte response message (WireGuard type 2).</param>
    /// <param name="handshakeState">The Noise state returned by <see cref="CreateInitiation"/>.</param>
    /// <returns>
    /// A tuple of:
    /// <c>senderIndex</c> — the responder's session index (message offset 4);
    /// <c>receiverIndex</c> — the index echoed back at message offset 8 (our local index);
    /// <c>sendKey</c> / <c>recvKey</c> — the derived 32-byte transport keys.
    /// </returns>
    public (uint senderIndex, uint receiverIndex, byte[] sendKey, byte[] recvKey) ProcessResponse(
        byte[] peerPublicKey,
        byte[] message,
        NoiseHandshakeState handshakeState)
    {
        var (senderIndex, sendKey, recvKey) = _handshake.ProcessResponse(message, handshakeState);

        var receiverIndex = BitConverter.ToUInt32(message, 8);

        lock (_lock)
        {
            if (_peerSessions.TryGetValue(peerPublicKey, out var session))
            {
                session.State = SessionState.Established;
                session.SendKey = sendKey;
                session.RecvKey = recvKey;
                session.RemoteIndex = senderIndex;
                session.HandshakeTime = DateTime.UtcNow;
            }
        }

        return (senderIndex, receiverIndex, sendKey, recvKey);
    }

    /// <summary>
    /// Checks whether the peer's session has completed its handshake and is in the
    /// <see cref="SessionState.Established"/> state.
    /// </summary>
    /// <param name="peerPublicKey">The peer's 32-byte public key.</param>
    /// <returns><c>true</c> if an established session exists for the peer; otherwise <c>false</c>.</returns>
    public bool IsSessionEstablished(byte[] peerPublicKey)
    {
        lock (_lock)
        {
            return _peerSessions.TryGetValue(peerPublicKey, out var session) &&
                   session.State == SessionState.Established;
        }
    }

    /// <summary>
    /// Looks up the peer's session by public key.
    /// </summary>
    /// <param name="peerPublicKey">The peer's 32-byte public key.</param>
    /// <returns>
    /// The live stored <see cref="PeerSession"/> instance (not a copy — treat
    /// mutations as synchronized by this class's lock), or <c>null</c> when no session
    /// exists for the peer.
    /// </returns>
    public PeerSession? GetSession(byte[] peerPublicKey)
    {
        lock (_lock)
        {
            _peerSessions.TryGetValue(peerPublicKey, out var session);
            return session;
        }
    }

    /// <summary>
    /// Looks up a session by the local session index we generated during the handshake.
    /// </summary>
    /// <param name="localIndex">The 4-byte local session index to search for.</param>
    /// <returns>
    /// The first matching <see cref="PeerSession"/> (live instance), or <c>null</c>
    /// when no session uses that index. The scan is linear and runs under the internal
    /// lock.
    /// </returns>
    public PeerSession? GetSessionByLocalIndex(uint localIndex)
    {
        lock (_lock)
        {
            foreach (var session in _peerSessions.Values)
            {
                if (session.LocalIndex == localIndex)
                    return session;
            }
            return null;
        }
    }

    /// <summary>
    /// Replaces the transport keys of an existing session (e.g. after a rekey
    /// handshake outside this class) and marks it
    /// <see cref="SessionState.Established"/>. No-op when no session exists for the
    /// peer.
    /// </summary>
    /// <param name="peerPublicKey">The peer's 32-byte public key.</param>
    /// <param name="sendKey">The new 32-byte transport send key.</param>
    /// <param name="recvKey">The new 32-byte transport receive key.</param>
    public void UpdateSessionKeys(byte[] peerPublicKey, byte[] sendKey, byte[] recvKey)
    {
        lock (_lock)
        {
            if (_peerSessions.TryGetValue(peerPublicKey, out var session))
            {
                session.SendKey = sendKey;
                session.RecvKey = recvKey;
                session.HandshakeTime = DateTime.UtcNow;
                session.State = SessionState.Established;
            }
        }
    }

    /// <summary>
    /// Clears the peer's session: disposes its Noise handshake state and securely
    /// zeroes the stored transport keys (<c>CryptographicOperations.ZeroMemory</c>)
    /// before removing the entry from the map. No-op when no session exists.
    /// </summary>
    /// <param name="peerPublicKey">The peer's 32-byte public key.</param>
    public void ClearSession(byte[] peerPublicKey)
    {
        lock (_lock)
        {
            if (_peerSessions.TryGetValue(peerPublicKey, out var session))
            {
                session.HandshakeState?.Dispose();
                session.HandshakeState = null;
                if (session.SendKey != null)
                    System.Security.Cryptography.CryptographicOperations.ZeroMemory(session.SendKey);
                if (session.RecvKey != null)
                    System.Security.Cryptography.CryptographicOperations.ZeroMemory(session.RecvKey);
            }
            _peerSessions.Remove(peerPublicKey);
        }
    }

    /// <summary>
    /// Clears every session: disposes each Noise handshake state and securely zeroes
    /// the stored transport keys (<c>CryptographicOperations.ZeroMemory</c>) before
    /// emptying the map.
    /// </summary>
    public void ClearAllSessions()
    {
        lock (_lock)
        {
            foreach (var session in _peerSessions.Values)
            {
                session.HandshakeState?.Dispose();
                session.HandshakeState = null;
                if (session.SendKey != null)
                    System.Security.Cryptography.CryptographicOperations.ZeroMemory(session.SendKey);
                if (session.RecvKey != null)
                    System.Security.Cryptography.CryptographicOperations.ZeroMemory(session.RecvKey);
            }
            _peerSessions.Clear();
        }
    }
}
