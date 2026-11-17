using System.Collections.Concurrent;

namespace WireGuard.NET.Protocol;

/// <summary>
/// Tracks per-peer transport key lifetimes and decides when a peer's session keys must
/// be rotated, implementing the REKEY_AFTER_TIME / REJECT_AFTER_TIME timer semantics of
/// the WireGuard protocol: a rekey handshake is initiated once
/// <c>REKEY_AFTER_TIME</c> (plus per-peer jitter) has elapsed since the session started
/// or the message counter reached <c>REKEY_AFTER_MESSAGES</c>, and traffic is rejected
/// outright once <c>REJECT_AFTER_TIME</c> or <c>REJECT_AFTER_MESSAGES</c> is exceeded.
/// A background timer checks all peers every 5 seconds and raises
/// <see cref="KeyRotationNeeded"/> for each peer due for rekey.
/// All members are thread-safe: peer state lives in a concurrent dictionary keyed by
/// the peer's 32-byte public key, and the timer lifecycle is guarded by a dedicated lock.
/// </summary>
public partial class KeyRotationManager
{
    private static readonly ByteArrayComparer _comparer = new();
    private readonly ConcurrentDictionary<byte[], KeyRotationState> _peerKeyStates = new(_comparer);
    private Timer? _keyRotationTimer;
    private readonly object _timerLock = new();
    private volatile bool _running;

    /// <summary>
    /// Raised on a timer-pool thread when a peer's transport keys are due for rotation.
    /// The event argument is the peer's 32-byte public key. Exceptions thrown by
    /// individual handlers are caught and reported via <c>Debug.WriteLine</c> so that
    /// one faulty handler cannot prevent rotation for the remaining peers.
    /// </summary>
    public event EventHandler<byte[]>? KeyRotationNeeded;

    private static readonly TimeSpan RekeyAfterTime = TimeSpan.FromSeconds(WireGuardConstants.REKEY_AFTER_TIME);
    private static readonly TimeSpan RekeyAttemptTime = TimeSpan.FromSeconds(WireGuardConstants.REKEY_ATTEMPT_TIME);
    private static readonly TimeSpan RejectAfterTime = TimeSpan.FromSeconds(WireGuardConstants.REJECT_AFTER_TIME);
    private static readonly TimeSpan CheckInterval = TimeSpan.FromSeconds(5);

    /// <summary>
    /// Starts the background rotation check. The first check runs immediately
    /// (zero due time) and then repeats every <c>CheckInterval</c> (5 seconds).
    /// No-op if the manager is already running. Thread-safe: guarded by the internal
    /// timer lock.
    /// </summary>
    public void Start()
    {
        lock (_timerLock)
        {
            if (_running) return;
            _running = true;
            _keyRotationTimer = new Timer(CheckKeyRotation, null, TimeSpan.Zero, CheckInterval);
        }
    }

    /// <summary>
    /// Stops the background rotation check and discards all per-peer key state.
    /// No-op if the manager is not running. Thread-safe: guarded by the internal
    /// timer lock. Note that the recorded key copies are simply dropped, not zeroed —
    /// the original key material is owned by the callers that supplied it.
    /// </summary>
    public void Stop()
    {
        lock (_timerLock)
        {
            if (!_running) return;
            _running = false;
            _keyRotationTimer?.Dispose();
            _keyRotationTimer = null;
            _peerKeyStates.Clear();
        }
    }

    /// <summary>
    /// Registers (or resets) the rotation state for a peer, starting a fresh session
    /// lifetime at the current UTC time with zeroed counters. A per-peer rekey jitter
    /// of −15..+15 seconds is applied so peers do not rekey in lockstep.
    /// </summary>
    /// <param name="peerPublicKey">The peer's 32-byte X25519 public key.</param>
    /// <param name="sendKey">The peer's 32-byte transport send key to record (cloned).</param>
    /// <param name="recvKey">The peer's 32-byte transport receive key to record (cloned).</param>
    public void InitializePeer(byte[] peerPublicKey, byte[] sendKey, byte[] recvKey)
    {
        var jitterSeconds = Random.Shared.Next(-15, 16);
        _peerKeyStates[peerPublicKey] = new KeyRotationState
        {
            SendKey = (byte[])sendKey.Clone(),
            RecvKey = (byte[])recvKey.Clone(),
            SessionStartTime = DateTime.UtcNow,
            LastSendTime = DateTime.UtcNow,
            LastRecvTime = DateTime.UtcNow,
            SendCount = 0,
            RecvCount = 0,
            NeedsRotation = false,
            RekeyJitter = TimeSpan.FromSeconds(jitterSeconds)
        };
    }

    /// <summary>
    /// Records that one outbound packet was sent to the peer: refreshes
    /// <see cref="KeyRotationState.LastSendTime"/> and atomically increments the send
    /// counter used for the <c>REKEY_AFTER_MESSAGES</c> threshold. No-op if the peer
    /// has not been initialized.
    /// </summary>
    /// <param name="peerPublicKey">The peer's 32-byte X25519 public key.</param>
    public void RecordSend(byte[] peerPublicKey)
    {
        if (_peerKeyStates.TryGetValue(peerPublicKey, out var state))
        {
            state.LastSendTime = DateTime.UtcNow;
            Interlocked.Increment(ref state.SendCount);
        }
    }

    /// <summary>
    /// Records that one inbound packet was received from the peer: refreshes
    /// <see cref="KeyRotationState.LastRecvTime"/> and atomically increments the
    /// receive counter used for the <c>REKEY_AFTER_MESSAGES</c> threshold. No-op if
    /// the peer has not been initialized.
    /// </summary>
    /// <param name="peerPublicKey">The peer's 32-byte X25519 public key.</param>
    public void RecordRecv(byte[] peerPublicKey)
    {
        if (_peerKeyStates.TryGetValue(peerPublicKey, out var state))
        {
            state.LastRecvTime = DateTime.UtcNow;
            Interlocked.Increment(ref state.RecvCount);
        }
    }

    /// <summary>
    /// Determines whether a new handshake should be initiated for the peer, per the
    /// WireGuard <c>REKEY_AFTER_TIME</c> / <c>REKEY_AFTER_MESSAGES</c> rules.
    /// </summary>
    /// <param name="peerPublicKey">The peer's 32-byte X25519 public key.</param>
    /// <returns>
    /// <c>true</c> when the peer was explicitly marked for rotation, when
    /// <c>REKEY_AFTER_TIME + RekeyJitter</c> has elapsed since the session started,
    /// or when the send or receive counter reached <c>REKEY_AFTER_MESSAGES</c>;
    /// <c>false</c> if the peer is unknown or no threshold has been reached.
    /// </returns>
    public bool ShouldInitiateRekey(byte[] peerPublicKey)
    {
        if (!_peerKeyStates.TryGetValue(peerPublicKey, out var state))
            return false;

        if (state.NeedsRotation)
            return true;

        var effectiveRekeyTime = RekeyAfterTime + state.RekeyJitter;
        var timeSinceStart = DateTime.UtcNow - state.SessionStartTime;
        if (timeSinceStart >= effectiveRekeyTime)
            return true;

        if (state.SendCountUlong >= WireGuardConstants.REKEY_AFTER_MESSAGES ||
            state.RecvCountUlong >= WireGuardConstants.REKEY_AFTER_MESSAGES)
            return true;

        return false;
    }

    /// <summary>
    /// Determines whether traffic for the peer must be rejected because its session
    /// keys are past their hard lifetime, per the WireGuard <c>REJECT_AFTER_TIME</c> /
    /// <c>REJECT_AFTER_MESSAGES</c> rules.
    /// </summary>
    /// <param name="peerPublicKey">The peer's 32-byte X25519 public key.</param>
    /// <returns>
    /// <c>true</c> when <c>REJECT_AFTER_TIME</c> has elapsed since the session started
    /// or a counter reached <c>REJECT_AFTER_MESSAGES</c>, meaning packets must be
    /// dropped and a new handshake is mandatory; also <c>true</c> for unknown peers.
    /// <c>false</c> when the session is still within its allowed lifetime.
    /// </returns>
    public bool ShouldReject(byte[] peerPublicKey)
    {
        if (!_peerKeyStates.TryGetValue(peerPublicKey, out var state))
            return true;

        var timeSinceStart = DateTime.UtcNow - state.SessionStartTime;
        if (timeSinceStart >= RejectAfterTime)
            return true;

        if (state.SendCountUlong >= WireGuardConstants.REJECT_AFTER_MESSAGES ||
            state.RecvCountUlong >= WireGuardConstants.REJECT_AFTER_MESSAGES)
            return true;

        return false;
    }

    /// <summary>
    /// Flags the peer so that its keys are rotated on the next check, bypassing the
    /// time and counter thresholds. No-op if the peer is not initialized.
    /// </summary>
    /// <param name="peerPublicKey">The peer's 32-byte X25519 public key.</param>
    public void MarkForRotation(byte[] peerPublicKey)
    {
        if (_peerKeyStates.TryGetValue(peerPublicKey, out var state))
        {
            state.NeedsRotation = true;
        }
    }

    /// <summary>
    /// Replaces the peer's transport keys after a successful rekey: stores clones of
    /// the new keys, resets the session start time and both counters, and clears any
    /// pending rotation flag. No-op if the peer is not initialized.
    /// </summary>
    /// <param name="peerPublicKey">The peer's 32-byte X25519 public key.</param>
    /// <param name="newSendKey">The new 32-byte transport send key (cloned).</param>
    /// <param name="newRecvKey">The new 32-byte transport receive key (cloned).</param>
    public void RotateKeys(byte[] peerPublicKey, byte[] newSendKey, byte[] newRecvKey)
    {
        if (_peerKeyStates.TryGetValue(peerPublicKey, out var state))
        {
            state.SendKey = (byte[])newSendKey.Clone();
            state.RecvKey = (byte[])newRecvKey.Clone();
            state.SessionStartTime = DateTime.UtcNow;
            Interlocked.Exchange(ref state.SendCount, 0);
            Interlocked.Exchange(ref state.RecvCount, 0);
            state.NeedsRotation = false;
        }
    }

    /// <summary>
    /// Removes the rotation state for a single peer. The recorded key copies are
    /// dropped, not zeroed; the original key material is owned elsewhere.
    /// </summary>
    /// <param name="peerPublicKey">The peer's 32-byte X25519 public key.</param>
    public void ClearPeer(byte[] peerPublicKey)
    {
        _peerKeyStates.TryRemove(peerPublicKey, out _);
    }

    /// <summary>
    /// Removes the rotation state for all peers. The recorded key copies are dropped,
    /// not zeroed; the original key material is owned elsewhere.
    /// </summary>
    public void ClearAllPeers()
    {
        _peerKeyStates.Clear();
    }

    /// <summary>
    /// Returns a point-in-time snapshot of the peer's rotation state with cloned key
    /// arrays, safe for the caller to inspect or mutate.
    /// </summary>
    /// <param name="peerPublicKey">The peer's 32-byte X25519 public key.</param>
    /// <returns>A deep copy of the current <see cref="KeyRotationState"/>, or
    /// <c>null</c> if the peer has never been initialized or has been cleared.</returns>
    public KeyRotationState? GetPeerState(byte[] peerPublicKey)
    {
        if (_peerKeyStates.TryGetValue(peerPublicKey, out var state))
        {
            return new KeyRotationState
            {
                SendKey = (byte[])state.SendKey.Clone(),
                RecvKey = (byte[])state.RecvKey.Clone(),
                SessionStartTime = state.SessionStartTime,
                LastSendTime = state.LastSendTime,
                LastRecvTime = state.LastRecvTime,
                SendCount = Interlocked.Read(ref state.SendCount),
                RecvCount = Interlocked.Read(ref state.RecvCount),
                NeedsRotation = state.NeedsRotation
            };
        }
        return null;
    }

    /// <summary>
    /// Timer callback invoked every <c>CheckInterval</c> (5 seconds): scans all peer
    /// states and raises <see cref="KeyRotationNeeded"/> for every peer whose rekey
    /// condition (explicit flag, elapsed time, or message counters) is met. Exits
    /// immediately when the manager has been stopped.
    /// </summary>
    private void CheckKeyRotation(object? state)
    {
        if (!_running) return;

        List<byte[]>? peersNeedingRotation = null;
        var now = DateTime.UtcNow;

        foreach (var kvp in _peerKeyStates)
        {
            var peerState = kvp.Value;
            var effectiveRekeyTime = RekeyAfterTime + peerState.RekeyJitter;
            var timeSinceStart = now - peerState.SessionStartTime;

            if (peerState.NeedsRotation ||
                timeSinceStart >= effectiveRekeyTime ||
                peerState.SendCountUlong >= WireGuardConstants.REKEY_AFTER_MESSAGES ||
                peerState.RecvCountUlong >= WireGuardConstants.REKEY_AFTER_MESSAGES)
            {
                peersNeedingRotation ??= new List<byte[]>();
                peersNeedingRotation.Add(kvp.Key);
            }
        }

        if (peersNeedingRotation != null)
        {
            foreach (var peerPublicKey in peersNeedingRotation)
            {
                try
                {
                    KeyRotationNeeded?.Invoke(this, peerPublicKey);
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"KeyRotationNeeded event handler threw: {ex.Message}");
                }
            }
        }
    }
}
