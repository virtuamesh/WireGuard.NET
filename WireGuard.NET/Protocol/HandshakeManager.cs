using System.Collections.Concurrent;
using WireGuard.NET.Protocol.Noise;

namespace WireGuard.NET.Protocol;

/// <summary>
/// Tracks pending outbound handshakes per peer and drives their lifecycle: retransmission with
/// backoff, DERP relay fallback, and timeout expiry.
/// </summary>
/// <remarks>
/// <para>
/// A 200 ms timer inspects all pending handshakes. Unanswered initiations are retransmitted via
/// <see cref="HandshakeRetryNeeded"/> with growing intervals (250 ms, 500 ms, 1 s, 2 s, 5 s). A
/// handshake that has made no progress within <see cref="WireGuardConstants.REKEY_ATTEMPT_TIME"/>
/// seconds (90 s) expires and <see cref="HandshakeTimedOut"/> is raised. Handshakes that were not
/// initiated via DERP raise <see cref="DerpFallbackNeeded"/> after 5 s without a response.
/// </para>
/// <para>
/// Pending state is held in a concurrent dictionary keyed by the peer's 32-byte public key.
/// Pending states own Noise handshake-state objects (which hold key material) and are disposed on
/// response, cancellation, or timeout.
/// </para>
/// </remarks>
public class HandshakeManager : IDisposable
{
    /// <summary>Comparer making byte-array dictionary keys behave as value keys.</summary>
    private static readonly ByteArrayComparer _comparer = new();
    /// <summary>Pending handshakes keyed by peer public key.</summary>
    private readonly ConcurrentDictionary<byte[], PendingHandshake> _pendingHandshakes = new(_comparer);
    /// <summary>Handshake supervision timer (200 ms period); <c>null</c> when stopped.</summary>
    private Timer? _handshakeTimer;
    /// <summary>Whether the manager is running (volatile for cross-thread visibility).</summary>
    private volatile bool _running;

    /// <summary>
    /// Raised when a handshake initiation should be transmitted. Arguments: the peer's public key
    /// and the wire-format initiation message.
    /// </summary>
    public event EventHandler<(byte[] peerPublicKey, byte[] message)>? SendHandshakeMessage;
    /// <summary>
    /// Raised when a pending handshake exceeded the 90 s attempt window and was discarded.
    /// Argument: the peer's public key.
    /// </summary>
    public event EventHandler<byte[]>? HandshakeTimedOut;
    /// <summary>
    /// Raised when a pending handshake should be retransmitted (retry with backoff).
    /// Argument: the peer's public key.
    /// </summary>
    public event EventHandler<byte[]>? HandshakeRetryNeeded;
    /// <summary>
    /// Raised when a direct-path handshake made no progress within 5 s and a DERP relay fallback
    /// is suggested. Argument: the peer's public key.
    /// </summary>
    public event EventHandler<byte[]>? DerpFallbackNeeded;

    /// <summary>Backoff schedule between handshake retransmissions (250 ms up to 5 s).</summary>
    private static readonly TimeSpan[] RetryIntervals = new[]
    {
        TimeSpan.FromMilliseconds(250),
        TimeSpan.FromMilliseconds(500),
        TimeSpan.FromSeconds(1),
        TimeSpan.FromSeconds(2),
        TimeSpan.FromSeconds(5)
    };

    /// <summary>Period without handshake progress after which a DERP relay fallback is suggested.</summary>
    private static readonly TimeSpan DerpFallbackDelay = TimeSpan.FromSeconds(5);

    /// <summary>Creates a handshake manager; call <see cref="Start"/> to begin supervision.</summary>
    public HandshakeManager()
    {
    }

    /// <summary>
    /// Starts the handshake supervision timer (the first check runs immediately, then every
    /// 200 ms). No-op if already running.
    /// </summary>
    public void Start()
    {
        if (_running) return;
        _running = true;
        _handshakeTimer = new Timer(CheckHandshakes, null, TimeSpan.Zero, TimeSpan.FromMilliseconds(200));
    }

    /// <summary>
    /// Stops the timer and discards all pending handshakes, disposing their Noise states.
    /// </summary>
    public void Stop()
    {
        if (!_running) return;
        _running = false;
        _handshakeTimer?.Dispose();
        _handshakeTimer = null;
        DisposeAllPendingStates();
        _pendingHandshakes.Clear();
    }

    /// <summary>
    /// Registers a new pending handshake for a peer and emits the initiation message.
    /// </summary>
    /// <param name="peerPublicKey">The peer's 32-byte public key.</param>
    /// <param name="initiationMessage">The wire-format handshake initiation to send.</param>
    /// <param name="handshakeState">The Noise state used to process the eventual response.</param>
    /// <param name="localIndex">The local session index carried in the initiation.</param>
    /// <param name="isDerpInitiated">
    /// Whether the handshake is sent via the DERP relay (such handshakes skip the relay-fallback
    /// suggestion).</param>
    /// <remarks>Any previously pending handshake for the same peer is replaced.</remarks>
    public void InitiateHandshake(byte[] peerPublicKey, byte[] initiationMessage, NoiseHandshakeState handshakeState, uint localIndex, bool isDerpInitiated = false)
    {
        var state = new PendingHandshake
        {
            PeerPublicKey = peerPublicKey,
            Message = initiationMessage,
            HandshakeState = handshakeState,
            LocalIndex = localIndex,
            StartTime = DateTime.UtcNow,
            LastSendTime = DateTime.UtcNow,
            RetryCount = 0,
            DerpFallbackFired = isDerpInitiated,
            IsDerpInitiated = isDerpInitiated
        };

        _pendingHandshakes[peerPublicKey] = state;
        SendHandshakeMessage?.Invoke(this, (peerPublicKey, initiationMessage));
    }

    /// <summary>
    /// Replaces the message and Noise state of an existing pending handshake (e.g. after a
    /// re-initiation).
    /// </summary>
    /// <param name="peerPublicKey">The peer's 32-byte public key.</param>
    /// <param name="newMessage">The new wire-format message.</param>
    /// <param name="newState">The new Noise state.</param>
    /// <param name="localIndex">The new local session index.</param>
    /// <remarks>No-op if no handshake is pending for the peer.</remarks>
    public void UpdateHandshakeMessage(byte[] peerPublicKey, byte[] newMessage, NoiseHandshakeState newState, uint localIndex)
    {
        if (_pendingHandshakes.TryGetValue(peerPublicKey, out var state))
        {
            // Dispose the old handshake state before replacing it (it holds private-key/PSK
            // clones) to prevent leaks.
            state.HandshakeState.Dispose();
            state.Message = newMessage;
            state.HandshakeState = newState;
            state.LocalIndex = localIndex;
        }
    }

    /// <summary>
    /// Removes and returns the pending handshake state for a peer upon receiving its response.
    /// </summary>
    /// <param name="peerPublicKey">The peer's 32-byte public key.</param>
    /// <param name="handshakeState">
    /// When returning <c>true</c>: the Noise state for finalizing the handshake; otherwise <c>null</c>.
    /// </param>
    /// <param name="localIndex">
    /// When returning <c>true</c>: the local session index of the initiation; otherwise 0.
    /// </param>
    /// <returns>
    /// <c>true</c> if a pending handshake existed and was removed; <c>false</c> for unknown or
    /// already-expired handshakes.
    /// </returns>
    public bool HandleResponse(byte[] peerPublicKey, out NoiseHandshakeState? handshakeState, out uint localIndex)
    {
        if (_pendingHandshakes.TryRemove(peerPublicKey, out var state))
        {
            handshakeState = state.HandshakeState;
            localIndex = state.LocalIndex;
            return true;
        }

        handshakeState = null;
        localIndex = 0;
        return false;
    }

    /// <summary>
    /// Determines whether a handshake is currently pending for a peer.
    /// </summary>
    /// <param name="peerPublicKey">The peer's 32-byte public key.</param>
    /// <returns><c>true</c> if an initiation is awaiting a response.</returns>
    public bool IsHandshakePending(byte[] peerPublicKey)
    {
        return _pendingHandshakes.ContainsKey(peerPublicKey);
    }

    /// <summary>
    /// Determines whether the peer's pending handshake was initiated via the DERP relay.
    /// </summary>
    /// <param name="peerPublicKey">The peer's 32-byte public key.</param>
    /// <returns>
    /// <c>true</c> if a DERP-initiated handshake is pending; <c>false</c> otherwise (including
    /// when no handshake is pending).
    /// </returns>
    public bool IsPendingDerpInitiated(byte[] peerPublicKey)
    {
        return _pendingHandshakes.TryGetValue(peerPublicKey, out var state) && state.IsDerpInitiated;
    }

    /// <summary>
    /// Cancels a peer's pending handshake and disposes its Noise state. No-op if none is pending.
    /// </summary>
    /// <param name="peerPublicKey">The peer's 32-byte public key.</param>
    public void ClearHandshake(byte[] peerPublicKey)
    {
        if (_pendingHandshakes.TryRemove(peerPublicKey, out var state))
        {
            state.HandshakeState.Dispose();
        }
    }

    /// <summary>
    /// Returns the wire-format message of the peer's pending handshake.
    /// </summary>
    /// <param name="peerPublicKey">The peer's 32-byte public key.</param>
    /// <returns>The pending initiation message, or <c>null</c> if no handshake is pending.</returns>
    public byte[]? GetPendingMessage(byte[] peerPublicKey)
    {
        return _pendingHandshakes.TryGetValue(peerPublicKey, out var state) ? state.Message : null;
    }

    /// <summary>
    /// Returns the local session index of the peer's pending handshake.
    /// </summary>
    /// <param name="peerPublicKey">The peer's 32-byte public key.</param>
    /// <returns>The local index, or <c>null</c> if no handshake is pending.</returns>
    public uint? GetPendingLocalIndex(byte[] peerPublicKey)
    {
        return _pendingHandshakes.TryGetValue(peerPublicKey, out var state) ? state.LocalIndex : null;
    }

    /// <summary>
    /// Returns how many retransmissions of the peer's pending handshake have been issued so far.
    /// </summary>
    /// <param name="peerPublicKey">The peer's 32-byte public key.</param>
    /// <returns>The retry count, or 0 if no handshake is pending.</returns>
    public int GetRetryCount(byte[] peerPublicKey)
    {
        return _pendingHandshakes.TryGetValue(peerPublicKey, out var state) ? state.RetryCount : 0;
    }

    /// <summary>
    /// Cancels all pending handshakes, disposing their Noise states.
    /// </summary>
    public void ClearAllHandshakes()
    {
        DisposeAllPendingStates();
        _pendingHandshakes.Clear();
    }

    /// <summary>Disposes the Noise state of every pending handshake (zeroing key material).</summary>
    private void DisposeAllPendingStates()
    {
        foreach (var kvp in _pendingHandshakes)
        {
            kvp.Value.HandshakeState?.Dispose();
        }
    }

    /// <summary>Stops the manager and discards all pending state.</summary>
    public void Dispose()
    {
        Stop();
    }

    /// <summary>
    /// Timer callback wrapper: runs <see cref="CheckHandshakesCore"/> with a catch-all guard.
    /// </summary>
    /// <param name="state">Unused timer state.</param>
    private void CheckHandshakes(object? state)
    {
        // An unhandled exception inside a Timer callback aborts the process outright (observed as
        // SIGABRT on Android); swallow it here to keep the VPN service alive.
        try
        {
            CheckHandshakesCore();
        }
        catch (Exception)
        {
            // The next tick will re-check; ignore this round's failure.
        }
    }

    /// <summary>
    /// Scans all pending handshakes and raises timeout, DERP-fallback, and retry events as needed.
    /// </summary>
    private void CheckHandshakesCore()
    {
        List<byte[]>? toRetry = null;
        List<byte[]>? toTimeout = null;
        List<byte[]>? toDerpFallback = null;

        if (!_running) return;

        var now = DateTime.UtcNow;

        // Note: never call ToList() directly on a ConcurrentDictionary — that goes through
        // ICollection<KVP>.CopyTo, which throws ArgumentException when racing with concurrent
        // additions/removals (this caused a production crash). Enumerating a ConcurrentDictionary
        // with foreach is thread-safe and never throws.
        foreach (var kvp in _pendingHandshakes)
        {
            var handshake = kvp.Value;
            var timeSinceLastSend = now - handshake.LastSendTime;
            var timeSinceStart = now - handshake.StartTime;

            if (timeSinceStart > TimeSpan.FromSeconds(WireGuardConstants.REKEY_ATTEMPT_TIME))
            {
                toTimeout ??= new List<byte[]>();
                toTimeout.Add(kvp.Key);
                if (_pendingHandshakes.TryRemove(kvp.Key, out var timedOut))
                {
                    // The Noise state of a timed-out pending handshake is disposed upon removal,
                    // zeroing it so private-key/PSK clones do not linger in memory.
                    timedOut.HandshakeState.Dispose();
                }
                continue;
            }

            if (!handshake.DerpFallbackFired && timeSinceStart >= DerpFallbackDelay && !handshake.IsDerpInitiated)
            {
                handshake.DerpFallbackFired = true;
                toDerpFallback ??= new List<byte[]>();
                toDerpFallback.Add(kvp.Key);
            }

            // [FIX 2026-10-04] DERP-initiated pending handshakes must also be retransmitted: the
            // previous condition excluded IsDerpInitiated, so such handshakes were sent exactly
            // once and then silently hung until the 90 s REKEY_ATTEMPT_TIME timeout — if the first
            // packet fell into the peer's Gone cooldown / relay-loss window while the local end
            // also ignored the peer's initiation due to tie-break, a bidirectional handshake black
            // hole formed (~60 s without connectivity observed on real devices). Retransmission
            // goes through HandshakeRetryNeeded → SendHandshakeToPeerAsync, which routes via DERP
            // according to the pending handshake's channel, so it stays compatible.
            if (timeSinceLastSend >= RetryIntervals[Math.Min(handshake.RetryCount, RetryIntervals.Length - 1)])
            {
                handshake.RetryCount++;
                handshake.LastSendTime = now;

                toRetry ??= new List<byte[]>();
                toRetry.Add(kvp.Key);
            }
        }

        if (toDerpFallback != null)
        {
            foreach (var peerPublicKey in toDerpFallback)
            {
                DerpFallbackNeeded?.Invoke(this, peerPublicKey);
            }
        }

        if (toRetry != null)
        {
            foreach (var peerPublicKey in toRetry)
            {
                HandshakeRetryNeeded?.Invoke(this, peerPublicKey);
            }
        }

        if (toTimeout != null)
        {
            foreach (var peerPublicKey in toTimeout)
            {
                HandshakeTimedOut?.Invoke(this, peerPublicKey);
            }
        }
    }

    /// <summary>Mutable state of one pending outbound handshake.</summary>
    private class PendingHandshake
    {
        /// <summary>The peer's 32-byte public key.</summary>
        public byte[] PeerPublicKey { get; set; } = Array.Empty<byte>();
        /// <summary>The wire-format initiation message awaiting a response.</summary>
        public byte[] Message { get; set; } = Array.Empty<byte>();
        /// <summary>Noise state for processing the response; owns sensitive key material.</summary>
        public NoiseHandshakeState HandshakeState { get; set; } = null!;
        /// <summary>Time (UtcNow) the handshake was first initiated.</summary>
        public DateTime StartTime { get; set; }
        /// <summary>Time (UtcNow) the message was last (re)sent.</summary>
        public DateTime LastSendTime { get; set; }
        /// <summary>Number of retransmissions issued so far.</summary>
        public int RetryCount { get; set; }
        /// <summary>Local session index carried in the initiation.</summary>
        public uint LocalIndex { get; set; }
        /// <summary>Whether the DERP-fallback suggestion has already fired for this handshake.</summary>
        public bool DerpFallbackFired { get; set; }
        /// <summary>Whether this handshake was initiated via the DERP relay.</summary>
        public bool IsDerpInitiated { get; set; }
    }
}
