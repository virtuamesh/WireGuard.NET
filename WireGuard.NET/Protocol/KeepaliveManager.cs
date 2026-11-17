using System.Collections.Concurrent;

namespace WireGuard.NET.Protocol;

/// <summary>
/// Schedules persistent keepalives per peer, implementing the WireGuard persistent-keepalive
/// mechanism.
/// </summary>
/// <remarks>
/// A 1 s timer evaluates every tracked peer. While a session is established, a keepalive is sent
/// via <see cref="SendKeepalive"/> whenever no outbound traffic has occurred for the configured
/// interval; before the session is established, the effective interval is doubled. Peers are keyed
/// by their 32-byte public keys; an interval of 0 disables keepalives for that peer. Timestamp
/// updates are unsynchronized (benign last-write-wins races).
/// </remarks>
public class KeepaliveManager
{
    /// <summary>Comparer making byte-array dictionary keys behave as value keys.</summary>
    private static readonly ByteArrayComparer _comparer = new();
    /// <summary>Per-peer keepalive state keyed by public key.</summary>
    private readonly ConcurrentDictionary<byte[], KeepaliveState> _peerKeepalives = new(_comparer);
    /// <summary>Keepalive scheduler timer (1 s period); <c>null</c> when stopped.</summary>
    private Timer? _keepaliveTimer;
    /// <summary>Whether the scheduler is running (volatile for cross-thread visibility).</summary>
    private volatile bool _running;

    /// <summary>
    /// Raised when a keepalive packet should be sent to a peer. Argument: the peer's public key.
    /// </summary>
    public event EventHandler<byte[]>? SendKeepalive;

    /// <summary>
    /// Starts the keepalive scheduler (first check after 1 s, then every second).
    /// No-op if already running.
    /// </summary>
    public void Start()
    {
        if (_running) return;

        _running = true;
        _keepaliveTimer = new Timer(CheckKeepalives, null, TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(1));
    }

    /// <summary>
    /// Stops the keepalive scheduler and disposes the timer. No-op if not running.
    /// </summary>
    public void Stop()
    {
        if (!_running) return;

        _running = false;
        _keepaliveTimer?.Dispose();
        _keepaliveTimer = null;
    }

    /// <summary>
    /// Begins tracking a peer for persistent keepalives.
    /// </summary>
    /// <param name="publicKey">The peer's 32-byte public key.</param>
    /// <param name="persistentKeepalive">
    /// Keepalive interval in seconds; 0 disables keepalives for this peer.
    /// </param>
    public void AddPeer(byte[] publicKey, int persistentKeepalive = 0)
    {
        _peerKeepalives[publicKey] = new KeepaliveState
        {
            PersistentKeepalive = persistentKeepalive,
            LastPacketSent = DateTime.MinValue,
            LastPacketReceived = DateTime.MinValue,
            LastKeepaliveSent = DateTime.MinValue,
            SessionEstablished = false
        };
    }

    /// <summary>
    /// Stops tracking a peer. No-op if unknown.
    /// </summary>
    /// <param name="publicKey">The peer's 32-byte public key.</param>
    public void RemovePeer(byte[] publicKey)
    {
        _peerKeepalives.TryRemove(publicKey, out _);
    }

    /// <summary>
    /// Records that a packet was received from a peer, refreshing its receive timestamp.
    /// </summary>
    /// <param name="publicKey">The peer's 32-byte public key.</param>
    public void PacketReceived(byte[] publicKey)
    {
        if (_peerKeepalives.TryGetValue(publicKey, out var state))
        {
            state.LastPacketReceived = DateTime.UtcNow;
        }
    }

    /// <summary>
    /// Records that a packet was sent to a peer, deferring the next keepalive.
    /// </summary>
    /// <param name="publicKey">The peer's 32-byte public key.</param>
    public void PacketSent(byte[] publicKey)
    {
        if (_peerKeepalives.TryGetValue(publicKey, out var state))
        {
            state.LastPacketSent = DateTime.UtcNow;
        }
    }

    /// <summary>
    /// Marks a peer's session as established, switching it to the regular keepalive interval.
    /// </summary>
    /// <param name="publicKey">The peer's 32-byte public key.</param>
    public void SessionEstablished(byte[] publicKey)
    {
        if (_peerKeepalives.TryGetValue(publicKey, out var state))
        {
            state.SessionEstablished = true;
            state.LastPacketSent = DateTime.UtcNow;
        }
    }

    /// <summary>
    /// Marks a peer's session as no longer established, switching it to the doubled interval.
    /// </summary>
    /// <param name="publicKey">The peer's 32-byte public key.</param>
    public void SessionReset(byte[] publicKey)
    {
        if (_peerKeepalives.TryGetValue(publicKey, out var state))
        {
            state.SessionEstablished = false;
        }
    }

    /// <summary>
    /// Timer callback wrapper: runs <see cref="CheckKeepalivesCore"/> with a catch-all guard.
    /// </summary>
    /// <param name="state">Unused timer state.</param>
    private void CheckKeepalives(object? state)
    {
        // An unhandled exception inside a Timer callback aborts the process outright; swallow it
        // here to keep the VPN service alive.
        try
        {
            CheckKeepalivesCore();
        }
        catch (Exception)
        {
            // The next tick will re-check; ignore this round's failure.
        }
    }

    /// <summary>
    /// Scans all tracked peers and raises <see cref="SendKeepalive"/> for those whose outbound
    /// silence exceeds their keepalive interval (doubled while no session is established).
    /// </summary>
    private void CheckKeepalivesCore()
    {
        List<byte[]>? keepaliveNeeded = null;

        if (!_running) return;

        var now = DateTime.UtcNow;

        // Note: never call ToList() directly on a ConcurrentDictionary — that goes through
        // ICollection<KVP>.CopyTo, which throws ArgumentException when racing with concurrent
        // additions/removals. Enumerating with foreach is thread-safe and never throws.
        foreach (var kvp in _peerKeepalives)
        {
            var peerState = kvp.Value;

            if (peerState.PersistentKeepalive > 0)
            {
                if (peerState.SessionEstablished)
                {
                    var lastActivity = peerState.LastPacketSent > peerState.LastKeepaliveSent
                        ? peerState.LastPacketSent
                        : peerState.LastKeepaliveSent;

                    if (lastActivity == DateTime.MinValue ||
                        (now - lastActivity).TotalSeconds >= peerState.PersistentKeepalive)
                    {
                        keepaliveNeeded ??= new List<byte[]>();
                        keepaliveNeeded.Add(kvp.Key);
                    }
                }
                else
                {
                    var lastActivity = peerState.LastPacketSent > peerState.LastKeepaliveSent
                        ? peerState.LastPacketSent
                        : peerState.LastKeepaliveSent;

                    var effectiveKeepalive = peerState.PersistentKeepalive * 2;

                    if (lastActivity == DateTime.MinValue ||
                        (now - lastActivity).TotalSeconds >= effectiveKeepalive)
                    {
                        keepaliveNeeded ??= new List<byte[]>();
                        keepaliveNeeded.Add(kvp.Key);
                    }
                }
            }
        }

        if (keepaliveNeeded != null)
        {
            foreach (var publicKey in keepaliveNeeded)
            {
                try
                {
                    SendKeepalive?.Invoke(this, publicKey);
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"SendKeepalive event handler threw: {ex.Message}");
                }

                if (_peerKeepalives.TryGetValue(publicKey, out var peerState))
                {
                    peerState.LastKeepaliveSent = DateTime.UtcNow;
                }
            }
        }
    }

    /// <summary>Mutable keepalive state of one tracked peer.</summary>
    private class KeepaliveState
    {
        /// <summary>Configured keepalive interval in seconds; 0 disables keepalives.</summary>
        public int PersistentKeepalive { get; set; }
        /// <summary>Time (UtcNow) of the last packet received from the peer.</summary>
        public DateTime LastPacketReceived { get; set; }
        /// <summary>Time (UtcNow) of the last packet sent to the peer.</summary>
        public DateTime LastPacketSent { get; set; }
        /// <summary>Time (UtcNow) of the last keepalive sent to the peer.</summary>
        public DateTime LastKeepaliveSent { get; set; }
        /// <summary>Whether the peer's session is currently established.</summary>
        public bool SessionEstablished { get; set; }
    }
}
