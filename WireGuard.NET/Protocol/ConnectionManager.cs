using System.Collections.Concurrent;
using System.Net;

namespace WireGuard.NET.Protocol;

/// <summary>
/// Tracks per-peer connection liveness: endpoint roaming updates, receive-activity timestamps,
/// and timeout detection for established sessions.
/// </summary>
/// <remarks>
/// A periodic timer (every 15 s) inspects all peers; an established peer that has not been heard
/// from for 150 seconds is reset and reported via <see cref="PeerTimedOut"/>. Peers are addressed
/// by their 32-byte public keys through a <see cref="ConcurrentDictionary{TKey,TValue}"/> shared
/// with the owning device.
/// </remarks>
public class ConnectionManager
{
    /// <summary>Peer table keyed by public key, shared with the owning device.</summary>
    private readonly ConcurrentDictionary<byte[], WireGuardPeer> _peers;
    /// <summary>Periodic connection-check timer; <c>null</c> when stopped.</summary>
    private Timer? _connectionTimer;
    /// <summary>Whether the manager is running (volatile for cross-thread visibility).</summary>
    private volatile bool _running;

    /// <summary>
    /// Raised when an established peer exceeded the connection timeout and has been reset.
    /// The event argument is the peer's public key.
    /// </summary>
    public event EventHandler<byte[]>? PeerTimedOut;

    /// <summary>
    /// Raised after a known peer's endpoint was updated (roaming).
    /// Arguments: the peer's public key and the new endpoint.
    /// </summary>
    public event EventHandler<(byte[] peerPublicKey, IPEndPoint newEndpoint)>? EndpointUpdated;

    /// <summary>Silence period after which an established peer is considered timed out (150 s).</summary>
    private static readonly TimeSpan ConnectionTimeout = TimeSpan.FromSeconds(150);
    /// <summary>Interval between periodic connection checks (15 s).</summary>
    private static readonly TimeSpan CheckInterval = TimeSpan.FromSeconds(15);

    /// <summary>
    /// Creates a connection manager operating on the given peer table.
    /// </summary>
    /// <param name="peers">Peer dictionary keyed by public key; must not be <c>null</c>.</param>
    public ConnectionManager(ConcurrentDictionary<byte[], WireGuardPeer> peers)
    {
        _peers = peers ?? throw new ArgumentNullException(nameof(peers));
    }

    /// <summary>
    /// Starts the periodic connection check. The first check runs immediately, then every 15 s.
    /// No-op if already running.
    /// </summary>
    public void Start()
    {
        if (_running) return;
        _running = true;
        _connectionTimer = new Timer(CheckConnections, null, TimeSpan.Zero, CheckInterval);
    }

    /// <summary>
    /// Stops the periodic connection check and disposes the timer. No-op if not running.
    /// </summary>
    public void Stop()
    {
        // [FIX 2026-08-17] The guard below was previously inverted (if (_running) return;), which meant:
        // while running, Stop() returned immediately and the timer was never disposed —
        // after WireGuardDevice.Stop(), CheckConnections kept firing every 15 s,
        // continuously iterating peers on a stopped device and potentially emitting timeout
        // events to an already-disposed socket.
        if (!_running) return;
        _running = false;
        _connectionTimer?.Dispose();
        _connectionTimer = null;
    }

    /// <summary>
    /// Updates the endpoint of a known peer (endpoint roaming).
    /// </summary>
    /// <param name="peerPublicKey">The peer's 32-byte public key.</param>
    /// <param name="newEndpoint">The peer's new network endpoint.</param>
    /// <remarks>
    /// No-op for unknown peers or when the endpoint is unchanged; otherwise raises
    /// <see cref="EndpointUpdated"/>.
    /// </remarks>
    public void UpdateEndpoint(byte[] peerPublicKey, IPEndPoint newEndpoint)
    {
        if (_peers.TryGetValue(peerPublicKey, out var peer))
        {
            var oldEndpoint = peer.Endpoint;
            if (!Equals(oldEndpoint, newEndpoint))
            {
                peer.Endpoint = newEndpoint;
                EndpointUpdated?.Invoke(this, (peerPublicKey, newEndpoint));
            }
        }
    }

    /// <summary>
    /// Records receive activity for a known peer, stamping its last-receive time with UtcNow.
    /// </summary>
    /// <param name="peerPublicKey">The peer's 32-byte public key.</param>
    public void RecordActivity(byte[] peerPublicKey)
    {
        if (_peers.TryGetValue(peerPublicKey, out var peer))
        {
            peer.LastRxTime = DateTime.UtcNow;
        }
    }

    /// <summary>
    /// Determines whether a peer has been heard from within the connection timeout.
    /// </summary>
    /// <param name="peerPublicKey">The peer's 32-byte public key.</param>
    /// <returns>
    /// <c>true</c> if the peer is known and its last receive activity is less than 150 s ago;
    /// <c>false</c> for unknown or timed-out peers.
    /// </returns>
    public bool IsPeerActive(byte[] peerPublicKey)
    {
        if (_peers.TryGetValue(peerPublicKey, out var peer))
        {
            var timeSinceLastActivity = DateTime.UtcNow - peer.LastRxTime;
            return timeSinceLastActivity < ConnectionTimeout;
        }
        return false;
    }

    /// <summary>
    /// Returns the time elapsed since the peer was last heard from.
    /// </summary>
    /// <param name="peerPublicKey">The peer's 32-byte public key.</param>
    /// <returns>
    /// The elapsed UTC time since the peer's last receive activity, or
    /// <see cref="TimeSpan.MaxValue"/> for unknown peers.
    /// </returns>
    public TimeSpan GetTimeSinceLastActivity(byte[] peerPublicKey)
    {
        if (_peers.TryGetValue(peerPublicKey, out var peer))
        {
            return DateTime.UtcNow - peer.LastRxTime;
        }
        return TimeSpan.MaxValue;
    }

    /// <summary>
    /// Collects the public keys of all currently inactive peers.
    /// </summary>
    /// <returns>
    /// A new list containing the public keys of peers that are unknown-timed-out or inactive;
    /// empty if all peers are active.
    /// </returns>
    public List<byte[]> GetInactivePeers()
    {
        var inactivePeers = new List<byte[]>();
        foreach (var kvp in _peers)
        {
            if (!IsPeerActive(kvp.Key))
            {
                inactivePeers.Add(kvp.Key);
            }
        }
        return inactivePeers;
    }

    /// <summary>
    /// Resets a known peer's session state: transport keys, the established flag, and all
    /// handshake/activity timestamps are cleared, forcing a fresh handshake.
    /// </summary>
    /// <param name="peerPublicKey">The peer's 32-byte public key.</param>
    public void ResetPeer(byte[] peerPublicKey)
    {
        if (_peers.TryGetValue(peerPublicKey, out var peer))
        {
            peer.ResetTransport();
            peer.IsEstablished = false;
            peer.LastHandshake = DateTime.MinValue;
            peer.LastRxTime = DateTime.MinValue;
            peer.LastTxTime = DateTime.MinValue;
        }
    }

    /// <summary>
    /// Timer callback: scans all peers, resets established peers whose receive silence exceeds
    /// the connection timeout, and raises <see cref="PeerTimedOut"/> for each.
    /// </summary>
    /// <param name="state">Unused timer state.</param>
    private void CheckConnections(object? state)
    {
        if (!_running) return;

        List<byte[]>? timedOutPeers = null;
        var now = DateTime.UtcNow;

        foreach (var kvp in _peers)
        {
            var peer = kvp.Value;
            var timeSinceLastRx = now - peer.LastRxTime;

            if (peer.IsEstablished && timeSinceLastRx > ConnectionTimeout)
            {
                timedOutPeers ??= new List<byte[]>();
                timedOutPeers.Add(kvp.Key);
            }
        }

        if (timedOutPeers != null)
        {
            foreach (var peerPublicKey in timedOutPeers)
            {
                ResetPeer(peerPublicKey);
                PeerTimedOut?.Invoke(this, peerPublicKey);
            }
        }
    }
}
