using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;

namespace WireGuard.NET.Protocol;

/// <summary>
/// Runtime state of one remote WireGuard peer: identity (public key), current
/// endpoint, the active transport plus a small grace queue of retired transports
/// (see the VM-SESSION-COLLAPSE-GRACE note), replay gatekeeping, traffic counters
/// and a bounded buffer of packets that arrived before the first transport existed.
/// Thread-safety: transport lifecycle operations are serialized by an internal lock;
/// traffic counters use <c>Interlocked</c> and the connectivity flags use volatile
/// reads/writes. Simple status properties (e.g. <see cref="LastHandshake"/>) are
/// unsynchronized and may observe stale values.
/// </summary>
public class WireGuardPeer : IDisposable
{
    /// <summary>
    /// The peer's 32-byte X25519 public key (cloned at construction); identifies the
    /// peer for handshakes and session lookups.
    /// </summary>
    public byte[] PublicKey { get; }

    /// <summary>
    /// Optional 32-byte preshared key for this peer; <c>null</c> when no PSK is used.
    /// </summary>
    public byte[]? PresharedKey { get; set; }

    /// <summary>
    /// The peer's current UDP endpoint; may be updated as the peer roams.
    /// </summary>
    public IPEndPoint? Endpoint { get; set; }

    /// <summary>
    /// The AllowedIPs routing filter: which destination networks are routed to this
    /// peer.
    /// </summary>
    public AllowedIPsFilter AllowedIPs { get; } = new();

    /// <summary>
    /// Persistent keepalive interval in seconds; 0 disables keepalives.
    /// </summary>
    public int PersistentKeepalive { get; set; }

    /// <summary>
    /// The UTC time of the last successful handshake with this peer.
    /// </summary>
    public DateTime LastHandshake { get; set; }

    /// <summary>
    /// The UTC time of the last inbound packet from this peer.
    /// </summary>
    public DateTime LastRxTime { get; set; }

    /// <summary>
    /// The UTC time of the last outbound packet to this peer.
    /// </summary>
    public DateTime LastTxTime { get; set; }

    /// <summary>
    /// Bytes received from this peer (plaintext length of decrypted packets),
    /// atomically read and written.
    /// </summary>
    public ulong RxBytes { get => Interlocked.Read(ref _rxBytes); set => Interlocked.Exchange(ref _rxBytes, value); }

    /// <summary>
    /// Bytes sent to this peer (plaintext length of encrypted packets),
    /// atomically read and written.
    /// </summary>
    public ulong TxBytes { get => Interlocked.Read(ref _txBytes); set => Interlocked.Exchange(ref _txBytes, value); }

    private ulong _rxBytes;
    private ulong _txBytes;

    /// <summary>
    /// Our 4-byte local session index for the current key generation.
    /// </summary>
    public uint LocalIndex { get; set; }

    /// <summary>
    /// The peer's 4-byte session index for the current key generation.
    /// </summary>
    public uint RemoteIndex { get; set; }

    /// <summary>
    /// Whether a session with this peer is currently established (unsynchronized
    /// read/write; may be momentarily stale).
    /// </summary>
    public bool IsEstablished { get; set; }

    /// <summary>
    /// The last known UDP endpoint before the handshake timed out and traffic moved
    /// to a DERP relay; kept for direct-path probing and recovery.
    /// </summary>
    public IPEndPoint? LastKnownUdpEndpoint { get; set; }

    // [VM-S5] TAI64N timestamp replay protection: per-peer record of the largest
    // handshake initiation timestamp seen so far; initiations whose timestamp does not
    // advance are rejected (standard wg behavior, cf. wireguard-go
    // handshake.lastTimestamp).
    private byte[]? _lastInitiationTimestamp;

    /// <summary>
    /// Validates and updates this peer's TAI64N initiation timestamp (12 bytes,
    /// big-endian; lexicographic order equals chronological order). Records the
    /// timestamp and returns <c>true</c> only when it is strictly newer; otherwise the
    /// initiation is a replay or stale one and the method returns <c>false</c>.
    /// Thread-safe: guarded by the internal lock.
    /// </summary>
    /// <param name="tai64n">The 12-byte big-endian TAI64N timestamp from the initiation message.</param>
    /// <returns>
    /// <c>true</c> when the timestamp advanced and was recorded; <c>false</c> when the
    /// input is not 12 bytes or is not strictly newer than the recorded maximum.
    /// </returns>
    public bool TryUpdateLastInitiationTimestamp(ReadOnlySpan<byte> tai64n)
    {
        if (tai64n.Length != 12)
            return false;

        lock (_lock)
        {
            if (_lastInitiationTimestamp != null &&
                tai64n.SequenceCompareTo(_lastInitiationTimestamp) <= 0)
            {
                return false;
            }
            _lastInitiationTimestamp = tai64n.ToArray();
            return true;
        }
    }

    private WireGuardTransport? _transport;

    /// <summary>
    /// [VM-SESSION-COLLAPSE-GRACE 2026-11-08] Retired-transport (send-key) retention
    /// queue, ordered newest → oldest.
    ///
    /// The original implementation retained only one generation of previous transport.
    /// In the jitter scenario where both sides initiate handshakes at the same time,
    /// testing showed 3 sessions being established within 7 seconds (localIndex
    /// 869362512 → 312459501 → …), each establishment evicting the previous
    /// generation, so the second-to-last key generation was gone within 2 seconds:
    /// the peer was still sending with it → decryption necessarily failed → packet
    /// loss → another handshake, forming a self-sustaining jitter loop (measured on
    /// the exit node: 380 VM-SESSION-COLLAPSE events per day and 25
    /// No-matching-session packet drops).
    ///
    /// Now the most recent 2 generations are retained (30-second TTL each), enough to
    /// cover one or two rapid re-handshakes, matching wireguard-go's keypair grace
    /// semantics; each generation keeps its own replay window, so replay protection
    /// is not weakened.
    /// </summary>
    private readonly List<(WireGuardTransport Transport, DateTime Expiry)> _retiredTransports = new();
    private const int MaxRetiredTransports = 2;
    private static readonly TimeSpan PreviousTransportTtl = TimeSpan.FromSeconds(30);
    private readonly object _lock = new();
    private bool _disposed;

    private readonly ConcurrentQueue<byte[]> _pendingPackets = new();
    private int _pendingPacketCount;
    private const int MaxPendingPackets = 256;

    /// <summary>
    /// Creates the peer state for the given public key.
    /// </summary>
    /// <param name="publicKey">The peer's 32-byte X25519 public key (cloned).</param>
    /// <exception cref="ArgumentException">Thrown when the public key is not 32 bytes.</exception>
    public WireGuardPeer(byte[] publicKey)
    {
        if (publicKey.Length != 32)
            throw new ArgumentException("PublicKey must be 32 bytes", nameof(publicKey));

        PublicKey = (byte[])publicKey.Clone();
    }

    /// <summary>
    /// Installs a new transport for the peer with the given key generation. The
    /// previous transport (if any) is moved into the retired-transports grace queue
    /// instead of being disposed immediately, so in-flight packets encrypted under the
    /// old generation can still be decrypted. Thread-safe: guarded by the internal
    /// lock.
    /// </summary>
    /// <param name="sendKey">The 32-byte transport send key for the new generation.</param>
    /// <param name="recvKey">The 32-byte transport receive key for the new generation.</param>
    /// <param name="isDerpConnected">Initial value of <see cref="IsDerpConnected"/> for the new session.</param>
    public void SetTransport(byte[] sendKey, byte[] recvKey, bool isDerpConnected = false)
    {
        lock (_lock)
        {
            if (_transport != null)
            {
                // Aligned with wireguard-go: the previous keypair keeps its original
                // replay window (old-counter replays are still rejected within
                // REJECT_AFTER_TIME). Do not zero the window, or packets already seen
                // under the old session could be replayed.
                RetireCurrentTransport();
            }
            _transport = new WireGuardTransport(sendKey, recvKey);
            _isDerpConnected = isDerpConnected;
        }
    }

    /// <summary>
    /// [VM-SESSION-COLLAPSE-GRACE 2026-11-08] Moves the current transport into the
    /// retired queue, retaining at most 2 generations. The caller must hold
    /// <c>_lock</c>.
    /// </summary>
    private void RetireCurrentTransport()
    {
        if (_transport == null) return;

        PruneRetiredTransports();
        _retiredTransports.Insert(0, (_transport, DateTime.UtcNow + PreviousTransportTtl));

        while (_retiredTransports.Count > MaxRetiredTransports)
        {
            var oldest = _retiredTransports[^1];
            _retiredTransports.RemoveAt(_retiredTransports.Count - 1);
            oldest.Transport.Dispose();
        }
    }

    /// <summary>
    /// [VM-SESSION-COLLAPSE-GRACE 2026-11-08] Removes expired retired transports
    /// (past their 30-second TTL), disposing each. The caller must hold
    /// <c>_lock</c>.
    /// </summary>
    private void PruneRetiredTransports()
    {
        var now = DateTime.UtcNow;
        for (var i = _retiredTransports.Count - 1; i >= 0; i--)
        {
            if (now <= _retiredTransports[i].Expiry) continue;
            _retiredTransports[i].Transport.Dispose();
            _retiredTransports.RemoveAt(i);
        }
    }

    /// <summary>
    /// Whether the peer currently has an active transport (key generation).
    /// Lock-free read; may be momentarily stale.
    /// </summary>
    public bool HasTransport => _transport != null;

    /// <summary>
    /// [VM-REPLAY-RECOVER-GATE 2026-10-31] Largest accepted receive counter (the
    /// replay window's high-water mark). Returns 0 when there is no session. Used to
    /// distinguish a replay rejection caused by "the same packet delivered twice"
    /// (counter equal to this value) from one caused by "the peer rebuilt its
    /// session" (counter far below this value) — only the latter may reset the
    /// window.
    /// </summary>
    public ulong LastReceivedCounter => _transport?.LastReceivedCounter ?? 0;

    /// <summary>
    /// [VM-REPLAY-RECOVER 2026-10-21] Resets the current transport's receive replay
    /// window. Intended only for the case where AEAD authentication passed but the
    /// window is not aligned (peer session rebuild, counter back to 0) — forged
    /// packets cannot pass AEAD authentication, so resetting does not weaken replay
    /// protection. Thread-safe: guarded by the internal lock.
    /// </summary>
    public void ResetReplayWindow()
    {
        lock (_lock)
        {
            _transport?.ResetReplayWindow();
        }
    }

    /// <summary>
    /// Buffers one packet that could not be sent yet (e.g. no established transport).
    /// The buffer holds at most 256 packets.
    /// </summary>
    /// <param name="packet">The raw packet bytes to buffer.</param>
    /// <returns>
    /// <c>true</c> when the packet was enqueued; <c>false</c> when the buffer is full
    /// and the packet was dropped.
    /// </returns>
    public bool TryEnqueuePendingPacket(byte[] packet)
    {
        if (Interlocked.Increment(ref _pendingPacketCount) > MaxPendingPackets)
        {
            Interlocked.Decrement(ref _pendingPacketCount);
            return false;
        }
        _pendingPackets.Enqueue(packet);
        return true;
    }

    /// <summary>
    /// Removes and returns all buffered pending packets in FIFO order, resetting the
    /// occupancy counter.
    /// </summary>
    /// <returns>The buffered packets (empty list when none are pending).</returns>
    public List<byte[]> DrainPendingPackets()
    {
        var packets = new List<byte[]>();
        while (_pendingPackets.TryDequeue(out var packet))
        {
            packets.Add(packet);
        }
        Interlocked.Exchange(ref _pendingPacketCount, 0);
        return packets;
    }

    /// <summary>
    /// Current number of packets sitting in the pending-packet buffer (bounded by 256).
    /// </summary>
    public int PendingPacketCount => Volatile.Read(ref _pendingPacketCount);

    /// <summary>
    /// Releases the peer: disposes the current transport and all retired transports
    /// (zeroing their key material). Idempotent.
    /// </summary>
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Disposal worker. When <paramref name="disposing"/> is <c>true</c>, disposes the
    /// current transport and every retired transport under the internal lock (their
    /// ChaCha20Poly1305 keys are zeroed in place).
    /// </summary>
    /// <param name="disposing"><c>true</c> when called from <see cref="Dispose()"/>; <c>false</c> from a finalizer.</param>
    protected virtual void Dispose(bool disposing)
    {
        if (_disposed)
            return;

        if (disposing)
        {
            lock (_lock)
            {
                _transport?.Dispose();
                foreach (var retired in _retiredTransports)
                {
                    retired.Transport.Dispose();
                }
                _retiredTransports.Clear();
            }
        }

        _disposed = true;
    }

    /// <summary>
    /// Whether this peer is currently connected through a DERP relay (volatile
    /// read/write; may be momentarily stale).
    /// </summary>
    public bool IsDerpConnected
    {
        get => Volatile.Read(ref _isDerpConnected);
        set => Volatile.Write(ref _isDerpConnected, value);
    }

    private bool _isDerpConnected;

    /// <summary>
    /// Set to <c>true</c> when this peer uses a TCP transport. The send path selects
    /// the TCP channel based on this flag (volatile read/write).
    /// </summary>
    public bool IsTcpConnected
    {
        get => Volatile.Read(ref _isTcpConnected);
        set => Volatile.Write(ref _isTcpConnected, value);
    }

    private bool _isTcpConnected;

    /// <summary>
    /// Set to <c>true</c> when this peer uses a WebSocket transport. The send path
    /// selects the WebSocket channel based on this flag (volatile read/write).
    /// </summary>
    public bool IsWebSocketConnected
    {
        get => Volatile.Read(ref _isWebSocketConnected);
        set => Volatile.Write(ref _isWebSocketConnected, value);
    }

    private bool _isWebSocketConnected;

    /// <summary>
    /// Encrypts one plaintext packet for the peer using the current transport.
    /// Updates the Tx byte counter and <see cref="LastTxTime"/>. Thread-safe: the
    /// transport reference is read under the internal lock.
    /// </summary>
    /// <param name="plaintextPacket">The plaintext packet bytes to encrypt.</param>
    /// <param name="localIndex">
    /// The 4-byte session index written into the packet header's receiver-index field
    /// (callers pass the peer's remote index, identifying our session to the
    /// receiver).
    /// </param>
    /// <returns>The encrypted WireGuard data message (16-byte header + ciphertext).</returns>
    /// <exception cref="InvalidOperationException">Thrown when no transport is installed.</exception>
    public byte[] EncryptPacket(byte[] plaintextPacket, uint localIndex)
    {
        // The transport reference is read under the same _lock, mutually exclusive
        // with SetTransport/ResetTransport/Dispose: this avoids reading a transport
        // instance that has already been disposed (keys zeroed), which would encrypt
        // with an all-zero key or crash from a race.
        WireGuardTransport transport;
        lock (_lock)
        {
            transport = _transport ?? throw new InvalidOperationException("Transport not initialized");
        }
        Interlocked.Add(ref _txBytes, (ulong)plaintextPacket.Length);
        LastTxTime = DateTime.UtcNow;
        return transport.EncryptPacket(plaintextPacket, localIndex);
    }

    /// <summary>
    /// Decrypts one inbound data packet using the current transport. Updates the Rx
    /// byte counter and <see cref="LastRxTime"/>. Thread-safe: the transport reference
    /// is read under the internal lock.
    /// </summary>
    /// <param name="encryptedPacket">The raw WireGuard data message (at least 16 bytes).</param>
    /// <param name="remoteIndex">
    /// When this method returns, the 4-byte session index read from the packet header
    /// (offset 4) — the receiver index identifying which of the receiver's sessions
    /// the packet belongs to.
    /// </param>
    /// <returns>The decrypted plaintext packet bytes.</returns>
    /// <exception cref="InvalidOperationException">Thrown when no transport is installed.</exception>
    /// <exception cref="ArgumentException">Thrown when the packet is too short or not a data packet.</exception>
    /// <exception cref="System.Security.Cryptography.CryptographicException">Thrown when authentication fails.</exception>
    /// <exception cref="InvalidOperationException">Thrown when a replay or invalid counter is detected.</exception>
    public byte[] DecryptPacket(byte[] encryptedPacket, out uint remoteIndex)
    {
        WireGuardTransport transport;
        lock (_lock)
        {
            transport = _transport ?? throw new InvalidOperationException("Transport not initialized");
        }
        Interlocked.Add(ref _rxBytes, (ulong)encryptedPacket.Length);
        LastRxTime = DateTime.UtcNow;
        return transport.DecryptPacket(encryptedPacket, out remoteIndex);
    }

    /// <summary>
    /// Attempts to decrypt an inbound packet with the retired (previous) transport
    /// generations, newest first — the grace path for packets that arrive right after
    /// a rekey under the just-replaced keys.
    /// </summary>
    /// <param name="encryptedPacket">The raw WireGuard data message to decrypt.</param>
    /// <param name="remoteIndex">
    /// When this method returns successfully, the 4-byte session index from the packet
    /// header; set to 0 when decryption fails.
    /// </param>
    /// <returns>
    /// The decrypted plaintext on success (Rx counters and <see cref="LastRxTime"/>
    /// updated); <c>null</c> when there are no unexpired retired transports or none of
    /// them can decrypt the packet.
    /// </returns>
    public byte[]? TryDecryptWithPreviousTransport(byte[] encryptedPacket, out uint remoteIndex)
    {
        remoteIndex = 0;

        // [VM-SESSION-COLLAPSE-GRACE 2026-11-08] Try the most recent retired
        // transports in order (newest → oldest). The lock is released after taking
        // the snapshot, before decrypting: DecryptPacket can be slow and must not
        // hold _lock for long. Disposed transports never appear in the snapshot
        // (PruneRetiredTransports runs under the lock).
        List<(WireGuardTransport Transport, DateTime Expiry)> snapshot;
        lock (_lock)
        {
            PruneRetiredTransports();
            if (_retiredTransports.Count == 0)
            {
                return null;
            }
            snapshot = new List<(WireGuardTransport, DateTime)>(_retiredTransports);
        }

        foreach (var entry in snapshot)
        {
            try
            {
                var plaintext = entry.Transport.DecryptPacket(encryptedPacket, out remoteIndex);
                Interlocked.Add(ref _rxBytes, (ulong)plaintext.Length);
                LastRxTime = DateTime.UtcNow;
                return plaintext;
            }
            catch
            {
                // This key generation does not match; fall through to an older generation
            }
        }

        remoteIndex = 0;
        return null;
    }

    /// <summary>
    /// Tears down the peer's transport state: disposes the current transport and all
    /// retired transports (zeroing their keys) and clears the retired queue. A
    /// subsequent <see cref="SetTransport"/> installs a fresh key generation.
    /// Thread-safe: guarded by the internal lock.
    /// </summary>
    public void ResetTransport()
    {
        lock (_lock)
        {
            _transport?.Dispose();
            foreach (var retired in _retiredTransports)
            {
                retired.Transport.Dispose();
            }
            _retiredTransports.Clear();
            _transport = null;
        }
    }
}
