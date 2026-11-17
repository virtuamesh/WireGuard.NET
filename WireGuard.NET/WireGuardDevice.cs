using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Threading.Channels;
using WireGuard.NET.Compression;
using WireGuard.NET.Keys;
using WireGuard.NET.Protocol;
using WireGuard.NET.Protocol.Noise;
using WireGuard.NET.Tun;

namespace WireGuard.NET;

/// <summary>
/// A userspace WireGuard device: owns the UDP socket, the TUN device, peer sessions,
/// handshakes, key rotation, keepalives, replay protection, and the auxiliary transports
/// (DERP / TCP / WebSocket). Moves plaintext IP packets between the TUN device and
/// encrypted WireGuard datagrams.
/// </summary>
/// <remarks>
/// Construct the device from a <see cref="WireGuardConfig"/>, then call
/// <see cref="StartAsync"/> to start it. The same instance can be stopped
/// (<see cref="Stop"/>) and started again; release all resources with <see cref="Dispose"/>.
/// </remarks>
public class WireGuardDevice : IDisposable
{
    private static readonly ByteArrayComparer _comparer = new();
    private readonly WireGuardConfig _config;
    private readonly KeyPair _keyPair;
    private readonly WireGuardHandshake _wireGuardHandshake;
    private readonly HandshakeManager _handshakeManager;
    private readonly ConnectionManager _connectionManager;
    private UdpClient? _udpClient;
    private UdpClient? _sendUdpClient;
    private bool _useSendUdpClient;

    /// <summary>
    /// [VM-WG-PROTECT 2026-11-05] Protection hook invoked for every UDP socket right after
    /// creation (Android: VpnService.Protect(fd)).
    /// The client app itself lives inside the VPN's UID range: once a mesh route overlapping
    /// the physical LAN is installed (e.g. a remote router 10.0.0.0/24 that sits on the same
    /// LAN as this machine), WireGuard's own UDP traffic toward 10.0.0.x:51820 gets pulled
    /// back into this process's TUN, forming a loop in which the peer handshake can never
    /// succeed. The correct fix is to protect each socket individually (same approach as
    /// tailscaled), NOT to use AddDisallowedApplication to exclude the whole app from the
    /// VPN (that would let diagnostic/tool traffic inside the app bypass the tunnel,
    /// manifesting as "ping from inside the app cannot reach mesh addresses").
    /// </summary>
    public Action<System.Net.Sockets.Socket>? UdpSocketProtector { get; set; }

    // ================= [VM-STUN-ON-WG-SOCKET 2026-11-05] =================
    // Only a STUN probe issued from the same UDP socket as the data plane yields a
    // public endpoint that peers can actually dial.
    private readonly List<string> _stunServers = new();   // host:port (hostnames are supported, resolved just before sending)
    // The pending-transaction table tracks the originating server: several STUN servers =
    // several destination addresses = the NAT assigns **different** public ports to the
    // same socket. With the previous "whoever replies last wins" behavior, the endpoint
    // reported to the control plane kept flapping between two ports (measured 61597 ↔ 43051
    // on a 20s cycle), triggering repeated peer probing and netmap pushes.
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, (DateTime At, string Server)> _stunPending
        = new(StringComparer.Ordinal);
    private IPEndPoint? _stunPublicEndpoint;

    /// <summary>[VM-STUN-STABLE-ENDPOINT 2026-11-09] Which STUN server produced the current endpoint, and when it was confirmed.</summary>
    private string? _stunPublicEndpointSource;
    private DateTime _stunPublicEndpointAt = DateTime.MinValue;

    /// <summary>[VM-STUN-STABLE-ENDPOINT] Source-switch threshold: another server's mapping is accepted only after the preferred server has been silent for this long.</summary>
    private static readonly TimeSpan StunEndpointSourceGrace = TimeSpan.FromMinutes(5);
    private Task? _stunProbeTask;

    /// <summary>
    /// The most recent public mapping observed on the WireGuard socket (null = not yet
    /// observed / already expired). This is the "authoritative srflx": its port matches
    /// the data-plane 5-tuple and it can be distributed to peers directly.
    /// </summary>
    public IPEndPoint? StunPublicEndpoint => Volatile.Read(ref _stunPublicEndpoint);

    /// <summary>Raised when the public mapping is updated (first observation or port change).</summary>
    public event EventHandler<IPEndPoint>? StunPublicEndpointChanged;

    /// <summary>
    /// Sets the STUN servers (in host:port form); takes effect from the next Start and can
    /// be updated at any time. Passing an empty list disables probing (conservative
    /// approach: rather report no public endpoint than report a wrong one).
    /// </summary>
    /// <param name="servers">STUN server addresses in "host:port" form, or null/empty to disable STUN probing.</param>
    public void SetStunServers(IEnumerable<string>? servers)
    {
        lock (_stunServers)
        {
            _stunServers.Clear();
            if (servers != null)
            {
                foreach (var s in servers)
                {
                    if (string.IsNullOrWhiteSpace(s)) continue;
                    var trimmed = s.Trim();
                    if (!trimmed.Contains(':')) continue;
                    if (!_stunServers.Contains(trimmed)) _stunServers.Add(trimmed);
                }
            }
        }
    }
    // Whether the primary UDP socket is dual-stack (IPv6 + DualMode).
    // A dual-stack socket can send and receive both IPv4 and IPv6 traffic, which fixes
    // "Address family not supported by protocol" errors when a peer endpoint is IPv6.
    private bool _isDualMode;
    private ITunDevice? _tunDevice;
    private readonly ConcurrentDictionary<byte[], WireGuardPeer> _peers = new(_comparer);
    private readonly ConcurrentDictionary<uint, PeerSessionInfo> _indexToPeer = new();
    private readonly KeepaliveManager _keepaliveManager;
    private readonly KeyRotationManager _keyRotationManager;
    private readonly CookieProtector _cookieProtector;
    private readonly RateLimiter _rateLimiter;
    private CancellationTokenSource? _cancellationTokenSource;
    private bool _disposed;
    private bool _running;
    private bool _stopping;
    private readonly bool _useMockTunDevice;
    private DateTime _lastDuplicateResponseLog = DateTime.MinValue;
    private int _duplicateResponseCount;
    private DateTime _lastNoSessionLog = DateTime.MinValue;
    private int _noSessionCount;
    private readonly ConcurrentDictionary<byte[], DateTime> _lastRehandshakeTime = new(_comparer);
    // [VM-FIRST-CONNECT 2026-10-21] First-send anchor for peers that have never completed
    // a handshake: when a peer keeps sending packets but gets no handshake response at all
    // for longer than UnconfirmedHandshakeFallbackDelay, it falls back to DERP quickly. It
    // is cleared as soon as the handshake succeeds (LastHandshake/LastRx refresh); expired
    // anchors (10min) are reclaimed by the periodic cleanup.
    private readonly ConcurrentDictionary<byte[], DateTime> _firstUnconfirmedSendTime = new(_comparer);
    private readonly List<Task> _runningTasks = [];
    private readonly object _taskLock = new();
    private readonly ConcurrentDictionary<IPEndPoint, UdpAuthFailureTracker> _udpAuthFailures = new();
    private static readonly TimeSpan UdpAuthFailureWindow = TimeSpan.FromMinutes(2);
    private const int MaxUdpAuthFailures = 5;

    // These two channels get TryComplete'd when their read loops exit (see
    // TunReadLoopAsync/UdpReceiveLoopAsync), so they MUST be recreated on every StartAsync;
    // otherwise a Stop→Start cycle on the same instance loses 100% of packets (zombie channels).
    private Channel<byte[]> _tunPacketChannel = CreateTunPacketChannel();

    private Channel<(byte[] Packet, IPEndPoint RemoteEndPoint)> _udpPacketChannel = CreateUdpPacketChannel();

    private static Channel<byte[]> CreateTunPacketChannel() => Channel.CreateBounded<byte[]>(new BoundedChannelOptions(16384)
    {
        SingleReader = true,
        SingleWriter = true,
        FullMode = BoundedChannelFullMode.DropOldest
    });

    private static Channel<(byte[] Packet, IPEndPoint RemoteEndPoint)> CreateUdpPacketChannel() =>
        Channel.CreateBounded<(byte[], IPEndPoint)>(new BoundedChannelOptions(16384)
        {
            SingleReader = true,
            SingleWriter = true,
            FullMode = BoundedChannelFullMode.DropOldest
        });

    private readonly Channel<(byte[] EncryptedPacket, WireGuardPeer Peer)> _sendChannel =
        Channel.CreateBounded<(byte[], WireGuardPeer)>(new BoundedChannelOptions(16384)
        {
            SingleReader = true,
            SingleWriter = false,
            FullMode = BoundedChannelFullMode.DropNewest
        });

    private readonly Channel<(byte[] PeerPublicKey, byte[] Packet)> _derpPacketChannel =
        Channel.CreateBounded<(byte[], byte[])>(new BoundedChannelOptions(8192)
        {
            SingleReader = true,
            SingleWriter = false,
            FullMode = BoundedChannelFullMode.DropNewest
        });

    private readonly ConcurrentDictionary<byte[], HashSet<uint>> _peerToIndices = new(_comparer);

    /// <summary>
    /// Raised when an encrypted packet for a DERP-relayed peer must be sent; the host is
    /// responsible for delivering the datagram via its DERP relay connection.
    /// </summary>
    public event EventHandler<(byte[] PeerPublicKey, byte[] Packet)>? SendPacketViaDerp;

    /// <summary>Raised when an encrypted packet for a peer marked as TCP transport must be sent.</summary>
    public event EventHandler<(byte[] PeerPublicKey, byte[] Packet)>? SendPacketViaTcp;

    /// <summary>Raised when an encrypted packet for a peer marked as WebSocket transport must be sent.</summary>
    public event EventHandler<(byte[] PeerPublicKey, byte[] Packet)>? SendPacketViaWebSocket;

    /// <summary>Raised for every device log entry; the level is one of "DBG", "INF", "WRN", "ERR".</summary>
    public event EventHandler<(string Level, string Message)>? OnLog;

    /// <summary>
    /// Optional filter applied to plaintext IP packets read from TUN, before they are
    /// encrypted and routed to a peer. Return false to drop the packet.
    /// </summary>
    public Func<byte[], bool>? OutboundPacketFilter { get; set; }

    /// <summary>
    /// Optional filter applied to decrypted plaintext IP packets, before they are written
    /// to TUN. Receives (peer public key, packet); return false to drop the packet.
    /// </summary>
    public Func<byte[], byte[], bool>? InboundPacketFilter { get; set; }

    /// <summary>
    /// Packet compressor: compresses IP packets after they are read from the TUN layer and
    /// before WireGuard encryption; decompresses after decryption and before writing to
    /// TUN. Null disables compression.
    /// </summary>
    public IPacketCompressor? PacketCompressor { get; set; }

    private void Log(string level, string message)
    {
        OnLog?.Invoke(this, (level, message));
    }

    // ---- Hot-path log throttling ----
    // Key background (2026-09-29 production case on a Silicon Valley node): after a node
    // that had been offline for a long time reconnected, expired counters in the peer's
    // old session produced a per-packet "Replay attack detected" WRN flood; combined with
    // per-packet DBG string building (BitConverter.ToString hex conversion + full
    // _indexToPeer scan string building), the log flood saturated the CPU / thread pool and
    // queued the host's sinks, slowing /api/status and other local APIs to 3.4s~7.4s
    // (clients with a 3s timeout mis-reported "Local API unreachable").
    // Fix: throttle same-key hot-path logs per window (only one entry is logged within a
    // window, together with the number of suppressed entries).
    private readonly ConcurrentDictionary<string, (DateTime WindowStartUtc, int Suppressed)> _logThrottle = new();
    private static readonly TimeSpan LogThrottleWindow = TimeSpan.FromSeconds(30);
    // The key space may be unbounded (e.g. receiverIndex grows as sessions rotate); when the limit is exceeded the map is simply cleared and counting restarts.
    private const int LogThrottleMapMax = 256;

    /// <summary>Window throttling: returns true when this entry should be logged; suppressed is the number of entries suppressed within the current window.</summary>
    private bool ShouldLogThrottled(string key, out int suppressed)
    {
        var now = DateTime.UtcNow;
        var log = true;
        var suppressedLocal = 0;
        _logThrottle.AddOrUpdate(key,
            _ => (now, 0),
            (_, prev) =>
            {
                if (now - prev.WindowStartUtc < LogThrottleWindow)
                {
                    log = false;
                    suppressedLocal = prev.Suppressed + 1;
                    return (prev.WindowStartUtc, suppressedLocal);
                }
                return (now, 0);
            });
        suppressed = suppressedLocal;
        if (_logThrottle.Count > LogThrottleMapMax)
        {
            _logThrottle.Clear();
        }
        return log;
    }

    /// <summary>
    /// Hot-path DBG logging switch (default false; per-packet logging only when the host
    /// explicitly enables it).
    /// Key background: the log message is pre-built with $"..." at the call site (including
    /// expensive BitConverter.ToString hex conversions), so the per-packet CPU/GC cost is
    /// paid even when DBG is filtered out downstream.
    /// </summary>
    public bool IsDebugEnabled { get; set; }

    // Dual-stack socket endpoint normalization: a DualMode IPv6 socket bound to [::]
    // uses IPv4-mapped IPv6 addresses (::ffff:x.x.x.x) when sending/receiving IPv4 traffic.
    // Without endpoint normalization:
    //   - Sending: SendTo with an IPv4 endpoint on a DualMode socket may throw EAFNOSUPPORT
    //   - Receiving: peer.Endpoint gets stored as ::ffff:x.x.x.x, which never matches later
    //     IPv4 endpoint comparisons
    // Therefore IPv4 endpoints are mapped to IPv6 before sending and restored to IPv4
    // after receiving, keeping the stored form consistent.

    private IPEndPoint? NormalizeSendEndpoint(IPEndPoint? endpoint)
    {
        if (!_isDualMode || endpoint == null) return endpoint;
        var addr = endpoint.Address;
        if (addr.AddressFamily == AddressFamily.InterNetwork)
        {
            // IPv4 -> IPv4-mapped IPv6, so the DualMode socket sends an IPv4 datagram
            var mapped = addr.IsIPv4MappedToIPv6 ? addr : addr.MapToIPv6();
            return new IPEndPoint(mapped, endpoint.Port);
        }
        return endpoint;
    }

    private IPEndPoint? NormalizeReceiveEndpoint(IPEndPoint? endpoint)
    {
        if (!_isDualMode || endpoint == null) return endpoint;
        var addr = endpoint.Address;
        if (addr.AddressFamily == AddressFamily.InterNetworkV6 && addr.IsIPv4MappedToIPv6)
        {
            // IPv4-mapped IPv6 -> restored to IPv4, keeping peer.Endpoint storage consistent
            return new IPEndPoint(addr.MapToIPv4(), endpoint.Port);
        }
        return endpoint;
    }

    /// <summary>
    /// Initializes a new WireGuard device with the specified configuration.
    /// A default <see cref="Compression.PacketCompressor"/> is installed so that every
    /// device instance can decompress inbound compressed frames.
    /// </summary>
    /// <param name="config">The device configuration; the private key must be exactly 32 bytes.</param>
    /// <param name="useMockTunDevice">When true, <see cref="CreateTunDevice"/> creates a mock TUN device instead of a platform-specific one.</param>
    /// <exception cref="ArgumentException">Thrown when <paramref name="config"/>.PrivateKey is null or not exactly 32 bytes long.</exception>
    public WireGuardDevice(WireGuardConfig config, bool useMockTunDevice = false)
    {
        _config = config;

        if (config.PrivateKey == null || config.PrivateKey.Length != 32)
        {
            throw new ArgumentException("Private key must be 32 bytes", nameof(config.PrivateKey));
        }

        _keyPair = new KeyPair(config.PrivateKey);
        _wireGuardHandshake = new WireGuardHandshake(_keyPair.PrivateKey);
        _wireGuardHandshake.OnDebugLog += (sender, msg) => Log("DBG", $"[Handshake] {msg}");
        // CPU-amplification protection against forged MAC1-valid initiations: a global token
        // bucket keyed by peer public key, injected into the handshake layer and applied
        // before Noise decryption attempts (at most 3 X25519 operations per candidate).
        _rateLimiter = new RateLimiter();
        _wireGuardHandshake.PeerRateLimiter = _rateLimiter;
        _handshakeManager = new HandshakeManager();
        _connectionManager = new ConnectionManager(_peers);
        _keepaliveManager = new KeepaliveManager();
        _keyRotationManager = new KeyRotationManager();
        _cookieProtector = new CookieProtector();
        _useMockTunDevice = useMockTunDevice;

        // [FIX 2026-10-15] Initialize the compressor by default: guarantee that **every**
        // device instance can decompress.
        // Background: asymmetric compression enablement once caused a production outage —
        // NodeManager unconditionally called EnablePacketCompression(name, true);
        // WireGuardNETService (Linux CLI) overrode the method, but AndroidWireGuardService
        // did not override it (Base has an empty implementation), so Android's
        // PacketCompressor was null; [0x01] frames compressed by the Linux end were written
        // to TUN as if they were IP packets on Android, and the kernel rejected them with
        // EINVAL → all TCP data in the ubuntuserver24→Android direction was lost
        // (ping worked, RDP failed with 0x7, SSH disconnected). IsEnabled defaults to true,
        // matching NodeManager's "compression enabled by default" semantics; decompression
        // no longer depends on IsEnabled (see PacketCompressor.Decompress).
        PacketCompressor = new WireGuard.NET.Compression.PacketCompressor();

        _cookieProtector.Initialize(_keyPair.PublicKey);

        var pubKeyPreview = BitConverter.ToString(_keyPair.PublicKey)[..Math.Min(40, _keyPair.PublicKey.Length * 3)];
        System.Diagnostics.Debug.WriteLine($"[WireGuardDevice] Initialized with PublicKey={pubKeyPreview}...");

        _keyRotationManager.KeyRotationNeeded += OnKeyRotationNeeded;
        _connectionManager.PeerTimedOut += OnPeerTimedOut;
    }

    private Timer? _indexCleanupTimer;
    private static readonly TimeSpan IndexCleanupInterval = TimeSpan.FromMinutes(2);
    private const int MaxIndexMappingsPerPeer = 10;
    private const int MaxTotalIndexMappings = 5000;
    // Zombie threshold for incomplete mappings (those still awaiting a handshake response):
    // handshake RTT is on the order of milliseconds and HandshakeManager's fastest
    // retransmit interval is 250ms, so a mapping still incomplete after 15s is treated as a
    // zombie whose response was lost (remote=0/completed=False).
    private static readonly TimeSpan PendingMappingStaleTimeout = TimeSpan.FromSeconds(15);
    /// <summary>
    /// UDP dead-link detection: only while there is active sending (a packet sent within the
    /// last 10s) AND both LastRxTime and LastHandshake have had no updates for this long is
    /// the session considered silently dropped by the peer, triggering a switch to DERP and
    /// a re-handshake. Requiring LastHandshake to be stale too is essential: a re-handshake
    /// response itself refreshes LastRxTime, so checking LastRxTime alone creates a
    /// self-sustaining "detect → re-handshake → response feeds liveness → detect again" loop
    /// (redundant re-handshake storms across the whole mesh every 30s).
    /// Instance property so tests and deployments can tune it.
    /// [FIX 2026-10-14] 60s->30s: with DERP keepalive at 10s and UDP keepalive at 20s, 30s
    /// without any response is enough to declare the link dead, shortening the black-hole
    /// window (production: Android↔ubuntuserver24 dead links blacked out for 60-143s, during
    /// which all TCP broke while standalone ICMP packets still got through, manifesting as
    /// "ping works but RDP/SSH fail").
    /// </summary>
    public TimeSpan UdpDeadLinkTimeout { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// [VM-FIRST-CONNECT 2026-10-21] Fast DERP fallback delay for peers that have never
    /// completed a handshake: when a peer has an endpoint but gets no handshake response at
    /// all (neither LastHandshake nor LastRx) for 8s of continuous sending, the endpoint is
    /// most likely dead (a stale NAT mapping after a long offline period / an unreachable
    /// peer); traffic switches to DERP immediately and the handshake is re-initiated via the
    /// relay, instead of waiting for the full handshake timeout (~90s). Instance property so
    /// tests and deployments can tune it.
    /// </summary>
    public TimeSpan UnconfirmedHandshakeFallbackDelay { get; set; } = TimeSpan.FromSeconds(8);

    /// <summary>Gets the name of the underlying TUN device, or <c>null</c> if no TUN device has been created or assigned.</summary>
    public string? TunInterfaceName => _tunDevice?.Name;

    /// <summary>
    /// Assigns an already-created TUN device (e.g. a platform adapter owned by the host)
    /// instead of creating one via <see cref="CreateTunDevice"/>.
    /// </summary>
    /// <param name="tunDevice">The TUN device to use for the tunnel.</param>
    public void SetTunDevice(ITunDevice tunDevice)
    {
        _tunDevice = tunDevice;
    }

    /// <summary>
    /// Creates the platform-specific TUN device (or a mock, when the device was constructed
    /// with <c>useMockTunDevice: true</c>), applying the MTU from the configuration.
    /// </summary>
    /// <param name="tunDeviceName">The interface name of the device to create.</param>
    public void CreateTunDevice(string tunDeviceName = "WireGuard.NET")
    {
        _tunDevice = TunDeviceFactory.Create(tunDeviceName, _useMockTunDevice, mtu: _config.Mtu);
    }

    /// <summary>
    /// Starts the device: binds the UDP socket, applies the peer configuration, starts all
    /// managers and background loops (TUN read/write, UDP send/receive, keepalive, key
    /// rotation, index cleanup, STUN probing), and initiates handshakes with the configured
    /// peers. Calling this on an already-running instance is a no-op.
    /// </summary>
    /// <returns>A task that completes once the device is started; the background loops keep running afterwards.</returns>
    /// <remarks>May be called again after <see cref="Stop"/> to restart the same instance.</remarks>
    public Task StartAsync()
    {
        if (_running) return Task.CompletedTask;
        // [VM-UDP-SINGLE-BIND 2026-11-01] When the same instance gets StartAsync'd again
        // (page reconnects, state-machine fallback retries), binding once more without
        // closing the old socket leaves two SO_REUSEADDR bindings on the same port; inbound
        // handshakes may land on the old (stale-key) socket and be silently dropped,
        // manifesting as "the log keeps showing Direct-path probe FAILED, only DERP works".
        // Release the previous round's leftover sockets/clients first, so a given instance
        // always holds at most one binding.
        if (_udpClient != null || _sendUdpClient != null)
        {
            Log("WRN", "StartAsync: previous UDP socket still bound, closing before re-bind");
            try { _udpClient?.Close(); } catch { }
            _udpClient = null;
            try { _sendUdpClient?.Close(); } catch { }
            _sendUdpClient = null;
            _useSendUdpClient = false;
        }

        Log("INF", $"StartAsync: binding UDP to port {_config.ListenPort}");
        // Key fix: use a dual-stack socket (IPv6 + DualMode) instead of an IPv4-only socket.
        // The default UdpClient() uses AddressFamily.InterNetwork (IPv4); with an IPv6 peer
        // endpoint SendTo throws EAFNOSUPPORT -> DERP fallback -> DERP also fails -> peer
        // unreachable. A dual-stack socket binds to [::] (IPv6Any) with DualMode enabled and
        // can send and receive both IPv4/IPv6.
        try
        {
            _udpClient = new UdpClient(AddressFamily.InterNetworkV6);
            _udpClient.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            _udpClient.Client.DualMode = true;
            _udpClient.Client.Bind(new IPEndPoint(IPAddress.IPv6Any, _config.ListenPort));
            _isDualMode = true;
            Log("INF", "StartAsync: dual-stack UDP (IPv6+DualMode) bound");
        }
        catch (Exception ex)
        {
            // Fallback: some environments don't support DualMode; fall back to IPv4-only
            Log("WRN", $"Dual-mode UDP bind failed ({ex.Message}), falling back to IPv4-only");
            _udpClient?.Dispose();
            _udpClient = new UdpClient();
            _udpClient.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            _udpClient.Client.Bind(new IPEndPoint(IPAddress.Any, _config.ListenPort));
            _isDualMode = false;
        }
        // Enlarging the socket buffers is best-effort: platforms such as macOS may reject
        // 8MB due to maxsockbuf limits, so fall back level by level; never blocks startup.
        foreach (var (rcv, snd) in new[] { (8 * 1024 * 1024, 2 * 1024 * 1024), (2 * 1024 * 1024, 1024 * 1024), (256 * 1024, 256 * 1024) })
        {
            try
            {
                _udpClient.Client.ReceiveBufferSize = rcv;
                _udpClient.Client.SendBufferSize = snd;
                break;
            }
            catch (SocketException)
            {
            }
        }
        // [VM-WG-PROTECT] Best-effort protect (failure doesn't block: some platforms / non-VPN scenarios return false)
        TryProtectUdpSocket(_udpClient);
        TryProtectUdpSocket(_sendUdpClient);


        Log("INF", "StartAsync: UDP bound, configuring peers");
        _cancellationTokenSource = new CancellationTokenSource();

        // [VM-STUN-ON-WG-SOCKET] Periodically probe the public mapping on the same socket.
        // Must happen after _cancellationTokenSource is created: an earlier version ran it
        // before, StartAsync threw NullReferenceException and the whole tunnel failed to
        // come up (observed on a real device 2026-11-06 00:22).
        StartStunProbeLoop(_cancellationTokenSource.Token);

        // Recreate the channels that were TryComplete'd during the previous Stop, fixing
        // packet loss on same-instance restart. Channel instances are passed as parameters
        // into the background loops: loops from the previous round TryComplete the
        // instance they consume, never the new fields of the same name created this round
        // (otherwise the new channels would be completed prematurely by zombie loops after
        // Stop→Start, silently dropping all packets and blocking re-handshakes).
        var tunChannel = CreateTunPacketChannel();
        var udpChannel = CreateUdpPacketChannel();
        _tunPacketChannel = tunChannel;
        _udpPacketChannel = udpChannel;

        _running = true;
        _stopping = false;

        foreach (var peerConfig in _config.Peers)
        {
            var peer = new WireGuardPeer(peerConfig.PublicKey)
            {
                PresharedKey = peerConfig.PresharedKey,
                Endpoint = peerConfig.Endpoint,
                PersistentKeepalive = peerConfig.PersistentKeepalive
            };

            foreach (var allowedIp in peerConfig.AllowedIPs)
            {
                peer.AllowedIPs.AddAllowedIP(allowedIp.Address, allowedIp.PrefixLength);
            }

            _peers[peerConfig.PublicKey] = peer;
            _keepaliveManager.AddPeer(peerConfig.PublicKey, peerConfig.PersistentKeepalive);
        }

        Log("INF", $"StartAsync: peers configured ({_config.Peers.Count}), starting managers");
        _keepaliveManager.SendKeepalive += OnSendKeepalive;
        _keepaliveManager.Start();

        _handshakeManager.SendHandshakeMessage += OnSendHandshakeMessage;
        _handshakeManager.HandshakeTimedOut += OnHandshakeTimedOut;
        _handshakeManager.HandshakeRetryNeeded += OnHandshakeRetryNeeded;
        _handshakeManager.DerpFallbackNeeded += OnDerpFallbackNeeded;
        _handshakeManager.Start();

        _keyRotationManager.Start();
        _connectionManager.Start();

        _cookieProtector.StartCleanup();
        _rateLimiter.StartCleanup();
        _indexCleanupTimer = new Timer(CleanupIndexMappings, null, IndexCleanupInterval, IndexCleanupInterval);
        _statsTimer = new Timer(LogStats, null, TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(30));
        _directPathProbeTimer = new Timer(ProbeDirectPath, null, DirectPathProbeInterval, DirectPathProbeInterval);

        Log("INF", $"StartAsync: initiating handshakes with {_config.Peers.Count} peers");
        foreach (var peerConfig in _config.Peers)
        {
            if (peerConfig.Endpoint != null)
            {
                InitiateHandshakeWithPeer(peerConfig.PublicKey, peerConfig.Endpoint);
            }
            else if (SendPacketViaDerp != null)
            {
                InitiateHandshakeWithPeer(peerConfig.PublicKey, null);
            }
        }

        if (_tunDevice != null)
        {
            Log("INF", "StartAsync: starting TUN device");
            _tunDevice.Start();
            Log("INF", "StartAsync: TUN device started, setting addresses");

            if (_config.Address != null)
            {
                _tunDevice.SetAddress(_config.Address.ToString(), _config.AddressPrefixLength);
                Log("INF", $"StartAsync: IPv4 address set to {_config.Address}/{_config.AddressPrefixLength}");
            }

            if (_config.AddressV6 != null)
            {
                _tunDevice.SetAddressIPv6(_config.AddressV6.ToString(), _config.AddressV6PrefixLength);
                Log("INF", $"StartAsync: IPv6 address set to {_config.AddressV6}/{_config.AddressV6PrefixLength}");
            }

            TrackBackgroundTask(TunReadLoopAsync(tunChannel, _cancellationTokenSource.Token));
            TrackBackgroundTask(TunProcessLoopAsync(tunChannel, _cancellationTokenSource.Token));
            Log("INF", "StartAsync: TUN read/process loops tracked");
        }

        TrackBackgroundTask(UdpReceiveLoopAsync(udpChannel, _cancellationTokenSource.Token));
        TrackBackgroundTask(UdpProcessLoopAsync(udpChannel, _cancellationTokenSource.Token));
        TrackBackgroundTask(DerpProcessLoopAsync(_cancellationTokenSource.Token));
        TrackBackgroundTask(SendLoopAsync(_cancellationTokenSource.Token));
        Log("INF", "StartAsync: UDP receive/process/send loops tracked, returning");

        return Task.CompletedTask;
    }

    private void TrackBackgroundTask(Task task)
    {
        lock (_taskLock)
        {
            _runningTasks.Add(task);
        }

        _ = task.ContinueWith(t =>
        {
            lock (_taskLock)
            {
                _runningTasks.Remove(t);
            }
        }, TaskContinuationOptions.ExecuteSynchronously);
    }

    private void AddIndexMapping(uint index, PeerSessionInfo info)
    {
        _indexToPeer[index] = info;
        var indices = _peerToIndices.GetOrAdd(info.PeerPublicKey, _ => new HashSet<uint>());
        lock (indices)
        {
            indices.Add(index);
        }
    }

    /// <summary>
    /// NoiseHandshakeState holds cloned copies of the device private key/PSK; it must be
    /// Disposed (zeroed) when an index mapping is removed, otherwise the key material stays
    /// on the managed heap until GC. Every path that removes an _indexToPeer entry should call this.
    /// </summary>
    private static void DisposeSessionHandshakeState(PeerSessionInfo? info)
    {
        info?.HandshakeState?.Dispose();
    }

    /// <summary>
    /// Purges the peer's zombie incomplete index mappings (left behind when a handshake
    /// response was lost; identified by remote=0/completed=False).
    /// Handshake RTT is on the order of milliseconds, so an incomplete mapping alive longer
    /// than PendingMappingStaleTimeout is a zombie; keeping it around blocks the
    /// re-handshake decision on ProcessData's mapping-miss path, causing data packets to be
    /// silently dropped for a long time after the peer's session is invalidated (e.g. a
    /// server restart).
    /// </summary>
    private void PurgeStalePendingIndexMappings(byte[] peerPublicKey, DateTime now)
    {
        foreach (var kvp in _indexToPeer)
        {
            if (!kvp.Value.IsCompleted &&
                now - kvp.Value.CreatedAt > PendingMappingStaleTimeout &&
                _comparer.Equals(kvp.Value.PeerPublicKey, peerPublicKey))
            {
                if (_indexToPeer.TryRemove(kvp.Key, out var staleInfo))
                {
                    DisposeSessionHandshakeState(staleInfo);
                    if (_peerToIndices.TryGetValue(peerPublicKey, out var staleIndices))
                    {
                        lock (staleIndices)
                        {
                            staleIndices.Remove(kvp.Key);
                        }
                    }
                    Log("DBG", $"Purged stale pending index mapping {kvp.Key} for peer {BitConverter.ToString(peerPublicKey)[..20]}... (age {(int)(now - kvp.Value.CreatedAt).TotalSeconds}s)");
                }
            }
        }
    }

    private void InitiateHandshakeWithPeer(byte[] peerPublicKey, IPEndPoint? endpoint)
    {
        try
        {
            if (!_peers.TryGetValue(peerPublicKey, out var peer))
            {
                return;
            }

            // [VM-HS-BACKOFF 2026-11-08] Exponential backoff for consecutive handshake failures.
            //
            // Background: when the peer is offline (phone locked, laptop shut down) there was
            // no backoff at all — WireGuard's REKEY_ATTEMPT_TIME (90s) elapsed and the
            // handshake restarted immediately. Measured on an exit node: three offline peers
            // (iPhone/Redmi/mac-mini) each got one handshake attempt every 95 seconds, 1047
            // attempts over 10 hours, 100% failing, each one adding/removing a pending index
            // mapping (persistent session-table churn).
            // Per-peer consecutive failure counts now back off 0s → 30s → 2m → 5m → 15m (capped).
            if (_handshakeFailureCount.TryGetValue(peerPublicKey, out var failures) && failures > 0)
            {
                var backoff = GetHandshakeBackoff(failures);
                if (_handshakeNextAllowedAt.TryGetValue(peerPublicKey, out var nextAllowed) &&
                    DateTime.UtcNow < nextAllowed)
                {
                    Log("DBG", $"Handshake backoff active for peer {BitConverter.ToString(peerPublicKey)[..20]}... " +
                        $"(failures={failures}, retry in {(nextAllowed - DateTime.UtcNow).TotalSeconds:F0}s)");
                    return;
                }
            }

            var isDerpInitiation = endpoint == null;
            
            if (_handshakeManager.IsHandshakePending(peerPublicKey))
            {
                var existingIsDerp = _handshakeManager.IsPendingDerpInitiated(peerPublicKey);
                if (existingIsDerp == isDerpInitiation)
                {
                    return;
                }

                _handshakeManager.ClearHandshake(peerPublicKey);
            }

            var (initiationMessage, handshakeState, localIndex) = _wireGuardHandshake.CreateInitiation(
                peer.PublicKey, peer.PresharedKey,
                cookie: endpoint != null ? _cookieProtector.GetCookieForEndpoint(endpoint) : null);

            if (endpoint != null)
            {
                peer.Endpoint = endpoint;
            }

            RemoveOldHandshakeIndexMappings(peerPublicKey, localIndex);

            AddIndexMapping(localIndex, new PeerSessionInfo
            {
                PeerPublicKey = peerPublicKey,
                HandshakeState = handshakeState,
                LocalIndex = localIndex
            });

            _handshakeManager.InitiateHandshake(peerPublicKey, initiationMessage, handshakeState, localIndex, isDerpInitiated: isDerpInitiation);
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[WireGuardDevice] Failed to initiate handshake: {ex.GetType().Name}: {ex.Message}");
        }
    }

    private void RemoveOldHandshakeIndexMappings(byte[] peerPublicKey, uint newIndex)
    {
        var now = DateTime.UtcNow;
        if (_peerToIndices.TryGetValue(peerPublicKey, out var indices))
        {
            lock (indices)
            {
                var toRemove = new List<uint>();
                foreach (var idx in indices)
                {
                    if (idx == newIndex) continue;
                    if (_indexToPeer.TryGetValue(idx, out var info))
                    {
                        // Key fix: use ExpiresAt for expiry, consistent with the previous
                        // transport TTL (30 seconds). Completed mappings are kept until
                        // ExpiresAt so in-flight packets of the old session can still be
                        // routed; incomplete mappings are cleaned after 30 seconds.
                        if (info.IsCompleted)
                        {
                            if (info.ExpiresAt < now)
                                toRemove.Add(idx);
                        }
                        else if ((now - info.CreatedAt) > TimeSpan.FromSeconds(30))
                        {
                            toRemove.Add(idx);
                        }
                    }
                    else
                    {
                        toRemove.Add(idx);
                    }
                }

                foreach (var idx in toRemove)
                {
                    if (_indexToPeer.TryRemove(idx, out var removedInfo))
                    {
                        DisposeSessionHandshakeState(removedInfo);
                    }
                    indices.Remove(idx);
                }
            }
        }
    }

    /// <summary>
    /// [VM-SESSION-COLLAPSE 2026-10-23] Collapses the peer's old session mappings when a new
    /// session is established.
    ///
    /// [VM-SESSION-RETAIN 2026-11-08] Changed from "delete immediately" to "retain with grace":
    /// deleting immediately turned old-session packets still in flight into orphans whose
    /// receiverIndex could no longer be found (ProcessData logs "No-matching-session ...
    /// dropped"), even though the peer layer's previous-generation transport still retained
    /// the keys for 30s — as long as the index mapping was still there, those late packets
    /// could have been decrypted normally. Production on an exit node still showed 8-10
    /// drops per hour.
    ///
    /// Only two categories are cleaned now, with thresholds consistent with
    /// RemoveOldHandshakeIndexMappings to avoid two rule sets fighting each other:
    ///   · old sessions that are completed and past ExpiresAt (30s after creation)
    ///   · zombie pending mappings that are incomplete and created more than 15s ago
    /// </summary>
    private void CollapseStaleSessions(byte[] peerPublicKey, uint keepIndex)
    {
        if (!_peerToIndices.TryGetValue(peerPublicKey, out var indices))
        {
            return;
        }
        var now = DateTime.UtcNow;
        var toRemove = new List<uint>();
        var retained = 0;
        lock (indices)
        {
            foreach (var idx in indices)
            {
                if (idx == keepIndex)
                {
                    continue;
                }
                if (!_indexToPeer.TryGetValue(idx, out var old))
                {
                    continue;
                }

                if (old.IsCompleted)
                {
                    if (old.ExpiresAt < now)
                    {
                        toRemove.Add(idx);
                    }
                    else
                    {
                        // Retained within the grace period: late packets of the old session can still be routed to the peer and decrypted with the previous transport
                        retained++;
                    }
                }
                else
                {
                    // [VM-HS-PENDING-KEEP 2026-11-09] An incomplete pending mapping must not be
                    // deleted just because it was "created more than 15s ago": the handshake
                    // itself stays alive for REKEY_ATTEMPT_TIME (90s), retransmitting at
                    // 250ms~5s intervals, and **retransmissions reuse the same localIndex**.
                    // Once the mapping is deleted, a late response from the peer becomes
                    // "receiverIndex … NOT FOUND", and the local end, believing the handshake
                    // failed, keeps retransmitting — under network switches/weak networks both
                    // sides repeatedly rebuild sessions (measured: all pings lost for 30~60s
                    // after a network switch). Only zombie entries that are no longer the
                    // current pending are cleaned.
                    var pendingIndex = _handshakeManager.GetPendingLocalIndex(peerPublicKey);
                    if (pendingIndex.HasValue && pendingIndex.Value == idx)
                    {
                        retained++;
                        continue;
                    }
                    if ((now - old.CreatedAt) > TimeSpan.FromSeconds(15))
                    {
                        toRemove.Add(idx);
                    }
                }
            }
        }
        foreach (var idx in toRemove)
        {
            if (_indexToPeer.TryRemove(idx, out var stale))
            {
                DisposeSessionHandshakeState(stale);
                lock (indices)
                {
                    indices.Remove(idx);
                }
                // Cleaning only after the grace period has expired is expected behavior, no longer a warning; log only when a zombie pending is genuinely reclaimed early
                Log(stale.IsCompleted ? "DBG" : "WRN",
                    $"[VM-SESSION-COLLAPSE] collapsed stale session idx={idx} (completed={stale.IsCompleted}) keeping idx={keepIndex}");
            }
        }

        if (retained > 0)
        {
            Log("DBG", $"[VM-SESSION-RETAIN] kept {retained} recent session(s) for peer {BitConverter.ToString(peerPublicKey)[..20]}... within 30s grace (avoid dropping in-flight packets)");
        }
    }

    private void RemoveOldIndexMappings(byte[] peerPublicKey)
    {
        if (_peerToIndices.TryRemove(peerPublicKey, out var indices))
        {
            lock (indices)
            {
                foreach (var idx in indices)
                {
                    if (_indexToPeer.TryRemove(idx, out var removedInfo))
                    {
                        DisposeSessionHandshakeState(removedInfo);
                    }
                }
            }
        }
        else
        {
            var keysToRemove = _indexToPeer
                .Where(kvp => _comparer.Equals(kvp.Value.PeerPublicKey, peerPublicKey))
                .Select(kvp => kvp.Key)
                .ToList();

            foreach (var key in keysToRemove)
            {
                if (_indexToPeer.TryRemove(key, out var removedInfo))
                {
                    DisposeSessionHandshakeState(removedInfo);
                }
            }
        }
    }

    private void LogStats(object? state)
    {
        var tunDrop = Interlocked.Read(ref _tunDropCount);
        var udpDrop = Interlocked.Read(ref _udpDropCount);
        var tunWriteFail = Interlocked.Read(ref _tunWriteFailCount);
        var encryptFail = Interlocked.Read(ref _encryptFailCount);
        var noTransportDrop = Interlocked.Read(ref _noTransportDropCount);
        var sendDrop = Interlocked.Read(ref _sendDropCount);
        var tunPackets = Interlocked.Read(ref _tunPacketCount);

        if (tunDrop > 0 || udpDrop > 0 || tunWriteFail > 0 || encryptFail > 0 || noTransportDrop > 0 || sendDrop > 0)
        {
            Log("INF", $"[Stats] tunPkts={tunPackets} tunDrop={tunDrop} udpDrop={udpDrop} tunWriteFail={tunWriteFail} encryptFail={encryptFail} noTransportDrop={noTransportDrop} sendDrop={sendDrop}");
        }
    }

    private void CleanupIndexMappings(object? state)
    {
        var now = DateTime.UtcNow;
        var staleCutoff = now - TimeSpan.FromMinutes(5);

        var keysToRemove = new List<uint>();

        foreach (var kvp in _indexToPeer)
        {
            if (kvp.Value.IsCompleted)
            {
                // [FIX 2026-10-09] Active-session mapping exemption: ExpiresAt is written once
                // when the mapping is created (+30s) and is never renewed; the old logic also
                // deleted the index mapping of the *currently active* session after 30s —
                // from then on, the session's inbound packets permanently missed the primary
                // lookup and could only self-heal via ProcessData's fallback (scanning by
                // peer.LocalIndex), and once LocalIndex was overwritten by a new handshake
                // the session was permanently lost (one of the causes of continuously rising
                // server-side noTransportDrop and silently dropped DERP return traffic).
                // Now old mappings are cleaned after the 30s grace only when the owning
                // session has already been superseded by a newer session of that peer
                // (LocalIndex is no longer the current LocalIndex, or the transport/session
                // has been reset) — the ability of the previous transport to decrypt old
                // in-flight packets is retained unchanged.
                var isActiveSession = _peers.TryGetValue(kvp.Value.PeerPublicKey, out var ownerPeer) &&
                    ownerPeer.HasTransport &&
                    ownerPeer.IsEstablished &&
                    ownerPeer.LocalIndex == kvp.Value.LocalIndex;
                if (!isActiveSession && kvp.Value.ExpiresAt < now)
                {
                    keysToRemove.Add(kvp.Key);
                }
            }
            else if (kvp.Value.CreatedAt < staleCutoff)
            {
                keysToRemove.Add(kvp.Key);
            }
        }

        foreach (var key in keysToRemove)
        {
            if (_indexToPeer.TryRemove(key, out var info))
            {
                if (_peerToIndices.TryGetValue(info.PeerPublicKey, out var indices))
                {
                    lock (indices) { indices.Remove(key); }
                }
                DisposeSessionHandshakeState(info);
            }
        }

        if (_indexToPeer.Count > MaxTotalIndexMappings)
        {
            var excess = _indexToPeer.Count - MaxTotalIndexMappings + 100;
            var oldestKeys = new List<uint>();
            var oldestTime = DateTime.MaxValue;

            foreach (var kvp in _indexToPeer)
            {
                if (kvp.Value.CreatedAt < oldestTime)
                {
                    oldestTime = kvp.Value.CreatedAt;
                }
            }

            var threshold = oldestTime;
            for (int pass = 0; pass < 10 && oldestKeys.Count < excess; pass++)
            {
                var passThreshold = threshold.AddMinutes(pass + 1);
                foreach (var kvp in _indexToPeer)
                {
                    if (kvp.Value.CreatedAt <= passThreshold && !oldestKeys.Contains(kvp.Key))
                    {
                        oldestKeys.Add(kvp.Key);
                        if (oldestKeys.Count >= excess) break;
                    }
                }
            }

            foreach (var key in oldestKeys)
            {
                if (_indexToPeer.TryRemove(key, out var info))
                {
                    if (_peerToIndices.TryGetValue(info.PeerPublicKey, out var indices))
                    {
                        lock (indices) { indices.Remove(key); }
                    }
                    DisposeSessionHandshakeState(info);
                }
            }
        }

        var expiredRehandshakeKeys = _lastRehandshakeTime
            .Where(kvp => now - kvp.Value > TimeSpan.FromMinutes(10))
            .Select(kvp => kvp.Key)
            .ToList();

        foreach (var key in expiredRehandshakeKeys)
        {
            _lastRehandshakeTime.TryRemove(key, out _);
        }

        // [VM-FIRST-CONNECT 2026-10-21] Reclaim expired never-handshaked anchors: an anchor
        // older than 10 minutes means nobody has been sending to that peer for a long time
        // (peer removed / traffic stopped); prevents the dictionary from growing unboundedly over time
        var expiredUnconfirmedKeys = _firstUnconfirmedSendTime
            .Where(kvp => now - kvp.Value > TimeSpan.FromMinutes(10))
            .Select(kvp => kvp.Key)
            .ToList();

        foreach (var key in expiredUnconfirmedKeys)
        {
            _firstUnconfirmedSendTime.TryRemove(key, out _);
        }

        var expiredUdpAuth = _udpAuthFailures
            .Where(kvp => DateTime.UtcNow - kvp.Value.LastFailureTime > UdpAuthFailureWindow)
            .Select(kvp => kvp.Key)
            .ToList();

        foreach (var key in expiredUdpAuth)
        {
            _udpAuthFailures.TryRemove(key, out _);
        }

        var expiredDataAuth = _dataDecryptFailures
            .Where(kvp => DateTime.UtcNow - kvp.Value.LastFailureTime > UdpAuthFailureWindow)
            .Select(kvp => kvp.Key)
            .ToList();

        foreach (var key in expiredDataAuth)
        {
            _dataDecryptFailures.TryRemove(key, out _);
        }

        var expiredProbes = _lastDirectProbeTime
            .Where(kvp => now - kvp.Value > TimeSpan.FromMinutes(10))
            .Select(kvp => kvp.Key)
            .ToList();

        foreach (var key in expiredProbes)
        {
            _lastDirectProbeTime.TryRemove(key, out _);
        }
    }

    private void OnHandshakeRetryNeeded(object? sender, byte[] peerPublicKey)
    {
        if (!_peers.TryGetValue(peerPublicKey, out var peer))
        {
            return;
        }

        try
        {
            var pendingMessage = _handshakeManager.GetPendingMessage(peerPublicKey);
            if (pendingMessage != null)
            {
                _ = SafeExecuteAsync(() => SendHandshakeToPeerAsync(peerPublicKey, pendingMessage), "HandshakeRetry");
            }
            else
            {
                var (initiationMessage, handshakeState, localIndex) = _wireGuardHandshake.CreateInitiation(
                    peer.PublicKey, peer.PresharedKey,
                    cookie: peer.Endpoint != null ? _cookieProtector.GetCookieForEndpoint(peer.Endpoint) : null);

                RemoveOldHandshakeIndexMappings(peerPublicKey, localIndex);

                AddIndexMapping(localIndex, new PeerSessionInfo
                {
                    PeerPublicKey = peerPublicKey,
                    HandshakeState = handshakeState,
                    LocalIndex = localIndex
                });

                _handshakeManager.UpdateHandshakeMessage(peerPublicKey, initiationMessage, handshakeState, localIndex);
                _ = SafeExecuteAsync(() => SendHandshakeToPeerAsync(peerPublicKey, initiationMessage), "HandshakeRetry");
            }
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[WireGuardDevice] Failed to create retry handshake: {ex.Message}");
        }
    }

    private void OnSendHandshakeMessage(object? sender, (byte[] peerPublicKey, byte[] message) args)
    {
        _ = SafeExecuteAsync(() => SendHandshakeToPeerAsync(args.peerPublicKey, args.message), "SendHandshakeMessage");
    }

    private async Task SendHandshakeToPeerAsync(byte[] peerPublicKey, byte[] message)
    {
        if (!_peers.TryGetValue(peerPublicKey, out var peer))
        {
            return;
        }

        // Handshake messages are routed according to "the transport used by THIS handshake",
        // not the peer's current data transport: even while the peer is in DERP mode, a
        // UDP-initiated handshake (e.g. ProbeDirectPath's direct-path probe, or
        // OnPeerTimedOut's reconnect) must go over UDP, otherwise the connection could
        // never switch back to the direct path.
        var pendingIsDerp = _handshakeManager.IsHandshakePending(peerPublicKey) &&
                            _handshakeManager.IsPendingDerpInitiated(peerPublicKey);

        if (!pendingIsDerp && peer.Endpoint != null && !peer.Endpoint.Address.Equals(IPAddress.Any) && _udpClient != null)
        {
            try
            {
                _udpClient.Client.SendTo(message, SocketFlags.None, NormalizeSendEndpoint(peer.Endpoint)!);
                // Track the mac1 of the sent message, used to decrypt a possible cookie reply from the peer (AEAD AD)
                _cookieProtector.TrackSentMac1(peer.Endpoint, message);
                return;
            }
            catch (Exception ex)
            {
                Log("WRN", $"Failed to send handshake via UDP to {peer.Endpoint}: {ex.Message}, falling back to DERP");
                if (SendPacketViaDerp != null)
                {
                    SendPacketViaDerp(this, (peerPublicKey, message));
                }
                return;
            }
        }

        if (peer.IsDerpConnected && SendPacketViaDerp != null)
        {
            SendPacketViaDerp(this, (peerPublicKey, message));
        }
        else if (peer.IsTcpConnected && SendPacketViaTcp != null)
        {
            SendPacketViaTcp(this, (peerPublicKey, message));
        }
        else if (peer.IsWebSocketConnected && SendPacketViaWebSocket != null)
        {
            SendPacketViaWebSocket(this, (peerPublicKey, message));
        }
        else if (peer.Endpoint != null && !peer.Endpoint.Address.Equals(IPAddress.Any) && _udpClient != null)
        {
            try
            {
                _udpClient.Client.SendTo(message, SocketFlags.None, NormalizeSendEndpoint(peer.Endpoint)!);
                _cookieProtector.TrackSentMac1(peer.Endpoint, message);
            }
            catch (Exception ex)
            {
                Log("WRN", $"Failed to send handshake via UDP to {peer.Endpoint}: {ex.Message}, falling back to DERP");
                if (SendPacketViaDerp != null)
                {
                    SendPacketViaDerp(this, (peerPublicKey, message));
                }
            }
        }
        else if (SendPacketViaDerp != null)
        {
            SendPacketViaDerp(this, (peerPublicKey, message));
        }
        else
        {
            Log("WRN", $"Cannot send handshake: no UDP endpoint and no DERP (endpoint={peer.Endpoint}, SendPacketViaDerp={SendPacketViaDerp != null})");
        }
    }

    /// <summary>
    /// Tie-break winner's retransmission after ignoring the peer's initiation
    /// ([FIX 2026-10-04]): immediately resend our pending initiation along the arrival
    /// channel of that initiation — DERP arrival goes back via DERP, UDP arrival goes
    /// directly to its source endpoint (bypassing the pending message's channel affinity,
    /// because the peer just proved itself reachable via that channel). The same pending
    /// message is retransmitted (no new timestamp); if the peer happens to have already
    /// processed this initiation it de-duplicates it as a replay, so this is safe and idempotent.
    /// </summary>
    private void ResendPendingHandshakeViaArrivalChannel(byte[] peerPublicKey, IPEndPoint arrivalEndPoint)
    {
        try
        {
            var pendingMessage = _handshakeManager.GetPendingMessage(peerPublicKey);
            if (pendingMessage == null) return;

            if (IsDerpEndpoint(arrivalEndPoint))
            {
                SendPacketViaDerp?.Invoke(this, (peerPublicKey, pendingMessage));
                Log("INF", $"ProcessInitiation: resent pending initiation via arrival channel DERP for peer {BitConverter.ToString(peerPublicKey)[..20]}...");
                return;
            }

            if (_udpClient != null)
            {
                try
                {
                    _udpClient.Client.SendTo(pendingMessage, SocketFlags.None, NormalizeSendEndpoint(arrivalEndPoint)!);
                    // Track the mac1 of the sent message, used to decrypt a possible cookie reply from the peer (AEAD AD)
                    _cookieProtector.TrackSentMac1(arrivalEndPoint, pendingMessage);
                    Log("INF", $"ProcessInitiation: resent pending initiation via arrival channel UDP {arrivalEndPoint} for peer {BitConverter.ToString(peerPublicKey)[..20]}...");
                }
                catch (Exception ex)
                {
                    Log("WRN", $"ProcessInitiation: failed to resend pending initiation via UDP to {arrivalEndPoint}: {ex.Message}, falling back to DERP");
                    SendPacketViaDerp?.Invoke(this, (peerPublicKey, pendingMessage));
                }
            }
            else
            {
                SendPacketViaDerp?.Invoke(this, (peerPublicKey, pendingMessage));
            }
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[WireGuardDevice] ResendPendingHandshakeViaArrivalChannel failed: {ex.Message}");
        }
    }

    private void OnDerpFallbackNeeded(object? sender, byte[] peerPublicKey)
    {
        if (SendPacketViaDerp == null) return;

        var currentMessage = _handshakeManager.GetPendingMessage(peerPublicKey);
        if (currentMessage != null)
        {
            SendPacketViaDerp(this, (peerPublicKey, currentMessage));
        }
    }

    private void OnHandshakeTimedOut(object? sender, byte[] peerPublicKey)
    {
        // [VM-HS-BACKOFF 2026-11-08] Record one handshake failure and schedule a backoff window.
        // When the peer is offline, retry blindly every 95 seconds no more; switch to 30s → 2m → 5m → 15m exponential backoff.
        RegisterHandshakeFailure(peerPublicKey);

        // [FIX 2026-10-14] Timeout while a direct-path probe is in flight → judge the probe
        // failed: failure count +1 and stretch the probe-ban interval along the backoff
        // ladder (30s→30m), breaking the "probe → timeout → probe again" death loop.
        if (_probeInFlight.ContainsKey(peerPublicKey))
        {
            MarkProbeFailed(peerPublicKey, "handshake timed out");
        }

        // [FIX 2026-10-08] After a handshake timeout, also clean up the peer's incomplete
        // index mappings (zombie signature remote=0/completed=False). The old
        // implementation only flipped the DERP flag; zombie mappings lingered for up to 5
        // minutes (CleanupIndexMappings' staleCutoff), during which the re-handshake decision
        // on ProcessData's mapping-miss path stayed blocked by them — after the peer's
        // session was invalidated (e.g. a server restart losing sessions), data packets
        // kept being silently dropped.
        foreach (var kvp in _indexToPeer)
        {
            if (!kvp.Value.IsCompleted && _comparer.Equals(kvp.Value.PeerPublicKey, peerPublicKey))
            {
                if (_indexToPeer.TryRemove(kvp.Key, out var staleInfo))
                {
                    DisposeSessionHandshakeState(staleInfo);
                    if (_peerToIndices.TryGetValue(peerPublicKey, out var staleIndices))
                    {
                        lock (staleIndices)
                        {
                            staleIndices.Remove(kvp.Key);
                        }
                    }
                    // [VM-LOG-FLOOD / 2026-10-15] Throttled per peer: a flapping peer
                    // produces multiple handshake timeouts per minute, and each zombie
                    // mapping logged one INF (18944 entries per 24h on an exit node, nearly
                    // 70% of the WG-DEV flood). Cleanup logic unchanged; only the log is limited.
                    if (ShouldLogThrottled($"handshake-timeout:{Convert.ToHexString(peerPublicKey)}", out var htSuppressed))
                    {
                        Log("INF", $"Handshake timed out for peer {BitConverter.ToString(peerPublicKey)[..20]}..., removed stale pending index mapping {kvp.Key}"
                            + (htSuppressed > 0 ? $" (suppressed {htSuppressed})" : string.Empty));
                    }
                }
            }
        }

        if (_peers.TryGetValue(peerPublicKey, out var peer))
        {
            if (peer.Endpoint != null && !peer.Endpoint.Address.Equals(IPAddress.Any) && SendPacketViaDerp != null)
            {
                Log("WRN", $"UDP handshake timed out, switching to DERP for peer {BitConverter.ToString(peerPublicKey)[..20]}...");
                // Keep the last known UDP endpoint so ProbeDirectPath can periodically probe and switch back to the direct path
                peer.LastKnownUdpEndpoint = peer.Endpoint;
                peer.Endpoint = null;
                peer.IsDerpConnected = true;
                // [FIX 2026-10-14] DERP stickiness: ban direct-path probing for 5 minutes
                // after switching back to the relay, letting the DERP session stabilize via
                // keepalive(10s)/rekey(120s) before evaluating the direct path again.
                MarkDerpSticky(peerPublicKey);
            }
            else if (SendPacketViaDerp != null)
            {
                peer.IsDerpConnected = true;
                MarkDerpSticky(peerPublicKey);
            }
        }
    }

    private void ProbeDirectPath(object? state)
    {
        if (!_running || _stopping) return;

        foreach (var kvp in _peers)
        {
            try
            {
                var peer = kvp.Value;
                if (!peer.IsDerpConnected) continue;

                // [FIX 2026-10-14] Validation-window handling for the previous probe round:
                // do not probe again while the window is open; if the window expired without
                // any direct-path data arriving → the probe is judged failed and the next
                // probe interval is stretched along the backoff ladder.
                if (_probeValidationUntil.TryGetValue(kvp.Key, out var validateUntil))
                {
                    if (DateTime.UtcNow >= validateUntil)
                    {
                        MarkProbeFailed(kvp.Key, "no direct data within validation window");
                    }
                    continue;
                }

                // [FIX 2026-10-08] Probing is banned while the session is healthy: a probe
                // handshake would overwrite the existing healthy session (root cause of the
                // mutual-trampling storm), see the DirectPathProbeSessionHealthyAge comment.
                // Probe only when the session has gone stale (not refreshed within a rekey cycle).
                if (peer.IsEstablished && DateTime.UtcNow - peer.LastHandshake < DirectPathProbeSessionHealthyAge)
                {
                    continue;
                }

                var endpoint = peer.Endpoint ?? peer.LastKnownUdpEndpoint;
                if (endpoint == null || endpoint.Address.Equals(IPAddress.Any)) continue;
                if (_handshakeManager.IsHandshakePending(kvp.Key)) continue;

                // [FIX 2026-10-14] Hysteresis gate (replacing the old blindly periodic
                // re-probe throttled only by 30s): in-flight probe deduplication + failure
                // exponential backoff + DERP sticky cooldown. For CGNAT↔CGNAT peers (e.g.
                // Android↔ubuntuserver24) the direct path is unreachable; the old logic
                // probed every 150s and failed every time, forming an eternal
                // "probe → 90s timeout → 60s dead-link black hole" loop.
                if (!IsProbeAllowed(kvp.Key)) continue;

                if (_lastDirectProbeTime.TryGetValue(kvp.Key, out var last) &&
                    DateTime.UtcNow - last < DirectPathProbePeerThrottle)
                {
                    continue;
                }
                _lastDirectProbeTime[kvp.Key] = DateTime.UtcNow;
                MarkProbeStarted(kvp.Key);

                Log("DBG", $"ProbeDirectPath: probing direct UDP path for DERP-connected peer {BitConverter.ToString(kvp.Key)[..20]}... (endpoint={endpoint})");
                InitiateHandshakeWithPeer(kvp.Key, endpoint);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[WireGuardDevice] ProbeDirectPath failed: {ex.Message}");
            }
        }
    }

    private void OnKeyRotationNeeded(object? sender, byte[] peerPublicKey)
    {
        if (_handshakeManager.IsHandshakePending(peerPublicKey))
        {
            return;
        }

        if (_peers.TryGetValue(peerPublicKey, out var peer))
        {
            // [FIX 2026-10-19] Rekey follows the current data channel: a DERP session's rekey
            // must go via DERP. The old logic blindly used peer.Endpoint (possibly an
            // unverified direct endpoint written by a P2P upgrade) to rekey over UDP; under
            // 4G/CGNAT there was no response → the old session keys expired
            // (REJECT_AFTER_TIME) → bidirectional data black-holed until the handshake
            // timeout / dead-link detection switched back to DERP. Direct sessions
            // (IsDerpConnected=false) still rekey over UDP to the endpoint, unchanged.
            if (peer.IsDerpConnected && SendPacketViaDerp != null)
            {
                InitiateHandshakeWithPeer(peerPublicKey, null);
            }
            else
            {
                InitiateHandshakeWithPeer(peerPublicKey, peer.Endpoint);
            }
        }
    }

    private void OnPeerTimedOut(object? sender, byte[] peerPublicKey)
    {
        if (_peers.TryGetValue(peerPublicKey, out var peer))
        {
            peer.ResetTransport();
            _keepaliveManager.SessionReset(peerPublicKey);
            RemoveOldIndexMappings(peerPublicKey);

            if (peer.Endpoint != null && SendPacketViaDerp != null)
            {
                // [FIX 2026-10-19] While a session-timeout re-handshake is in flight, the data
                // flow stays on DERP instead of being force-switched to UDP: the old logic's
                // peer.IsDerpConnected = false hijacked data onto the unverified UDP endpoint;
                // under CGNAT/4G the peer was unreachable → data black-holed until the 90s
                // handshake timeout (one of the direct mechanisms of long mobile outages).
                // Now the data keeps flowing via DERP; if the UDP re-handshake is actually
                // reachable, once its response arrives over UDP, ProcessResponse switches back
                // to the direct path automatically (IsDerpConnected=false +
                // Endpoint=remoteEndPoint), so direct-path recovery is lossless.
                peer.IsDerpConnected = true;
                InitiateHandshakeWithPeer(peerPublicKey, peer.Endpoint);
            }
            else if (peer.Endpoint != null)
            {
                InitiateHandshakeWithPeer(peerPublicKey, peer.Endpoint);
            }
            else if (SendPacketViaDerp != null)
            {
                peer.IsDerpConnected = true;
                InitiateHandshakeWithPeer(peerPublicKey, null);
            }
        }
    }

    private void OnSendKeepalive(object? sender, byte[] publicKey)
    {
        _ = SafeExecuteAsync(() => { SendKeepalivePacket(publicKey); return Task.CompletedTask; }, "SendKeepalive");
    }

    private void FlushPendingPackets(WireGuardPeer peer)
    {
        var pendingPackets = peer.DrainPendingPackets();
        if (pendingPackets.Count == 0) return;

        Log("INF", $"Flushing {pendingPackets.Count} pending packets for peer {BitConverter.ToString(peer.PublicKey)[..20]}...");

        foreach (var packet in pendingPackets)
        {
            try
            {
                SendOrEnqueueEncryptedPacket(packet, peer);
            }
            catch
            {
            }
        }
    }

    private void SendKeepalivePacket(byte[] publicKey)
    {
        if (_stopping) return;

        if (_peers.TryGetValue(publicKey, out var peer))
        {
            if (peer.HasTransport)
            {
                var keepalivePacket = Array.Empty<byte>();
                SendOrEnqueueEncryptedPacket(keepalivePacket, peer);
            }
            else
            {
                // [FIX 2026-10-19] When there is no transport, handshake initiation follows
                // the current transport mode: in DERP mode the handshake goes via DERP first —
                // peer.Endpoint may be an unverified endpoint written by a P2P upgrade, and
                // under 4G/CGNAT a UDP handshake black-holes; direct sessions still use UDP.
                if (peer.IsDerpConnected && SendPacketViaDerp != null)
                {
                    InitiateHandshakeWithPeer(publicKey, null);
                }
                else if (peer.Endpoint != null)
                {
                    InitiateHandshakeWithPeer(publicKey, peer.Endpoint);
                }
                else if (SendPacketViaDerp != null)
                {
                    InitiateHandshakeWithPeer(publicKey, null);
                }
            }
        }
    }

    private async Task SafeExecuteAsync(Func<Task> action, string actionName)
    {
        try
        {
            await action();
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[WireGuardDevice] {actionName} failed: {ex.GetType().Name}: {ex.Message}");
        }
    }

    private async Task TunReadLoopAsync(Channel<byte[]> channel, CancellationToken cancellationToken)
    {
        await Task.Yield();
        Log("INF", "TUN read loop started");
        var consecutiveErrors = 0;
        DateTime lastErrorLogTime = DateTime.MinValue;
        while (!cancellationToken.IsCancellationRequested && _tunDevice != null)
        {
            try
            {
                var packet = await _tunDevice.ReadPacketAsync(cancellationToken);
                if (!channel.Writer.TryWrite(packet))
                {
                    Interlocked.Increment(ref _tunDropCount);
                }
                consecutiveErrors = 0;
            }
            catch (Tun.TunDeviceStoppedException)
            {
                Log("WRN", "TUN device stopped unexpectedly (adapter may have been disabled), attempting to restart...");
                if (await TryRestartTunDeviceAsync())
                {
                    continue;
                }
                break;
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (ObjectDisposedException)
            {
                break;
            }
            catch (Exception ex)
            {
                consecutiveErrors++;
                if (consecutiveErrors <= 3 || DateTime.UtcNow - lastErrorLogTime > TimeSpan.FromSeconds(30))
                {
                    Log("ERR", $"Error reading from TUN: {ex.GetType().Name}: {ex.Message}");
                    lastErrorLogTime = DateTime.UtcNow;
                }
                if (consecutiveErrors > 10)
                {
                    await Task.Delay(1000, cancellationToken).ConfigureAwait(false);
                }
                if (consecutiveErrors > 100)
                {
                    Log("WRN", "TUN device has too many consecutive errors, attempting to restart...");
                    if (await TryRestartTunDeviceAsync())
                    {
                        consecutiveErrors = 0;
                        continue;
                    }
                    break;
                }
            }
        }
        channel.Writer.TryComplete();
        Log("DBG", "TUN read loop exited");
    }

    private async Task TunProcessLoopAsync(Channel<byte[]> channel, CancellationToken cancellationToken)
    {
        await Task.Yield();
        Log("INF", "TUN process loop started");
        await foreach (var packet in channel.Reader.ReadAllAsync(cancellationToken))
        {
            try
            {
                ProcessTunPacket(packet);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[WireGuardDevice] Error processing TUN packet: {ex.Message}");
            }
        }
        Log("DBG", "TUN process loop exited");
    }

    private async Task<bool> TryRestartTunDeviceAsync()
    {
        // The device may have been stopped while we poll for a restart: pass the
        // cancellation token so the delays don't block the shutdown path.
        var cancellationToken = _cancellationTokenSource?.Token ?? CancellationToken.None;

        if (_tunDevice is Tun.WindowsWintunDevice wintunDevice)
        {
            for (int attempt = 1; attempt <= 5; attempt++)
            {
                Log("DBG", $"Attempting to restart TUN device (attempt {attempt}/5)...");
                
                try
                {
                    if (wintunDevice.RestartSession())
                    {
                        Log("DBG", "TUN device restarted successfully, re-applying address...");
                        
                        if (_config.Address != null)
                        {
                            wintunDevice.SetAddress(_config.Address.ToString(), _config.AddressPrefixLength);
                        }
                        if (_config.AddressV6 != null)
                        {
                            wintunDevice.SetAddressIPv6(_config.AddressV6.ToString(), _config.AddressV6PrefixLength);
                        }

                        OnTunDeviceRestarted?.Invoke(this, EventArgs.Empty);
                        return true;
                    }
                }
                catch (Exception ex)
                {
                    Log("WRN", $"TUN restart attempt {attempt} failed: {ex.Message}");
                }

                try { await Task.Delay(3000, cancellationToken); } catch (OperationCanceledException) { return false; } // Device already stopped; abort restart polling
            }

            Log("ERR", "Failed to restart TUN device after 5 attempts");
            return false;
        }

        if (_tunDevice is Tun.LinuxTunDevice linuxTunDevice)
        {
            for (int attempt = 1; attempt <= 5; attempt++)
            {
                Log("DBG", $"Attempting to restart Linux TUN device (attempt {attempt}/5)...");

                try
                {
                    linuxTunDevice.Stop();
                    linuxTunDevice.Start();

                    Log("DBG", "Linux TUN device restarted successfully, re-applying address...");

                    if (_config.Address != null)
                    {
                        linuxTunDevice.SetAddress(_config.Address.ToString(), _config.AddressPrefixLength);
                    }
                    if (_config.AddressV6 != null)
                    {
                        linuxTunDevice.SetAddressIPv6(_config.AddressV6.ToString(), _config.AddressV6PrefixLength);
                    }

                    OnTunDeviceRestarted?.Invoke(this, EventArgs.Empty);
                    return true;
                }
                catch (Exception ex)
                {
                    Log("WRN", $"Linux TUN restart attempt {attempt} failed: {ex.Message}");
                }

                try { await Task.Delay(3000, cancellationToken); } catch (OperationCanceledException) { return false; } // Device already stopped; abort restart polling
            }

            Log("ERR", "Failed to restart Linux TUN device after 5 attempts");
            return false;
        }

        if (_tunDevice is Tun.MacOSUtunDevice macOSUtunDevice)
        {
            for (int attempt = 1; attempt <= 5; attempt++)
            {
                try
                {
                    Log("INF", $"Attempting to restart macOS utun device (attempt {attempt}/5)...");
                    macOSUtunDevice.Stop();
                    macOSUtunDevice.Start();

                    Log("DBG", "macOS utun device restarted successfully, re-applying address...");

                    if (_config.Address != null)
                    {
                        macOSUtunDevice.SetAddress(_config.Address.ToString(), _config.AddressPrefixLength);
                    }
                    if (_config.AddressV6 != null)
                    {
                        macOSUtunDevice.SetAddressIPv6(_config.AddressV6.ToString(), _config.AddressV6PrefixLength);
                    }

                    OnTunDeviceRestarted?.Invoke(this, EventArgs.Empty);
                    return true;
                }
                catch (Exception ex)
                {
                    Log("WRN", $"macOS utun restart attempt {attempt} failed: {ex.Message}");
                }

                try { await Task.Delay(3000, cancellationToken); } catch (OperationCanceledException) { return false; } // Device already stopped; abort restart polling
            }

            Log("ERR", "Failed to restart macOS utun device after 5 attempts");
            return false;
        }

        Log("WRN", "TUN device type does not support restart");
        return false;
    }

    /// <summary>
    /// Raised when the underlying TUN device was restarted after an unexpected stop
    /// (e.g. the adapter was disabled) and its addresses were re-applied.
    /// </summary>
    public event EventHandler? OnTunDeviceRestarted;

    private DateTime _lastNoTransportLog = DateTime.MinValue;
    private readonly TimeSpan _noTransportLogInterval = TimeSpan.FromSeconds(10);
    private DateTime _lastTunPacketLog = DateTime.MinValue;
    private readonly TimeSpan _tunPacketLogInterval = TimeSpan.FromSeconds(5);
    private long _tunPacketCount;

    /// <summary>Count of dropped multicast/broadcast packets (for diagnostics; not included in logs).</summary>
    private long _tunMulticastDropped;
    private long _tunExitPacketCount;
    private long _tunDropCount;
    private long _udpDropCount;
    private long _tunWriteFailCount;
    private long _encryptFailCount;
    private long _noTransportDropCount;
    private long _sendDropCount;
    private Timer? _statsTimer;

    // DERP switch-back probing: while a peer is in DERP mode, periodically initiate a
    // direct handshake to its last known UDP endpoint; once a handshake completes over UDP,
    // ProcessResponse/ProcessData automatically sets IsDerpConnected back to false.
    // [FIX 2026-10-08] Healthy-session probe ban threshold: probing is skipped when the
    // session is established and LastHandshake is more recent than this age. After a probe
    // handshake is answered via the peer's DERP mode, it overwrites the existing healthy
    // session locally via SetTransport (likewise on the peer), so both sides' periodic
    // probing formed a mutual-trampling handshake storm (measured: the same peer
    // re-handshaking every 15-45s). 150s exceeds the WG rekey cycle (~120s): healthy
    // sessions are refreshed naturally by rekey and probes never trigger; when a session
    // has truly gone stale (rekey failing persistently), the probe still fires, so the
    // recovery scenario (REKEY_ATTEMPT_TIME deadlock escape) is unaffected.
    private Timer? _directPathProbeTimer;
    private static readonly TimeSpan DirectPathProbeInterval = TimeSpan.FromSeconds(15);
    private static readonly TimeSpan DirectPathProbePeerThrottle = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan DirectPathProbeSessionHealthyAge = TimeSpan.FromSeconds(150);
    private readonly ConcurrentDictionary<byte[], DateTime> _lastDirectProbeTime = new(_comparer);

    // ===== [FIX 2026-10-14] Transport state-machine hysteresis: cure for the pathological
    // DERP ↔ direct-UDP flapping =====
    // Production evidence (2026-10-14, ubuntuserver24 journalctl):
    // Android(cellular CGNAT)↔ubuntuserver24(broadband CGNAT) had 393 handshake timeouts
    // vs 88 completions over a full day; the death loop was
    // "DERP session stale after 150s → ProbeDirectPath probes the direct path → UDP
    //  handshake times out after 90s (CGNAT unreachable) → 60s dead-link black hole (all
    //  TCP broken) → OnHandshakeTimedOut switches back to DERP → re-probe 150s later".
    // The hysteresis quartet:
    //   1) Probe-failure exponential backoff (30s→1m→2m→5m→15m→30m capped), replacing the
    //      blindly periodic re-probe;
    //   2) After a probe handshake "succeeds", a direct data packet from that peer must
    //      arrive within 30s or the probe is judged failed (guards against probe-then-die);
    //   3) A 5-minute sticky cooldown bans probing right after switching to DERP, giving
    //      the DERP session a chance to stabilize via keepalive/rekey;
    //   4) While a probe is in flight, data packets keep flowing via DERP (the data stream
    //      is not hijacked onto the unverified UDP endpoint).
    // Direct data packets (initiation/data arriving over UDP) reset the backoff at any
    // time — peers with a public IP (e.g. a DC machine) should be directly reachable in
    // the first place and are not mistakenly punished by the backoff policy designed for
    // CGNAT peers behind subnets (backoff state is maintained per peer).

    /// <summary>Probe-failure backoff ladder steps (indexed by consecutive failure count; the last step is the cap).</summary>
    private static readonly TimeSpan[] ProbeBackoffLadder =
    {
        TimeSpan.FromSeconds(30),
        TimeSpan.FromMinutes(1),
        TimeSpan.FromMinutes(2),
        TimeSpan.FromMinutes(5),
        TimeSpan.FromMinutes(15),
        TimeSpan.FromMinutes(30)
    };

    /// <summary>Probe-ban cooldown after switching to DERP (DERP stickiness): avoids probing the direct path again immediately after returning to the relay.</summary>
    private static readonly TimeSpan DerpStickyCooldown = TimeSpan.FromMinutes(5);

    /// <summary>Validation window after a probe handshake completes: if no direct data packet from that peer arrives within the window, this probe counts as failed.</summary>
    private static readonly TimeSpan ProbeValidationWindow = TimeSpan.FromSeconds(30);

    /// <summary>
    /// [VM-REPLAY-RECOVER-GATE 2026-10-31] Upper bound of the counter start range for which a
    /// "replay window reset" is allowed. After the peer rebuilds its session the counter
    /// starts from 0 again, and normal traffic quickly moves past this value; only a counter
    /// within this range AND strictly smaller than windowLast is judged as a rebuild —
    /// everything else (duplicate delivery / replay of old packets) is dropped without
    /// resetting the window.
    /// </summary>
    private const ulong ReplayRecoverStartCounter = 32;

    /// <summary>
    /// [VM-REPLAY-RECOVER-GATE 2026-10-31] Determines whether a packet that "passed AEAD but
    /// was rejected by the replay window" has the shape of a peer session rebuild (the counter
    /// starting over from 0); only this shape is allowed to reset the replay window:
    ///  · the counter must be strictly smaller than the largest value already accepted by the
    ///    window (equality means re-delivery of the same packet, where a reset would only
    ///    duplicate delivery);
    ///  · the counter must fall within the session start range (&lt;= <see cref="ReplayRecoverStartCounter"/>),
    ///    otherwise it is a historical packet of an old session, and resetting would roll back
    ///    the anti-replay state.
    /// </summary>
    /// <param name="counter">The packet counter observed on the received packet.</param>
    /// <param name="windowLast">The largest counter already accepted by the replay window.</param>
    /// <returns><c>true</c> when the packet looks like the first packets of a rebuilt peer session (reset allowed); otherwise, <c>false</c>.</returns>
    public static bool IsReplayRestartSignature(ulong counter, ulong windowLast)
        => counter < windowLast && counter <= ReplayRecoverStartCounter;

    /// <summary>Peer public key -> consecutive probe failure count (decides the backoff ladder step).</summary>
    private readonly ConcurrentDictionary<byte[], int> _probeFailureCount = new(_comparer);
    /// <summary>Peer public key -> probe-ban deadline imposed by failure backoff.</summary>
    private readonly ConcurrentDictionary<byte[], DateTime> _probeBackoffUntil = new(_comparer);
    /// <summary>Peer public key -> DERP sticky probe-ban deadline (set when a handshake timeout / dead link switches to DERP).</summary>
    private readonly ConcurrentDictionary<byte[], DateTime> _derpStickyUntil = new(_comparer);
    /// <summary>Peer public key -> in-flight direct-path probe marker (start time; consumed on timeout/completion/validation failure).</summary>
    private readonly ConcurrentDictionary<byte[], DateTime> _probeInFlight = new(_comparer);
    /// <summary>Peer public key -> validation deadline after a probe completes (receiving a direct data packet passes validation).</summary>
    private readonly ConcurrentDictionary<byte[], DateTime> _probeValidationUntil = new(_comparer);

    // ===== [VM-HS-BACKOFF 2026-11-08] Handshake failure backoff =====
    /// <summary>Peer public key -> consecutive handshake failure count (cleared on success).</summary>
    private readonly ConcurrentDictionary<byte[], int> _handshakeFailureCount = new(_comparer);
    /// <summary>Peer public key -> the earliest time a new handshake initiation is allowed.</summary>
    private readonly ConcurrentDictionary<byte[], DateTime> _handshakeNextAllowedAt = new(_comparer);

    /// <summary>
    /// [VM-NETCHANGE-BACKOFF-RESET 2026-11-09] Clears the per-peer handshake failure backoff.
    /// </summary>
    /// <remarks>
    /// A network change means the path conditions changed as a whole (Wi-Fi/cellular switch,
    /// gateway change, sleep/resume), so all previously accumulated "consecutive failure"
    /// evidence is void. Without clearing, the backoff lasts up to 15 minutes, manifesting
    /// as long unreachability after a network switch (measured recovery took 30~60s, even
    /// longer when stacked with the peer's Gone cooldown).
    /// </remarks>
    public void ResetHandshakeBackoff()
    {
        var affected = _handshakeFailureCount.Count;
        _handshakeFailureCount.Clear();
        _handshakeNextAllowedAt.Clear();
        if (affected > 0)
        {
            Log("INF", $"[VM-NETCHANGE] cleared handshake backoff for {affected} peer(s) (network changed)");
        }
    }

    /// <summary>
    /// [VM-HS-BACKOFF 2026-11-08] Maps the consecutive failure count to a backoff duration.
    /// One failure is not punished (0); afterwards 30s → 2m → 5m → 15m (capped).
    /// Purpose: offline nodes (phone locked / laptop shut down) no longer spin through a
    /// futile handshake every 95 seconds.
    /// </summary>
    /// <param name="consecutiveFailures">The number of consecutive handshake failures for a peer.</param>
    /// <returns>The duration to wait before the next handshake attempt is allowed.</returns>
    private static TimeSpan GetHandshakeBackoff(int consecutiveFailures) => consecutiveFailures switch
    {
        <= 0 => TimeSpan.Zero,
        1 => TimeSpan.Zero,
        2 => TimeSpan.FromSeconds(30),
        3 => TimeSpan.FromMinutes(2),
        4 => TimeSpan.FromMinutes(5),
        _ => TimeSpan.FromMinutes(15)
    };

    /// <summary>[VM-HS-BACKOFF 2026-11-08] Records one handshake failure and schedules the backoff.</summary>
    private void RegisterHandshakeFailure(byte[] peerPublicKey)
    {
        var failures = _handshakeFailureCount.AddOrUpdate(peerPublicKey, 1, static (_, v) => v + 1);
        var backoff = GetHandshakeBackoff(failures);
        if (backoff > TimeSpan.Zero)
        {
            _handshakeNextAllowedAt[peerPublicKey] = DateTime.UtcNow + backoff;
            Log("DBG", $"Handshake failure #{failures} for peer {BitConverter.ToString(peerPublicKey)[..20]}..., " +
                $"next attempt in {backoff.TotalSeconds:F0}s");
        }
    }

    /// <summary>[VM-HS-BACKOFF 2026-11-08] Handshake succeeded: clears the failure count and the backoff window.</summary>
    private void ResetHandshakeBackoff(byte[] peerPublicKey)
    {
        if (_handshakeFailureCount.TryRemove(peerPublicKey, out var had) && had > 2)
        {
            Log("INF", $"Handshake recovered for peer {BitConverter.ToString(peerPublicKey)[..20]}... after {had} consecutive failures");
        }
        _handshakeNextAllowedAt.TryRemove(peerPublicKey, out _);
    }
    /// <summary>
    /// [VM-LAN-PROBE-EXEMPT 2026-11-01] Peer public key -> whether the currently in-flight probe is a "same-LAN, hysteresis-exempt" probe.
    /// Direct connections inside the same LAN (candidate address falls inside the machine's
    /// trusted LAN subnets) do not depend on NAT mapping assumptions, so the premises of
    /// stickiness/backoff do not hold and bypassing the hysteresis is allowed; their failures
    /// are not counted toward backoff either, to avoid crushing WAN probes along with them.
    /// </summary>
    private readonly ConcurrentDictionary<byte[], bool> _probeIsLan = new(_comparer);

    /// <summary>
    /// Marks a direct-path probe as started (in flight). During the probe, data packets
    /// still flow via DERP; the data path is not hijacked.
    /// </summary>
    private void MarkProbeStarted(byte[] peerPublicKey, bool isLanProbe = false)
    {
        _probeInFlight[peerPublicKey] = DateTime.UtcNow;
        _probeValidationUntil.TryRemove(peerPublicKey, out _);
        if (isLanProbe) _probeIsLan[peerPublicKey] = true;
        else _probeIsLan.TryRemove(peerPublicKey, out _);
    }

    /// <summary>
    /// The probe handshake has completed (a response arrived over UDP): this only proves
    /// "half the path works"; enter the 30s data validation window. Only when a direct data
    /// packet from that peer arrives within the window is the probe judged a true success
    /// (MarkDirectPathHealthy).
    /// </summary>
    private void MarkProbeHandshakeCompleted(byte[] peerPublicKey)
    {
        _probeIsLan.TryRemove(peerPublicKey, out _);
        if (_probeInFlight.TryRemove(peerPublicKey, out _))
        {
            _probeValidationUntil[peerPublicKey] = DateTime.UtcNow + ProbeValidationWindow;
            Log("DBG", $"Direct-path probe handshake completed for peer {BitConverter.ToString(peerPublicKey)[..20]}..., validating direct data within {ProbeValidationWindow.TotalSeconds:F0}s");
        }
    }

    /// <summary>
    /// The probe is judged failed: failure count +1, the probe-ban deadline is set from the
    /// backoff ladder, and the in-flight/validation state is cleared.
    /// </summary>
    private void MarkProbeFailed(byte[] peerPublicKey, string reason)
    {
        _probeInFlight.TryRemove(peerPublicKey, out _);
        _probeValidationUntil.TryRemove(peerPublicKey, out _);

        // [VM-LAN-PROBE-EXEMPT 2026-11-01] Same-LAN probe failures are not counted toward
        // backoff: such failures have nothing to do with NAT mappings (the peer may just be
        // temporarily offline / port not open); counting them would crush the same peer's
        // WAN probes too for 30s→30min, ultimately manifesting as "even same-LAN peers can
        // permanently only use DERP".
        if (_probeIsLan.TryRemove(peerPublicKey, out var wasLan) && wasLan)
        {
            Log("DBG", $"Direct-path LAN probe failed for peer {BitConverter.ToString(peerPublicKey)[..20]}... ({reason}) - not counted toward backoff");
            return;
        }

        var count = _probeFailureCount.AddOrUpdate(peerPublicKey, 1, (_, c) => c + 1);
        var backoff = ProbeBackoffLadder[Math.Min(count - 1, ProbeBackoffLadder.Length - 1)];
        _probeBackoffUntil[peerPublicKey] = DateTime.UtcNow + backoff;
        Log("INF", $"Direct-path probe FAILED for peer {BitConverter.ToString(peerPublicKey)[..20]}... ({reason}), consecutive failures={count}, backing off {backoff.TotalSeconds:F0}s");
    }

    /// <summary>
    /// A direct (UDP) data/handshake packet from that peer arrived: hard evidence that the
    /// direct path is healthy. Within the validation window this passes the probe
    /// validation; regardless of the window, the failure count and backoff are cleared
    /// (continuous direct traffic proves no further backoff is needed).
    /// </summary>
    private void MarkDirectPathHealthy(byte[] peerPublicKey)
    {
        var inValidationWindow = _probeValidationUntil.TryRemove(peerPublicKey, out _);
        var hadFailures = _probeFailureCount.TryRemove(peerPublicKey, out _);
        _probeBackoffUntil.TryRemove(peerPublicKey, out _);
        if (inValidationWindow && hadFailures)
        {
            Log("INF", $"Direct-path probe VALIDATED for peer {BitConverter.ToString(peerPublicKey)[..20]}... (direct data received), backoff cleared");
        }
    }

    /// <summary>
    /// Sticky cooldown after switching to DERP: bans ProbeDirectPath from probing the direct
    /// path again while the cooldown lasts.
    /// </summary>
    private void MarkDerpSticky(byte[] peerPublicKey)
    {
        _derpStickyUntil[peerPublicKey] = DateTime.UtcNow + DerpStickyCooldown;
    }

    /// <summary>
    /// Whether initiating a direct-path probe against this peer is allowed: no probe in
    /// flight, not inside the failure-backoff period, and not inside the DERP sticky cooldown.
    /// </summary>
    private bool IsProbeAllowed(byte[] peerPublicKey)
    {
        if (_probeInFlight.ContainsKey(peerPublicKey)) return false;
        if (_probeBackoffUntil.TryGetValue(peerPublicKey, out var backoffUntil) &&
            DateTime.UtcNow < backoffUntil)
        {
            return false;
        }
        if (_derpStickyUntil.TryGetValue(peerPublicKey, out var stickyUntil) &&
            DateTime.UtcNow < stickyUntil)
        {
            return false;
        }
        return true;
    }

    /// <summary>
    /// Clears all probe-hysteresis state of a single peer (called on session reset / peer removal).
    /// </summary>
    private void ClearProbeState(byte[] peerPublicKey)
    {
        _probeInFlight.TryRemove(peerPublicKey, out _);
        _probeIsLan.TryRemove(peerPublicKey, out _);
        _probeValidationUntil.TryRemove(peerPublicKey, out _);
        _probeFailureCount.TryRemove(peerPublicKey, out _);
        _probeBackoffUntil.TryRemove(peerPublicKey, out _);
        _derpStickyUntil.TryRemove(peerPublicKey, out _);
    }

    /// <summary>
    /// [FIX 2026-10-16] Resets the "probe-ban" style hysteresis state of all peers
    /// (failure backoff, DERP stickiness, pending validation windows, failure counts).
    /// Called by higher layers on network change / sleep-resume: both stickiness (5min after
    /// switching to DERP) and backoff (30s→30m) are based on stale network-path assumptions
    /// that are all void after a network change — typical scenario: a device moving from a
    /// CGNAT mobile network to an open Wi-Fi, where the direct path is already usable but is
    /// held back by the sticky cooldown for up to 5 minutes, forced to keep detouring via DERP.
    /// <see cref="_probeInFlight"/> is not cleared (in-flight handshakes are left to finish
    /// naturally, avoiding a duplicate-probe storm); the probe itself carries the 30s data
    /// validation window, and a failed probe re-accumulates backoff, so no pathological
    /// flapping results.
    /// [FIX 2026-10-16 addendum] <see cref="_lastDirectProbeTime"/> is cleared as well:
    /// otherwise the 15s probe timer could still be throttled by the 30s rate limit after the
    /// reset (_lastDirectProbeTime less than 30s since the last probe), so the nominal
    /// "re-probe immediately" semantics could lag reality by up to 30s.
    /// </summary>
    /// <remarks>Thread-safe; safe to call at any time while the device is running or stopped.</remarks>
    public void ResetDirectPathProbeStates()
    {
        var suppressed = _probeBackoffUntil.Count + _derpStickyUntil.Count;
        _probeBackoffUntil.Clear();
        _derpStickyUntil.Clear();
        _probeFailureCount.Clear();
        _probeValidationUntil.Clear();
        _lastDirectProbeTime.Clear();
        if (suppressed > 0)
        {
            Log("INF", $"Direct-path probe hysteresis reset for all peers ({suppressed} suppressions cleared): network change invalidates previous path assumptions, re-probing immediately");
        }
    }

    /// <summary>
    /// [VM-PROBE-WITHOUT-HIJACK 2026-11-01] Initiates a direct-path probe against the specified
    /// candidate endpoint that does NOT hijack the data path. It only writes the candidate into
    /// <see cref="WireGuardPeer.LastKnownUdpEndpoint"/> and initiates a UDP handshake to that
    /// address; <see cref="WireGuardPeer.Endpoint"/> and <see cref="WireGuardPeer.IsDerpConnected"/>
    /// stay unchanged, so data keeps flowing via DERP/TCP during the probe; as soon as a direct
    /// data packet/handshake response from that peer arrives, the existing ProcessResponse/
    /// ProcessData logic naturally switches to the direct path and clears the DERP flag.
    ///
    /// Background: the old approach of the higher layer (P2P-Direct policy) wrote the candidate
    /// endpoint into the device first and waited 5s for a handshake; if the candidate did not
    /// work, that amounted to tearing down a working DERP path (data black-holed for seconds),
    /// and most candidates were NAT'd unreachable addresses, manifesting as "periodic
    /// disconnects / certain peers stuck at 100% packet loss for long periods".
    /// </summary>
    /// <param name="peerPublicKey">The public key of the peer to probe.</param>
    /// <param name="candidate">The candidate UDP endpoint to probe.</param>
    /// <param name="bypassHysteresis">When true, skips the quiet-window/backoff/sticky gates (used for same-LAN candidates whose direct path does not depend on NAT mappings).</param>
    /// <returns>false when probing is currently not allowed (not running / peer missing / a probe is already in flight / failure backoff / a handshake is pending); true when the probe was initiated.</returns>
    public bool TryProbeEndpoint(byte[] peerPublicKey, IPEndPoint candidate, bool bypassHysteresis = false)
    {
        if (!_running || _stopping || candidate == null) return false;
        if (!_peers.TryGetValue(peerPublicKey, out var peer)) return false;
        if (_handshakeManager.IsHandshakePending(peerPublicKey)) return false;

        if (!bypassHysteresis)
        {
            // [VM-PROBE-QUIET-WINDOW] Do not disturb sessions whose handshake was just
            // established/refreshed (<20s): a probe handshake consumes the peer's handshake
            // state and triggers a session switch; probing inside the just-stabilized window
            // was measured to cause 3~6s of data-plane jitter (receiverIndex invalidated →
            // packet loss). Wait for the session to reach steady state before probing.
            if (peer.HasTransport && (DateTime.UtcNow - peer.LastHandshake) < TimeSpan.FromSeconds(20)) return false;
            if (!IsProbeAllowed(peerPublicKey)) return false;
        }
        else
        {
            // [VM-LAN-PROBE-EXEMPT 2026-11-01] Same-LAN probe: keep only the "no concurrent
            // probes" constraint, exempting the failure backoff and DERP stickiness — their
            // premise (NAT mappings may be stale) does not hold for LAN-direct connections.
            if (_probeInFlight.ContainsKey(peerPublicKey)) return false;
        }

        peer.LastKnownUdpEndpoint = candidate;
        _lastDirectProbeTime[peerPublicKey] = DateTime.UtcNow;
        MarkProbeStarted(peerPublicKey, isLanProbe: bypassHysteresis);

        Log("DBG", $"Probe (no hijack) for peer {BitConverter.ToString(peerPublicKey)[..20]}... candidate={candidate}, data path unchanged, lanExempt={bypassHysteresis}");
        InitiateHandshakeWithPeer(peerPublicKey, candidate);
        return true;
    }

    /// <summary>
    /// [VM-RESELECT-GATE 2026-10-31] The remaining direct-path suppression time for this peer
    /// (probe in flight / failure backoff / post-probe validation window; the maximum of all).
    /// Zero means the data path may currently be switched to the direct endpoint.
    /// The higher layer (NodeManager endpoint reselection) uses this as a gate: while the
    /// direct path is under suppression, the peer endpoint must not be changed to a new public
    /// candidate — otherwise every relay packet received would trigger another reselection, the
    /// endpoint would be overwritten repeatedly by unreachable public candidates, forming an
    /// idle "probe → fail → reselect again" loop plus dual-path duplicate delivery.
    /// Does not include the DERP sticky cooldown: stickiness only constrains "initiating
    /// probes" (already checked inside ProbeDirectPath); the endpoint itself must still be
    /// written as early as possible, otherwise the peer has no UDP endpoint to probe during
    /// the sticky period and the direct upgrade is postponed indefinitely.
    /// </summary>
    /// <param name="peerPublicKey">The public key of the peer.</param>
    /// <returns>The remaining suppression time; <see cref="TimeSpan.Zero"/> when the direct path may be (re)selected now.</returns>
    public TimeSpan GetDirectPathSuppression(byte[] peerPublicKey)
    {
        var now = DateTime.UtcNow;
        var remaining = TimeSpan.Zero;

        void Consider(TimeSpan candidate)
        {
            if (candidate > remaining) remaining = candidate;
        }

        if (_probeInFlight.TryGetValue(peerPublicKey, out var startedAt))
        {
            // Probe in flight: grant it a full validation-window budget so the higher layer does not rewrite the endpoint mid-probe.
            var elapsed = now - startedAt;
            Consider(TimeSpan.FromSeconds(Math.Max(0, ProbeValidationWindow.TotalSeconds - elapsed.TotalSeconds)));
        }
        if (_probeValidationUntil.TryGetValue(peerPublicKey, out var validateUntil) && validateUntil > now)
        {
            Consider(validateUntil - now);
        }
        if (_probeBackoffUntil.TryGetValue(peerPublicKey, out var backoffUntil) && backoffUntil > now)
        {
            Consider(backoffUntil - now);
        }

        return remaining;
    }

    // Per-source throttling of data decryption failures: forged packets with an unknown
    // receiverIndex trigger an O(n) full-table scan + decryption attempts; once the threshold
    // is reached, decryption attempts are skipped for the window (the limited re-handshake
    // logic is kept to allow recovery).
    private readonly ConcurrentDictionary<IPEndPoint, UdpAuthFailureTracker> _dataDecryptFailures = new();


    /// <summary>
    /// Determines whether the destination address of a TUN packet is multicast/broadcast
    /// (IPv4 224.0.0.0/4 and 255.255.255.255; IPv6 ff00::/8).
    /// A first-byte check only — sufficient and allocation-free, since this method runs
    /// for every packet on the data path.
    /// </summary>
    private static bool IsMulticastOrBroadcast(byte[] packet)
    {
        var version = (packet[0] >> 4) & 0x0F;

        if (version == 4)
        {
            if (packet.Length < 20) { return false; }
            var first = packet[16];
            if (first >= 224 && first <= 239) { return true; }   // 224.0.0.0/4
            return packet[16] == 255 && packet[17] == 255 && packet[18] == 255 && packet[19] == 255;
        }

        if (version == 6)
        {
            if (packet.Length < 40) { return false; }
            return packet[24] == 0xFF;                            // ff00::/8
        }

        return false;
    }

    private void ProcessTunPacket(byte[] packet)
    {
        if (packet.Length < 20)
        {
            return;
        }

        // [VM-TUN-MCAST 2026-11-13] Multicast/broadcast never enters the tunnel and is not
        // logged either. In a 2-hour capture on this machine, 27 "No peer found for TUN
        // packet ... dst=224.0.0.251:5353" entries were all mDNS: such packets should never
        // match any peer in the first place and ought to be dropped silently before the peer
        // table — otherwise the log drowns in meaningless warnings while the genuinely
        // useful "destination has no route" signals get buried.
        if (IsMulticastOrBroadcast(packet))
        {
            Interlocked.Increment(ref _tunMulticastDropped);
            return;
        }

        if (OutboundPacketFilter != null && !OutboundPacketFilter(packet))
        {
            return;
        }

        WireGuardPeer? matchedPeer = null;
        WireGuardPeer? exitNodePeer = null;
        int bestPrefixLength = -1;

        foreach (var kvp in _peers)
        {
            var peer = kvp.Value;
            var match = peer.AllowedIPs.MatchPacket(packet);
            if (!match.IsMatch)
                continue;

            if (match.IsDefaultRoute)
            {
                exitNodePeer ??= peer;
            }
            else
            {
                if (match.PrefixLength > bestPrefixLength)
                {
                    bestPrefixLength = match.PrefixLength;
                    matchedPeer = peer;
                }
                else if (match.PrefixLength == bestPrefixLength)
                {
                    // Equal-prefix tie-break: prefer the peer with a healthy session.
                    // Background: key rotation / stale persisted state can leave the same
                    // virtual IP claimed by both an old and a new peer, and dictionary
                    // iteration order is nondeterministic — after a server restart (zombie
                    // peers resurrected from the state file) this once sent all traffic to a
                    // zombie that had "never completed a handshake", while the real peer's
                    // healthy DERP session never received a single data packet (only the
                    // keepalive timer's direct sends were visible).
                    // Rule: a peer with transport and an established session wins; when
                    // equally healthy, the one with the more recent LastHandshake wins;
                    // on a continued tie the incumbent stays.
                    var incumbent = matchedPeer!;
                    var incumbentHealthy = incumbent.HasTransport && incumbent.IsEstablished;
                    var candidateHealthy = peer.HasTransport && peer.IsEstablished;
                    var preferCandidate = incumbentHealthy != candidateHealthy
                        ? candidateHealthy
                        : peer.LastHandshake > incumbent.LastHandshake;
                    if (preferCandidate)
                    {
                        matchedPeer = peer;
                    }
                }
            }
        }

        var targetPeer = matchedPeer ?? exitNodePeer;
        if (targetPeer != null)
        {
            Interlocked.Increment(ref _tunPacketCount);
            if (targetPeer == exitNodePeer && matchedPeer == null)
                Interlocked.Increment(ref _tunExitPacketCount);

            SendOrEnqueueEncryptedPacket(packet, targetPeer);
        }
        else
        {
            var now = DateTime.UtcNow;
            if (now - _lastTunPacketLog > _tunPacketLogInterval)
            {
                var version = (packet[0] >> 4) & 0x0F;
                // [VM-TUN-DST 2026-11-08] Include the destination address: otherwise we only
                // know "some packet could not be sent" and cannot tell a missing peer-table
                // entry from local traffic targeting a subnet route that was never delivered.
                var dstText = DescribePacketDestination(packet, version);
                Log("WRN", $"No peer found for TUN packet v{version} len={packet.Length}, dst={dstText}, peers count={_peers.Count}");
                _lastTunPacketLog = now;
            }
        }
    }

    private void SendOrEnqueueEncryptedPacket(byte[] packet, WireGuardPeer peer)
    {
        if (!peer.HasTransport)
        {
            if (!_handshakeManager.IsHandshakePending(peer.PublicKey))
            {
                if (peer.Endpoint != null && SendPacketViaDerp != null)
                {
                    InitiateHandshakeWithPeer(peer.PublicKey, peer.Endpoint);
                }
                else if (peer.Endpoint != null)
                {
                    InitiateHandshakeWithPeer(peer.PublicKey, peer.Endpoint);
                }
                else if (SendPacketViaDerp != null)
                {
                    InitiateHandshakeWithPeer(peer.PublicKey, null);
                }
            }

            if (peer.TryEnqueuePendingPacket(packet))
            {
                var now = DateTime.UtcNow;
                if (now - _lastNoTransportLog > _noTransportLogInterval)
                {
                    Log("WRN", $"SendEncrypted: no transport for peer {BitConverter.ToString(peer.PublicKey)[..20]}..., packet buffered ({peer.PendingPacketCount}), handshake initiated");
                    _lastNoTransportLog = now;
                }
            }
            else
            {
                Interlocked.Increment(ref _noTransportDropCount);
            }
            return;
        }

        if (_keyRotationManager.ShouldReject(peer.PublicKey))
        {
            _keyRotationManager.MarkForRotation(peer.PublicKey);
            if (!_handshakeManager.IsHandshakePending(peer.PublicKey))
            {
                InitiateHandshakeWithPeer(peer.PublicKey, peer.Endpoint);
            }

            if (peer.TryEnqueuePendingPacket(packet))
            {
                return;
            }

            Interlocked.Increment(ref _noTransportDropCount);
            return;
        }

        if (_keyRotationManager.ShouldInitiateRekey(peer.PublicKey))
        {
            InitiateHandshakeWithPeer(peer.PublicKey, peer.Endpoint);
            if (_handshakeManager.IsHandshakePending(peer.PublicKey) && !peer.HasTransport)
            {
                if (peer.TryEnqueuePendingPacket(packet))
                {
                    return;
                }
            }
        }

        // Compression layer: compress the plaintext IP packet before encryption.
        // The payload is replaced only when PacketCompressor is enabled and Compress
        // returns non-null (i.e. compression was effective).
        var payloadToEncrypt = packet;
        if (PacketCompressor != null && PacketCompressor.IsEnabled)
        {
            var compressed = PacketCompressor.Compress(packet);
            if (compressed != null)
            {
                payloadToEncrypt = compressed;
            }
        }

        byte[] encrypted;
        try
        {
            encrypted = peer.EncryptPacket(payloadToEncrypt, peer.RemoteIndex);
        }
        catch (Exception ex)
        {
            Interlocked.Increment(ref _encryptFailCount);
            System.Diagnostics.Debug.WriteLine($"[WireGuardDevice] Failed to encrypt packet: {ex.Message}");
            return;
        }

        _keyRotationManager.RecordSend(peer.PublicKey);

        if (!_sendChannel.Writer.TryWrite((encrypted, peer)))
        {
            Interlocked.Increment(ref _sendDropCount);
        }
    }

    private async Task DerpProcessLoopAsync(CancellationToken cancellationToken)
    {
        await Task.Yield();
        await foreach (var (peerPublicKey, packet) in _derpPacketChannel.Reader.ReadAllAsync(cancellationToken))
        {
            try
            {
                await ProcessDerpPacketAsync(peerPublicKey, packet);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[WireGuardDevice] Error processing DERP packet: {ex.GetType().Name}: {ex.Message}");
            }
        }
    }

    private async Task SendLoopAsync(CancellationToken cancellationToken)
    {
        await Task.Yield();
        var batch = new List<(byte[] EncryptedPacket, WireGuardPeer Peer)>(64);
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                batch.Clear();
                if (!_sendChannel.Reader.TryRead(out var first))
                {
                    try
                    {
                        first = await _sendChannel.Reader.ReadAsync(cancellationToken);
                    }
                    catch (OperationCanceledException) { break; }
                    catch (ChannelClosedException) { break; }
                }
                batch.Add(first);

                while (batch.Count < 64 && _sendChannel.Reader.TryRead(out var item))
                {
                    batch.Add(item);
                }

                for (int i = 0; i < batch.Count; i++)
                {
                    try
                    {
                        SendEncryptedPacketDirect(batch[i].EncryptedPacket, batch[i].Peer);
                    }
                    catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[WireGuardDevice] Failed to send packet to peer: {ex.Message}"); }
                }
            }
            catch (OperationCanceledException) { break; }
            catch (ChannelClosedException) { break; }
            catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[WireGuardDevice] SendLoop error: {ex.Message}"); }
        }
    }

    private void SendEncryptedPacketDirect(byte[] encrypted, WireGuardPeer peer)
    {
        // [FIX 2026-10-08] Fast transport dead-link detection (applies to every transport
        // path): when the session is established and this end is actively sending, but no
        // packet from that peer has arrived for UdpDeadLinkTimeout in a row, the session has
        // most likely been silently dropped by the peer (peer restart losing sessions,
        // mutual trampling of bidirectional sessions, etc. — the WireGuard protocol silently
        // drops packets for invalid sessions with no error feedback whatsoever). Trigger a
        // re-handshake immediately to establish a new session; if currently on UDP and DERP is
        // available, also switch sends to DERP as a safety net. Otherwise this end would keep
        // sending into the dead session until the higher layer's 150s connection timeout
        // (measured black holes of several minutes).
        var deadLinkNow = DateTime.UtcNow;
        var activelySending = peer.LastTxTime != DateTime.MinValue && deadLinkNow - peer.LastTxTime < TimeSpan.FromSeconds(10);
        var noRxRecently = (peer.LastRxTime == DateTime.MinValue || deadLinkNow - peer.LastRxTime > UdpDeadLinkTimeout) &&
            (peer.LastHandshake == DateTime.MinValue || deadLinkNow - peer.LastHandshake > UdpDeadLinkTimeout);
        if (peer.IsEstablished && activelySending && noRxRecently)
        {
            var throttled = _lastRehandshakeTime.TryGetValue(peer.PublicKey, out var lastRehandshake) &&
                deadLinkNow - lastRehandshake < TimeSpan.FromSeconds(30);
            if (!throttled)
            {
                _lastRehandshakeTime[peer.PublicKey] = deadLinkNow;
                if (!peer.IsDerpConnected && SendPacketViaDerp != null)
                {
                    peer.IsDerpConnected = true;
                    // [FIX 2026-10-14] A dead-link switch to DERP also enters the sticky cooldown, preventing a probe from retrying the direct path immediately
                    MarkDerpSticky(peer.PublicKey);
                    Log("WRN", $"Transport dead-link detected for peer {BitConverter.ToString(peer.PublicKey)[..20]}... (no packets received for {(deadLinkNow - peer.LastRxTime).TotalSeconds:F0}s while actively sending) - switching to DERP and re-initiating handshake");
                }
                else
                {
                    Log("WRN", $"Transport dead-link detected for peer {BitConverter.ToString(peer.PublicKey)[..20]}... (no packets received for {(deadLinkNow - peer.LastRxTime).TotalSeconds:F0}s while actively sending) - re-initiating handshake");
                }
                InitiateHandshakeWithPeer(peer.PublicKey, peer.Endpoint);
            }
        }

        // [VM-FIRST-CONNECT 2026-10-21] Fast DERP fallback for peers that have never
        // completed a handshake: in scenarios like recovery from a long offline period or a
        // server misreporting endpoints, the peer keeps sending packets to a dead endpoint
        // and the handshake never gets a response; the existing fallback (handshake timeout
        // ~90s before OnHandshakeTimedOut switches to DERP) is too slow. When sending has
        // continued for UnconfirmedHandshakeFallbackDelay(8s) without any response, switch to
        // DERP immediately:
        //   · save the endpoint into LastKnownUdpEndpoint so ProbeDirectPath can
        //     periodically probe and switch back to the direct path;
        //   · InitiateHandshakeWithPeer(key, null) re-initiates the handshake via the DERP
        //     relay (isDerpInitiated);
        //   · MarkDerpSticky's 5min probe ban + _lastRehandshakeTime's 30s throttle work
        //     together with the existing hysteresis to prevent flapping;
        //   · once the handshake succeeds (LastHandshake/LastRx refreshed), the anchor is
        //     cleared and the normal path resumes.
        // While a probe is in flight (_probeInFlight) the data already flows via DERP, so
        // IsDerpConnected is already true here and this block is naturally skipped.
        if (peer.LastHandshake != DateTime.MinValue || peer.LastRxTime != DateTime.MinValue)
        {
            _firstUnconfirmedSendTime.TryRemove(peer.PublicKey, out _);
        }
        else if (!peer.IsEstablished && !peer.IsDerpConnected && activelySending && SendPacketViaDerp != null)
        {
            var firstSend = _firstUnconfirmedSendTime.GetOrAdd(peer.PublicKey, deadLinkNow);
            var waitingForHandshake = deadLinkNow - firstSend;
            if (waitingForHandshake >= UnconfirmedHandshakeFallbackDelay)
            {
                var throttled = _lastRehandshakeTime.TryGetValue(peer.PublicKey, out var lastRetry) &&
                    deadLinkNow - lastRetry < TimeSpan.FromSeconds(30);
                if (!throttled)
                {
                    _lastRehandshakeTime[peer.PublicKey] = deadLinkNow;
                    peer.LastKnownUdpEndpoint = peer.Endpoint;
                    peer.Endpoint = null;
                    peer.IsDerpConnected = true;
                    MarkDerpSticky(peer.PublicKey);
                    Log("WRN", $"No handshake response for {waitingForHandshake:F0}s since first send (peer never handshook) - switching to DERP relay and initiating DERP handshake");
                    InitiateHandshakeWithPeer(peer.PublicKey, null);
                }
            }
        }

        // Transport routing priority: DERP > TCP > WebSocket > UDP > DERP fallback
        if (peer.IsDerpConnected && SendPacketViaDerp != null)
        {
            SendPacketViaDerp(this, (peer.PublicKey, encrypted));
            _keepaliveManager.PacketSent(peer.PublicKey);
        }
        else if (peer.IsTcpConnected && SendPacketViaTcp != null)
        {
            SendPacketViaTcp(this, (peer.PublicKey, encrypted));
            _keepaliveManager.PacketSent(peer.PublicKey);
        }
        else if (peer.IsWebSocketConnected && SendPacketViaWebSocket != null)
        {
            SendPacketViaWebSocket(this, (peer.PublicKey, encrypted));
            _keepaliveManager.PacketSent(peer.PublicKey);
        }
        // [FIX 2026-10-14] While a direct-path probe is in flight, data packets are banned
        // from UDP: a probe is merely a "try"; hijacking the data flow onto the unverified UDP
        // endpoint (a dead end under CGNAT) sends all TCP data into a black hole for the
        // probe's 90s timeout window (the direct mechanism of the production RDP 0x7 / SSH
        // disconnects). The probe handshake packet itself still goes over UDP via
        // SendHandshakeToPeerAsync; the data flow stays on DERP until the probe passes
        // validation (ProcessData receiving direct data → IsDerpConnected=false switches
        // back naturally).
        else if (peer.Endpoint != null && !peer.Endpoint.Address.Equals(IPAddress.Any) && _udpClient != null &&
                 !_probeInFlight.ContainsKey(peer.PublicKey))
        {
            try
            {
                var useSendClient = _useSendUdpClient && _sendUdpClient != null;
                var client = useSendClient ? _sendUdpClient : _udpClient;
                // _sendUdpClient is IPv4-only, so no mapping is applied; endpoints are normalized only for the dual-stack _udpClient
                var sendEndpoint = useSendClient ? peer.Endpoint : NormalizeSendEndpoint(peer.Endpoint);
                if (client == null || sendEndpoint == null) return;
                client.Client.SendTo(encrypted, sendEndpoint);
                _keepaliveManager.PacketSent(peer.PublicKey);
            }
            catch (Exception)
            {
                peer.IsDerpConnected = true;
                if (SendPacketViaDerp != null)
                {
                    SendPacketViaDerp(this, (peer.PublicKey, encrypted));
                    _keepaliveManager.PacketSent(peer.PublicKey);
                }
            }
        }
        else if (SendPacketViaDerp != null)
        {
            SendPacketViaDerp(this, (peer.PublicKey, encrypted));
            _keepaliveManager.PacketSent(peer.PublicKey);
        }
    }

    private async Task UdpReceiveLoopAsync(Channel<(byte[] Packet, IPEndPoint RemoteEndPoint)> channel, CancellationToken cancellationToken)
    {
        await Task.Yield();
        while (!cancellationToken.IsCancellationRequested && _udpClient != null)
        {
            try
            {
                // ReceiveAsync with a cancellationToken: Stop() cancels the token to wake the
                // loop up and exit immediately, without relying on socket Close — avoids the
                // previous round's loop reaching TryComplete only after this round's StartAsync.
                var result = await _udpClient.ReceiveAsync(cancellationToken);
                var endpoint = NormalizeReceiveEndpoint(result.RemoteEndPoint);
                if (!channel.Writer.TryWrite((result.Buffer, endpoint!)))
                {
                    Interlocked.Increment(ref _udpDropCount);
                }
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (ObjectDisposedException)
            {
                break;
            }
            catch (SocketException ex) when (ex.SocketErrorCode == SocketError.OperationAborted)
            {
                break;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[WireGuardDevice] Error receiving UDP packet: {ex.Message}");
                try { await Task.Delay(1000, cancellationToken); } catch (OperationCanceledException) { break; }
            }
        }
        channel.Writer.TryComplete();
    }

    private async Task UdpProcessLoopAsync(Channel<(byte[] Packet, IPEndPoint RemoteEndPoint)> channel, CancellationToken cancellationToken)
    {
        await Task.Yield();
        await foreach (var item in channel.Reader.ReadAllAsync(cancellationToken))
        {
            try
            {
                await ProcessUdpPacketAsync(item.Packet, item.RemoteEndPoint);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[WireGuardDevice] Error processing UDP packet: {ex.Message}");
            }
        }
    }

    private async Task ProcessUdpPacketAsync(byte[] packet, IPEndPoint remoteEndPoint)
    {
        if (packet.Length < 4) return;

        // [VM-STUN-ON-WG-SOCKET] STUN responses are peeled off first: their first byte is not
        // a WireGuard type, so letting them reach the later parsing would only classify them
        // as unknown messages. On a hit we return immediately without WireGuard processing.
        if (StunEndpointDiscovery.LooksLikeStun(packet) && HandleStunResponse(packet))
        {
            return;
        }

        var type = BitConverter.ToUInt32(packet, 0) & 0xFF;

        if (type == WireGuardConstants.TYPE_INITIATION)
        {
            if (_udpAuthFailures.TryGetValue(remoteEndPoint, out var tracker) && tracker.IsBlocked)
            {
                // Packets with a valid MAC1 are still allowed from rate-limited endpoints:
                // MAC1 proves the message targets this node's public key, preventing an
                // attacker from blocking a legitimate peer's endpoint with junk packets
                // carrying forged source IPs.
                var mac1Valid = packet.Length == WireGuardConstants.HANDSHAKE_INITIATION_LEN &&
                                WireGuardHandshake.ValidateMac1(_keyPair.PublicKey, packet, packet.Length - 32);
                if (!mac1Valid)
                {
                    return;
                }
            }
        }

        switch (type)
        {
            case WireGuardConstants.TYPE_INITIATION:
                await ProcessInitiationAsync(packet, remoteEndPoint);
                break;
            case WireGuardConstants.TYPE_RESPONSE:
                await ProcessResponseAsync(packet, remoteEndPoint);
                break;
            case WireGuardConstants.TYPE_DATA:
                await ProcessDataAsync(packet, remoteEndPoint);
                break;
            case WireGuardConstants.TYPE_COOKIE:
                await ProcessCookieAsync(packet, remoteEndPoint);
                break;
        }
    }

    /// <summary>
    /// [VM-HS-RETRY 2026-10-23] Cache of the last handshake response per peer (key = Base64 peer key).
    /// The peer's wireguard-go handshake retry re-sends the same initiation message (same
    /// TAI64N); the standard kernel semantics are "replayed initiation → re-send the cached
    /// response". Previously such initiations were dropped as stale timestamps, so the peer's
    /// 5s retries never worked, leaving a dead zone until it reset its handshake state after
    /// 90s (measured ~2 minutes; repeatedly observed in iPhone network-switch/reconnect
    /// scenarios).
    /// </summary>
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, (byte[] Tai64n, byte[] Response, DateTime CachedAt)> _handshakeResponseCache = new();

    private async Task ProcessInitiationAsync(byte[] packet, IPEndPoint remoteEndPoint)
    {
        // Any failure path between ReadInitiation and storing the index mapping MUST Dispose
        // this state (it holds clones of the device private key/PSK); after a successful
        // hand-over it is Disposed and nulled uniformly below.
        NoiseHandshakeState? unownedHandshakeState = null;
        try
        {
            // CPU/log amplification protection against forged initiations: MAC1 validation and
            // rate limiting both run before Noise decryption; the per-packet debug log is
            // downgraded to DBG so an attacker cannot flood the INF log.
            Log("DBG", $"ProcessInitiation: packet size={packet.Length}, isDerp={IsDerpEndpoint(remoteEndPoint)}");

            var (handshakeState, senderIndex, peerPublicKey, timestamp) =
                _wireGuardHandshake.ReadInitiation(packet, _peers.Keys);
            unownedHandshakeState = handshakeState;

            if (peerPublicKey == null || peerPublicKey.Length == 0)
            {
                Log("WRN", $"ProcessInitiation: handshake returned null peerPublicKey, packet size={packet.Length}");
                unownedHandshakeState.Dispose();
                unownedHandshakeState = null;
                return;
            }

            var peerKeyHex = BitConverter.ToString(peerPublicKey)[..Math.Min(40, peerPublicKey.Length * 3)];
            Log("DBG", $"ProcessInitiation: received from peer {peerKeyHex}..., isDerp={IsDerpEndpoint(remoteEndPoint)}, peers count={_peers.Count}");

            if (!_peers.ContainsKey(peerPublicKey))
            {
                Log("WRN", $"ProcessInitiation: peer {peerKeyHex}... NOT found in peers list! Known peers: {string.Join(", ", _peers.Keys.Select(k => BitConverter.ToString(k)[..Math.Min(20, k.Length * 3)] + "..."))}");
                unownedHandshakeState.Dispose();
                unownedHandshakeState = null;
                return;
            }

            // TAI64N timestamp anti-replay (standard wg behavior): reject initiations whose timestamp does not advance.
            if (_peers.TryGetValue(peerPublicKey, out var peerForTs) &&
                !peerForTs.TryUpdateLastInitiationTimestamp(timestamp))
            {
                // [VM-HS-RETRY 2026-10-23] Retried initiation (a retransmitted copy with the
                // same TAI64N) → re-send the cached response (standard kernel semantics: a
                // replayed initiation gets the cached response re-sent). The peer's
                // wireguard-go retries every 5s reusing the same handshake message; dropping
                // it outright left the peer's retries forever ineffective, a dead zone until
                // it reset its handshake state after 90s.
                var responseCacheKey = Convert.ToBase64String(peerPublicKey);
                if (_handshakeResponseCache.TryGetValue(responseCacheKey, out var cachedRetry) &&
                    cachedRetry.Tai64n.AsSpan().SequenceEqual(timestamp) &&
                    DateTime.UtcNow - cachedRetry.CachedAt < TimeSpan.FromSeconds(30))
                {
                    Log("INF", $"ProcessInitiation: retry initiation from peer {peerKeyHex}..., re-sending cached response");
                    if (IsDerpEndpoint(remoteEndPoint) && SendPacketViaDerp != null)
                    {
                        SendPacketViaDerp(this, (peerPublicKey, cachedRetry.Response));
                    }
                    else
                    {
                        try
                        {
                            _udpClient.Client.SendTo(cachedRetry.Response, SocketFlags.None, NormalizeSendEndpoint(remoteEndPoint)!);
                        }
                        catch (Exception sendEx)
                        {
                            Log("DBG", $"Retry response send via UDP failed: {sendEx.Message}");
                        }
                    }
                }
                else
                {
                    Log("DBG", $"ProcessInitiation: replayed/stale initiation timestamp from peer {peerKeyHex}..., dropping");
                }
                unownedHandshakeState.Dispose();
                unownedHandshakeState = null;
                return;
            }

            if (_peers.TryGetValue(peerPublicKey, out var peerForPsk) && peerForPsk.PresharedKey != null)
            {
                handshakeState.SetPresharedKey(peerForPsk.PresharedKey);
                Log("DBG", $"ProcessInitiation: set PSK for peer {peerKeyHex}...");
            }

            // Deterministic convergence for simultaneous handshakes: both sides apply the
            // same ShouldYieldToPeerInitiation rule; the winner (lexicographically larger key,
            // see the comment at the method implementation) ignores the other side's
            // initiation and keeps its own pending initiation (converging to initiator via
            // the next retransmission / after the peer yields), while the loser yields to
            // become a pure responder, ultimately converging on a single session.
            // If the winner also responded normally and let the peer's initiation create a
            // responder session, each side would hold two sessions whose SetTransport calls
            // on the single WireGuardPeer object overwrite each other; resending from
            // counter 0 then hits the peer's replay window (Replay attack), LastRx never
            // updates, timeout re-handshakes fire, and a handshake storm forms.
            // — Note: placing it here rather than before CreateResponse causes no ordering
            // side effects; placing it after the timestamp update ensures retransmitted copies
            // of the same initiation are deduplicated and dropped by the timestamp check.
            if (_handshakeManager.IsHandshakePending(peerPublicKey) &&
                !ShouldYieldToPeerInitiation(_keyPair.PublicKey, peerPublicKey))
            {
                // [VM-TIEBREAK-ROAM 2026-10-03] The winner ignores this initiation, but standard
                // WireGuard continuously roams/updates the peer endpoint from the UDP source of
                // any authenticated packet; the previous ignore branch returned immediately and
                // lost that learning opportunity. When the yielding side (e.g. an iPhone) sits
                // behind CGNAT whose NAT port has drifted (real port ≠ the in-library remap of
                // :51820) while this side's Endpoint for that peer is still a dead value from the
                // library, our pending initiation/responses keep being sent to a dead port, and
                // the peer's "Handshake did not complete" retry storm can last minutes (measured
                // 8-minute black hole on a real device, finally converging only via a NAT-mapping
                // expiry gap). After learning the real UDP source, our subsequent
                // initiation/responses hit the peer's dynamic NAT port directly.
                if (!IsDerpEndpoint(remoteEndPoint) &&
                    _peers.TryGetValue(peerPublicKey, out var roamingPeer) &&
                    (roamingPeer.Endpoint == null || !roamingPeer.Endpoint.Equals(remoteEndPoint)))
                {
                    var staleEndpoint = roamingPeer.Endpoint;
                    roamingPeer.Endpoint = remoteEndPoint;
                    ResetUdpAuthFailures(remoteEndPoint);
                    Log("INF", $"ProcessInitiation: tie-break win ignoring initiation, learned new UDP endpoint {remoteEndPoint} (was {staleEndpoint}) for peer {BitConverter.ToString(peerPublicKey)[..20]}...");
                }
                // [FIX 2026-10-04] While ignoring the peer's initiation, immediately re-send
                // our pending initiation along its arrival channel: the arrival of the
                // initiation itself proves that channel currently reaches the peer, and the
                // yielding side is waiting for our initiation to converge. The old
                // implementation only ignored without re-sending — if our pending initiation
                // was DERP-initiated (HandshakeManager does not retransmit such pendings) and
                // its first send happened to be dropped inside the peer's Gone cooldown window,
                // every initiation from the peer would be ignored here, and the deadlock
                // persisted until the 90s REKEY_ATTEMPT_TIME timeout, only broken by
                // ProbeDirectPath (measured ~60s of unreachability after reconnect on a real
                // device).
                ResendPendingHandshakeViaArrivalChannel(peerPublicKey, remoteEndPoint);
                Log("INF", $"ProcessInitiation: simultaneous initiation - ignoring peer's initiation (local key wins tie-break, keeping our pending initiation) for peer {BitConverter.ToString(peerPublicKey)[..20]}...");
                unownedHandshakeState.Dispose();
                unownedHandshakeState = null;
                return;
            }

            var (response, localIndex, sendKey, recvKey) =
                _wireGuardHandshake.CreateResponse(handshakeState, senderIndex, peerPublicKey,
                    cookie: IsDerpEndpoint(remoteEndPoint) ? null : _cookieProtector.GetCookieForEndpoint(remoteEndPoint));

            if (_handshakeManager.IsHandshakePending(peerPublicKey) &&
                ShouldYieldToPeerInitiation(_keyPair.PublicKey, peerPublicKey))
            {
                // Simultaneous handshake and this end loses the tie-break: the side with the
                // lexicographically smaller public key yields (clears its own pending
                // initiation and becomes a pure responder); the winner's behavior is the ignore
                // branch above. Both sides apply the same rule, ultimately converging on a
                // single session with the larger-key side as initiator.
                var pendingLocalIndex = _handshakeManager.GetPendingLocalIndex(peerPublicKey);
                var wasDerpInitiated = _handshakeManager.IsPendingDerpInitiated(peerPublicKey);
                _handshakeManager.ClearHandshake(peerPublicKey);

                // [FIX 2026-10-14] Yielding clears our pending: if that pending was a
                // direct-path probe, its timeout event will never fire, so the in-flight
                // probe/validation window must be cancelled here as well; otherwise
                // IsProbeAllowed stays stuck forever (that peer could never probe the direct
                // path again).
                _probeInFlight.TryRemove(peerPublicKey, out _);
                _probeValidationUntil.TryRemove(peerPublicKey, out _);

                if (pendingLocalIndex.HasValue && pendingLocalIndex.Value != localIndex)
                {
                    if (_indexToPeer.TryRemove(pendingLocalIndex.Value, out var yieldedInfo))
                    {
                        DisposeSessionHandshakeState(yieldedInfo);
                        if (_peerToIndices.TryGetValue(peerPublicKey, out var pendingIndices))
                        {
                            lock (pendingIndices)
                            {
                                pendingIndices.Remove(pendingLocalIndex.Value);
                            }
                        }
                    }
                    Log("INF", $"ProcessInitiation: simultaneous initiation - yielded to peer's initiation (via {(IsDerpEndpoint(remoteEndPoint) ? "DERP" : "UDP")}), cleared our {(wasDerpInitiated ? "DERP" : "UDP")}-initiated handshake (localIndex={pendingLocalIndex.Value}) for peer {BitConverter.ToString(peerPublicKey)[..20]}...");
                }
                else
                {
                    Log("INF", $"ProcessInitiation: simultaneous initiation - yielded to peer's initiation (via {(IsDerpEndpoint(remoteEndPoint) ? "DERP" : "UDP")}), cleared our {(wasDerpInitiated ? "DERP" : "UDP")}-initiated handshake for peer {BitConverter.ToString(peerPublicKey)[..20]}...");
                }
            }

            var isDerpInitiation = IsDerpEndpoint(remoteEndPoint);
            if (isDerpInitiation && _peers.TryGetValue(peerPublicKey, out var existingPeer))
            {
                if (existingPeer.HasTransport && !existingPeer.IsDerpConnected && existingPeer.IsEstablished)
                {
                    var timeSinceLastHandshake = DateTime.UtcNow - existingPeer.LastHandshake;
                    var peerInitiatingRekey = _keyRotationManager.ShouldReject(peerPublicKey) || _keyRotationManager.ShouldInitiateRekey(peerPublicKey);
                    Log("INF", $"ProcessInitiation: DERP initiation from peer {BitConverter.ToString(peerPublicKey)[..20]}... with existing UDP session (rekey={peerInitiatingRekey}, lastHandshake={timeSinceLastHandshake.TotalSeconds:F0}s ago) - accepting to sync session");
                }
            }

            var now = DateTime.UtcNow;
            if (_peerToIndices.TryGetValue(peerPublicKey, out var indices))
            {
                lock (indices)
                {
                    var toRemove = new List<uint>();
                    foreach (var idx in indices)
                    {
                        if (idx == localIndex) continue;
                        if (_indexToPeer.TryGetValue(idx, out var info) && info.IsCompleted && (now - info.CreatedAt) > TimeSpan.FromSeconds(30))
                            toRemove.Add(idx);
                    }
                    foreach (var key in toRemove)
                    {
                        if (_indexToPeer.TryRemove(key, out var staleInfo))
                        {
                            DisposeSessionHandshakeState(staleInfo);
                        }
                        indices.Remove(key);
                    }
                }
            }

            AddIndexMapping(localIndex, new PeerSessionInfo
            {
                PeerPublicKey = peerPublicKey,
                // The responder's handshake state was fully consumed inside CreateResponse
                // (WriteMessage + Split); it is not stored in the mapping and is Disposed
                // immediately after, zeroing the private key/PSK clones.
                HandshakeState = null,
                LocalIndex = localIndex,
                PeerIndex = senderIndex
            });
            handshakeState.Dispose();
            unownedHandshakeState = null;

            if (_peers.TryGetValue(peerPublicKey, out var peer))
            {
                peer.SetTransport(sendKey, recvKey);
                peer.LocalIndex = localIndex;
                peer.RemoteIndex = senderIndex;
                peer.LastHandshake = DateTime.UtcNow;
                peer.IsEstablished = true;
                // [VM-HS-BACKOFF 2026-11-08] Handshake succeeded; clear the backoff
                ResetHandshakeBackoff(peerPublicKey);

                var isDerpPacket = IsDerpEndpoint(remoteEndPoint);
                peer.IsDerpConnected = isDerpPacket;

                Log("INF", $"ProcessInitiation: session established localIndex={localIndex}, peerIndex={senderIndex}, peer={BitConverter.ToString(peerPublicKey)[..20]}...");

                Log("INF", $"Handshake completed with peer {BitConverter.ToString(peerPublicKey)[..20]}... via {(isDerpPacket ? "DERP" : "UDP")}");
                Log("DBG", $"Handshake keys: sendKey={BitConverter.ToString(sendKey, 0, 8)}..., recvKey={BitConverter.ToString(recvKey, 0, 8)}..., localIndex={localIndex}, remoteIndex={senderIndex}");

                _indexToPeer[localIndex] = _indexToPeer[localIndex] with { IsCompleted = true };

                // [VM-SESSION-COLLAPSE] The new session immediately collapses the peer's old sessions (prevents overlapping multi-session windows)
                CollapseStaleSessions(peerPublicKey, localIndex);

                // Simultaneous handshake and this end won the tie-break (did not yield): keep
                // our pending initiation and wait for its response to arrive to converge; clean
                // up only when we already yielded or there is no pending initiation left.
                if (!_handshakeManager.IsHandshakePending(peerPublicKey) ||
                    ShouldYieldToPeerInitiation(_keyPair.PublicKey, peerPublicKey))
                {
                    _handshakeManager.ClearHandshake(peerPublicKey);
                }
                _keyRotationManager.InitializePeer(peerPublicKey, sendKey, recvKey);
                _keepaliveManager.SessionEstablished(peerPublicKey);
                _connectionManager.RecordActivity(peerPublicKey);

                if (!isDerpPacket)
                {
                    // [FIX 2026-10-14] An initiation arriving directly over UDP: hard evidence the direct path is healthy; clear the backoff
                    MarkDirectPathHealthy(peerPublicKey);
                    var oldEndpoint = peer.Endpoint;
                    peer.Endpoint = remoteEndPoint;
                    ResetUdpAuthFailures(remoteEndPoint);
                    if (oldEndpoint == null || !oldEndpoint.Equals(remoteEndPoint))
                    {
                        OnPeerEndpointChanged?.Invoke(this, (peerPublicKey, remoteEndPoint));
                    }
                }
            }

            var isDerp = IsDerpEndpoint(remoteEndPoint);

            // [VM-HS-RETRY] Cache this response: when the peer's handshake retry (same TAI64N) arrives, re-send it.
            _handshakeResponseCache[Convert.ToBase64String(peerPublicKey)] =
                ((byte[])timestamp.Clone(), response, DateTime.UtcNow);

            if (isDerp && SendPacketViaDerp != null)
            {
                SendPacketViaDerp(this, (peerPublicKey, response));
            }
            else if (_udpClient != null && !isDerp)
            {
                try
                {
                    _udpClient.Client.SendTo(response, SocketFlags.None, NormalizeSendEndpoint(remoteEndPoint)!);
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"[WireGuardDevice] Failed to send response via UDP: {ex.Message}");
                    if (SendPacketViaDerp != null)
                    {
                        SendPacketViaDerp(this, (peerPublicKey, response));
                    }
                }
            }

            if (peer != null)
            {
                FlushPendingPackets(peer);
            }
        }
        catch (System.Security.Cryptography.CryptographicException cryptoEx)
            when (cryptoEx.Message.Contains("No matching peer found", StringComparison.OrdinalIgnoreCase))
        {
            // [VM-HS-UNKNOWN-PEER 2026-11-08] An initiation arrived that matches no known peer.
            //
            // Two possible origins, neither an error on this end:
            //   1. The peer re-registered/reinstalled and changed its public key, and the
            //      control plane has not synced the new key yet;
            //   2. The old session was destroyed while the peer keeps retransmitting the same
            //      handshake packet (WireGuard's retry window can last up to 90s).
            //
            // The old implementation logged this as a plain exception ERR and counted one
            // "auth failure" for that UDP endpoint — the former produced false alarms
            // (measured: 2 on this machine, 11 in 5h on an exit node), and the latter could
            // misjudge a legitimate peer's endpoint as an attack source inside
            // CleanUdpAuthFailures. It is now dropped silently with only a DBG log, and no
            // failure count is recorded.
            unownedHandshakeState?.Dispose();
            Log("DBG", $"ProcessInitiation: initiation did not match any known peer (stale retry or un-synced key), dropped from {remoteEndPoint}");
        }
        catch (Exception ex)
        {
            // ReadInitiation succeeded but later processing failed: the handshake state was never handed over to an index mapping, so Dispose (zero) it here as a safety net.
            unownedHandshakeState?.Dispose();
            Log("ERR", $"ProcessInitiationAsync error: {ex.GetType().Name}: {ex.Message}");
            if (!IsDerpEndpoint(remoteEndPoint))
            {
                // Only count packets that passed MAC1 validation but failed later processing:
                // MAC1-failing junk packets cost the attacker almost nothing (one Blake2s)
                // and the source IP can be forged, so counting them would get legitimate
                // peers' endpoints wrongly banned.
                var mac1Valid = packet.Length == WireGuardConstants.HANDSHAKE_INITIATION_LEN &&
                                WireGuardHandshake.ValidateMac1(_keyPair.PublicKey, packet, packet.Length - 32);
                if (mac1Valid)
                {
                    var tracker = _udpAuthFailures.GetOrAdd(remoteEndPoint, _ => new UdpAuthFailureTracker());
                    tracker.RecordFailure();

                    CleanUdpAuthFailures();
                }
            }
        }
    }

    private async Task ProcessResponseAsync(byte[] packet, IPEndPoint remoteEndPoint)
    {
        try
        {
            if (packet.Length < 12) return;

            var respSenderIndex = BitConverter.ToUInt32(packet, 4);
            var receiverIndex = BitConverter.ToUInt32(packet, 8);

            PeerSessionInfo? sessionInfo = null;
            if (_indexToPeer.TryGetValue(receiverIndex, out var info))
            {
                sessionInfo = info;
            }

            if (sessionInfo == null)
            {
                Interlocked.Increment(ref _duplicateResponseCount);
                var now = DateTime.UtcNow;
                if (now - _lastDuplicateResponseLog > TimeSpan.FromSeconds(10))
                {
                    var knownIndices = _indexToPeer
                        .OrderByDescending(kvp => kvp.Value.CreatedAt)
                        .Take(15)
                        .Select(kvp => $"{kvp.Key}(peer={BitConverter.ToString(kvp.Value.PeerPublicKey)[..Math.Min(11, BitConverter.ToString(kvp.Value.PeerPublicKey).Length)]},age={(int)(now - kvp.Value.CreatedAt).TotalSeconds}s,completed={kvp.Value.IsCompleted})");
                    Log("WRN", $"ProcessResponse: receiverIndex={receiverIndex} NOT FOUND in {_indexToPeer.Count} mappings, respSenderIndex={respSenderIndex}, known=[{string.Join(", ", knownIndices)}]");
                    _lastDuplicateResponseLog = now;
                    _duplicateResponseCount = 0;
                }
                return;
            }

            if (sessionInfo.IsCompleted)
            {
                System.Diagnostics.Debug.WriteLine($"[WireGuardDevice] ProcessResponse: ignoring duplicate response for already completed handshake (receiver index {receiverIndex})");
                return;
            }

            if (_peers.TryGetValue(sessionInfo.PeerPublicKey, out var activePeer) && activePeer.IsEstablished)
            {
                var timeSinceLastHandshake = DateTime.UtcNow - activePeer.LastHandshake;
                var hasCompletedMapping = _indexToPeer.Any(kvp =>
                    _comparer.Equals(kvp.Value.PeerPublicKey, sessionInfo.PeerPublicKey) &&
                    kvp.Value.IsCompleted &&
                    kvp.Key != sessionInfo.LocalIndex);

                var hasPendingHandshake = _handshakeManager.IsHandshakePending(sessionInfo.PeerPublicKey);
                if (hasCompletedMapping && timeSinceLastHandshake < TimeSpan.FromSeconds(30) && !hasPendingHandshake)
                {
                    Log("INF", $"ProcessResponse: ignoring stale response for peer {BitConverter.ToString(sessionInfo.PeerPublicKey)[..20]}... - a newer session already exists ({timeSinceLastHandshake.TotalSeconds:F0}s ago), removing stale index mapping");
                    _indexToPeer.TryRemove(receiverIndex, out var staleInfo2);
                    DisposeSessionHandshakeState(staleInfo2);
                    if (_peerToIndices.TryGetValue(sessionInfo.PeerPublicKey, out var staleIndices))
                    {
                        lock (staleIndices)
                        {
                            staleIndices.Remove(receiverIndex);
                        }
                    }
                    return;
                }
            }

            // [FIX 2026-10-08] If the response to a ProbeDirectPath probe handshake (UDP-initiated)
            // arrives via DERP, the UDP direct path has not actually recovered; accepting the
            // response while the peer already has a healthy DERP session would pointlessly
            // SetTransport-overwrite the existing session (probe = trampling). Drop the probe
            // response and clear the pending state, keeping the current session. When UDP truly
            // recovers, the peer's data packets switch back to UDP automatically via
            // ProcessData — no need to depend on the probe response.
            if (IsDerpEndpoint(remoteEndPoint) &&
                !_handshakeManager.IsPendingDerpInitiated(sessionInfo.PeerPublicKey) &&
                _peers.TryGetValue(sessionInfo.PeerPublicKey, out var probeTargetPeer) &&
                probeTargetPeer.IsEstablished &&
                DateTime.UtcNow - probeTargetPeer.LastHandshake < DirectPathProbeSessionHealthyAge)
            {
                Log("INF", $"ProcessResponse: ignoring direct-path probe response via DERP for peer {BitConverter.ToString(sessionInfo.PeerPublicKey)[..20]}... - healthy DERP session exists (last handshake {(DateTime.UtcNow - probeTargetPeer.LastHandshake).TotalSeconds:F0}s ago)");
                // [FIX 2026-10-14] Probe response looped back via DERP → the direct path does not actually work; judge the probe failed
                // [FIX 2026-10-19] Count a failure only when a probe is genuinely in flight: responses of
                // non-probe UDP-initiated handshakes (timeout reconnects etc.) looping back via DERP must not pollute the probe backoff counters
                if (_probeInFlight.ContainsKey(sessionInfo.PeerPublicKey))
                {
                    MarkProbeFailed(sessionInfo.PeerPublicKey, "probe response returned via DERP");
                }
                _indexToPeer.TryRemove(receiverIndex, out var probeInfo);
                DisposeSessionHandshakeState(probeInfo);
                _handshakeManager.ClearHandshake(sessionInfo.PeerPublicKey);
                return;
            }

            // Keep the old session before writing IsCompleted=true; if the old session already
            // exists and its isEstablished state has not timed out, do not delete the existing
            // index.
            // Note: the IsCompleted early-return branch above already handled the completed
            // case, so sessionInfo here is definitely incomplete; the dead code where
            // isRetryResponse was always false has been removed.
            _indexToPeer[receiverIndex] = sessionInfo with { IsCompleted = true };

            try
            {
                if (sessionInfo.HandshakeState == null)
                {
                    if (_peers.TryGetValue(sessionInfo.PeerPublicKey, out var existingPeer) && existingPeer.IsEstablished)
                    {
                        var timeSinceHandshake = DateTime.UtcNow - existingPeer.LastHandshake;
                        if (timeSinceHandshake < TimeSpan.FromSeconds(30))
                    {
                        // Critical fix: the original code deleted receiverIndex unconditionally.
                        // Changed to: if the old index already exists and is completed, keep the
                        // old index (do not delete it), so TUN data packets can still find the session.
                        _indexToPeer.TryRemove(receiverIndex, out var staleNullInfo);
                        DisposeSessionHandshakeState(staleNullInfo);
                        Log("INF", $"ProcessResponse: handshake state null but active session exists for peer {BitConverter.ToString(sessionInfo.PeerPublicKey)[..20]}... - keeping existing session (last handshake {timeSinceHandshake.TotalSeconds:F0}s ago)");
                        return;
                    }
                }
                Log("WRN", $"ProcessResponse: handshake state is null for receiverIndex={receiverIndex}, peer {BitConverter.ToString(sessionInfo.PeerPublicKey)[..20]}... and no active session");
                _indexToPeer.TryRemove(receiverIndex, out var nullInfo);
                DisposeSessionHandshakeState(nullInfo);
                return;
                }

                var (senderIndex, sendKey, recvKey) = _wireGuardHandshake.ProcessResponse(
                    packet, sessionInfo.HandshakeState);

                // After the response has been processed the handshake state is consumed (Split
                // produced the transport keys): Dispose it immediately to zero the private-key/PSK
                // clones it holds, and clear the reference in the mapping to avoid a double Dispose.
                sessionInfo.HandshakeState.Dispose();
                _indexToPeer[sessionInfo.LocalIndex] = sessionInfo with { PeerIndex = senderIndex, IsCompleted = true, HandshakeState = null };

                _handshakeManager.HandleResponse(sessionInfo.PeerPublicKey, out var pendingState, out _);
                // The pending state and sessionInfo.HandshakeState may be the same instance
                // (InitiateHandshake stores it in both places); NoiseHandshakeState.Dispose is
                // idempotent, so the duplicate call is safe.
                pendingState?.Dispose();

                if (_peers.TryGetValue(sessionInfo.PeerPublicKey, out var peer))
                {
                    var cleanupNow = DateTime.UtcNow;

                    // Critical fix: old index mappings are no longer deleted immediately. The old
                    // session's index mapping is cleaned up lazily after the ExpiresAt time
                    // (performed by CleanupExpiredIndexMappingsPeriodicAsync).
                    // This way, within 30 seconds after the new session is established, packets
                    // using the old receiverIndex still route to the peer correctly and decrypt
                    // successfully through the previous transport (ReplayProtector already reset).
                    // This fixes the decryption failures seen when, after a DERP handshake
                    // completed, the peer kept sending data packets under the old session keys.
                    // (Above, this index's mapping has already been updated to the completed state with HandshakeState=null)

                    Log("INF", $"ProcessResponse: session established localIndex={sessionInfo.LocalIndex}, peerIndex={senderIndex}, peer={BitConverter.ToString(sessionInfo.PeerPublicKey)[..20]}...");

                    // [VM-SESSION-COLLAPSE] A new session immediately collapses the peer's older sessions
                    CollapseStaleSessions(sessionInfo.PeerPublicKey, sessionInfo.LocalIndex);

                    // [FIX 2026-10-14] A direct-path probe response arrived: via UDP → the probe
                    // handshake completed, enter the 30s direct-data validation window; via DERP →
                    // the direct path is unreachable, count the probe as failed and back off.
                    // [FIX 2026-10-19] Only count a probe result when a probe is actually in flight:
                    // responses of ordinary DERP rekey/reconnect handshakes also arrive via DERP,
                    // and the old logic counted every one of them as a probe failure, so the failure
                    // counter was polluted by unrelated handshakes (production-measured counts
                    // 471/8296/8315) and direct-path probing was wrongly backed off to the
                    // 30-minute tier.
                    if (_probeInFlight.ContainsKey(sessionInfo.PeerPublicKey))
                    {
                        if (IsDerpEndpoint(remoteEndPoint))
                        {
                            MarkProbeFailed(sessionInfo.PeerPublicKey, "handshake response arrived via DERP");
                        }
                        else
                        {
                            MarkProbeHandshakeCompleted(sessionInfo.PeerPublicKey);
                        }
                    }

                    var isDerpPacket = IsDerpEndpoint(remoteEndPoint);
                    if (isDerpPacket && peer.HasTransport && !peer.IsDerpConnected && peer.IsEstablished)
                    {
                        var timeSinceLastHandshake = DateTime.UtcNow - peer.LastHandshake;
                        var hasPendingHandshake = _handshakeManager.IsHandshakePending(sessionInfo.PeerPublicKey);
                        Log("INF", $"ProcessResponse: DERP response for peer {BitConverter.ToString(sessionInfo.PeerPublicKey)[..20]}... with existing UDP session (pending={hasPendingHandshake}, lastHandshake={timeSinceLastHandshake.TotalSeconds:F0}s ago) - accepting to sync session");
                    }

                    peer.SetTransport(sendKey, recvKey);
                    peer.LocalIndex = sessionInfo.LocalIndex;
                    peer.RemoteIndex = senderIndex;
                    peer.LastHandshake = DateTime.UtcNow;
                    peer.IsEstablished = true;
                    // [VM-HS-BACKOFF 2026-11-08] Handshake succeeded; clear the backoff
                    ResetHandshakeBackoff(sessionInfo.PeerPublicKey);

                    peer.IsDerpConnected = isDerpPacket;

                    Log("INF", $"Handshake completed with peer {BitConverter.ToString(sessionInfo.PeerPublicKey)[..20]}... via {(isDerpPacket ? "DERP" : "UDP")}");

                    _keyRotationManager.InitializePeer(sessionInfo.PeerPublicKey, sendKey, recvKey);
                    _keepaliveManager.SessionEstablished(sessionInfo.PeerPublicKey);
                    _connectionManager.RecordActivity(sessionInfo.PeerPublicKey);

                    if (!isDerpPacket)
                    {
                        var oldEndpoint = peer.Endpoint;
                        peer.Endpoint = remoteEndPoint;
                        ResetUdpAuthFailures(remoteEndPoint);
                        if (oldEndpoint == null || !oldEndpoint.Equals(remoteEndPoint))
                        {
                            OnPeerEndpointChanged?.Invoke(this, (sessionInfo.PeerPublicKey, remoteEndPoint));
                        }
                    }

                    _handshakeManager.ClearHandshake(sessionInfo.PeerPublicKey);

                    FlushPendingPackets(peer);

                    SendKeepalivePacket(peer.PublicKey);
                }
            }
            catch (NoiseHandshakeConsumedException)
            {
                System.Diagnostics.Debug.WriteLine($"[WireGuardDevice] ProcessResponse: handshake state already consumed for receiver index {receiverIndex}");
            }
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[WireGuardDevice] Failed to process response: {ex.Message}");
        }
    }

    private async Task ProcessDataAsync(byte[] packet, IPEndPoint remoteEndPoint, byte[]? derpSourcePeerKey = null)
    {
        if (packet.Length < 16) return;

        var receiverIndex = BitConverter.ToUInt32(packet, 4);
        var isDerpSource = derpSourcePeerKey != null;

        WireGuardPeer? matchedPeer = null;
        byte[]? decrypted = null;
        byte[]? sourcePeerPublicKey = derpSourcePeerKey;
        bool sessionCompleted = false;

        WireGuardPeer? peerRef = null;
        // [VM-REPLAY-RECOVER-GATE 2026-10-31] This packet has already been classified as a
        // duplicate/stale packet and deliberately dropped; the subsequent "failed decrypt"
        // logging and the fallback decryption are skipped entirely.
        var replayDropped = false;
        if (_indexToPeer.TryGetValue(receiverIndex, out var sessionInfo))
        {
            sourcePeerPublicKey = sessionInfo.PeerPublicKey;
            sessionCompleted = sessionInfo.IsCompleted;
            if (_peers.TryGetValue(sessionInfo.PeerPublicKey, out var peer) && peer.HasTransport)
            {
                peerRef = peer;
            }
        }
        else if (derpSourcePeerKey != null)
        {
            // Per-packet WRN during a storm plus string building from a full _indexToPeer scan
            // amplifies into a log flood: build the string only after the rate limiter admits it
            if (ShouldLogThrottled($"data-idx-notfound:{receiverIndex}", out var idxSuppressed))
            {
                var knownIndices = _indexToPeer
                    .Where(kvp => _comparer.Equals(kvp.Value.PeerPublicKey, derpSourcePeerKey))
                    .Select(kvp => $"{kvp.Key}(local={kvp.Value.LocalIndex},remote={kvp.Value.PeerIndex},completed={kvp.Value.IsCompleted})")
                    .ToList();
                Log("WRN", $"ProcessData: receiverIndex={receiverIndex} NOT FOUND for DERP peer {BitConverter.ToString(derpSourcePeerKey)[..20]}..., known=[{string.Join(", ", knownIndices)}]"
                    + (idxSuppressed > 0 ? $" (suppressed {idxSuppressed})" : string.Empty));
            }
        }

        // Rate-limit decryption failures per source: forged packets carrying an unknown
        // receiverIndex amplify into a full-table scan + AEAD decryption attempts; above the
        // threshold, decryption attempts are skipped for the rest of the window (the
        // rate-limited re-handshake logic further down is unaffected).
        var dataDecryptThrottled = !isDerpSource &&
            _dataDecryptFailures.TryGetValue(remoteEndPoint, out var decryptTracker) &&
            decryptTracker.IsBlocked;

        if (peerRef != null && !dataDecryptThrottled)
        {
            try
            {
                decrypted = peerRef.DecryptPacket(packet, out _);
                _keepaliveManager.PacketReceived(peerRef.PublicKey);
                _keyRotationManager.RecordRecv(peerRef.PublicKey);
                _connectionManager.RecordActivity(peerRef.PublicKey);
                matchedPeer = peerRef;

                var isDerpPacket = IsDerpEndpoint(remoteEndPoint);
                if (!isDerpPacket)
                {
                    // [FIX 2026-10-14] A direct-path data packet from this peer arrived: hard
                    // evidence that the direct path is healthy. If inside the probe validation
                    // window, the probe validates; either way the failure backoff is reset to
                    // zero (peers with a public IP are directly reachable by nature and should
                    // not be collateral damage of a subnet-CGNAT peer's backoff).
                    MarkDirectPathHealthy(peerRef.PublicKey);
                    var oldEndpoint = peerRef.Endpoint;
                    peerRef.Endpoint = remoteEndPoint;
                    if (peerRef.IsDerpConnected)
                    {
                        peerRef.IsDerpConnected = false;
                        Log("INF", $"Peer {BitConverter.ToString(peerRef.PublicKey)[..20]}... switched from DERP to UDP (endpoint: {remoteEndPoint})");
                    }
                    if (oldEndpoint == null || !oldEndpoint.Equals(remoteEndPoint))
                    {
                        OnPeerEndpointChanged?.Invoke(this, (peerRef.PublicKey, remoteEndPoint));
                    }
                }
                else
                {
                    if (!peerRef.IsDerpConnected)
                    {
                        peerRef.IsDerpConnected = true;
                        Log("INF", $"Peer {BitConverter.ToString(peerRef.PublicKey)[..20]}... switched from UDP to DERP via data packet");
                    }
                }
            }
            catch (Exception ex)
            {
                // [VM-REPLAY-RECOVER 2026-10-21] AEAD authentication runs before the replay-window
                // check — reaching this point means the packet has already authenticated (genuine
                // peer data), so the only explanation for the counter anomaly is a peer session
                // rebuild (counter back to 0) while the local window is still positioned at the
                // old session (measured: with iOS re-handshaking frequently, counter=0 hit
                // windowLast=9/11 and everything was rejected; the link stayed down for tens of
                // minutes until the old mapping expired and self-healed). Reset the window to
                // align with the peer's new session and re-run packet parsing:
                // forged packets cannot pass AEAD authentication, so the reset does not weaken
                // replay protection.
                var replayRecovered = false;
                // [VM-REPLAY-RECOVER-GATE 2026-10-31] Reset the window only for the "peer session
                // rebuilt" shape:
                // (1) counter == the highest accepted counter (windowLast) → re-delivery of the
                //     same latest packet (delivered once per path over DERP+direct, or a peer
                //     retransmit); resetting the window would only inject the same plaintext into
                //     TUN a second time, and in the logs it shows up as one REPLAY-RECOVER noise
                //     line every ~70s;
                // (2) counter above the session-start range (> ReplayRecoverStartCounter) → a
                //     historical packet from the old session; resetting the window would roll back
                //     replay-protection state and admit the old packet (a security weakness).
                // Only (3) — counter inside the start range and strictly below windowLast — is a
                //     genuine "peer counter reset to zero" (the original scenario: iOS
                //     re-handshaking frequently, counter=0 hitting windowLast=9/11).
                var replayCounter = packet.Length >= 16 ? BitConverter.ToUInt64(packet, 8) : ulong.MaxValue;
                var replayWindowLast = peerRef.LastReceivedCounter;
                var isRestartSignature = IsReplayRestartSignature(replayCounter, replayWindowLast);

                if (ex.Message.Contains("Replay attack") && peerRef.HasTransport)
                {
                    if (!isRestartSignature)
                    {
                        // Duplicate delivery / stale-packet replay: drop it outright, without
                        // entering the subsequent "failed decrypt" logging or fallback decryption,
                        // so that a normal replay-protection block is not rendered as a
                        // packet-loss incident.
                        replayDropped = true;
                        if (ShouldLogThrottled($"replay-drop:{receiverIndex}", out var dropSuppressed))
                        {
                            Log("DBG", $"[VM-REPLAY-RECOVER-GATE] peer {BitConverter.ToString(peerRef.PublicKey)[..20]}... replay rejected, NOT resetting window "
                                + $"(counter={replayCounter}, windowLast={replayWindowLast}) - duplicate delivery or stale packet, dropped"
                                + (dropSuppressed > 0 ? $" (suppressed {dropSuppressed})" : string.Empty));
                        }
                    }
                    else
                    {
                        try
                        {
                            peerRef.ResetReplayWindow();
                            decrypted = peerRef.DecryptPacket(packet, out _);
                            _keepaliveManager.PacketReceived(peerRef.PublicKey);
                            _keyRotationManager.RecordRecv(peerRef.PublicKey);
                            _connectionManager.RecordActivity(peerRef.PublicKey);
                            matchedPeer = peerRef;
                            replayRecovered = true;

                            if (ShouldLogThrottled($"replay-recover:{receiverIndex}", out var recSuppressed))
                            {
                                Log("WRN", $"[VM-REPLAY-RECOVER] peer {BitConverter.ToString(peerRef.PublicKey)[..20]}... replay window reset, packet accepted (idx={receiverIndex}, counter={replayCounter}, windowLast={replayWindowLast}, {ex.Message})"
                                    + (recSuppressed > 0 ? $" (suppressed {recSuppressed})" : string.Empty));
                            }
                        }
                        catch (Exception ex2)
                        {
                            Log("DBG", $"[VM-REPLAY-RECOVER] retry after window reset still failed: {ex2.GetType().Name}: {ex2.Message}");
                        }
                    }
                }

                // Replay-validation failures (old-session packets from a peer that reconnected
                // after being offline for a while) fire per packet; rate-limiting avoids a log flood.
                // [VM-REPLAY-RECOVER-LOG 2026-10-31] On a successful recovery (plaintext already
                // recovered after the window reset) no failure is reported: previously this printed
                // unconditionally, producing the self-contradictory log sequence "replay window
                // reset, packet accepted" immediately followed by "Failed to decrypt data packet",
                // which was easily misread as packet loss during production triage.
                if (!replayRecovered && !replayDropped && ShouldLogThrottled($"data-decrypt-fail:{receiverIndex}", out var failSuppressed))
                {
                    var peerKeyHex = BitConverter.ToString(peerRef.PublicKey)[..20];
                    Log("WRN", $"Failed to decrypt data packet from peer {peerKeyHex}... (idx={receiverIndex}, sessionCompleted={sessionCompleted}): {ex.Message}"
                        + (failSuppressed > 0 ? $" (suppressed {failSuppressed})" : string.Empty));
                }

                var prevDecrypted = replayDropped ? null : peerRef.TryDecryptWithPreviousTransport(packet, out _);
                if (prevDecrypted != null)
                {
                    decrypted = prevDecrypted;
                    _keepaliveManager.PacketReceived(peerRef.PublicKey);
                    _keyRotationManager.RecordRecv(peerRef.PublicKey);
                    _connectionManager.RecordActivity(peerRef.PublicKey);
                    matchedPeer = peerRef;
                }
                else if (!isDerpSource && !replayDropped)
                {
                    RecordDataDecryptFailure(remoteEndPoint);
                }
            }
        }

        if (!replayDropped && matchedPeer == null && decrypted == null && !dataDecryptThrottled)
        {
            WireGuardPeer? fallbackPeer = null;
            foreach (var kvp in _peers)
            {
                if (kvp.Value.LocalIndex == receiverIndex && kvp.Value.HasTransport)
                {
                    fallbackPeer = kvp.Value;
                    sourcePeerPublicKey = kvp.Value.PublicKey;
                    break;
                }
            }

            if (fallbackPeer == null)
            {
                foreach (var kvp in _peers)
                {
                    if (kvp.Value.RemoteIndex == receiverIndex && kvp.Value.HasTransport)
                    {
                        fallbackPeer = kvp.Value;
                        sourcePeerPublicKey = kvp.Value.PublicKey;
                        break;
                    }
                }
            }

            if (fallbackPeer == null && derpSourcePeerKey != null && _peers.TryGetValue(derpSourcePeerKey, out var derpPeer))
            {
                fallbackPeer = derpPeer;
                sourcePeerPublicKey = derpPeer.PublicKey;
            }

            if (fallbackPeer != null)
            {
                try
                {
                    decrypted = fallbackPeer.DecryptPacket(packet, out _);
                    _keepaliveManager.PacketReceived(fallbackPeer.PublicKey);
                    _keyRotationManager.RecordRecv(fallbackPeer.PublicKey);
                    _connectionManager.RecordActivity(fallbackPeer.PublicKey);
                    matchedPeer = fallbackPeer;

                    AddIndexMapping(receiverIndex, new PeerSessionInfo
                    {
                        PeerPublicKey = fallbackPeer.PublicKey,
                        LocalIndex = fallbackPeer.LocalIndex,
                        PeerIndex = fallbackPeer.RemoteIndex,
                        IsCompleted = true,
                        CreatedAt = DateTime.UtcNow
                    });
                }
                catch (Exception fallbackEx)
                {
                    var prevDecrypted = fallbackPeer.TryDecryptWithPreviousTransport(packet, out _);
                    if (prevDecrypted != null)
                    {
                        decrypted = prevDecrypted;
                        _keepaliveManager.PacketReceived(fallbackPeer.PublicKey);
                        _keyRotationManager.RecordRecv(fallbackPeer.PublicKey);
                        _connectionManager.RecordActivity(fallbackPeer.PublicKey);
                        matchedPeer = fallbackPeer;
                        Log("INF", $"ProcessData: decrypted with previous transport for peer {BitConverter.ToString(fallbackPeer.PublicKey)[..20]}... (receiverIndex={receiverIndex})");
                    }
                    else
                    {
                        // Per-packet WRN during a storm plus hex string building (replay/old-session
                        // packets); rate-limit to avoid a log flood
                        if (ShouldLogThrottled($"data-fallback-fail:{receiverIndex}", out var fbSuppressed))
                        {
                            Log("WRN", $"ProcessData: fallback decrypt failed for peer {BitConverter.ToString(fallbackPeer.PublicKey)[..20]}...: {fallbackEx.Message}"
                                + (fbSuppressed > 0 ? $" (suppressed {fbSuppressed})" : string.Empty));
                        }
                        if (!isDerpSource)
                        {
                            RecordDataDecryptFailure(remoteEndPoint);
                        }
                    }
                }
            }
        }

        if (matchedPeer != null && !isDerpSource)
        {
            // Successful decryption proves this source is legitimate; clear its failure count
            _dataDecryptFailures.TryRemove(remoteEndPoint, out _);
        }

        if (matchedPeer == null && decrypted == null)
        {
            Interlocked.Increment(ref _noSessionCount);
            var now = DateTime.UtcNow;
            if (now - _lastNoSessionLog > TimeSpan.FromSeconds(30))
            {
                byte[]? logPeerKey = sourcePeerPublicKey;
                if (logPeerKey == null)
                {
                    foreach (var kvp in _peers)
                    {
                        if (kvp.Value.Endpoint != null && kvp.Value.Endpoint.Equals(remoteEndPoint))
                        {
                            logPeerKey = kvp.Value.PublicKey;
                            break;
                        }
                    }
                }

                var peerKeyStr = logPeerKey != null ? BitConverter.ToString(logPeerKey)[..20] : $"endpoint={remoteEndPoint}";
                int peerMappingCount = 0;
                if (logPeerKey != null)
                {
                    peerMappingCount = _indexToPeer.Count(kvp => _comparer.Equals(kvp.Value.PeerPublicKey, logPeerKey));
                }
                Log("WRN", $"No-matching-session: {_noSessionCount} packets dropped (peer={peerKeyStr}, peerMappings={peerMappingCount}, totalMappings={_indexToPeer.Count})");
                _lastNoSessionLog = now;
                _noSessionCount = 0;
            }

            byte[]? rehandshakePeerKey = null;
            IPEndPoint? rehandshakeEndpoint = null;

            if (sourcePeerPublicKey != null && _peers.TryGetValue(sourcePeerPublicKey, out var derpPeer))
            {
                rehandshakePeerKey = derpPeer.PublicKey;
                rehandshakeEndpoint = derpPeer.Endpoint;
                // [FIX 2026-10-15] When the peer is reachable only via DERP, a handshake
                // initiation sent to a stale direct endpoint never arrives; recovery then waits
                // for the peer's own rekey timer (up to ~120s), during which all packets using
                // the old receiverIndex are lost.
                // The packet itself arrived via DERP, which means the current working path is
                // DERP: trigger a DERP initiation with a null endpoint (in
                // InitiateHandshakeWithPeer, null means the DERP route); the handshake completes
                // over DERP within seconds, and subsequent direct-path data packets will set
                // IsDerpConnected back to false automatically.
                if (isDerpSource || derpPeer.IsDerpConnected)
                {
                    rehandshakeEndpoint = null;
                }
            }
            else
            {
                foreach (var kvp in _peers)
                {
                    var peer = kvp.Value;
                    if (peer.Endpoint != null && peer.Endpoint.Equals(remoteEndPoint))
                    {
                        rehandshakePeerKey = peer.PublicKey;
                        rehandshakeEndpoint = peer.Endpoint;
                        break;
                    }
                }

                if (rehandshakePeerKey == null)
                {
                    foreach (var kvp in _peers)
                    {
                        if (kvp.Value.RemoteIndex == receiverIndex)
                        {
                            rehandshakePeerKey = kvp.Value.PublicKey;
                            rehandshakeEndpoint = kvp.Value.Endpoint;
                            break;
                        }
                    }
                }

                // Same as above: when the packet arrived via DERP, the re-handshake also takes the
                // DERP route, avoiding a UDP path that cannot reach the peer
                if (rehandshakePeerKey != null && isDerpSource)
                {
                    rehandshakeEndpoint = null;
                }
            }

            if (rehandshakePeerKey != null)
            {
                // [FIX 2026-10-08] The pending check now uses HandshakeManager (the authoritative
                // state, with a 90s self-timeout). The old implementation scanned _indexToPeer for
                // incomplete mappings: zombie mappings left over after a handshake timeout
                // (remote=0/completed=False) blocked re-handshakes here and, combined with a dead
                // peer session (e.g. after a server restart), formed a long-lived black hole.
                // Over-aged zombie mappings are also cleaned up so the session table self-heals.
                if (_handshakeManager.IsHandshakePending(rehandshakePeerKey))
                {
                    return;
                }

                PurgeStalePendingIndexMappings(rehandshakePeerKey, now);

                if (_lastRehandshakeTime.TryGetValue(rehandshakePeerKey, out var lastTime) &&
                    now - lastTime < TimeSpan.FromSeconds(30))
                {
                    return;
                }
                _lastRehandshakeTime[rehandshakePeerKey] = now;

                var jitterMs = RandomNumberGenerator.GetInt32(1000, 5000);
                _ = Task.Run(async () =>
                {
                    await Task.Delay(jitterMs);
                    InitiateHandshakeWithPeer(rehandshakePeerKey, rehandshakeEndpoint);
                });
            }
        }

        if (decrypted != null)
        {
            // Decompression layer: runs after DecryptPacket and before the write to TUN.
            // [FIX 2026-10-15] Decompression is no longer gated on IsEnabled: the peer may have
            // compression enabled while the local configuration is out of sync (previously
            // AndroidWireGuardService did not override EnablePacketCompression, so Linux
            // compressed while Android did not decompress, and [0x01] frames were written to TUN
            // as if they were IP packets → kernel EINVAL → all TCP lost). The self-describing
            // protocol (1 flag byte) requires this end to always be able to decompress. If the
            // data after decompression still starts with the compression flag byte (0x01
            // decompression failed / 0x00 not stripped), it is judged corrupt or
            // protocol-asymmetric and deliberately dropped — writing it to TUN would only
            // produce a kernel EINVAL and a TCP data black hole.
            if (PacketCompressor != null)
            {
                try
                {
                    var decompressed = PacketCompressor.Decompress(decrypted);
                    if (decompressed != null)
                    {
                        decrypted = decompressed;
                    }
                    else if (decrypted.Length > 0 &&
                             (decrypted[0] == WireGuard.NET.Compression.PacketCompressor.FlagCompressed ||
                              decrypted[0] == WireGuard.NET.Compression.PacketCompressor.FlagUncompressed))
                    {
                        Interlocked.Increment(ref _tunWriteFailCount);
                        if (ShouldLogThrottled("decompress-drop", out var decompSuppressed))
                        {
                            Log("WRN", $"Dropping packet: compressed flag 0x{decrypted[0]:X2} but decompression produced no payload (len={decrypted.Length}){(decompSuppressed > 0 ? $", suppressed {decompSuppressed}" : "")}");
                        }
                        return;
                    }
                }
                catch (Exception ex)
                {
                    Interlocked.Increment(ref _tunWriteFailCount);
                    Log("WRN", $"Failed to decompress packet: {ex.Message}, dropping packet");
                    return;
                }
            }

            if (decrypted.Length > 0)
            {
                // [FIX 2026-10-15] Last-resort IP packet validation before writing to TUN: the
                // kernel returns EINVAL for malformed packets outright (observed on Android
                // VpnService), and the failure has no feedback path, forming a TCP black hole.
                // Invalid packets (version not 4/6, total-length field exceeding the buffer,
                // exceeding the MTU) are dropped here and logged.
                if (!IsValidIpPacket(decrypted, out var invalidReason))
                {
                    Interlocked.Increment(ref _tunWriteFailCount);
                    if (ShouldLogThrottled("tun-invalid-ip", out var ipSuppressed))
                    {
                        Log("WRN", $"Dropping malformed IP packet before TUN write: {invalidReason} (len={decrypted.Length}, firstByte=0x{decrypted[0]:X2}){(ipSuppressed > 0 ? $", suppressed {ipSuppressed}" : "")}");
                    }
                    return;
                }

                if (matchedPeer != null)
                {
                    OnPacketReceivedWithPeer?.Invoke(this, (matchedPeer.PublicKey, decrypted));
                }

                if (InboundPacketFilter != null && matchedPeer != null && !InboundPacketFilter(matchedPeer.PublicKey, decrypted))
                {
                    return;
                }

                if (_exitNodeMode && matchedPeer != null && IsExitNodeTraffic(decrypted))
                {
                }
                else if (_tunDevice != null)
                {
                    try
                    {
                        await _tunDevice.WritePacketAsync(decrypted);
                    }
                    catch (ObjectDisposedException)
                    {
                    }
                    catch (Exception ex)
                    {
                        Interlocked.Increment(ref _tunWriteFailCount);
                        Log("ERR", $"Failed to write packet to TUN: {ex.Message}");
                    }
                }
                else
                {
                    Log("WRN", $"[INBOUND] TUN device is null, cannot write decrypted packet (len={decrypted.Length})");
                }
            }

            OnPacketReceived?.Invoke(this, decrypted);
        }
    }

    /// <summary>
    /// [FIX 2026-10-15] Validates that the buffer is a well-formed IPv4/IPv6 packet: version
    /// bits, total-length field consistent with the actual buffer length, and not exceeding
    /// the MTU. Used as the last line of defense before writing to TUN — a write of a
    /// malformed packet returns EINVAL with no feedback, forming a "ping works but all TCP
    /// data is lost" black hole (one of the production root causes).
    /// </summary>
    private static bool IsValidIpPacket(byte[] packet, out string reason)
    {
        reason = string.Empty;
        if (packet.Length < 20)
        {
            reason = "packet too short for IP header";
            return false;
        }

        var version = (packet[0] >> 4) & 0x0F;
        int headerLength;
        int totalLength;
        if (version == 4)
        {
            headerLength = (packet[0] & 0x0F) * 4;
            if (headerLength < 20)
            {
                reason = $"IPv4 IHL too small ({headerLength})";
                return false;
            }
            totalLength = (packet[2] << 8) | packet[3];
        }
        else if (version == 6)
        {
            headerLength = 40;
            if (packet.Length < headerLength)
            {
                reason = "packet too short for IPv6 header";
                return false;
            }
            totalLength = ((packet[4] << 8) | packet[5]) + headerLength;
        }
        else
        {
            reason = $"unsupported IP version {version}";
            return false;
        }

        if (packet.Length < headerLength)
        {
            reason = $"buffer shorter than IP header (len={packet.Length}, header={headerLength})";
            return false;
        }
        if (totalLength < headerLength || totalLength > packet.Length + 4)
        {
            reason = $"total length field {totalLength} inconsistent with buffer len={packet.Length}";
            return false;
        }
        if (packet.Length > 65535)
        {
            reason = $"packet exceeds max IP size (len={packet.Length})";
            return false;
        }
        return true;
    }

    private bool IsExitNodeTraffic(byte[] packet)
    {
        if (packet.Length < 20) return false;
        var version = (packet[0] >> 4) & 0x0F;
        if (version != 4) return false;

        var dstIpBytes = packet.Skip(16).Take(4).ToArray();
        if (dstIpBytes[0] == 100 && dstIpBytes[1] == 100) return false;
        if (dstIpBytes[0] == 127) return false;
        if (dstIpBytes[0] == 224) return false;

        return true;
    }

    private Task ProcessCookieAsync(byte[] packet, IPEndPoint remoteEndPoint)
    {
        _cookieProtector.ProcessCookieReply(packet, remoteEndPoint);
        return Task.CompletedTask;
    }

    private static bool IsDerpEndpoint(IPEndPoint endpoint)
    {
        return endpoint.Address.Equals(IPAddress.Any) && endpoint.Port == 0;
    }

    /// <summary>
    /// Deterministic yield rule for simultaneous handshakes: the side whose static public key
    /// sorts lower lexicographically yields (it clears its own pending initiation and becomes
    /// the responder). Both sides apply the same rule, so they finally converge to a single
    /// session with the larger public key as initiator.
    /// </summary>
    private static bool ShouldYieldToPeerInitiation(byte[] localPublicKey, byte[] peerPublicKey)
    {
        return localPublicKey.AsSpan().SequenceCompareTo(peerPublicKey) < 0;
    }

    private void CleanUdpAuthFailures()
    {
        var expired = _udpAuthFailures
            .Where(kvp => DateTime.UtcNow - kvp.Value.LastFailureTime > UdpAuthFailureWindow)
            .Select(kvp => kvp.Key)
            .ToList();

        foreach (var key in expired)
        {
            _udpAuthFailures.TryRemove(key, out _);
        }
    }

    private void ResetUdpAuthFailures(IPEndPoint endpoint)
    {
        _udpAuthFailures.TryRemove(endpoint, out _);
        // A completed handshake proves the endpoint is legitimate and also lifts the
        // data-decryption rate limit
        _dataDecryptFailures.TryRemove(endpoint, out _);
    }

    private void RecordDataDecryptFailure(IPEndPoint endpoint)
    {
        var tracker = _dataDecryptFailures.GetOrAdd(endpoint, _ => new UdpAuthFailureTracker());
        tracker.RecordFailure();
    }

    /// <summary>Raised for every decrypted plaintext IP packet, after the TUN write has been attempted.</summary>
    public event EventHandler<byte[]>? OnPacketReceived;

    /// <summary>Raised for every decrypted plaintext IP packet, together with the public key of the peer that sent it.</summary>
    public event EventHandler<(byte[] PeerPublicKey, byte[] Packet)>? OnPacketReceivedWithPeer;

    /// <summary>Raised when a peer's remote endpoint is updated (e.g. after roaming, endpoint learning, or an explicit notification).</summary>
    public event EventHandler<(byte[] PeerPublicKey, IPEndPoint NewEndpoint)>? OnPeerEndpointChanged;

    private bool _exitNodeMode;
    private bool _udpOutboundBound;

    /// <summary>Gets a value indicating whether the UDP outbound socket is currently bound to a specific physical interface.</summary>
    public bool IsUdpOutboundBound => _udpOutboundBound;

    /// <summary>
    /// Enables or disables exit-node mode. When enabled, IPv4 traffic that qualifies as
    /// exit-node traffic (excluding loopback, multicast, and shared address space) is routed
    /// through the tunnel.
    /// </summary>
    /// <param name="enabled">true to enable exit-node mode; false to disable it.</param>
    public void SetExitNodeMode(bool enabled)
    {
        _exitNodeMode = enabled;
        Log("INF", $"Exit node mode {(enabled ? "enabled" : "disabled")}");
    }

    /// <summary>
    /// Updates the IPv6 address and prefix length of the TUN device at runtime. The address
    /// is parsed and validated before it is applied; invalid addresses are rejected without
    /// touching the system network stack.
    /// </summary>
    /// <param name="address">The new IPv6 address in textual form.</param>
    /// <param name="prefixLength">The prefix length of the address.</param>
    public void UpdateIPv6Address(string address, int prefixLength)
    {
        if (_tunDevice == null)
        {
            Log("WRN", "UpdateIPv6Address: TUN device not available");
            return;
        }

        try
        {
            // Parse and validate before passing down to the TUN device: invalid addresses are
            // rejected before they can touch the system network stack
            var parsed = IPAddress.Parse(address);
            if (parsed.AddressFamily != AddressFamily.InterNetworkV6)
            {
                throw new ArgumentException($"Not an IPv6 address: {address}", nameof(address));
            }
            _tunDevice.SetAddressIPv6(parsed.ToString(), prefixLength);
            _config.AddressV6 = parsed;
            _config.AddressV6PrefixLength = prefixLength;
            Log("INF", $"UpdateIPv6Address: IPv6 address updated to {parsed}/{prefixLength}");
        }
        catch (Exception ex)
        {
            Log("ERR", $"UpdateIPv6Address: Failed to update IPv6 address: {ex.Message}");
        }
    }

    private const int IP_UNICAST_IF = 31;

    /// <summary>
    /// Binds UDP outbound traffic to a specific physical network interface so that exit-node
    /// traffic leaves through the intended interface instead of looping back into the
    /// tunnel. First tries a dedicated send socket bound to <paramref name="localIpAddress"/>;
    /// otherwise falls back to setting IP_UNICAST_IF on the main UDP socket.
    /// </summary>
    /// <param name="interfaceIndex">The index of the physical interface to bind to.</param>
    /// <param name="localIpAddress">Optional local IP address to bind a dedicated send socket to.</param>
    public void SetUdpOutboundInterface(uint interfaceIndex, string? localIpAddress = null)
    {
        Log("INF", $"SetUdpOutboundInterface: interfaceIndex={interfaceIndex}, localIpAddress={localIpAddress ?? "null"}");

        if (!string.IsNullOrEmpty(localIpAddress))
        {
            try
            {
                _sendUdpClient?.Close();
                _sendUdpClient = new UdpClient(AddressFamily.InterNetwork);
                _sendUdpClient.Client.Bind(new IPEndPoint(IPAddress.Parse(localIpAddress), 0));
                TryProtectUdpSocket(_sendUdpClient);   // [VM-WG-PROTECT]
                _useSendUdpClient = true;
                _udpOutboundBound = true;
                Log("INF", $"Created dedicated send UDP socket bound to {localIpAddress}:0 for exit node traffic");
                return;
            }
            catch (Exception ex)
            {
                Log("WRN", $"Failed to create dedicated send UDP socket bound to {localIpAddress}: {ex.Message}");
                _useSendUdpClient = false;
            }
        }

        if (_udpClient != null)
        {
            try
            {
                _udpClient.Client.SetSocketOption(
                    SocketOptionLevel.IP,
                    (SocketOptionName)IP_UNICAST_IF,
                    (int)interfaceIndex);
                _udpOutboundBound = true;
                Log("INF", $"Set IP_UNICAST_IF to interface index {interfaceIndex} (host byte order)");
                return;
            }
            catch (Exception ex)
            {
                Log("WRN", $"IP_UNICAST_IF failed: {ex.Message}");
            }
        }

        Log("WRN", "All methods to bind UDP outbound to physical interface failed. Exit node may cause routing loops!");
        _udpOutboundBound = false;
    }

    /// <summary>
    /// Clears the UDP outbound interface binding established by
    /// <see cref="SetUdpOutboundInterface"/>, restoring default routing for UDP traffic.
    /// </summary>
    public void ClearUdpOutboundInterface()
    {
        _udpOutboundBound = false;

        try
        {
            if (_udpClient != null)
            {
                _udpClient.Client.SetSocketOption(
                    SocketOptionLevel.IP,
                    (SocketOptionName)IP_UNICAST_IF,
                    0);
                Log("INF", "Cleared IP_UNICAST_IF on main UDP socket");
            }
        }
        catch (Exception ex)
        {
            Log("WRN", $"Failed to clear IP_UNICAST_IF: {ex.Message}");
        }

        try
        {
            if (_sendUdpClient != null)
            {
                _sendUdpClient.Close();
                _sendUdpClient = null;
                _useSendUdpClient = false;
                Log("INF", "Closed dedicated send UDP socket");
            }
        }
        catch (Exception ex)
        {
            Log("WRN", $"Failed to close dedicated send UDP socket: {ex.Message}");
        }
    }

    private async Task<int> SendUdpPacketAsync(byte[] data, IPEndPoint endpoint)
    {
        // _sendUdpClient is explicitly created IPv4-only (AddressFamily.InterNetwork) and is
        // used solely to bind exit-node traffic to a specific physical interface; it must not
        // be given an IPv6 mapping. Normalize only the primary _udpClient (dual-stack).
        if (_useSendUdpClient && _sendUdpClient != null)
        {
            return await _sendUdpClient.SendAsync(data, data.Length, endpoint);
        }

        if (_udpClient != null)
        {
            return await _udpClient.SendAsync(data, data.Length, NormalizeSendEndpoint(endpoint));
        }

        throw new InvalidOperationException("No UDP client available for sending");
    }

    /// <summary>
    /// Injects a plaintext IP packet into the outbound path as if it had been read from the
    /// TUN device: the packet is encrypted and enqueued for the specified peer. If the peer
    /// has no established transport yet, a handshake is initiated instead and the packet is
    /// dropped.
    /// </summary>
    /// <param name="peerPublicKey">The public key of the target peer.</param>
    /// <param name="ipPacket">The plaintext IP packet to send.</param>
    public async Task InjectPacketToPeerAsync(byte[] peerPublicKey, byte[] ipPacket)
    {
        if (!_running || _stopping || ipPacket == null || ipPacket.Length == 0) return;

        if (!_peers.TryGetValue(peerPublicKey, out var peer))
        {
            return;
        }

        if (!peer.HasTransport)
        {
            if (!_handshakeManager.IsHandshakePending(peerPublicKey))
            {
                if (peer.Endpoint != null)
                    InitiateHandshakeWithPeer(peerPublicKey, peer.Endpoint);
                else if (SendPacketViaDerp != null)
                    InitiateHandshakeWithPeer(peerPublicKey, null);
            }
            return;
        }

        try
        {
            SendOrEnqueueEncryptedPacket(ipPacket, peer);
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[WireGuardDevice] Failed to inject packet to peer: {ex.Message}");
        }
    }

    /// <summary>
    /// Injects a WireGuard encrypted packet that arrived over the DERP relay transport into
    /// the receive pipeline (a non-UDP source). The packet is queued on the DERP channel and
    /// processed asynchronously.
    /// </summary>
    /// <param name="peerPublicKey">The public key of the peer that sent the packet.</param>
    /// <param name="packet">The encrypted WireGuard packet.</param>
    public void InjectPacketFromDerp(byte[] peerPublicKey, byte[] packet)
    {
        if (packet == null || packet.Length == 0)
        {
            Log("WRN", $"InjectPacketFromDerp: null or empty packet from peer {BitConverter.ToString(peerPublicKey)[..Math.Min(20, peerPublicKey.Length * 3)]}...");
            return;
        }

        if (!_running || _stopping)
        {
            // A close/restart window can accumulate a large backlog of in-flight packets;
            // per-packet WRN amplifies into a log flood, so rate-limit per window
            if (ShouldLogThrottled("inject-not-running", out var notRunningSuppressed))
            {
                Log("WRN", $"InjectPacketFromDerp: device not running (running={_running}, stopping={_stopping}), dropping {packet.Length} bytes from peer {BitConverter.ToString(peerPublicKey)[..Math.Min(20, peerPublicKey.Length * 3)]}..."
                    + (notRunningSuppressed > 0 ? $" (suppressed {notRunningSuppressed})" : string.Empty));
            }
            return;
        }

        if (!_derpPacketChannel.Writer.TryWrite((peerPublicKey, packet)))
        {
            if (ShouldLogThrottled("inject-channel-full", out var fullSuppressed))
            {
                Log("WRN", $"InjectPacketFromDerp: channel full, dropping {packet.Length} bytes from peer {BitConverter.ToString(peerPublicKey)[..Math.Min(20, peerPublicKey.Length * 3)]}..."
                    + (fullSuppressed > 0 ? $" (suppressed {fullSuppressed})" : string.Empty));
            }
            Interlocked.Increment(ref _udpDropCount);
        }
        else if (IsDebugEnabled)
        {
            Log("DBG", $"InjectPacketFromDerp: queued {packet.Length} bytes from peer {BitConverter.ToString(peerPublicKey)[..Math.Min(20, peerPublicKey.Length * 3)]}..., channel count={_derpPacketChannel.Reader.Count}");
        }
    }

    /// <summary>
    /// Injects a WireGuard encrypted packet that arrived over the TCP transport.
    /// Reuses the DERP channel for processing, because TCP packets, like DERP packets, are
    /// encrypted packets from a non-UDP source.
    /// </summary>
    public void InjectPacketFromTcp(byte[] peerPublicKey, byte[] packet)
        => InjectPacketFromDerp(peerPublicKey, packet);

    /// <summary>
    /// Injects a WireGuard encrypted packet that arrived over the WebSocket transport.
    /// Reuses the DERP channel for processing.
    /// </summary>
    public void InjectPacketFromWebSocket(byte[] peerPublicKey, byte[] packet)
        => InjectPacketFromDerp(peerPublicKey, packet);

    private async Task ProcessDerpPacketAsync(byte[] peerPublicKey, byte[] packet)
    {
        try
        {
            if (packet.Length < 4) return;

            var derpEndpoint = new IPEndPoint(IPAddress.Any, 0);

            var type = BitConverter.ToUInt32(packet, 0) & 0xFF;

            if (IsDebugEnabled)
            {
                var peerKeyHex = BitConverter.ToString(peerPublicKey)[..Math.Min(40, peerPublicKey.Length * 3)];
                Log("DBG", $"ProcessDerpPacket: peer={peerKeyHex}..., type={type}, size={packet.Length}");
            }

            switch (type)
            {
                case WireGuardConstants.TYPE_INITIATION:
                    await ProcessInitiationAsync(packet, derpEndpoint);
                    break;
                case WireGuardConstants.TYPE_RESPONSE:
                    await ProcessResponseAsync(packet, derpEndpoint);
                    break;
                case WireGuardConstants.TYPE_DATA:
                    await ProcessDataAsync(packet, derpEndpoint, peerPublicKey);
                    break;
                case WireGuardConstants.TYPE_COOKIE:
                    await ProcessCookieAsync(packet, derpEndpoint);
                    break;
            }
        }
        catch (Exception ex)
        {
            // Per-packet ERR during a storm (e.g. replay-validation failures) amplifies into a log flood; rate-limit per window
            if (ShouldLogThrottled("derp-proc-err", out var errSuppressed))
            {
                Log("ERR", $"Error processing DERP packet: {ex.GetType().Name}: {ex.Message}"
                    + (errSuppressed > 0 ? $" (suppressed {errSuppressed})" : string.Empty));
            }
        }
    }

    /// <summary>
    /// Adds a peer from the given configuration and registers it with the keepalive manager.
    /// If the device is already running, a handshake is initiated toward the peer (directly
    /// if an endpoint is configured, otherwise via DERP when a DERP handler is available).
    /// </summary>
    /// <param name="peerConfig">The peer configuration (public key, optional PSK, endpoint, allowed IPs, keepalive).</param>
    public void AddPeer(PeerConfig peerConfig)
    {
        var peer = new WireGuardPeer(peerConfig.PublicKey)
        {
            PresharedKey = peerConfig.PresharedKey,
            Endpoint = peerConfig.Endpoint,
            PersistentKeepalive = peerConfig.PersistentKeepalive
        };

        foreach (var allowedIp in peerConfig.AllowedIPs)
        {
            peer.AllowedIPs.AddAllowedIP(allowedIp.Address, allowedIp.PrefixLength);
        }

        _peers[peerConfig.PublicKey] = peer;
        _keepaliveManager.AddPeer(peerConfig.PublicKey, peerConfig.PersistentKeepalive);

        if (_running)
        {
            if (peerConfig.Endpoint != null)
            {
                InitiateHandshakeWithPeer(peerConfig.PublicKey, peerConfig.Endpoint);
            }
            else if (SendPacketViaDerp != null)
            {
                InitiateHandshakeWithPeer(peerConfig.PublicKey, null);
            }
        }
    }

    /// <summary>
    /// Applies an in-place update to an existing peer (e.g. changing its endpoint or PSK).
    /// Does nothing if the peer is unknown.
    /// </summary>
    /// <param name="publicKey">The public key of the peer to update.</param>
    /// <param name="updateAction">Callback that mutates the peer object.</param>
    public void UpdatePeer(byte[] publicKey, Action<WireGuardPeer> updateAction)
    {
        if (_peers.TryGetValue(publicKey, out var peer))
        {
            updateAction(peer);
        }
    }

    /// <summary>
    /// Removes a peer and all of its associated state: keepalive registration, handshake and
    /// key-rotation state, probe hysteresis, handshake backoff, and index mappings.
    /// </summary>
    /// <param name="publicKey">The public key of the peer to remove.</param>
    public void RemovePeer(byte[] publicKey)
    {
        _peers.TryRemove(publicKey, out _);
        _keepaliveManager.RemovePeer(publicKey);
        _handshakeManager.ClearHandshake(publicKey);
        _keyRotationManager.ClearPeer(publicKey);
        // [FIX 2026-10-14] Probe hysteresis state is cleared as well, so dictionary entries do not accumulate as peers are added/removed
        ClearProbeState(publicKey);
        // [VM-HS-BACKOFF 2026-11-08] Handshake backoff state is cleaned up together with peer removal
        _handshakeFailureCount.TryRemove(publicKey, out _);
        _handshakeNextAllowedAt.TryRemove(publicKey, out _);

        RemoveOldIndexMappings(publicKey);
    }

    /// <summary>Gets the peer with the given public key.</summary>
    /// <param name="publicKey">The public key of the peer.</param>
    /// <returns>The matching peer, or null if it is not configured.</returns>
    public WireGuardPeer? GetPeer(byte[] publicKey)
    {
        _peers.TryGetValue(publicKey, out var peer);
        return peer;
    }

    /// <summary>Gets all configured peers.</summary>
    /// <returns>All currently configured peers.</returns>
    public IEnumerable<WireGuardPeer> GetAllPeers()
    {
        return _peers.Values;
    }

    /// <summary>
    /// Finds the public key of the peer whose allowed-IP set contains the given address.
    /// </summary>
    /// <param name="ipBytes">The IP address to look up, in network byte order.</param>
    /// <returns>The matching peer's public key, or null if no peer claims the address.</returns>
    public byte[]? FindPeerPublicKeyByAllowedIp(byte[] ipBytes)
    {
        var ipAddress = new System.Net.IPAddress(ipBytes);
        foreach (var kvp in _peers)
        {
            if (kvp.Value.AllowedIPs != null && kvp.Value.AllowedIPs.IsAllowed(ipAddress))
            {
                return kvp.Key;
            }
        }
        return null;
    }

    /// <summary>
    /// Collects the endpoint IP addresses (as strings) of all peers that have a configured
    /// endpoint, de-duplicated.
    /// </summary>
    /// <returns>The list of peer endpoint IP addresses.</returns>
    public List<string> GetPeerEndpointIps()
    {
        var result = new List<string>();
        foreach (var kvp in _peers)
        {
            if (kvp.Value.Endpoint != null)
            {
                var epStr = kvp.Value.Endpoint.Address.ToString();
                if (!string.IsNullOrEmpty(epStr))
                {
                    result.Add(epStr);
                }
            }
        }
        return result.Distinct().ToList();
    }

    /// <summary>Alias for <see cref="GetPeerEndpointIps"/>.</summary>
    /// <returns>The list of peer endpoint IP addresses.</returns>
    public List<string> GetAllPeerEndpointIps() => GetPeerEndpointIps();

    /// <summary>
    /// Raises <see cref="OnPeerEndpointChanged"/> for an externally learned endpoint change
    /// (e.g. discovered by the host application). Wildcard addresses are ignored.
    /// </summary>
    /// <param name="peerPublicKey">The public key of the peer whose endpoint changed.</param>
    /// <param name="newEndpoint">The peer's new remote endpoint.</param>
    public void NotifyPeerEndpointChanged(byte[] peerPublicKey, IPEndPoint newEndpoint)
    {
        if (newEndpoint.Address.Equals(IPAddress.Any)) return;
        if (newEndpoint.Address.Equals(IPAddress.IPv6Any)) return;

        OnPeerEndpointChanged?.Invoke(this, (peerPublicKey, newEndpoint));
    }

    /// <summary>Builds a snapshot of the device status, including per-peer statistics.</summary>
    /// <returns>The current device status.</returns>
    public DeviceStatus GetStatus()
    {
        var peers = _peers.Values.Select(p => new PeerStatus
        {
            PublicKey = Convert.ToBase64String(p.PublicKey),
            Endpoint = p.Endpoint?.ToString(),
            LastHandshake = p.LastHandshake,
            RxBytes = p.RxBytes,
            TxBytes = p.TxBytes,
            IsDerpConnected = p.IsDerpConnected
        }).ToList();

        return new DeviceStatus
        {
            IsRunning = _running,
            PublicKey = Convert.ToBase64String(_keyPair.PublicKey),
            ListenPort = _config.ListenPort,
            Peers = peers
        };
    }

    /// <summary>
    /// Resets the session state of a peer (transport, keepalive, key rotation, handshake, and
    /// index mappings) so that a fresh handshake is required. Probe hysteresis memory
    /// (failure backoff and DERP stickiness) is intentionally preserved.
    /// </summary>
    /// <param name="publicKey">The public key of the peer.</param>
    public void ResetPeerSession(byte[] publicKey)
    {
        if (_peers.TryGetValue(publicKey, out var peer))
        {
            System.Diagnostics.Debug.WriteLine($"[WireGuardDevice] Resetting session for peer {BitConverter.ToString(publicKey)[..20]}...");
            peer.ResetTransport();
            _keepaliveManager.SessionReset(publicKey);
            _keyRotationManager.ClearPeer(publicKey);
            _handshakeManager.ClearHandshake(publicKey);
            RemoveOldIndexMappings(publicKey);
            // [FIX 2026-10-14] Cancel in-flight probes/validation windows (the pending entry was
            // already cleared, so the timeout event will never fire; leaving them would deadlock
            // IsProbeAllowed forever); keep the failure backoff and DERP stickiness — they encode
            // the prior that "this peer is unreachable directly", and a session reset must not
            // reset hysteresis memory.
            _probeInFlight.TryRemove(publicKey, out _);
            _probeValidationUntil.TryRemove(publicKey, out _);
        }
    }

    /// <summary>
    /// Initiates a handshake with a peer over the DERP relay transport, bypassing any known
    /// direct endpoint. Requires a <see cref="SendPacketViaDerp"/> handler.
    /// </summary>
    /// <param name="publicKey">The public key of the peer.</param>
    public void InitiateDerpHandshake(byte[] publicKey)
    {
        if (_peers.TryGetValue(publicKey, out var peer))
        {
            if (SendPacketViaDerp != null)
            {
                Log("INF", $"Initiating DERP handshake for peer {BitConverter.ToString(publicKey)[..20]}...");
                InitiateHandshakeWithPeer(publicKey, null);
            }
            else
            {
                Log("WRN", $"Cannot initiate DERP handshake for peer {BitConverter.ToString(publicKey)[..20]}... - SendPacketViaDerp not set");
            }
        }
    }

    /// <summary>
    /// Stops the device: stops the managers, disposes the timers, cancels the background
    /// loops, waits briefly for running tasks, and releases the TUN device. The same
    /// instance can be started again with <see cref="StartAsync"/>.
    /// </summary>
    public void Stop()
    {
        if (!_running) return;

        _running = false;
        _stopping = true;

        _keepaliveManager.Stop();
        _handshakeManager.Stop();
        _keyRotationManager.Stop();
        _connectionManager.Stop();

        _cookieProtector.StopCleanup();
        _rateLimiter.StopCleanup();
        _indexCleanupTimer?.Dispose();
        _indexCleanupTimer = null;
        _statsTimer?.Dispose();
        _statsTimer = null;
        _directPathProbeTimer?.Dispose();
        _directPathProbeTimer = null;

        _cancellationTokenSource?.Cancel();

        try
        {
            var tasks = new List<Task>();
            lock (_taskLock)
            {
                tasks.AddRange(_runningTasks);
            }

            if (tasks.Count > 0)
            {
                var allTask = Task.WhenAll(tasks);
                try
                {
                    allTask.Wait(TimeSpan.FromSeconds(5));
                }
                catch (AggregateException)
                {
                }
                catch (TimeoutException)
                {
                }
            }
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[WireGuardDevice] Error waiting for background tasks: {ex.Message}");
        }

        if (_tunDevice != null)
        {
            try
            {
                _tunDevice.Stop();
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[WireGuardDevice] Error stopping TUN device: {ex.Message}");
            }
        }

        try
        {
            _udpClient?.Close();
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[WireGuardDevice] Error closing UDP client: {ex.Message}");
        }
        _udpClient = null;

        try
        {
            _sendUdpClient?.Close();
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[WireGuardDevice] Error closing send UDP client: {ex.Message}");
        }
        _sendUdpClient = null;
        _useSendUdpClient = false;

        foreach (var info in _indexToPeer.Values)
        {
            DisposeSessionHandshakeState(info);
        }
        _indexToPeer.Clear();
        _peerToIndices.Clear();

        _cancellationTokenSource?.Dispose();
        _cancellationTokenSource = null;

        _stopping = false;
    }

    /// <summary>
    /// Releases all resources held by the device: stops it, disposes the handshake
    /// machinery, the cryptographic material, and all peers. The device cannot be restarted
    /// afterwards.
    /// </summary>
    public void Dispose()
    {
        if (!_disposed)
        {
            Stop();

            _wireGuardHandshake.Dispose();
            _handshakeManager.Dispose();
            _cookieProtector.Dispose();
            _keyPair.Dispose();

            foreach (var peer in _peers.Values)
            {
                peer.Dispose();
            }
            _peers.Clear();

            _disposed = true;
        }
    }

    /// <summary>
    /// [VM-TUN-DST 2026-11-08] Parses the destination address / protocol / port from the IP
    /// header; for diagnostic logging only. Called on the receive hot path: on any parse
    /// failure it returns "?" and never throws.
    /// </summary>
    private static string DescribePacketDestination(byte[] packet, int version)
    {
        try
        {
            if (version == 4 && packet.Length >= 20)
            {
                var dst = new IPAddress(packet.AsSpan(16, 4));
                var proto = packet[9];
                var ihl = (packet[0] & 0x0F) * 4;
                var port = 0;
                if ((proto == 6 || proto == 17) && packet.Length >= ihl + 4)
                {
                    port = (packet[ihl + 2] << 8) | packet[ihl + 3];
                }
                var protoName = proto switch { 6 => "tcp", 17 => "udp", 1 => "icmp", _ => proto.ToString() };
                return port > 0 ? $"{dst}:{port}/{protoName}" : $"{dst}/{protoName}";
            }

            if (version == 6 && packet.Length >= 40)
            {
                var dst = new IPAddress(packet.AsSpan(24, 16));
                var proto = packet[6];
                var port = 0;
                if ((proto == 6 || proto == 17) && packet.Length >= 44)
                {
                    port = (packet[40] << 8) | packet[41];
                }
                var protoName = proto switch { 6 => "tcp", 17 => "udp", 58 => "icmp6", _ => proto.ToString() };
                return port > 0 ? $"[{dst}]:{port}/{protoName}" : $"[{dst}]/{protoName}";
            }
        }
        catch
        {
            // Diagnostic use only; any parse exception must not affect the main flow
        }

        return "?";
    }

    /// <summary>
    /// Bookkeeping record for a local-index → peer mapping: tracks the handshake state while
    /// the handshake is in flight and the session once it is established.
    /// </summary>
    private record PeerSessionInfo
    {
        public byte[] PeerPublicKey { get; init; } = Array.Empty<byte>();
        public NoiseHandshakeState? HandshakeState { get; init; }
        public uint LocalIndex { get; init; }
        public uint PeerIndex { get; init; }
        public bool IsCompleted { get; init; }
        public DateTime CreatedAt { get; init; } = DateTime.UtcNow;
        /// <summary>
        /// Expiry time of the index mapping. After expiry the old session's index mapping is
        /// cleaned up, but until then old-session packets (using the old receiverIndex) still
        /// route to the peer correctly and decrypt via the previous transport.
        /// </summary>
        public DateTime ExpiresAt { get; init; } = DateTime.UtcNow.AddSeconds(30);
    }

    /// <summary>[VM-WG-PROTECT] Invokes the external protection hook on an already-created UDP socket; exceptions are only logged.</summary>
    private void TryProtectUdpSocket(UdpClient? client)
    {
        var protector = UdpSocketProtector;
        if (client == null || protector == null) return;
        try
        {
            protector(client.Client);
        }
        catch (Exception ex)
        {
            Log("WRN", $"UdpSocketProtector failed: {ex.Message}");
        }
    }

    /// <summary>[VM-STUN-ON-WG-SOCKET] Periodically sends STUN Binding requests (every 20s); replies are picked off by the receive loop.</summary>
    private void StartStunProbeLoop(CancellationToken cancellationToken)
    {
        List<string> servers;
        lock (_stunServers)
        {
            if (_stunServers.Count == 0) return;
            servers = _stunServers.ToList();
        }

        // Resolve host:port into an IPEndPoint right before sending (the domain may change
        // over time; the 5-minute cache is handled by the DNS layer)
        static IPEndPoint? Resolve(string hostPort)
        {
            try
            {
                var idx = hostPort.LastIndexOf(':');
                if (idx <= 0) return null;
                var host = hostPort[..idx];
                if (!int.TryParse(hostPort[(idx + 1)..], out var port) || port <= 0 || port > 65535) return null;
                if (IPAddress.TryParse(host, out var ip)) return new IPEndPoint(ip, port);
                var addrs = Dns.GetHostAddresses(host);
                var v4 = addrs.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork) ?? addrs.FirstOrDefault();
                return v4 == null ? null : new IPEndPoint(v4, port);
            }
            catch
            {
                return null;
            }
        }

        _stunProbeTask = Task.Run(async () =>
        {
            var first = true;
            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    if (_udpClient != null)
                    {
                        foreach (var serverName in servers)
                        {
                            var server = Resolve(serverName);
                            if (server == null) continue;
                            // Keep only transaction IDs from the last 5s to avoid unbounded growth
                            foreach (var kv in _stunPending)
                            {
                                if ((DateTime.UtcNow - kv.Value.At).TotalSeconds > 5) _stunPending.TryRemove(kv.Key, out _);
                            }

                            var request = StunEndpointDiscovery.BuildBindingRequest(out var txId);
                            _stunPending[Convert.ToHexString(txId)] = (DateTime.UtcNow, serverName);
                            try
                            {
                                await _udpClient.SendAsync(request, server, cancellationToken).ConfigureAwait(false);
                            }
                            catch (Exception ex)
                            {
                                Log("DBG", $"STUN probe send failed to {server}: {ex.Message}");
                            }
                        }
                    }
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    Log("WRN", $"STUN probe loop error: {ex.Message}");
                }

                // Probe again 2s after the first attempt (to cover NAT flapping right after
                // binding), then every 20s
                var delay = first ? TimeSpan.FromSeconds(2) : TimeSpan.FromSeconds(20);
                first = false;
                try
                {
                    await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }
        }, cancellationToken);
    }

    /// <summary>[VM-STUN-ON-WG-SOCKET] Parses a STUN reply and updates the public mapping; returns whether the datagram was consumed.</summary>
    private bool HandleStunResponse(byte[] packet)
    {
        try
        {
            if (!StunEndpointDiscovery.TryParseBindingResponse(packet, out var txId, out var mapped) || mapped == null)
            {
                return false;   // Not a reply to a request we sent (or unrecognized format) → hand back to the normal flow
            }

            var key = Convert.ToHexString(txId);
            if (!_stunPending.TryRemove(key, out var pending))
            {
                return true;    // Transaction ID mismatch: a STUN message but not for this probe, safe to drop
            }

            var previous = Volatile.Read(ref _stunPublicEndpoint);

            // [VM-STUN-STABLE-ENDPOINT 2026-11-09] Stick to the preferred server: different STUN
            // servers observe different NAT mappings of the same socket (different ports);
            // previously whichever replied last won, so the endpoint flapped between two ports
            // every 20 seconds, and the control plane kept pushing endpoint changes and peers
            // kept re-probing. Now the first server to answer is pinned; the source is switched
            // only after it has been silent for more than 5 minutes (most likely dead).
            var sameSource = string.Equals(_stunPublicEndpointSource, pending.Server, StringComparison.OrdinalIgnoreCase);
            var sourceStale = DateTime.UtcNow - _stunPublicEndpointAt > StunEndpointSourceGrace;
            if (!sameSource && previous != null && !sourceStale)
            {
                Log("DBG", $"STUN(on WG socket): ignoring mapping {mapped} from {pending.Server} (keeping stable endpoint from {_stunPublicEndpointSource})");
                return true;
            }

            _stunPublicEndpointSource = pending.Server;
            _stunPublicEndpointAt = DateTime.UtcNow;
            Volatile.Write(ref _stunPublicEndpoint, mapped);
            if (previous == null || !previous.Equals(mapped))
            {
                Log("INF", $"STUN(on WG socket): public endpoint {mapped} (was {previous?.ToString() ?? "none"}, source {pending.Server})");
                try { StunPublicEndpointChanged?.Invoke(this, mapped); } catch { }
            }
            return true;
        }
        catch (Exception ex)
        {
            Log("DBG", $"STUN response parse failed: {ex.Message}");
            return false;
        }
    }

    private class UdpAuthFailureTracker
    {
        public int FailureCount;
        public DateTime FirstFailureTime = DateTime.UtcNow;
        public DateTime LastFailureTime = DateTime.UtcNow;

        public bool IsBlocked => FailureCount >= MaxUdpAuthFailures &&
                                 DateTime.UtcNow - FirstFailureTime < UdpAuthFailureWindow;

        public void RecordFailure()
        {
            if (DateTime.UtcNow - FirstFailureTime > UdpAuthFailureWindow)
            {
                FailureCount = 0;
                FirstFailureTime = DateTime.UtcNow;
            }
            FailureCount++;
            LastFailureTime = DateTime.UtcNow;
        }

        public void Reset()
        {
            FailureCount = 0;
        }
    }
}
