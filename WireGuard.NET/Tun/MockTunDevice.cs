using System.Net;

namespace WireGuard.NET.Tun;

/// <summary>
/// In-memory <see cref="ITunDevice"/> for unit tests. Packets written via
/// <see cref="WritePacketAsync"/> are captured (cloned) for later inspection with
/// <see cref="GetSentPackets"/>; test code injects inbound packets with
/// <see cref="EnqueueReceivedPacket"/> and <see cref="ReadPacketAsync"/> dequeues them,
/// polling every 10 ms while the queue is empty. Address configuration is recorded on
/// <see cref="Address"/>/<see cref="PrefixLength"/>; routes are accepted and ignored.
/// <para>
/// Thread-safety: all state is guarded by a single lock, so reads, writes, enqueue and
/// inspection can be called from any thread. ReadPacketAsync honors the caller's
/// cancellation token (via Task.Delay) but does not observe Stop().
/// </para>
/// </summary>
public class MockTunDevice : ITunDevice
{
    private readonly List<byte[]> _sentPackets = new();
    private readonly Queue<byte[]> _receiveQueue = new();
    private readonly object _lock = new();
    private bool _running;
    private CancellationTokenSource? _cts;

    /// <summary>Gets the mock interface name ("mock-tun0").</summary>
    public string Name { get; } = "mock-tun0";

    /// <summary>Gets the mock interface MTU (1420).</summary>
    public int Mtu { get; } = 1420;

    /// <summary>Gets the address last assigned via SetAddress/SetAddressIPv6, if any.</summary>
    public IPAddress? Address { get; private set; }

    /// <summary>Gets the prefix length last assigned via SetAddress/SetAddressIPv6.</summary>
    public int PrefixLength { get; private set; }

    /// <summary>
    /// Marks the mock device as running and installs a fresh internal cancellation source.
    /// Idempotent.
    /// </summary>
    public void Start()
    {
        lock (_lock)
        {
            if (_running) return;
            _running = true;
            _cts = new CancellationTokenSource();
        }
    }

    /// <summary>
    /// Marks the mock device as stopped and cancels the internal cancellation source.
    /// Idempotent.
    /// </summary>
    public void Stop()
    {
        lock (_lock)
        {
            if (!_running) return;
            _running = false;
            _cts?.Cancel();
            _cts?.Dispose();
        }
    }

    /// <summary>
    /// Dequeues the next packet injected via <see cref="EnqueueReceivedPacket"/>, polling
    /// every 10 ms while the queue is empty.
    /// </summary>
    /// <param name="cancellationToken">Cooperative cancellation for the poll wait.</param>
    /// <returns>The next injected packet (cloned at enqueue time).</returns>
    public async Task<byte[]> ReadPacketAsync(CancellationToken cancellationToken = default)
    {
        while (true)
        {
            lock (_lock)
            {
                if (_receiveQueue.Count > 0)
                {
                    return _receiveQueue.Dequeue();
                }
            }

            await Task.Delay(10, cancellationToken);
        }
    }

    /// <summary>
    /// Records the packet (cloned) for later inspection with <see cref="GetSentPackets"/>.
    /// </summary>
    /// <param name="packet">The packet being "sent".</param>
    /// <param name="cancellationToken">Ignored.</param>
    public Task WritePacketAsync(byte[] packet, CancellationToken cancellationToken = default)
    {
        lock (_lock)
        {
            _sentPackets.Add((byte[])packet.Clone());
        }
        return Task.CompletedTask;
    }

    /// <summary>
    /// Records the parsed address and prefix length on <see cref="Address"/> and
    /// <see cref="PrefixLength"/>.
    /// </summary>
    /// <param name="address">The address literal to record.</param>
    /// <param name="prefixLength">The prefix length to record.</param>
    public void SetAddress(string address, int prefixLength)
    {
        Address = IPAddress.Parse(address);
        PrefixLength = prefixLength;
    }

    /// <summary>
    /// Records the parsed IPv6 address and prefix length; equivalent to <see cref="SetAddress"/>.
    /// </summary>
    /// <param name="address">The IPv6 address literal to record.</param>
    /// <param name="prefixLength">The prefix length to record.</param>
    public void SetAddressIPv6(string address, int prefixLength)
    {
        SetAddress(address, prefixLength);
    }

    /// <summary>
    /// Accepted and ignored — the mock device keeps no route table.
    /// </summary>
    /// <param name="cidrDestination">Ignored.</param>
    /// <param name="gateway">Ignored.</param>
    public void AddRoute(string cidrDestination, string? gateway = null)
    {
    }

    /// <summary>
    /// Accepted and ignored — the mock device keeps no route table.
    /// </summary>
    /// <param name="cidrDestination">Ignored.</param>
    public void DeleteRoute(string cidrDestination)
    {
    }

    /// <summary>
    /// Injects a packet to be returned by a subsequent <see cref="ReadPacketAsync"/> call.
    /// The packet is cloned so later external mutation does not affect the queued data.
    /// </summary>
    /// <param name="packet">The packet to enqueue.</param>
    public void EnqueueReceivedPacket(byte[] packet)
    {
        lock (_lock)
        {
            _receiveQueue.Enqueue((byte[])packet.Clone());
        }
    }

    /// <summary>
    /// Returns a snapshot of all packets captured via <see cref="WritePacketAsync"/>.
    /// </summary>
    public byte[][] GetSentPackets()
    {
        lock (_lock)
        {
            return _sentPackets.ToArray();
        }
    }

    /// <summary>
    /// Clears the captured-packet list returned by <see cref="GetSentPackets"/>.
    /// </summary>
    public void ClearSentPackets()
    {
        lock (_lock)
        {
            _sentPackets.Clear();
        }
    }

    /// <summary>
    /// Stops the mock device. Idempotent.
    /// </summary>
    public void Dispose()
    {
        Stop();
    }
}
