namespace WireGuard.NET.Tun;

/// <summary>
/// Platform-independent contract for a TUN (layer-3 virtual network interface) device that
/// exchanges raw IP packets with the host networking stack.
/// <para>
/// Lifecycle: <see cref="Start"/> creates or opens the underlying adapter; address, MTU and
/// route configuration is only valid while the device is started; <see cref="Stop"/> (or
/// <see cref="IDisposable.Dispose"/>) tears the device down again. Creating the adapter
/// usually requires elevated privileges (Administrator on Windows, root or CAP_NET_ADMIN on
/// Linux, root on macOS).
/// </para>
/// <para>
/// Buffer semantics: <see cref="ReadPacketAsync"/> yields exactly one complete IP packet per
/// call (IPv4 or IPv6, no link-layer or platform framing) in a freshly allocated array;
/// <see cref="WritePacketAsync"/> consumes exactly one complete IP packet.
/// </para>
/// <para>
/// Thread-safety: implementations expect a single concurrent reader and a single concurrent
/// writer; read loops observe <see cref="Stop"/> via cooperative cancellation and/or by
/// throwing <see cref="TunDeviceStoppedException"/>.
/// </para>
/// </summary>
public interface ITunDevice : IDisposable
{
    /// <summary>Gets the TUN interface name (on macOS the actual kernel-assigned name once known, e.g. utun7).</summary>
    string Name { get; }

    /// <summary>Gets the interface MTU in bytes (typically 1420 for WireGuard).</summary>
    int Mtu { get; }

    /// <summary>
    /// Creates or opens the underlying TUN adapter and makes it ready for address/route
    /// configuration and packet I/O. Idempotent.
    /// </summary>
    void Start();

    /// <summary>
    /// Tears the device down: cancels in-flight reads, releases OS resources and removes the
    /// interface. Idempotent.
    /// </summary>
    void Stop();

    /// <summary>
    /// Reads one complete IP packet from the device.
    /// </summary>
    /// <param name="cancellationToken">Cooperative cancellation for the read wait.</param>
    /// <returns>
    /// The packet bytes (no platform framing), or an empty array when the device stops
    /// gracefully; a device invalidated mid-operation throws
    /// <see cref="TunDeviceStoppedException"/>.
    /// </returns>
    Task<byte[]> ReadPacketAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Writes one complete IP packet to the device. Transient failures (EAGAIN/EINTR) are
    /// retried; behavior on persistent failure is platform-specific (Linux/macOS throw,
    /// Windows may silently drop the packet after exhausting retries).
    /// </summary>
    /// <param name="packet">The complete IP packet (IPv4 or IPv6) to inject.</param>
    /// <param name="cancellationToken">Cooperative cancellation for the write wait.</param>
    Task WritePacketAsync(byte[] packet, CancellationToken cancellationToken = default);

    /// <summary>
    /// Assigns a unicast address to the interface. Accepts an IPv4 or IPv6 address literal and
    /// routes it through the platform-appropriate configuration path.
    /// </summary>
    /// <param name="address">The address literal (e.g. "10.0.0.1").</param>
    /// <param name="prefixLength">The on-link prefix length (0-32 for IPv4, 0-128 for IPv6).</param>
    void SetAddress(string address, int prefixLength);

    /// <summary>
    /// Assigns an IPv6 unicast address to the interface (equivalent to
    /// <see cref="SetAddress"/> with an IPv6 literal on all current implementations).
    /// </summary>
    /// <param name="address">The IPv6 address literal.</param>
    /// <param name="prefixLength">The on-link prefix length (0-128).</param>
    void SetAddressIPv6(string address, int prefixLength);

    /// <summary>
    /// Adds a route to the routing table pointing <paramref name="cidrDestination"/> at this
    /// TUN interface (or at <paramref name="gateway"/> when one is given).
    /// </summary>
    /// <param name="cidrDestination">Destination prefix in CIDR notation (e.g. "10.0.0.0/24", "fd00::/8").</param>
    /// <param name="gateway">Optional next-hop address.</param>
    void AddRoute(string cidrDestination, string? gateway = null);

    /// <summary>
    /// Removes a previously added route. Missing routes are treated as a normal cleanup
    /// condition (logged or ignored, not thrown).
    /// </summary>
    /// <param name="cidrDestination">Destination prefix in CIDR notation.</param>
    void DeleteRoute(string cidrDestination);
}
