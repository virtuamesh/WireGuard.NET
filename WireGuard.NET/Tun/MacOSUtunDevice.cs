using System;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace WireGuard.NET.Tun;

/// <summary>
/// macOS utun device backed by a kernel control socket. <see cref="Start"/> opens an
/// AF_SYSTEM / SYSPROTO_CONTROL socket, resolves the "com.apple.net.utun_control" kernel
/// control via the CTLIOCGINFO ioctl, connects with a sockaddr_ctl address (unit 0, so the
/// kernel assigns the interface) and disables SIGPIPE on the descriptor. The kernel-assigned
/// interface name (utunN) is discovered via getsockopt and exposed through <see cref="Name"/>;
/// the MTU is applied with ifconfig(8). Addresses and routes are configured best-effort via
/// ifconfig(8), route(8) and sysctl(8).
/// <para>
/// Platform requirements: creating utun interfaces requires root privileges.
/// </para>
/// <para>
/// Buffer semantics: utun prefixes every packet with a 4-byte address-family pseudo-header
/// (the AF value in network byte order — i.e. in the last of the four bytes on little-endian
/// systems). ReadPacketAsync strips the header and returns the bare IP packet;
/// WritePacketAsync prepends AF_INET (2) for IPv4 or AF_INET6 (30 on macOS) for IPv6.
/// </para>
/// <para>
/// Lifecycle/thread-safety: ReadPacketAsync polls the descriptor and observes Stop() via an
/// internal cancellation source that is recreated on every Start(); EINTR(4)/EAGAIN(35) are
/// retried, and writes retry transient errors up to three times. Start/Stop are not
/// thread-safe; expect a single concurrent reader and writer.
/// </para>
/// </summary>
public partial class MacOSUtunDevice : ITunDevice
{
    private const int AF_SYSTEM = 32;
    private const int AF_SYS_CONTROL = 2;
    private const uint CTLIOCGINFO = 0xc0644e03;
    private const string UTUN_CONTROL_NAME = "com.apple.net.utun_control";
    private const int DEFAULT_MTU = 1420;
    private const int POLLIN = 0x0001;
    private const int POLL_TIMEOUT_MS = 100;
    private const int MAX_READ_BUFFER_SIZE = 65536 + 4;
    private const int MAX_WRITE_RETRIES = 3;
    private const int WRITE_RETRY_DELAY_MS = 1;
    private const int EINTR = 4;
    private const int EAGAIN = 35;

    private readonly string _name;
    private readonly int _mtu;
    private int _fd = -1;
    private bool _disposed;
    private bool _started;
    private CancellationTokenSource? _readCts;
    private string? _actualInterfaceName;

    /// <summary>
    /// Gets the interface name: the actual kernel-assigned utun name (e.g. "utun7") once
    /// discovered, otherwise the requested name.
    /// </summary>
    public string Name => _actualInterfaceName ?? _name;

    /// <summary>Gets the configured interface MTU.</summary>
    public int Mtu => _mtu;

    /// <summary>
    /// Creates the device with the requested interface name and MTU. The descriptor is not
    /// opened until <see cref="Start"/>; note that macOS assigns the real unit number and
    /// <paramref name="name"/> only serves as a fallback display name.
    /// </summary>
    /// <param name="name">Requested/fallback interface name (default "utun0").</param>
    /// <param name="mtu">Interface MTU, clamped to the range 576-9000.</param>
    /// <exception cref="ArgumentOutOfRangeException">The MTU is outside 576-9000.</exception>
    public MacOSUtunDevice(string name = "utun0", int mtu = DEFAULT_MTU)
    {
        if (mtu < 576 || mtu > 9000)
            throw new ArgumentOutOfRangeException(nameof(mtu), "MTU must be between 576 and 9000");

        _name = name;
        _mtu = mtu;
    }

    /// <summary>
    /// poll(2) descriptor structure: the watched file descriptor, the subscribed events
    /// (<c>events</c>) and the events actually returned by the kernel (<c>revents</c>).
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct PollFd
    {
        public int fd;
        public short events;
        public short revents;
    }

    private const int SOCK_DGRAM = 2;
    private const int SYSPROTO_CONTROL = 2;
    private const int SOL_SOCKET = 0xffff;
    private const int SO_NOSIGPIPE = 0x1022;
    private const int F_SETFL = 4;
    private const int O_NONBLOCK = 4;
    private const int SIOCGIFNAME = 0x8910;

    /// <summary>
    /// Creates the utun kernel control socket: opens an AF_SYSTEM/SYSPROTO_CONTROL socket,
    /// resolves the "com.apple.net.utun_control" control via CTLIOCGINFO, connects with a
    /// sockaddr_ctl (unit 0 = kernel-assigned), disables SIGPIPE on the descriptor, discovers
    /// the kernel-assigned interface name and applies the MTU via ifconfig(8). Idempotent; on
    /// failure the socket is closed and the exception propagates.
    /// </summary>
    /// <exception cref="SystemException">The socket could not be created (insufficient privileges), or the utun control could not be resolved or connected (control unavailable or interface in use).</exception>
    public void Start()
    {
        if (_started) return;

        try
        {
            _fd = socket(AF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
            if (_fd < 0)
            {
                var errno = Marshal.GetLastWin32Error();
                throw new SystemException($"Failed to create utun socket (errno={errno}). Ensure the application has the necessary privileges.");
            }

            var info = new ctl_info { ctl_name = UTUN_CONTROL_NAME };
            if (ioctl(_fd, CTLIOCGINFO, ref info) < 0)
            {
                var errno = Marshal.GetLastWin32Error();
                throw new SystemException($"Failed to get utun control info (errno={errno}). The utun kernel extension may not be available.");
            }

            var addr = new sockaddr_ctl
            {
                sc_len = (byte)Marshal.SizeOf<sockaddr_ctl>(),
                sc_family = AF_SYSTEM,
                sc_sysaddr = AF_SYS_CONTROL,
                sc_id = info.ctl_id,
                sc_unit = 0,
                sc_reserved = new uint[5]
            };

            if (connect(_fd, ref addr, Marshal.SizeOf<sockaddr_ctl>()) < 0)
            {
                var errno = Marshal.GetLastWin32Error();
                throw new SystemException($"Failed to connect utun device (errno={errno}). Another process may be using the utun interface.");
            }

            var nosigpipe = new byte[] { 1 };
            setsockopt(_fd, SOL_SOCKET, SO_NOSIGPIPE, nosigpipe, nosigpipe.Length);

            _actualInterfaceName = GetUtunInterfaceName();

            ConfigureMtu();

            _started = true;
        }
        catch
        {
            Cleanup();
            throw;
        }
    }

    private string? GetUtunInterfaceName()
    {
        try
        {
            var optlen = 256;
            var optval = new byte[optlen];
            if (getsockopt(_fd, 2, 2, optval, ref optlen) == 0)
            {
                var nameBytes = new byte[Math.Min(optlen, 64)];
                Array.Copy(optval, nameBytes, nameBytes.Length);
                var nullIndex = Array.IndexOf(nameBytes, (byte)0);
                if (nullIndex > 0)
                    nameBytes = nameBytes[..nullIndex];
                return System.Text.Encoding.ASCII.GetString(nameBytes);
            }
        }
        catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[MacOSUtun] Failed to get utun interface name: {ex.Message}"); }

        return _name;
    }

    private void ConfigureMtu()
    {
        try
        {
            var ifaceName = _actualInterfaceName ?? _name;
            var process = new System.Diagnostics.Process
            {
                StartInfo = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "ifconfig",
                    Arguments = $"{ifaceName} mtu {_mtu}",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                }
            };
            process.Start();
            process.WaitForExit(TimeSpan.FromSeconds(5));
        }
        catch
        {
        }
    }

    /// <summary>
    /// Cancels in-flight reads, closes the descriptor and marks the device stopped. Idempotent;
    /// the device can be restarted with <see cref="Start"/>.
    /// </summary>
    public void Stop()
    {
        if (!_started) return;
        // Cancel and clear _readCts: the next ReadPacketAsync recreates it via ??=.
        // Without nulling it out, the read loop after a restart would keep holding the
        // already-canceled token and spin idly on the in-place restart.
        _readCts?.Cancel();
        _readCts?.Dispose();
        _readCts = null;
        Cleanup();
        _started = false;
    }

    private void Cleanup()
    {
        if (_fd >= 0)
        {
            try { close(_fd); } catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[MacOSUtun] Error closing fd {_fd}: {ex.Message}"); }
            _fd = -1;
        }
    }

    /// <summary>
    /// Reads one complete IP packet from the utun descriptor, polling with a 100 ms timeout
    /// until data arrives or cancellation is requested. The utun 4-byte address-family
    /// pseudo-header is stripped before the packet is returned. Transient errors
    /// (EINTR(4)/EAGAIN(35)) are retried; EOF and cancellation return an empty array.
    /// </summary>
    /// <param name="cancellationToken">Additional cooperative cancellation, combined with the internal Stop-linked token.</param>
    /// <returns>The packet bytes, or an empty array on graceful stop/EOF.</returns>
    /// <exception cref="InvalidOperationException">The device is not started.</exception>
    /// <exception cref="SystemException">poll()/read() failed with an unexpected errno, or the descriptor reported an error condition.</exception>
    public async Task<byte[]> ReadPacketAsync(CancellationToken cancellationToken = default)
    {
        if (!_started || _fd < 0)
            throw new InvalidOperationException("Device not started");

        _readCts ??= new CancellationTokenSource();

        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken, _readCts.Token);

        var buffer = new byte[MAX_READ_BUFFER_SIZE];

        while (!linkedCts.Token.IsCancellationRequested)
        {
            var pfd = new PollFd
            {
                fd = _fd,
                events = POLLIN,
                revents = 0
            };

            var pollResult = poll(ref pfd, 1, POLL_TIMEOUT_MS);
            if (pollResult < 0)
            {
                var errno = Marshal.GetLastWin32Error();
                if (errno == EINTR)
                    continue;
                throw new SystemException($"poll() failed on utun device (errno={errno})");
            }

            if (pollResult == 0)
            {
                await Task.Yield();
                continue;
            }

            if ((pfd.revents & POLLIN) != 0)
            {
                var bytesRead = read(_fd, buffer, (IntPtr)buffer.Length);
                if (bytesRead.ToInt64() <= 0)
                {
                    if (bytesRead.ToInt64() < 0)
                    {
                        var errno = Marshal.GetLastWin32Error();
                        if (errno == EINTR || errno == EAGAIN)
                            continue;
                        throw new SystemException($"Failed to read from utun device (errno={errno})");
                    }
                    return Array.Empty<byte>();
                }

                var dataLength = (int)bytesRead.ToInt64() - 4;
                if (dataLength <= 0)
                    continue;

                var packet = new byte[dataLength];
                Buffer.BlockCopy(buffer, 4, packet, 0, dataLength);
                return packet;
            }

            if ((pfd.revents & (~(short)POLLIN)) != 0)
            {
                throw new SystemException($"utun device error condition (revents={pfd.revents})");
            }
        }

        return Array.Empty<byte>();
    }

    /// <summary>
    /// Writes one complete IP packet to the utun descriptor, prepending the 4-byte
    /// address-family pseudo-header (AF_INET = 2 for IPv4, AF_INET6 = 30 for IPv6, in network
    /// byte order). Empty packets are ignored. Retries transient errors (EAGAIN(35)/EINTR(4))
    /// up to three times with a 1 ms delay.
    /// </summary>
    /// <param name="packet">The complete IP packet to inject.</param>
    /// <param name="cancellationToken">Honored only while retrying (the write itself is synchronous).</param>
    /// <exception cref="InvalidOperationException">The device is not started.</exception>
    /// <exception cref="SystemException">write() failed after exhausting retries.</exception>
    public async Task WritePacketAsync(byte[] packet, CancellationToken cancellationToken = default)
    {
        if (!_started || _fd < 0)
            throw new InvalidOperationException("Device not started");

        if (packet == null || packet.Length == 0)
            return;

        var buffer = new byte[packet.Length + 4];
        if (packet[0] >> 4 == 4)
            buffer[3] = 2;
        else if (packet[0] >> 4 == 6)
            buffer[3] = 30;
        else
            buffer[3] = 0;

        Buffer.BlockCopy(packet, 0, buffer, 4, packet.Length);

        for (var attempt = 0; attempt < MAX_WRITE_RETRIES; attempt++)
        {
            var written = write(_fd, buffer, (IntPtr)buffer.Length);
            if (written.ToInt64() < 0)
            {
                var errno = Marshal.GetLastWin32Error();
                if ((errno == EAGAIN || errno == EINTR) && attempt < MAX_WRITE_RETRIES - 1)
                {
                    await Task.Delay(TimeSpan.FromMilliseconds(WRITE_RETRY_DELAY_MS), cancellationToken);
                    continue;
                }
                throw new SystemException($"Failed to write packet to utun device (errno={errno}, size={packet.Length})");
            }

            return;
        }
    }

    /// <summary>
    /// Assigns a unicast address to the interface via ifconfig(8): IPv4 as
    /// "inet &lt;addr&gt; &lt;addr&gt; netmask &lt;mask&gt;", IPv6 as "inet6 &lt;addr&gt;/&lt;plen&gt; -nud"
    /// followed by a sysctl(8) call disabling DAD (net.inet6.ip6.dad_count=0), then brings
    /// the interface up. Best-effort: failures are traced, not thrown.
    /// </summary>
    /// <param name="address">The address literal (IPv4 or IPv6; a ':' selects the IPv6 path).</param>
    /// <param name="prefixLength">The on-link prefix length (netmask for IPv4, /plen for IPv6).</param>
    /// <exception cref="InvalidOperationException">The device is not started.</exception>
    public void SetAddress(string address, int prefixLength)
    {
        if (!_started)
            throw new InvalidOperationException("Device not started");

        var ifaceName = _actualInterfaceName ?? _name;

        try
        {
            var isIpv6 = address.Contains(':');

            if (isIpv6)
            {
                var process = new System.Diagnostics.Process
                {
                    StartInfo = new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = "ifconfig",
                        Arguments = $"{ifaceName} inet6 {address}/{prefixLength} -nud",
                        UseShellExecute = false,
                        CreateNoWindow = true,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true
                    }
                };
                process.Start();
                process.WaitForExit(TimeSpan.FromSeconds(10));

                if (process.ExitCode != 0)
                {
                    var error = process.StandardError.ReadToEnd();
                    System.Diagnostics.Trace.WriteLine($"[MacOSUtun] ifconfig set inet6 address failed: {error}");
                }

                try
                {
                    var sysctlProcess = new System.Diagnostics.Process
                    {
                        StartInfo = new System.Diagnostics.ProcessStartInfo
                        {
                            FileName = "sysctl",
                            Arguments = $"-w net.inet6.ip6.dad_count=0",
                            UseShellExecute = false,
                            CreateNoWindow = true,
                            RedirectStandardOutput = true,
                            RedirectStandardError = true
                        }
                    };
                    sysctlProcess.Start();
                    sysctlProcess.WaitForExit(TimeSpan.FromSeconds(5));
                }
                catch (Exception ex) { System.Diagnostics.Trace.WriteLine($"[MacOSUtun] Failed to set IPv6 via sysctl: {ex.Message}"); }
            }
            else
            {
                var mask = CidrToNetmask(prefixLength);
                var process = new System.Diagnostics.Process
                {
                    StartInfo = new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = "ifconfig",
                        Arguments = $"{ifaceName} inet {address} {address} netmask {mask}",
                        UseShellExecute = false,
                        CreateNoWindow = true,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true
                    }
                };
                process.Start();
                process.WaitForExit(TimeSpan.FromSeconds(10));

                if (process.ExitCode != 0)
                {
                    var error = process.StandardError.ReadToEnd();
                    System.Diagnostics.Trace.WriteLine($"[MacOSUtun] ifconfig set inet address failed: {error}");
                }
            }

            var upProcess = new System.Diagnostics.Process
            {
                StartInfo = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "ifconfig",
                    Arguments = $"{ifaceName} up",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                }
            };
            upProcess.Start();
            upProcess.WaitForExit(TimeSpan.FromSeconds(10));
        }
        catch (Exception ex)
        {
            System.Diagnostics.Trace.WriteLine($"[MacOSUtun] Failed to set IP address on {ifaceName}: {ex.Message}");
        }
    }

    /// <summary>
    /// Assigns an IPv6 unicast address; equivalent to <see cref="SetAddress"/> with an IPv6
    /// literal (SetAddress already dispatches on the address text).
    /// </summary>
    public void SetAddressIPv6(string address, int prefixLength)
    {
        SetAddress(address, prefixLength);
    }

    /// <summary>
    /// Adds a route via route(8): "route add [-inet6] -net &lt;network&gt;[/plen] ...", pointing
    /// either at the gateway (when one is given) or at this utun interface. IPv4 destinations
    /// are converted to a dotted netmask. Best-effort: failures are traced, not thrown.
    /// </summary>
    /// <param name="destination">Destination prefix in CIDR notation; a ':' selects IPv6.</param>
    /// <param name="gateway">Optional next-hop address; when null the route points at this interface.</param>
    public void AddRoute(string destination, string? gateway = null)
    {
        try
        {
            var isIpv6 = destination.Contains(':');
            string args;

            if (isIpv6)
            {
                var parts = destination.Split('/');
                var network = parts[0];
                var prefixLen = parts.Length > 1 ? parts[1] : "128";
                args = gateway != null
                    ? $"add -inet6 -net {network}/{prefixLen} {gateway}"
                    : $"add -inet6 -net {network}/{prefixLen} -interface {_actualInterfaceName ?? _name}";
            }
            else
            {
                var parts = destination.Split('/');
                var network = parts[0];
                var prefixLen = parts.Length > 1 ? int.Parse(parts[1]) : 32;
                var mask = CidrToNetmask(prefixLen);
                args = gateway != null
                    ? $"add -net {network} -netmask {mask} {gateway}"
                    : $"add -net {network} -netmask {mask} -interface {_actualInterfaceName ?? _name}";
            }

            var process = new System.Diagnostics.Process
            {
                StartInfo = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "route",
                    Arguments = args,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                }
            };
            process.Start();
            process.WaitForExit(TimeSpan.FromSeconds(10));
        }
        catch (Exception ex)
        {
            System.Diagnostics.Trace.WriteLine($"[MacOSUtun] Failed to add route {destination}: {ex.Message}");
        }
    }

    /// <summary>
    /// Deletes a route via route(8): "route delete [-inet6] -net ...". Best-effort: failures
    /// are traced, not thrown.
    /// </summary>
    /// <param name="destination">Destination prefix in CIDR notation; a ':' selects IPv6.</param>
    public void DeleteRoute(string destination)
    {
        try
        {
            var isIpv6 = destination.Contains(':');
            string args;

            if (isIpv6)
            {
                var parts = destination.Split('/');
                var network = parts[0];
                var prefixLen = parts.Length > 1 ? parts[1] : "128";
                args = $"delete -inet6 -net {network}/{prefixLen}";
            }
            else
            {
                var parts = destination.Split('/');
                var network = parts[0];
                var prefixLen = parts.Length > 1 ? int.Parse(parts[1]) : 32;
                var mask = CidrToNetmask(prefixLen);
                args = $"delete -net {network} -netmask {mask}";
            }

            var process = new System.Diagnostics.Process
            {
                StartInfo = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "route",
                    Arguments = args,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                }
            };
            process.Start();
            process.WaitForExit(TimeSpan.FromSeconds(10));
        }
        catch (Exception ex)
        {
            System.Diagnostics.Trace.WriteLine($"[MacOSUtun] Failed to delete route {destination}: {ex.Message}");
        }
    }

    private static string CidrToNetmask(int cidr)
    {
        uint mask = 0xffffffff << (32 - cidr);
        var bytes = BitConverter.GetBytes(mask);
        if (BitConverter.IsLittleEndian)
            Array.Reverse(bytes);
        return string.Join(".", bytes.Select(b => b.ToString()));
    }

    /// <summary>
    /// Stops the device and releases the read cancellation source and descriptor. Idempotent.
    /// </summary>
    public void Dispose()
    {
        if (!_disposed)
        {
            _readCts?.Cancel();
            _readCts?.Dispose();
            _readCts = null;
            Stop();
            _disposed = true;
        }
    }
}
