using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace WireGuard.NET.Tun;

/// <summary>
/// Linux TUN device backed by the /dev/net/tun character device. <see cref="Start"/> opens the
/// node, attaches it to a fresh TUN interface via the TUNSETIFF ioctl (IFF_TUN | IFF_NO_PI,
/// so the descriptor carries raw IP packets with no link-layer header and no packet-info
/// prefix), brings the interface up and applies the MTU. Address and route configuration
/// shells out to ip(8); bringing the interface up has an SIOCSIFFLAGS ioctl fallback when
/// ip(8) is unavailable.
/// <para>
/// Platform requirements: the <c>tun</c> kernel module must be loadable (a /dev/net/tun node
/// is created via mknod when missing), and the process needs root or CAP_NET_ADMIN privileges
/// to open the device and configure the interface.
/// </para>
/// <para>
/// Buffer semantics: each read returns one complete IP packet via a single read(2) into a
/// 64 KiB buffer; each write passes one complete IP packet to write(2).
/// </para>
/// <para>
/// Lifecycle/thread-safety: ReadPacketAsync runs a poll(2) loop on a thread-pool thread and
/// observes Stop() via an internal cancellation source that is recreated on every Start();
/// Stop() also closes the descriptor so the poll wakes up. EINTR(4)/EAGAIN(11) are retried; a
/// dead descriptor (EBADFD(77)/EBADF(9)/ENODEV(19) or POLLNVAL) surfaces as
/// <see cref="TunDeviceStoppedException"/>, as does persistent POLLERR (after 100 consecutive
/// errors). Start/Stop are not thread-safe; expect a single concurrent reader and writer.
/// </para>
/// </summary>
public partial class LinuxTunDevice : ITunDevice
{
    private const string TUN_DEV = "/dev/net/tun";
    private const int TUNSETIFF = 0x400454ca;
    private const int IFF_TUN = 0x0001;
    private const int IFF_NO_PI = 0x1000;
    private const int SIOCSIFADDR = 0x8916;
    private const int SIOCSIFNETMASK = 0x891c;
    private const int SIOCSIFFLAGS = 0x8914;
    private const int IFF_UP = 0x1;
    private const int IFF_RUNNING = 0x40;
    private const int DEFAULT_MTU = 1420;
    private const int POLLIN = 0x0001;
    private const int POLL_TIMEOUT_MS = 1000;

    private readonly string _name;
    private readonly int _mtu;
    private int _fd = -1;
    private bool _disposed;
    private bool _started;
    private int _consecutivePollErrors;
    private CancellationTokenSource? _readCts;

    /// <summary>Gets the TUN interface name.</summary>
    public string Name => _name;

    /// <summary>Gets the configured interface MTU.</summary>
    public int Mtu => _mtu;

    /// <summary>
    /// Creates the device with the requested interface name and MTU. The descriptor is not
    /// opened until <see cref="Start"/>.
    /// </summary>
    /// <param name="name">Interface name (default "wg0").</param>
    /// <param name="mtu">Interface MTU; values &lt;= 0 fall back to the 1420 default.</param>
    public LinuxTunDevice(string name = "wg0", int mtu = DEFAULT_MTU)
    {
        _name = name;
        _mtu = mtu > 0 ? mtu : DEFAULT_MTU;
    }

    private const int O_RDWR = 0x0002;

    /// <summary>
    /// Ensures /dev/net/tun exists, opens it (O_RDWR), creates the TUN interface via the
    /// TUNSETIFF ioctl (IFF_TUN | IFF_NO_PI), brings the interface up and applies the MTU.
    /// Idempotent; on failure the descriptor is closed and the exception propagates.
    /// </summary>
    /// <exception cref="SystemException">The device node could not be opened (missing tun module or missing privileges), the interface could not be created (name already in use or missing permissions), or configuration failed.</exception>
    public void Start()
    {
        if (_started) return;

        try
        {
            EnsureTunDeviceNode();

            _fd = open(TUN_DEV, O_RDWR);
            if (_fd < 0)
            {
                var errno = Marshal.GetLastWin32Error();
                throw new SystemException(
                    $"Failed to open {TUN_DEV} (errno={errno}). " +
                    "Ensure the tun kernel module is loaded (modprobe tun) and you have root/CAP_NET_ADMIN capabilities.");
            }

            var ifr = new IfReq
            {
                ifrn_name = _name,
                ifru_flags = (IntPtr)(IFF_TUN | IFF_NO_PI)
            };

            if (ioctl(_fd, TUNSETIFF, ref ifr) < 0)
            {
                var errno = Marshal.GetLastWin32Error();
                close(_fd);
                _fd = -1;
                throw new SystemException(
                    $"Failed to create TUN interface '{_name}' (errno={errno}). " +
                    "The interface may already exist or you lack permissions.");
            }

            BringInterfaceUp();
            SetMtu(_mtu);

            _started = true;
        }
        catch
        {
            Cleanup();
            throw;
        }
    }

    private void EnsureTunDeviceNode()
    {
        if (File.Exists(TUN_DEV))
            return;

        try
        {
            RunCommandChecked("mkdir", "-p", "/dev/net");
            RunCommandChecked("mknod", "/dev/net/tun", "c", "10", "200");
            RunCommandChecked("chmod", "666", "/dev/net/tun");
        }
        catch
        {
        }
    }

    private void BringInterfaceUp()
    {
        try
        {
            RunCommandChecked("ip", "link", "set", "dev", _name, "up");
        }
        catch (Exception)
        {
            var sockFd = socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.IP);
            if (sockFd < 0)
            {
                return;
            }

            try
            {
                var ifr = new IfReq { ifrn_name = _name };
                ifr.ifru_flags = (IntPtr)(IFF_UP | IFF_RUNNING);
                ioctl(sockFd, SIOCSIFFLAGS, ref ifr);
            }
            finally
            {
                close(sockFd);
            }
        }
    }

    private void SetMtu(int mtu)
    {
        RunCommandChecked("ip", "link", "set", "dev", _name, "mtu", mtu.ToString());
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
            close(_fd);
            _fd = -1;
        }
    }

    /// <summary>
    /// Reads one complete IP packet from the TUN descriptor, polling with a 1-second timeout
    /// until data arrives, cancellation is requested or the device dies. Transient errors
    /// (EINTR/EAGAIN) are retried; EOF and cancellation return an empty array.
    /// </summary>
    /// <param name="cancellationToken">Additional cooperative cancellation, combined with the internal Stop-linked token.</param>
    /// <returns>The packet bytes, or an empty array on graceful stop/EOF.</returns>
    /// <exception cref="InvalidOperationException">The device is not started.</exception>
    /// <exception cref="TunDeviceStoppedException">The descriptor became invalid (EBADFD/EBADF/ENODEV/POLLNVAL) or POLLERR persisted.</exception>
    /// <exception cref="SystemException">poll()/read() failed with an unexpected errno.</exception>
    public Task<byte[]> ReadPacketAsync(CancellationToken cancellationToken = default)
    {
        if (!_started || _fd < 0)
            throw new InvalidOperationException("Device not started");

        _readCts ??= new CancellationTokenSource();

        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken, _readCts.Token);

        var token = linkedCts.Token;

        return Task.Run(() =>
        {
            while (!token.IsCancellationRequested)
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
                    if (errno == 4)
                        continue;
                    throw new SystemException($"poll() failed on TUN device (errno={errno})");
                }

                if (pollResult == 0)
                    continue;

                if ((pfd.revents & POLLIN) != 0)
                {
                    var buffer = new byte[65536];
                    var bytesRead = read(_fd, buffer, (IntPtr)buffer.Length);
                    if (bytesRead.ToInt64() <= 0)
                    {
                        if (bytesRead.ToInt64() < 0)
                        {
                            var errno = Marshal.GetLastWin32Error();
                            if (errno == 4 || errno == 11)
                                continue;
                            if (errno == 77 || errno == 9 || errno == 19)
                                throw new TunDeviceStoppedException($"Device stopped: TUN file descriptor is invalid (errno={errno})");
                            throw new SystemException($"Failed to read from TUN device (errno={errno})");
                        }
                        return Array.Empty<byte>();
                    }

                    var packet = new byte[bytesRead.ToInt64()];
                    Buffer.BlockCopy(buffer, 0, packet, 0, (int)bytesRead);
                    return packet;
                }

                const short POLLERR = 0x008;
                const short POLLHUP = 0x010;
                const short POLLNVAL = 0x020;

                var errorEvents = pfd.revents & ~(short)POLLIN;
                if (errorEvents != 0)
                {
                    if ((errorEvents & POLLNVAL) != 0)
                    {
                        throw new TunDeviceStoppedException("Device stopped: TUN device file descriptor is invalid (POLLNVAL)");
                    }
                    if ((errorEvents & POLLHUP) != 0)
                    {
                        return Array.Empty<byte>();
                    }
                    if ((errorEvents & POLLERR) != 0)
                    {
                        _consecutivePollErrors++;
                        if (_consecutivePollErrors > 100)
                        {
                            _consecutivePollErrors = 0;
                            throw new TunDeviceStoppedException("Device stopped: TUN device persistent error (POLLERR)");
                        }
                        Thread.Sleep(1);
                        continue;
                    }
                    continue;
                }
                _consecutivePollErrors = 0;
            }

            return Array.Empty<byte>();
        }, token);
    }

    /// <summary>
    /// Writes one complete IP packet with write(2), retrying transient errors (EAGAIN(11) /
    /// EINTR(4)) up to three times with a 1 ms delay between attempts. Partial writes are
    /// debug-logged but not retried.
    /// </summary>
    /// <param name="packet">The complete IP packet to inject.</param>
    /// <param name="cancellationToken">Honored only while retrying (the write itself is synchronous).</param>
    /// <exception cref="InvalidOperationException">The device is not started.</exception>
    /// <exception cref="SystemException">write() failed after exhausting retries.</exception>
    public async Task WritePacketAsync(byte[] packet, CancellationToken cancellationToken = default)
    {
        if (!_started || _fd < 0)
            throw new InvalidOperationException("Device not started");

        var maxRetries = 3;
        for (var attempt = 0; attempt < maxRetries; attempt++)
        {
            var written = write(_fd, packet, (IntPtr)packet.Length);
            if (written.ToInt64() < 0)
            {
                var errno = Marshal.GetLastWin32Error();
                if ((errno == 11 || errno == 4) && attempt < maxRetries - 1)
                {
                    await Task.Delay(TimeSpan.FromMilliseconds(1), cancellationToken);
                    continue;
                }
                throw new SystemException($"Failed to write packet to TUN device (errno={errno})");
            }

            if (written.ToInt64() < packet.Length)
            {
                LogPartialWrite(written.ToInt64(), packet.Length);
            }

            return;
        }
    }

    private static void LogPartialWrite(long written, int total)
    {
        System.Diagnostics.Debug.WriteLine($"Partial TUN write: {written}/{total} bytes");
    }

    /// <summary>Gets the raw TUN file descriptor, or -1 when the device is not started.</summary>
    public int GetFileDescriptor() => _fd;

    /// <summary>
    /// Assigns a unicast address to the interface, dispatching on the parsed address family:
    /// IPv4 via "ip addr replace", IPv6 via "ip -6 addr replace ... nodad" (replace rather
    /// than add, so a pre-existing address after an interface restart does not fail).
    /// </summary>
    /// <param name="address">The address literal (IPv4 or IPv6).</param>
    /// <param name="prefixLength">The on-link prefix length.</param>
    /// <exception cref="InvalidOperationException">The device is not started.</exception>
    /// <exception cref="ArgumentException">The address family is neither IPv4 nor IPv6.</exception>
    public void SetAddress(string address, int prefixLength)
    {
        if (!_started)
            throw new InvalidOperationException("Device not started");

        var ipAddress = IPAddress.Parse(address);

        if (ipAddress.AddressFamily == AddressFamily.InterNetwork)
        {
            SetIPv4Address(ipAddress, prefixLength);
        }
        else if (ipAddress.AddressFamily == AddressFamily.InterNetworkV6)
        {
            SetIPv6Address(ipAddress, prefixLength);
        }
        else
        {
            throw new ArgumentException($"Unsupported address family: {ipAddress.AddressFamily}", nameof(address));
        }
    }

    /// <summary>
    /// Assigns an IPv6 unicast address; equivalent to <see cref="SetAddress"/> with an IPv6
    /// literal (SetAddress already dispatches on the parsed address family).
    /// </summary>
    public void SetAddressIPv6(string address, int prefixLength)
    {
        SetAddress(address, prefixLength);
    }

    /// <summary>
    /// Adds a route via ip(8): "ip [-6] route add &lt;cidr&gt; dev &lt;name&gt;". The
    /// <paramref name="gateway"/> parameter is accepted for interface compatibility but ignored
    /// by this implementation (routes always point at the TUN interface).
    /// </summary>
    /// <param name="cidrDestination">Destination prefix in CIDR notation; a ':' selects the IPv6 route table.</param>
    /// <param name="gateway">Ignored.</param>
    public void AddRoute(string cidrDestination, string? gateway = null)
    {
        var isIpv6 = cidrDestination.Contains(':');
        if (isIpv6)
            RunCommandChecked("ip", "-6", "route", "add", cidrDestination, "dev", _name);
        else
            RunCommandChecked("ip", "route", "add", cidrDestination, "dev", _name);
    }

    /// <summary>
    /// Deletes a route via ip(8): "ip [-6] route del &lt;cidr&gt; dev &lt;name&gt;". Failures
    /// are logged and swallowed — including deleting a route that no longer exists.
    /// </summary>
    /// <param name="cidrDestination">Destination prefix in CIDR notation; a ':' selects the IPv6 route table.</param>
    public void DeleteRoute(string cidrDestination)
    {
        try
        {
            var isIpv6 = cidrDestination.Contains(':');
            if (isIpv6)
                RunCommandChecked("ip", "-6", "route", "del", cidrDestination, "dev", _name);
            else
                RunCommandChecked("ip", "route", "del", cidrDestination, "dev", _name);
        }
        catch (Exception ex)
        {
            // Deleting a route that no longer exists is a normal cleanup path — log it, do not throw.
            System.Diagnostics.Debug.WriteLine($"[LinuxTun] DeleteRoute({cidrDestination}) failed: {ex.Message}");
        }
    }

    private void SetIPv4Address(IPAddress ipAddress, int prefixLength)
    {
        // Use "replace" instead of "add": after an interface restart the address may already exist, and "add" would fail with "File exists".
        RunCommandChecked("ip", "addr", "replace", $"{ipAddress}/{prefixLength}", "dev", _name);
    }

    private void SetIPv6Address(IPAddress ipAddress, int prefixLength)
    {
        RunCommandChecked("ip", "-6", "addr", "replace", $"{ipAddress}/{prefixLength}", "dev", _name, "nodad");
    }

    /// <summary>
    /// IPv4 socket address structure (16 bytes: 2-byte family, 2-byte port, 4-byte address,
    /// 8-byte zero padding) kept for ioctl-based address configuration.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct sockaddr_in
    {
        public short sin_family;
        public ushort sin_port;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public byte[] sin_addr;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] sin_zero;
    }

    // Execs the target program directly (bypassing any shell); arguments go through
    // ArgumentList, which rules out shell injection. The exit code is checked and a non-zero
    // code throws InvalidOperationException, preventing configuration commands from failing silently.
    /// <summary>
    /// Runs an external helper (ip(8), mknod, chmod, ...) and validates its exit code.
    /// </summary>
    /// <param name="fileName">Executable to run.</param>
    /// <param name="args">Argument list (passed via ProcessStartInfo.ArgumentList, no shell involved).</param>
    /// <exception cref="InvalidOperationException">The command failed to start, timed out (30 s), or exited with a non-zero code (stderr is included in the message).</exception>
    private static void RunCommandChecked(string fileName, params string[] args)
    {
        var psi = new System.Diagnostics.ProcessStartInfo
        {
            FileName = fileName,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        foreach (var arg in args)
        {
            psi.ArgumentList.Add(arg);
        }

        using var process = System.Diagnostics.Process.Start(psi)
            ?? throw new InvalidOperationException($"Failed to start command '{fileName}'");

        var stdoutTask = process.StandardOutput.ReadToEndAsync();
        var stderrTask = process.StandardError.ReadToEndAsync();

        if (!process.WaitForExit(30000))
        {
            try { process.Kill(); } catch { }
            throw new InvalidOperationException($"Command '{fileName} {string.Join(' ', args)}' timed out");
        }

        Task.WaitAll(new Task[] { stdoutTask, stderrTask }, TimeSpan.FromSeconds(5));

        if (process.ExitCode != 0)
        {
            var stderr = stderrTask.Status == TaskStatus.RanToCompletion ? stderrTask.Result.Trim() : "";
            throw new InvalidOperationException(
                $"Command '{fileName} {string.Join(' ', args)}' failed with exit code {process.ExitCode}: {stderr}");
        }
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
