using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Channels;

namespace WireGuard.NET.Tun;

/// <summary>
/// Windows TUN device backed by the Wintun driver (wintun.dll). The constructor probes
/// well-known locations for wintun.dll, loads it with LoadLibrary and resolves the exported
/// functions with GetProcAddress. <see cref="Start"/> opens an existing adapter by name or
/// creates a new one (recreating it once when the session cannot start on a pre-existing
/// adapter), resolves the adapter LUID/index and starts a maximum-capacity ring-buffer
/// session (WINTUN_MAX_RING_CAPACITY = 64 MiB). A background thread (ReadLoop) blocks on the
/// session read-wait event and pumps received packets into a bounded channel (capacity 16384,
/// DropOldest on overflow) that <see cref="ReadPacketAsync"/> awaits; writes allocate a ring
/// slot (WintunAllocateSendPacket), copy the packet in and submit it (WintunSendPacket).
/// <para>
/// Platform requirements: Windows only; wintun.dll must be present next to the application
/// (or on the DLL search path), and creating/deleting adapters and configuring addresses and
/// routes requires Administrator privileges (the driver is installed on first adapter
/// creation).
/// </para>
/// <para>
/// Lifecycle/thread-safety: Start/Stop are not thread-safe; the read loop is the single
/// channel writer, and WritePacketAsync may run concurrently with it. When the session dies
/// (ERROR_HANDLE_EOF or an unexpected read error), the read loop raises
/// <see cref="OnDeviceDisconnected"/>; <see cref="ReadPacketAsync"/> surfaces a stopped
/// device as <see cref="TunDeviceStoppedException"/>. Address configuration prefers the
/// native iphlpapi API (milliseconds) and falls back to a parameterized PowerShell
/// invocation (~1-2 s); routes are configured through netsh.
/// </para>
/// </summary>
public partial class WindowsWintunDevice : ITunDevice
{
    private IntPtr _adapter = IntPtr.Zero;
    private IntPtr _session = IntPtr.Zero;
    private readonly string _name;
    private Guid _adapterGuid;
    private bool _running;
    private CancellationTokenSource? _cts;
    private Thread? _readThread;
    private readonly Channel<byte[]> _packetChannel = Channel.CreateBounded<byte[]>(new BoundedChannelOptions(16384)
    {
        SingleReader = true,
        SingleWriter = true,
        FullMode = BoundedChannelFullMode.DropOldest
    });
    private WINTUN_LOGGER_CALLBACK? _loggerCallback;
    private NET_LUID _adapterLuid;
    private uint _adapterIndex;
    private bool _ipv6DadDisabled;
    
    private IntPtr _wintunDll = IntPtr.Zero;
    private IntPtr _wintunCreateAdapter = IntPtr.Zero;
    private IntPtr _wintunOpenAdapter = IntPtr.Zero;
    private IntPtr _wintunCloseAdapter = IntPtr.Zero;
    private IntPtr _wintunGetAdapterLuid = IntPtr.Zero;
    private IntPtr _wintunStartSession = IntPtr.Zero;
    private IntPtr _wintunEndSession = IntPtr.Zero;
    private IntPtr _wintunGetReadWaitEvent = IntPtr.Zero;
    private IntPtr _wintunReceivePacket = IntPtr.Zero;
    private IntPtr _wintunReleaseReceivePacket = IntPtr.Zero;
    private IntPtr _wintunAllocateSendPacket = IntPtr.Zero;
    private IntPtr _wintunSendPacket = IntPtr.Zero;
    private IntPtr _wintunSetLogger = IntPtr.Zero;
    private IntPtr _wintunGetRunningDriverVersion = IntPtr.Zero;
    private IntPtr _wintunDeleteDriver = IntPtr.Zero;
    private IntPtr _wintunEnumAdapters = IntPtr.Zero;
    private IntPtr _getAdapterName = IntPtr.Zero;

    /// <summary>Gets the adapter name.</summary>
    public string Name => _name;

    /// <summary>Gets the interface MTU (fixed at 1420 for this implementation).</summary>
    public int Mtu => 1420;

    /// <summary>Gets the adapter's interface LUID (valid after Start).</summary>
    public NET_LUID AdapterLuid => _adapterLuid;

    /// <summary>Gets the adapter's interface index (valid after Start).</summary>
    public uint AdapterIndex => _adapterIndex;

    /// <summary>Indicates whether the device is currently started.</summary>
    public bool IsRunning => _running;

    /// <summary>
    /// Raised when the Wintun session dies or the read loop exits unexpectedly (adapter
    /// disabled, handle invalidated, driver error) — the device is effectively stopped.
    /// </summary>
    public event EventHandler? OnDeviceDisconnected;

    /// <summary>
    /// Raised for every Wintun driver log line once a logger has been attached via
    /// <see cref="SetLogger"/>.
    /// </summary>
    public event EventHandler<(WintunLogLevel level, string message)>? OnLog;

    /// <summary>
    /// Creates the device and loads wintun.dll from the application directory (probing
    /// Native/, the base directory, driver/ and the default DLL search path). The adapter
    /// itself is not opened until <see cref="Start"/>.
    /// </summary>
    /// <param name="name">Adapter name (validated whenever addresses are configured).</param>
    /// <param name="adapterGuid">Optional stable adapter GUID; a random GUID is generated when omitted.</param>
    /// <exception cref="PlatformNotSupportedException">The operating system is not Windows.</exception>
    /// <exception cref="InvalidOperationException">wintun.dll was not found, could not be loaded, or is missing required exports.</exception>
    public WindowsWintunDevice(string name, Guid? adapterGuid = null)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            throw new PlatformNotSupportedException("WindowsWintunDevice only supports Windows");

        _name = name;
        _adapterGuid = adapterGuid ?? Guid.NewGuid();
        
        LoadWintunLibrary();
    }

    /// <summary>
    /// Loads wintun.dll and resolves the exported function pointers; throws when the library
    /// is missing or does not export the mandatory functions (Create/Open/Close adapter,
    /// StartSession).
    /// </summary>
    private void LoadWintunLibrary()
    {
        var appDir = AppDomain.CurrentDomain.BaseDirectory;
        bool loaded = false;

        var possiblePaths = new[]
        {
            Path.Combine(appDir, "Native", "wintun.dll"),
            Path.Combine(appDir, "wintun.dll"),
            Path.Combine(appDir, "driver", "wintun.dll"),
            "wintun.dll"
        };

        foreach (var path in possiblePaths)
        {
            if (File.Exists(path))
            {
                _wintunDll = LoadLibrary(path);
                if (_wintunDll != IntPtr.Zero)
                {
                    loaded = true;
                    break;
                }
            }
        }

        if (!loaded)
        {
            throw new InvalidOperationException("Failed to load wintun.dll. Please ensure the file exists in the application directory.");
        }

        _wintunCreateAdapter = GetProcAddress(_wintunDll, "WintunCreateAdapter");
        _wintunOpenAdapter = GetProcAddress(_wintunDll, "WintunOpenAdapter");
        _wintunCloseAdapter = GetProcAddress(_wintunDll, "WintunCloseAdapter");
        _wintunGetAdapterLuid = GetProcAddress(_wintunDll, "WintunGetAdapterLUID");
        _wintunStartSession = GetProcAddress(_wintunDll, "WintunStartSession");
        _wintunEndSession = GetProcAddress(_wintunDll, "WintunEndSession");
        _wintunGetReadWaitEvent = GetProcAddress(_wintunDll, "WintunGetReadWaitEvent");
        _wintunReceivePacket = GetProcAddress(_wintunDll, "WintunReceivePacket");
        _wintunReleaseReceivePacket = GetProcAddress(_wintunDll, "WintunReleaseReceivePacket");
        _wintunAllocateSendPacket = GetProcAddress(_wintunDll, "WintunAllocateSendPacket");
        _wintunSendPacket = GetProcAddress(_wintunDll, "WintunSendPacket");
        _wintunSetLogger = GetProcAddress(_wintunDll, "WintunSetLogger");
        _wintunGetRunningDriverVersion = GetProcAddress(_wintunDll, "WintunGetRunningDriverVersion");
        _wintunDeleteDriver = GetProcAddress(_wintunDll, "WintunDeleteDriver");
        _wintunEnumAdapters = GetProcAddress(_wintunDll, "WintunEnumAdapters");
        _getAdapterName = GetProcAddress(_wintunDll, "GetAdapterName");

        if (_wintunCreateAdapter == IntPtr.Zero || _wintunOpenAdapter == IntPtr.Zero || 
            _wintunCloseAdapter == IntPtr.Zero || _wintunStartSession == IntPtr.Zero)
        {
            throw new InvalidOperationException("Failed to resolve wintun.dll functions.");
        }
    }

    /// <summary>
    /// Attaches a logger callback to the Wintun driver; every log line is surfaced both via
    /// <see cref="OnLog"/> and the given <paramref name="logger"/> delegate.
    /// </summary>
    /// <param name="logger">Handler receiving (level, message) per driver log line.</param>
    public void SetLogger(Action<WintunLogLevel, string> logger)
    {
        _loggerCallback = (level, timestamp, message) =>
        {
            OnLog?.Invoke(this, (level, message));
            logger(level, message);
        };
        WintunSetLogger(_loggerCallback);
    }

    /// <summary>
    /// Opens the adapter by name (creating it on first use) and starts a maximum-capacity
    /// ring-buffer session plus the background read thread. When the session cannot start on a
    /// pre-existing adapter, the adapter is deleted and recreated once, then retried.
    /// Idempotent; on failure everything is cleaned up and the exception propagates.
    /// </summary>
    /// <exception cref="InvalidOperationException">The adapter could not be opened/created, the adapter index could not be resolved, or the session could not be started.</exception>
    public void Start()
    {
        if (_running) return;

        try
        {
            // First try to open an existing adapter.
            _adapter = WintunOpenAdapter(_name);
            bool adapterCreated = false;
            
            if (_adapter == IntPtr.Zero)
            {
                _adapter = WintunCreateAdapter(_name, "WireGuard.NET", IntPtr.Zero);
                adapterCreated = true;
                if (_adapter == IntPtr.Zero)
                {
                    var error = Marshal.GetLastWin32Error();
                    throw new InvalidOperationException($"Failed to create Wintun adapter: {error}");
                }
            }

            WintunGetAdapterLuid(_adapter, ref _adapterLuid);
            
            _adapterIndex = GetAdapterIndexByLuid(_adapterLuid);

            _session = WintunStartSession(_adapter, WINTUN_MAX_RING_CAPACITY);
            
            if (_session == IntPtr.Zero && !adapterCreated)
            {
                var error = Marshal.GetLastWin32Error();
                
                WintunCloseAdapter(_adapter);
                _adapter = IntPtr.Zero;
                
                Thread.Sleep(2000);
                
                _adapter = WintunCreateAdapter(_name, "WireGuard.NET", IntPtr.Zero);
                if (_adapter == IntPtr.Zero)
                    throw new InvalidOperationException($"Failed to create Wintun adapter after recreation: {Marshal.GetLastWin32Error()}");
                
                WintunGetAdapterLuid(_adapter, ref _adapterLuid);
                
                _adapterIndex = GetAdapterIndexByLuid(_adapterLuid);
                
                _session = WintunStartSession(_adapter, WINTUN_MAX_RING_CAPACITY);
                if (_session == IntPtr.Zero)
                    throw new InvalidOperationException($"Failed to start Wintun session after adapter recreation: {Marshal.GetLastWin32Error()}");
            }
            else if (_session == IntPtr.Zero)
            {
                throw new InvalidOperationException($"Failed to start Wintun session: {Marshal.GetLastWin32Error()}");
            }

            _running = true;
            _cts = new CancellationTokenSource();
            _readThread = new Thread(ReadLoop)
            {
                IsBackground = true
            };
            _readThread.Start();
        }
        catch
        {
            Cleanup();
            throw;
        }
    }

    /// <summary>
    /// Stops the read loop (with a 2-second join), completes the packet channel, ends the
    /// session, closes the adapter and unloads wintun.dll. Idempotent.
    /// </summary>
    public void Stop()
    {
        if (!_running) return;

        Cleanup();
    }

    /// <summary>
    /// Reads the next packet delivered by the read loop from the bounded channel. When the
    /// channel is closed by Stop/Cleanup (device stopped), throws
    /// <see cref="TunDeviceStoppedException"/>; cancellation propagates as
    /// OperationCanceledException.
    /// </summary>
    /// <param name="cancellationToken">Cooperative cancellation for the channel wait.</param>
    /// <returns>The received packet bytes.</returns>
    /// <exception cref="TunDeviceStoppedException">The device has been stopped.</exception>
    public async Task<byte[]> ReadPacketAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            return await _packetChannel.Reader.ReadAsync(cancellationToken);
        }
        catch (ChannelClosedException)
        {
            throw new TunDeviceStoppedException("Device stopped");
        }
    }

    /// <summary>
    /// Writes one complete IP packet into the send ring: allocates a ring slot, copies the
    /// packet in and submits it. When the ring is full, retries up to three times (1 ms
    /// apart) and then silently drops the packet.
    /// </summary>
    /// <param name="packet">The complete IP packet to inject.</param>
    /// <param name="cancellationToken">Not used; the write itself is synchronous.</param>
    /// <exception cref="InvalidOperationException">The device is not started.</exception>
    /// <exception cref="ArgumentException">The packet exceeds WINTUN_MAX_IP_PACKET_SIZE bytes.</exception>
    public Task WritePacketAsync(byte[] packet, CancellationToken cancellationToken = default)
    {
        if (!_running)
            throw new InvalidOperationException("Device not started");

        if (packet.Length > WINTUN_MAX_IP_PACKET_SIZE)
            throw new ArgumentException($"Packet size exceeds maximum of {WINTUN_MAX_IP_PACKET_SIZE} bytes");

        for (int retry = 0; retry < 3; retry++)
        {
            var writePacket = WintunAllocateSendPacket(_session, (uint)packet.Length);
            if (writePacket == IntPtr.Zero)
            {
                if (retry < 2)
                {
                    Thread.Sleep(1);
                    continue;
                }
                return Task.CompletedTask;
            }

            Marshal.Copy(packet, 0, writePacket, packet.Length);
            WintunSendPacket(_session, writePacket);
            return Task.CompletedTask;
        }

        return Task.CompletedTask;
    }

    /// <summary>
    /// Assigns a unicast address to the adapter. Validates the address/prefix/adapter name
    /// first (preventing injection and half-configured states), waits until the adapter is
    /// visible in the Windows network stack (up to 10 × 1 s), then prefers the native
    /// iphlpapi path (CreateUnicastIpAddressEntry, milliseconds) and falls back to a
    /// parameterized PowerShell invocation (~1-2 s) when the native path fails. In the
    /// fallback, only address-creation failure is fatal; interface-parameter adjustments are
    /// best-effort.
    /// </summary>
    /// <param name="address">The address literal (IPv4 or IPv6).</param>
    /// <param name="prefixLength">The on-link prefix length (0-32 for IPv4, 0-128 for IPv6).</param>
    /// <exception cref="ArgumentException">Unsupported address family or invalid adapter name.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Prefix length out of range for the address family.</exception>
    /// <exception cref="InvalidOperationException">The adapter is not visible in the network stack, or address configuration failed.</exception>
    public void SetAddress(string address, int prefixLength)
    {
        // Validate before invoking: reject invalid addresses/prefixes/adapter names before building any command, preventing injection and half-configured states.
        var parsedAddress = IPAddress.Parse(address);
        var isIpv6 = parsedAddress.AddressFamily == AddressFamily.InterNetworkV6;
        if (!isIpv6 && parsedAddress.AddressFamily != AddressFamily.InterNetwork)
        {
            throw new ArgumentException($"Unsupported address family: {parsedAddress.AddressFamily}", nameof(address));
        }
        var maxPrefix = isIpv6 ? 128 : 32;
        if (prefixLength < 0 || prefixLength > maxPrefix)
        {
            throw new ArgumentOutOfRangeException(nameof(prefixLength), $"Prefix length must be between 0 and {maxPrefix}");
        }
        ValidateAdapterName(_name);

        bool adapterVisible = false;
        for (int i = 0; i < 10; i++)
        {
            foreach (var iface in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (iface.Name == _name)
                {
                    adapterVisible = true;
                    break;
                }
            }
            if (!adapterVisible)
            {
                Thread.Sleep(1000);
            }
            else
            {
                break;
            }
        }

        if (!adapterVisible)
        {
            throw new InvalidOperationException($"Network adapter '{_name}' not visible after 10s wait");
        }

        // P0 connection-speed optimization (critical): prefer the native iphlpapi API
        // (CreateUnicastIpAddressEntry) to set the address — completes in-process within
        // milliseconds, eliminating the PowerShell child-process spawn (~1-2 s each time).
        // On native failure, fall back to the original PowerShell path (compatibility safety net).
        var nativeSw = System.Diagnostics.Stopwatch.StartNew();
        try
        {
            SetUnicastIpAddress(parsedAddress, prefixLength);
            nativeSw.Stop();
            System.Diagnostics.Trace.WriteLine(
                $"[ConnectTiming] Wintun SetAddress native {parsedAddress}/{prefixLength} ok in {nativeSw.ElapsedMilliseconds}ms");
            return;
        }
        catch (Exception nativeEx)
        {
            nativeSw.Stop();
            System.Diagnostics.Trace.WriteLine(
                $"[ConnectTiming] Wintun SetAddress native failed ({nativeSw.ElapsedMilliseconds}ms): {nativeEx.Message}; falling back to PowerShell");
        }

        // Parameterized arguments: the address/prefix/adapter name are passed into the script
        // through the script block's $args (see the critical-fix note at the psi construction
        // below) instead of being interpolated into the script body, eliminating command injection.
        // Only address-creation failure is fatal (non-zero exit code propagates);
        // interface-parameter adjustments remain best-effort.
        var addressFamily = isIpv6 ? "IPv6" : "IPv4";
        var script = $@"
$ErrorActionPreference = 'Stop'
$alias = $args[0]; $ip = $args[1]; $plen = [int]$args[2]
try {{
    $existing = Get-NetIPAddress -InterfaceAlias $alias -AddressFamily {addressFamily} -ErrorAction SilentlyContinue | Where-Object {{ $_.IPAddress -eq $ip }}
    if (-not $existing) {{
        New-NetIPAddress -InterfaceAlias $alias -IPAddress $ip -PrefixLength $plen -AddressFamily {addressFamily} | Out-Null
    }}
}} catch {{ Write-Error $_; exit 1 }}
Set-NetIPInterface -InterfaceAlias $alias -AddressFamily {addressFamily} -Dhcp Disabled -ErrorAction SilentlyContinue
";
        if (isIpv6)
        {
            script += @"
Set-NetIPInterface -InterfaceAlias $alias -AddressFamily IPv6 -RouterDiscovery Disabled -ErrorAction SilentlyContinue
Enable-NetAdapterBinding -Name $alias -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue
& netsh interface ipv6 set interface ""$alias"" dadtransmits=0 routerdiscovery=disabled managedaddress=disabled otherstateful=disabled | Out-Null
";
        }

        // Critical fix (for "Cannot validate argument on parameter 'InterfaceAlias'. The argument is null"):
        // powershell.exe's -Command **concatenates every remaining command-line argument into the
        // command text** (executed as separate statements after the script) instead of populating
        // $args inside the script — leaving $args[0..2] all null, so New-NetIPAddress failed
        // outright because -InterfaceAlias was null.
        // The correct approach: wrap the script in a script block `& { ... }` and pass the actual
        // arguments after the block; $args is only populated when the script block is invoked
        // (exit 1 still terminates the whole powershell process, so exit-code semantics are unchanged).
        // The adapter name is already restricted by ValidateAdapterName to letters/digits/spaces/_-. (no quotes),
        // so single-quoting it is safe; the address is IPAddress text and the prefix is an int — no injection surface.
        var psi = new System.Diagnostics.ProcessStartInfo
        {
            FileName = "powershell",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        psi.ArgumentList.Add("-NoProfile");
        psi.ArgumentList.Add("-NonInteractive");
        psi.ArgumentList.Add("-Command");
        psi.ArgumentList.Add(
            "& {" + script + "} '" + _name + "' '" + parsedAddress.ToString() + "' " + prefixLength);

        using var process = System.Diagnostics.Process.Start(psi)
            ?? throw new InvalidOperationException("Failed to start powershell");

        var stderrTask = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(30000))
        {
            try { process.Kill(); } catch { }
            throw new InvalidOperationException($"powershell SetAddress timed out for adapter '{_name}'");
        }

        if (process.ExitCode != 0)
        {
            var stderr = stderrTask.IsCompleted ? stderrTask.Result.Trim() : "";
            throw new InvalidOperationException(
                $"Failed to set address {parsedAddress}/{prefixLength} on adapter '{_name}' (exit={process.ExitCode}): {stderr}");
        }
    }

    /// <summary>
    /// Validates the adapter name against a strict whitelist (letters, digits, space, _, -,
    /// .; maximum 128 characters) so it can be safely embedded in PowerShell/netsh command
    /// lines.
    /// </summary>
    /// <param name="name">The adapter name to validate.</param>
    /// <exception cref="ArgumentException">The name is empty, too long, or contains characters outside the whitelist.</exception>
    private static void ValidateAdapterName(string name)
    {
        if (string.IsNullOrWhiteSpace(name) || name.Length > 128 ||
            !name.All(c => char.IsLetterOrDigit(c) || c is ' ' or '_' or '-' or '.'))
        {
            throw new ArgumentException($"Invalid adapter name: '{name}'", nameof(name));
        }
    }

    /// <summary>
    /// Adds a route via netsh ("netsh interface [ip|ipv6] add route prefix=... interface=...",
    /// with nexthop= when a gateway is given). Best-effort: failures are traced, not thrown.
    /// </summary>
    /// <param name="cidrDestination">Destination prefix in CIDR notation; a ':' selects the IPv6 route table.</param>
    /// <param name="gateway">Optional next-hop address.</param>
    public void AddRoute(string cidrDestination, string? gateway = null)
    {
        try
        {
            var parts = cidrDestination.Split('/');
            var destination = parts[0];
            var prefixLength = parts.Length > 1 ? int.Parse(parts[1]) : 32;
            var isIpv6 = destination.Contains(':');
            var gatewayArg = gateway ?? (isIpv6 ? "" : "");
            string arguments;
            if (isIpv6)
            {
                arguments = string.IsNullOrEmpty(gatewayArg)
                    ? $"interface ipv6 add route prefix={destination}/{prefixLength} interface=\"{_name}\""
                    : $"interface ipv6 add route prefix={destination}/{prefixLength} nexthop={gatewayArg} interface=\"{_name}\"";
            }
            else
            {
                arguments = string.IsNullOrEmpty(gatewayArg)
                    ? $"interface ip add route prefix={destination}/{prefixLength} interface=\"{_name}\""
                    : $"interface ip add route prefix={destination}/{prefixLength} nexthop={gatewayArg} interface=\"{_name}\"";
            }
            var psi = new System.Diagnostics.ProcessStartInfo
            {
                FileName = "netsh",
                Arguments = arguments,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };
            
            var process = System.Diagnostics.Process.Start(psi);
            if (process != null)
            {
                process.WaitForExit();
                if (process.ExitCode != 0)
                {
                    var error = process.StandardError.ReadToEnd();
                    System.Diagnostics.Trace.WriteLine($"[WINTUN] AddRoute failed: {cidrDestination} exit={process.ExitCode} err={error}");
                }
            }
        }
        catch (Exception ex)
        {
            System.Diagnostics.Trace.WriteLine($"[WINTUN] AddRoute exception: {cidrDestination} {ex.Message}");
        }
    }

    /// <summary>
    /// Deletes a route via netsh ("netsh interface [ip|ipv6] delete route prefix=...").
    /// Best-effort: all failures are silently swallowed.
    /// </summary>
    /// <param name="cidrDestination">Destination prefix in CIDR notation; a ':' selects the IPv6 route table.</param>
    public void DeleteRoute(string cidrDestination)
    {
        try
        {
            var parts = cidrDestination.Split('/');
            var destination = parts[0];
            var prefixLength = parts.Length > 1 ? int.Parse(parts[1]) : 32;
            var isIpv6 = destination.Contains(':');
            string arguments;
            if (isIpv6)
            {
                arguments = $"interface ipv6 delete route prefix={destination}/{prefixLength} interface=\"{_name}\"";
            }
            else
            {
                arguments = $"interface ip delete route prefix={destination}/{prefixLength} interface=\"{_name}\"";
            }
            var psi = new System.Diagnostics.ProcessStartInfo
            {
                FileName = "netsh",
                Arguments = arguments,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };
            
            var process = System.Diagnostics.Process.Start(psi);
            if (process != null)
            {
                process.WaitForExit();
            }
        }
        catch
        {
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
    /// Applies the MTU to the adapter's IP interface via the native SetIpInterfaceEntry API.
    /// </summary>
    /// <param name="mtu">The MTU in bytes.</param>
    public void SetMtu(int mtu)
    {
        SetAdapterMtu(_adapterIndex, mtu);
    }

    /// <summary>Gets the running Wintun driver version, or 0 when unavailable.</summary>
    public uint GetDriverVersion()
    {
        return WintunGetRunningDriverVersion();
    }

    /// <summary>
    /// Attempts to uninstall the Wintun driver. NOTE: currently always throws, because the
    /// underlying interop wrapper is a stub that returns false without invoking the export.
    /// </summary>
    /// <exception cref="InvalidOperationException">Always thrown (stub).</exception>
    public static void DeleteDriver()
    {
        if (!WintunDeleteDriver())
            throw new InvalidOperationException($"Failed to delete Wintun driver: {Marshal.GetLastWin32Error()}");
    }

    /// <summary>
    /// Enumerates the names of existing Wintun adapters. NOTE: currently always yields an
    /// empty sequence, because the underlying WintunEnumAdapters interop wrapper is a stub
    /// that returns false without invoking the export.
    /// </summary>
    public static IEnumerable<string> EnumAdapters()
    {
        var adapters = new List<string>();
        var callback = new WINTUN_ENUM_CALLBACK((adapter, param) =>
        {
            var nameBuffer = new StringBuilder(MAX_ADAPTER_NAME);
            if (GetAdapterName(adapter, nameBuffer, MAX_ADAPTER_NAME))
            {
                adapters.Add(nameBuffer.ToString());
            }
            return true;
        });

        WintunEnumAdapters(callback, IntPtr.Zero);
        return adapters;
    }

    /// <summary>
    /// Stops the device (see <see cref="Stop"/>). Idempotent.
    /// </summary>
    public void Dispose()
    {
        Stop();
    }

    /// <summary>
    /// Background read thread: waits on the session read-wait event (100 ms timeout), copies
    /// received packets out of the ring into the bounded packet channel (capacity 16384,
    /// DropOldest — a full channel discards the oldest packet), and raises
    /// <see cref="OnDeviceDisconnected"/> when the session dies (ERROR_HANDLE_EOF, session
    /// handle zeroed, ObjectDisposedException, or any unexpected read error).
    /// </summary>
    private void ReadLoop()
    {
        var readEvent = WintunGetReadWaitEvent(_session);

        while (_running && !_cts!.Token.IsCancellationRequested)
        {
            try
            {
                var result = WaitForSingleObject(readEvent, 100);
                if (result == WAIT_OBJECT_0)
                {
                    while (true)
                    {
                        uint packetSize;
                        var packet = WintunReceivePacket(_session, out packetSize);
                        if (packet == IntPtr.Zero)
                        {
                            var error = Marshal.GetLastWin32Error();
                            if (error == ERROR_NO_MORE_ITEMS)
                                break;

                            if (error == ERROR_HANDLE_EOF)
                            {
                                OnDeviceDisconnected?.Invoke(this, EventArgs.Empty);
                                return;
                            }

                            break;
                        }

                        if (packetSize > 0)
                        {
                            var data = new byte[packetSize];
                            Marshal.Copy(packet, data, 0, (int)packetSize);

                            if (!_packetChannel.Writer.TryWrite(data))
                            {
                            }
                        }

                        WintunReleaseReceivePacket(_session, packet);
                    }
                }

                if (_cts.Token.IsCancellationRequested)
                    break;

                if (_session == IntPtr.Zero)
                {
                    OnDeviceDisconnected?.Invoke(this, EventArgs.Empty);
                    return;
                }
            }
            catch (ObjectDisposedException)
            {
                OnDeviceDisconnected?.Invoke(this, EventArgs.Empty);
                return;
            }
            catch
            {
                OnDeviceDisconnected?.Invoke(this, EventArgs.Empty);
                return;
            }
        }
    }

    /// <summary>
    /// Stops the read loop, completes the packet channel, ends the session, closes the
    /// adapter, unloads wintun.dll and disposes the cancellation source. Idempotent.
    /// </summary>
    private void Cleanup()
    {
        _running = false;
        _packetChannel.Writer.TryComplete();
        _cts?.Cancel();

        if (_readThread != null && _readThread.IsAlive)
        {
            _readThread.Join(TimeSpan.FromSeconds(2));
        }

        if (_session != IntPtr.Zero)
        {
            WintunEndSession(_session);
            _session = IntPtr.Zero;
        }

        if (_adapter != IntPtr.Zero)
        {
            WintunCloseAdapter(_adapter);
            _adapter = IntPtr.Zero;
        }

        if (_wintunDll != IntPtr.Zero)
        {
            FreeLibrary(_wintunDll);
            _wintunDll = IntPtr.Zero;
        }

        _cts?.Dispose();
        _cts = null;
    }

    /// <summary>
    /// Tears down the current session and adapter (keeping wintun.dll loaded), waits 1
    /// second, then reopens or recreates the adapter, resolves its LUID/index and starts a
    /// fresh session and read thread.
    /// </summary>
    /// <returns>True when the session was restarted; false when the adapter/session could not be recreated.</returns>
    public bool RestartSession()
    {
        if (_session != IntPtr.Zero)
        {
            try
            {
                WintunEndSession(_session);
            }
            catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[WINTUN] Error ending session: {ex.Message}"); }
            _session = IntPtr.Zero;
        }

        if (_adapter != IntPtr.Zero)
        {
            try
            {
                WintunCloseAdapter(_adapter);
            }
            catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[WINTUN] Error closing adapter: {ex.Message}"); }
            _adapter = IntPtr.Zero;
        }

        _running = false;
        _cts?.Cancel();
        if (_readThread != null && _readThread.IsAlive)
        {
            _readThread.Join(TimeSpan.FromSeconds(2));
        }
        _cts?.Dispose();
        _cts = null;

        Thread.Sleep(1000);

        try
        {
            _adapter = WintunOpenAdapter(_name);
            if (_adapter == IntPtr.Zero)
            {
                _adapter = WintunCreateAdapter(_name, "WireGuard.NET", IntPtr.Zero);
            }

            if (_adapter == IntPtr.Zero)
            {
                return false;
            }

            WintunGetAdapterLuid(_adapter, ref _adapterLuid);
            _adapterIndex = GetAdapterIndexByLuid(_adapterLuid);

            _session = WintunStartSession(_adapter, WINTUN_MAX_RING_CAPACITY);
            if (_session == IntPtr.Zero)
            {
                WintunCloseAdapter(_adapter);
                _adapter = IntPtr.Zero;
                return false;
            }

            _running = true;
            _cts = new CancellationTokenSource();
            _readThread = new Thread(ReadLoop) { IsBackground = true };
            _readThread.Start();

            return true;
        }
        catch (Exception)
        {
            return false;
        }
    }

    /// <summary>
    /// Builds a SOCKADDR_INET matching the union layout in netioapi.h.
    /// Exploits BitConverter's re-parse behavior on little-endian machines to write the
    /// network-order (big-endian) address bytes into memory in their original order:
    /// e.g. bytes[0]=10 lands at offset 0 inside the sockaddr, exactly matching the native
    /// byte arrangement.
    /// </summary>
    private static SOCKADDR_INET BuildSockaddrInet(IPAddress address)
    {
        var result = new SOCKADDR_INET();
        var bytes = address.GetAddressBytes();
        if (bytes.Length == 4)
        {
            result.si_family = ADDRESS_FAMILY.AF_INET;
            result.sin_addr = BitConverter.ToUInt32(bytes, 0);
        }
        else
        {
            result.si_family = ADDRESS_FAMILY.AF_INET6;
            // IPv6 address is written 4 bytes at a time in network order (BitConverter.ToUInt32 on a little-endian machine preserves the byte order exactly)
            result.sin6_addr_w0 = BitConverter.ToUInt32(bytes, 0);
            result.sin6_addr_w1 = BitConverter.ToUInt32(bytes, 4);
            result.sin6_addr_w2 = BitConverter.ToUInt32(bytes, 8);
            result.sin6_addr_w3 = BitConverter.ToUInt32(bytes, 12);
        }
        return result;
    }

    /// <summary>
    /// Sets the interface unicast address via the native iphlpapi API
    /// (CreateUnicastIpAddressEntry). Completes in milliseconds, replacing the previous
    /// ~1-2 s PowerShell child-process path.
    /// </summary>
    /// <param name="address">The IP address to set (IPv4 or IPv6).</param>
    /// <param name="prefixLength">The on-link prefix length.</param>
    /// <param name="skipAsSource">When true, the address is excluded from default source-address selection (used for auxiliary IP/gateway/DNS-reserved addresses).</param>
    private void SetUnicastIpAddress(IPAddress address, int prefixLength, bool skipAsSource = false)
    {
        // [FIX] IPv6: disable DAD at the interface level (DadTransmits=0, one-shot) before
        // creating the address.
        // Otherwise the new address enters the tentative state and performs DAD
        // (dadtransmits=1 × 1s ≈ 1 second), during which it cannot communicate — after a
        // reconnect, IPv6 would become reachable ~1s later than IPv4 (IPv4 has no such process).
        // A TUN device is a point-to-point L3 interface with no neighbors, so DAD is meaningless;
        // this aligns with the netsh dadtransmits=0 behavior of the PowerShell fallback path.
        // It must be set BEFORE CreateUnicastIpAddressEntry: interface parameters only affect
        // addresses added afterwards, and addresses already in the tentative state are unaffected.
        if (address.AddressFamily == AddressFamily.InterNetworkV6)
            DisableIPv6Dad();

        var row = new MIB_UNICASTIPADDRESS_ROW();
        InitializeUnicastIpAddressEntry(ref row);
        row.Address = BuildSockaddrInet(address);
        row.InterfaceLuid = _adapterLuid;
        row.InterfaceIndex = _adapterIndex;
        row.OnLinkPrefixLength = (byte)prefixLength;
        row.ValidLifetime = 0xffffffff; // infinite
        row.PreferredLifetime = 0xffffffff;
        row.SkipAsSource = skipAsSource ? (byte)1 : (byte)0;

        var result = CreateUnicastIpAddressEntry(ref row);
        if (result != 0 && result != ERROR_OBJECT_ALREADY_EXISTS)
            throw new InvalidOperationException($"Failed to set IP address via native API: {result}");
    }

    /// <summary>
    /// Disables IPv6 DAD on the Wintun interface (DadTransmits=0); executed at most once per
    /// device instance. Uses a Get→modify→Set flow: SetIpInterfaceEntry applies the entire row
    /// to the interface, so the current values must be read back before changing a single
    /// field — otherwise the default/zero values of all remaining fields would be written
    /// along with it. Best-effort: failures are traced but do not block address configuration
    /// (semantically aligned with the PowerShell branch's "-ErrorAction SilentlyContinue").
    /// </summary>
    private void DisableIPv6Dad()
    {
        if (_ipv6DadDisabled) return;

        var row = new MIB_IPINTERFACE_ROW { Reserved = new byte[MIB_IPINTERFACE_ROW.ReservedSize] };
        row.InterfaceLuid = _adapterLuid;
        row.InterfaceIndex = _adapterIndex;
        row.Family = ADDRESS_FAMILY.AF_INET6;

        var result = GetIpInterfaceEntry(ref row);
        if (result != 0)
        {
            System.Diagnostics.Trace.WriteLine($"[Wintun] GetIpInterfaceEntry(IPv6) failed: {result}; skip DAD disable");
            return;
        }

        row.DadTransmits = 0;
        result = SetIpInterfaceEntry(ref row);
        if (result != 0)
        {
            System.Diagnostics.Trace.WriteLine($"[Wintun] SetIpInterfaceEntry(DadTransmits=0) failed: {result}");
            return;
        }

        _ipv6DadDisabled = true;
        System.Diagnostics.Trace.WriteLine("[Wintun] IPv6 DAD disabled (DadTransmits=0)");
    }

    /// <summary>
    /// Adds a route via CreateIpForwardEntry2 (IPv4/IPv6 supported); a zero-valued NextHop
    /// means the route points directly at this TUN interface.
    /// </summary>
    private void AddIpForwardEntry2(IPAddress destination, int prefixLength)
    {
        var row = new MIB_IPFORWARD_ROW2
        {
            InterfaceLuid = _adapterLuid,
            InterfaceIndex = _adapterIndex,
            DestinationPrefix = new IP_ADDRESS_PREFIX
            {
                Prefix = BuildSockaddrInet(destination),
                PrefixLength = (byte)prefixLength
            },
            NextHop = default, // 0.0.0.0 / :: — the route points directly at this TUN interface
            SitePrefixLength = 0,
            ValidLifetime = 0xffffffff,
            PreferredLifetime = 0xffffffff,
            Metric = 0,
            Protocol = 3 // MIB_IPPROTO_NET_MGMT
        };

        var result = CreateIpForwardEntry2(ref row);
        if (result != 0 && result != ERROR_OBJECT_ALREADY_EXISTS)
            throw new InvalidOperationException($"Failed to add route via native API: {result}");
    }

    /// <summary>
    /// Deletes a route via DeleteIpForwardEntry2 (matched by destination prefix + interface).
    /// </summary>
    private void DeleteIpForwardRoute2(IPAddress destination, int prefixLength)
    {
        var row = new MIB_IPFORWARD_ROW2
        {
            InterfaceLuid = _adapterLuid,
            InterfaceIndex = _adapterIndex,
            DestinationPrefix = new IP_ADDRESS_PREFIX
            {
                Prefix = BuildSockaddrInet(destination),
                PrefixLength = (byte)prefixLength
            }
        };

        var result = DeleteIpForwardEntry2(ref row);
        if (result != 0 && result != ERROR_NOT_FOUND)
            throw new InvalidOperationException($"Failed to delete route via native API: {result}");
    }

    /// <summary>
    /// Applies the MTU to the adapter's IP interface via the native SetIpInterfaceEntry API,
    /// locating the interface by the adapter LUID.
    /// </summary>
    private void SetAdapterMtu(uint ifIndex, int mtu)
    {
        var row = new MIB_IPINTERFACE_ROW { Reserved = new byte[MIB_IPINTERFACE_ROW.ReservedSize] };
        InitializeIpInterfaceEntry(ref row);
        row.InterfaceLuid = _adapterLuid;
        row.NlMtu = (uint)mtu;

        var result = SetIpInterfaceEntry(ref row);
        if (result != 0)
            throw new InvalidOperationException($"Failed to set MTU: {result}");
    }

    /// <summary>
    /// Resolves the interface index for the adapter LUID via ConvertInterfaceLuidToIndex.
    /// </summary>
    /// <exception cref="InvalidOperationException">The index could not be resolved after 30 attempts (30 × 500 ms).</exception>
    private uint GetAdapterIndexByLuid(NET_LUID luid)
    {
        uint index = 0;

        // Retry multiple times: the adapter may need time to register with the Windows network stack.
        for (int attempt = 0; attempt < 30; attempt++)
        {
            var result = ConvertInterfaceLuidToIndex(ref luid, ref index);
            if (result == 0)
            {
                return index;
            }
            
            Thread.Sleep(500);
        }
        
        throw new InvalidOperationException($"Failed to get adapter index after 30 attempts");
    }
}
