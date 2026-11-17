using System.Net;
using System.Runtime.InteropServices;
using System.Text;

namespace WireGuard.NET.Tun;

/// <summary>
/// P/Invoke / Win32 interop layer for <see cref="WindowsWintunDevice"/> (partial-class split).
/// Centralizes the native delegates, structures, Win32 constants and iphlpapi wrappers so they
/// are kept apart from the device lifecycle logic.
/// </summary>
public partial class WindowsWintunDevice
{
    #region Win32 Error / Wintun Constants

    private const int ERROR_BUFFER_OVERFLOW = 111;
    private const int ERROR_NO_MORE_ITEMS = 259;
    private const int ERROR_HANDLE_EOF = 38;
    private const int ERROR_OBJECT_ALREADY_EXISTS = 5010;
    private const int ERROR_NOT_FOUND = 1168;
    private const int WAIT_OBJECT_0 = 0;
    private const int WAIT_TIMEOUT = 258;
    private const uint WINTUN_MIN_RING_CAPACITY = 0x20000;
    private const uint WINTUN_MAX_RING_CAPACITY = 0x4000000;
    private const uint WINTUN_MAX_IP_PACKET_SIZE = 0xFFFF;
    private const int MAX_ADAPTER_NAME = 128;

    /// <summary>
    /// Log levels emitted by the Wintun driver logger callback.
    /// </summary>
    public enum WintunLogLevel
    {
        /// <summary>Informational message.</summary>
        Info,
        /// <summary>Warning message.</summary>
        Warn,
        /// <summary>Error message.</summary>
        Err
    }

    #endregion

    #region Native Structs / Enums

    /// <summary>
    /// Windows network interface LUID — a 64-bit locally unique identifier for a network
    /// adapter, stable across reboots (unlike the interface index).
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct NET_LUID
    {
        /// <summary>The 64-bit locally unique identifier value.</summary>
        public ulong Value;
    }

    // Critical fix: SOCKADDR_INET must match the union layout in Win32 netioapi.h byte for
    // byte (total length 28 bytes).
    // The old implementation used a union of nested managed structs whose field order did not
    // match the native layout (Address was not first), so CreateUnicastIpAddressEntry read the
    // wrong family field — the root cause of this API path never having worked before.
    // The struct is now explicit-layout: the IPv4 address sits at offset 4, the IPv6 address at
    // offsets 8-23, exactly aligned with the native union.
    // Address bytes are written to memory in network order (big-endian) using the trick of
    // re-parsing them with BitConverter on little-endian machines.
    // Note: all fields are uint, not ulong — a ulong field would raise the marshaling alignment
    // to 8 bytes, padding this struct inside its parent MIB_IPFORWARD_ROW2.DestinationPrefix
    // (native offset 12) out to offset 16 and shifting all subsequent fields, making
    // CreateIpForwardEntry2 fail with error 87 (ERROR_INVALID_PARAMETER).
    /// <summary>
    /// IPv4 / IPv6 union sockaddr container (28 bytes, exactly matching netioapi.h). The
    /// explicit offsets matter because the native type is a union: the family field lives at
    /// offset 0, the IPv4 address overlays the flow-info word at offset 4, and the 16-byte
    /// IPv6 address spans offsets 8-23.
    /// </summary>
    [StructLayout(LayoutKind.Explicit, Size = 28)]
    private struct SOCKADDR_INET
    {
        [FieldOffset(0)]
        public ADDRESS_FAMILY si_family;
        [FieldOffset(2)]
        public ushort sin_port;         // must always be 0 (address/route entries carry no port semantics)
        [FieldOffset(4)]
        public uint sin_addr;           // IPv4: raw bytes stored in network order
        [FieldOffset(4)]
        public uint sin6_flowinfo;
        [FieldOffset(8)]
        public uint sin6_addr_w0;       // IPv6 address in 4-byte groups, network order
        [FieldOffset(12)]
        public uint sin6_addr_w1;
        [FieldOffset(16)]
        public uint sin6_addr_w2;
        [FieldOffset(20)]
        public uint sin6_addr_w3;
        [FieldOffset(24)]
        public uint sin6_scope_id;
    }

    /// <summary>
    /// MIB_UNICASTIPADDRESS_ROW (netioapi.h). Field order matters: Address comes first,
    /// strictly matching the native structure; the interface is located by LUID or by Index
    /// (whichever one is not used must be set to 0). Initialize with
    /// InitializeUnicastIpAddressEntry before filling in the fields.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_UNICASTIPADDRESS_ROW
    {
        public SOCKADDR_INET Address;
        public NET_LUID InterfaceLuid;
        public uint InterfaceIndex;
        public IP_PREFIX_ORIGIN PrefixOrigin;
        public IP_SUFFIX_ORIGIN SuffixOrigin;
        public IP_DAD_STATE DadState;
        public uint ValidLifetime;
        public uint PreferredLifetime;
        public uint LeaseLifetime;
        public byte OnLinkPrefixLength;
        public byte SkipAsSource;
        public long CreationTimeStamp;
    }

    /// <summary>
    /// IP_ADDRESS_PREFIX (netioapi.h): the actual type of MIB_IPFORWARD_ROW2.DestinationPrefix,
    /// = SOCKADDR_INET + 1 byte of prefix length. Using a bare sockaddr here would be one byte
    /// short and shift all subsequent fields, making CreateIpForwardEntry2 fail with error 87
    /// (ERROR_INVALID_PARAMETER).
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct IP_ADDRESS_PREFIX
    {
        public SOCKADDR_INET Prefix;
        public byte PrefixLength;
    }

    /// <summary>
    /// MIB_IPFORWARD_ROW2 (netioapi.h): the modern route-table row, supporting IPv6 and CIDR
    /// prefixes; manipulated via CreateIpForwardEntry2 / DeleteIpForwardEntry2, replacing the
    /// old MIB_IPFORWARDROW. The sequential layout must match the native structure exactly —
    /// DestinationPrefix (at native offset 12) embeds IP_ADDRESS_PREFIX, so any padding or
    /// misalignment in the preceding fields shifts every field after it.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_IPFORWARD_ROW2
    {
        public NET_LUID InterfaceLuid;
        public uint InterfaceIndex;
        public IP_ADDRESS_PREFIX DestinationPrefix;
        public SOCKADDR_INET NextHop;
        public uint SitePrefixLength;
        public uint ValidLifetime;
        public uint PreferredLifetime;
        public uint Metric;
        public int Protocol;    // NL_ROUTE_PROTOCOL: MIB_IPPROTO_NET_MGMT = 3
        public uint Flags;      // Loopback/AutoconfigureStatus/Publish/Immortal bitfield union; all-zero means "no"
        public uint Age;
        public int Origin;      // NL_ROUTE_ORIGIN
    }

    /// <summary>
    /// MIB_IPINTERFACE_ROW (netioapi.h, Vista+): per-IP-interface parameter row. The leading
    /// fields (up to RouterDiscoveryBehavior) have had an ABI-stable layout since Vista and are
    /// declared field by field; the remaining fields (boolean bitfields, timeouts,
    /// ZoneIndices[16], etc.) are only filled in by GetIpInterfaceEntry and written back
    /// verbatim by SetIpInterfaceEntry, so they are not declared individually — a fixed-size
    /// reserved tail covers them. The reserved area is deliberately larger than the native
    /// structure on any known OS version (about 200 bytes on Win10/11): too small and native
    /// would write out of bounds into the marshaling buffer; the extra bytes when oversized are
    /// never read by native, which is safe.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_IPINTERFACE_ROW
    {
        public const int ReservedSize = 256;

        public NET_LUID InterfaceLuid;          // offset 0
        public uint InterfaceIndex;             // offset 8
        public ADDRESS_FAMILY Family;           // offset 12 (ushort)
        public uint NlMtu;                      // offset 16
        public uint InterfaceType;              // offset 20
        public uint ZoneIndex;                  // offset 24
        public byte InterfaceOffloadRod;        // offset 28 (NL_INTERFACE_OFFLOAD_ROD bitfield union)
        public uint DadTransmits;               // offset 32: number of DAD probes; 0 = DAD disabled
        public uint RouterDiscoveryBehavior;    // offset 36
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = ReservedSize)]
        public byte[] Reserved;                 // tail starting at offset 40; filled by Get, written back verbatim by Set
    }

    /// <summary>Windows ADDRESS_FAMILY values (winsock2.h) used by the iphlpapi structures.</summary>
    private enum ADDRESS_FAMILY : ushort
    {
        AF_UNSPEC = 0,
        AF_INET = 2,
        AF_INET6 = 23
    }

    /// <summary>NL_PREFIX_ORIGIN (netioapi.h): how the address prefix was obtained.</summary>
    private enum IP_PREFIX_ORIGIN
    {
        IpPrefixOriginOther = 0,
        IpPrefixOriginManual,
        IpPrefixOriginWellKnown,
        IpPrefixOriginDhcp,
        IpPrefixOriginRouterAdvertisement
    }

    /// <summary>NL_SUFFIX_ORIGIN (netioapi.h): how the address suffix was obtained.</summary>
    private enum IP_SUFFIX_ORIGIN
    {
        IpSuffixOriginOther = 0,
        IpSuffixOriginManual,
        IpSuffixOriginWellKnown,
        IpSuffixOriginDhcp,
        IpSuffixOriginLinkLayerAddress,
        IpSuffixOriginRandom
    }

    /// <summary>NL_DAD_STATE (netioapi.h): duplicate-address-detection state of an address.</summary>
    private enum IP_DAD_STATE
    {
        IpDadStateInvalid = 0,
        IpDadStateTentative,
        IpDadStateDuplicate,
        IpDadStateDeprecated,
        IpDadStatePreferred
    }

    #endregion

    #region Delegates

    /// <summary>
    /// WintunEnumAdapters callback: invoked once per existing adapter; return false to stop
    /// the enumeration.
    /// </summary>
    private delegate bool WINTUN_ENUM_CALLBACK(IntPtr adapter, IntPtr param);

    /// <summary>
    /// WintunSetLogger callback: receives one driver log line (level, 64-bit timestamp in
    /// 100-nanosecond units since 1601-01-01, UTF-16 message).
    /// </summary>
    private delegate void WINTUN_LOGGER_CALLBACK(WintunLogLevel level, long timestamp, [MarshalAs(UnmanagedType.LPWStr)] string message);

    /// <summary>
    /// WintunCreateAdapter: creates a new adapter (optionally under a stable GUID, or random
    /// when IntPtr.Zero) and returns its handle.
    /// </summary>
    private delegate IntPtr WintunCreateAdapterDelegate(
        [MarshalAs(UnmanagedType.LPWStr)] string name,
        [MarshalAs(UnmanagedType.LPWStr)] string tunnelType,
        IntPtr requestedGuid);

    /// <summary>WintunOpenAdapter: opens an existing adapter by name and returns its handle.</summary>
    private delegate IntPtr WintunOpenAdapterDelegate([MarshalAs(UnmanagedType.LPWStr)] string name);

    /// <summary>
    /// WintunCloseAdapter: releases an adapter handle obtained from
    /// WintunCreateAdapter/WintunOpenAdapter.
    /// </summary>
    private delegate void WintunCloseAdapterDelegate(IntPtr adapter);

    /// <summary>WintunGetAdapterLUID: retrieves the adapter's interface LUID.</summary>
    private delegate void WintunGetAdapterLuidDelegate(IntPtr adapter, out ulong luid);

    /// <summary>
    /// WintunStartSession: starts a ring-buffer session on the adapter with the given ring
    /// capacity in bytes (power of two, between WINTUN_MIN_RING_CAPACITY and
    /// WINTUN_MAX_RING_CAPACITY).
    /// </summary>
    private delegate IntPtr WintunStartSessionDelegate(IntPtr adapter, uint capacity);

    /// <summary>WintunEndSession: ends a session and frees its ring buffers.</summary>
    private delegate void WintunEndSessionDelegate(IntPtr session);

    /// <summary>
    /// WintunGetReadWaitEvent: returns the auto-reset event that is signaled whenever receive
    /// packets become available; the read loop waits on it.
    /// </summary>
    private delegate IntPtr WintunGetReadWaitEventDelegate(IntPtr session);

    /// <summary>
    /// WintunReceivePacket: dequeues the next received packet; returns a pointer directly
    /// into the ring (not a copy) and its size — the caller must copy it out and then release
    /// it with WintunReleaseReceivePacket.
    /// </summary>
    private delegate IntPtr WintunReceivePacketDelegate(IntPtr session, out uint packetSize);

    /// <summary>
    /// WintunReleaseReceivePacket: marks a previously received packet as consumed so its ring
    /// slot can be reused.
    /// </summary>
    private delegate void WintunReleaseReceivePacketDelegate(IntPtr session, IntPtr packet);

    /// <summary>
    /// WintunAllocateSendPacket: reserves a slot in the send ring for a packet of the given
    /// size and returns a pointer to copy the packet bytes into.
    /// </summary>
    private delegate IntPtr WintunAllocateSendPacketDelegate(IntPtr session, uint packetSize);

    /// <summary>
    /// WintunSendPacket: commits a packet filled via WintunAllocateSendPacket to the send
    /// ring for transmission.
    /// </summary>
    private delegate void WintunSendPacketDelegate(IntPtr session, IntPtr packet);

    /// <summary>WintunSetLogger: installs (or, with null, removes) the driver logger callback.</summary>
    private delegate void WintunSetLoggerDelegate(WINTUN_LOGGER_CALLBACK? logger);

    /// <summary>WintunGetRunningDriverVersion: returns the running driver version, or 0 on failure.</summary>
    private delegate uint WintunGetRunningDriverVersionDelegate();

    /// <summary>WintunDeleteDriver: uninstalls the driver when no adapters remain.</summary>
    private delegate bool WintunDeleteDriverDelegate();

    /// <summary>WintunEnumAdapters: enumerates existing adapters through the given callback.</summary>
    private delegate bool WintunEnumAdaptersDelegate(WINTUN_ENUM_CALLBACK callback, IntPtr param);

    /// <summary>WintunGetAdapterName: writes the adapter's name into the given buffer.</summary>
    private delegate bool GetAdapterNameDelegate(IntPtr adapter, StringBuilder nameBuffer, int bufferSize);

    #endregion

    #region Wintun Function Wrappers

    /// <summary>Invokes the WintunCreateAdapter export; returns IntPtr.Zero when the export is unavailable.</summary>
    private IntPtr WintunCreateAdapter(string name, string tunnelType, IntPtr requestedGuid)
    {
        if (_wintunCreateAdapter == IntPtr.Zero)
            return IntPtr.Zero;

        var func = Marshal.GetDelegateForFunctionPointer<WintunCreateAdapterDelegate>(_wintunCreateAdapter);
        return func(name, tunnelType, requestedGuid);
    }

    /// <summary>Invokes the WintunOpenAdapter export; returns IntPtr.Zero when the export is unavailable.</summary>
    private IntPtr WintunOpenAdapter(string name)
    {
        if (_wintunOpenAdapter == IntPtr.Zero)
            return IntPtr.Zero;

        var func = Marshal.GetDelegateForFunctionPointer<WintunOpenAdapterDelegate>(_wintunOpenAdapter);
        return func(name);
    }

    /// <summary>Invokes the WintunCloseAdapter export (no-op when unavailable).</summary>
    private void WintunCloseAdapter(IntPtr adapter)
    {
        if (_wintunCloseAdapter == IntPtr.Zero)
            return;

        var func = Marshal.GetDelegateForFunctionPointer<WintunCloseAdapterDelegate>(_wintunCloseAdapter);
        func(adapter);
    }

    /// <summary>
    /// Invokes the WintunGetAdapterLUID export; fills <paramref name="luid"/> with the
    /// adapter's interface LUID (left unchanged when the export is unavailable).
    /// </summary>
    private void WintunGetAdapterLuid(IntPtr adapter, ref NET_LUID luid)
    {
        if (_wintunGetAdapterLuid == IntPtr.Zero)
        {
            return;
        }

        var func = Marshal.GetDelegateForFunctionPointer<WintunGetAdapterLuidDelegate>(_wintunGetAdapterLuid);
        func(adapter, out ulong luidValue);
        luid = new NET_LUID { Value = luidValue };
    }

    /// <summary>Invokes the WintunStartSession export; returns IntPtr.Zero when the export is unavailable.</summary>
    private IntPtr WintunStartSession(IntPtr adapter, uint capacity)
    {
        if (_wintunStartSession == IntPtr.Zero)
            return IntPtr.Zero;

        var func = Marshal.GetDelegateForFunctionPointer<WintunStartSessionDelegate>(_wintunStartSession);
        return func(adapter, capacity);
    }

    /// <summary>Invokes the WintunEndSession export (no-op when unavailable).</summary>
    private void WintunEndSession(IntPtr session)
    {
        if (_wintunEndSession == IntPtr.Zero)
            return;

        var func = Marshal.GetDelegateForFunctionPointer<WintunEndSessionDelegate>(_wintunEndSession);
        func(session);
    }

    /// <summary>Invokes the WintunGetReadWaitEvent export; returns IntPtr.Zero when the export is unavailable.</summary>
    private IntPtr WintunGetReadWaitEvent(IntPtr session)
    {
        if (_wintunGetReadWaitEvent == IntPtr.Zero)
            return IntPtr.Zero;

        var func = Marshal.GetDelegateForFunctionPointer<WintunGetReadWaitEventDelegate>(_wintunGetReadWaitEvent);
        return func(session);
    }

    /// <summary>
    /// Invokes the WintunReceivePacket export; returns IntPtr.Zero (with packetSize 0) when no
    /// packet is available or the export is unavailable.
    /// </summary>
    private IntPtr WintunReceivePacket(IntPtr session, out uint packetSize)
    {
        packetSize = 0;
        if (_wintunReceivePacket == IntPtr.Zero)
            return IntPtr.Zero;

        var func = Marshal.GetDelegateForFunctionPointer<WintunReceivePacketDelegate>(_wintunReceivePacket);
        return func(session, out packetSize);
    }

    /// <summary>Invokes the WintunReleaseReceivePacket export (no-op when unavailable).</summary>
    private void WintunReleaseReceivePacket(IntPtr session, IntPtr packet)
    {
        if (_wintunReleaseReceivePacket == IntPtr.Zero)
            return;

        var func = Marshal.GetDelegateForFunctionPointer<WintunReleaseReceivePacketDelegate>(_wintunReleaseReceivePacket);
        func(session, packet);
    }

    /// <summary>
    /// Invokes the WintunAllocateSendPacket export; returns IntPtr.Zero when the send ring is
    /// full or the export is unavailable.
    /// </summary>
    private IntPtr WintunAllocateSendPacket(IntPtr session, uint packetSize)
    {
        if (_wintunAllocateSendPacket == IntPtr.Zero)
            return IntPtr.Zero;

        var func = Marshal.GetDelegateForFunctionPointer<WintunAllocateSendPacketDelegate>(_wintunAllocateSendPacket);
        return func(session, packetSize);
    }

    /// <summary>Invokes the WintunSendPacket export (no-op when unavailable).</summary>
    private void WintunSendPacket(IntPtr session, IntPtr packet)
    {
        if (_wintunSendPacket == IntPtr.Zero)
            return;

        var func = Marshal.GetDelegateForFunctionPointer<WintunSendPacketDelegate>(_wintunSendPacket);
        func(session, packet);
    }

    /// <summary>Invokes the WintunSetLogger export (no-op when unavailable).</summary>
    private void WintunSetLogger(WINTUN_LOGGER_CALLBACK? logger)
    {
        if (_wintunSetLogger == IntPtr.Zero)
            return;

        var func = Marshal.GetDelegateForFunctionPointer<WintunSetLoggerDelegate>(_wintunSetLogger);
        func(logger);
    }

    /// <summary>Invokes the WintunGetRunningDriverVersion export; returns 0 when unavailable.</summary>
    private uint WintunGetRunningDriverVersion()
    {
        if (_wintunGetRunningDriverVersion == IntPtr.Zero)
            return 0;

        var func = Marshal.GetDelegateForFunctionPointer<WintunGetRunningDriverVersionDelegate>(_wintunGetRunningDriverVersion);
        return func();
    }

    /// <summary>Stub: always returns false — driver removal is not implemented (the export is never invoked).</summary>
    private static bool WintunDeleteDriver()
    {
        return false;
    }

    /// <summary>
    /// Stub: always returns false — adapter enumeration is not implemented (the export is
    /// never invoked); callers therefore see an empty enumeration.
    /// </summary>
    private static bool WintunEnumAdapters(WINTUN_ENUM_CALLBACK callback, IntPtr param)
    {
        return false;
    }

    /// <summary>Stub: always returns false — adapter-name retrieval is not implemented (the export is never invoked).</summary>
    private static bool GetAdapterName(IntPtr adapter, StringBuilder nameBuffer, int bufferSize)
    {
        return false;
    }

    #endregion

    #region P/Invoke

    /// <summary>Loads wintun.dll (or another module) into the process; returns IntPtr.Zero on failure.</summary>
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr LoadLibrary(string lpFileName);

    /// <summary>Unloads a module loaded by LoadLibrary.</summary>
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool FreeLibrary(IntPtr hLibModule);

    /// <summary>Resolves an exported function pointer by (ANSI) name; returns IntPtr.Zero when not found.</summary>
    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    /// <summary>
    /// Initializes an MIB_UNICASTIPADDRESS_ROW with default values; required before filling in
    /// the address/interface fields and calling CreateUnicastIpAddressEntry.
    /// </summary>
    [DllImport("iphlpapi.dll")]
    private static extern void InitializeUnicastIpAddressEntry(ref MIB_UNICASTIPADDRESS_ROW row);

    /// <summary>
    /// Creates the unicast IP address entry on the interface identified by the row's
    /// LUID/index. Returns NO_ERROR (0) on success, ERROR_OBJECT_ALREADY_EXISTS (5010) when
    /// the address is already present, or another Win32 error code.
    /// </summary>
    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint CreateUnicastIpAddressEntry(ref MIB_UNICASTIPADDRESS_ROW row);

    // The MIB_IPFORWARD_ROW2 family needs no Initialize call (callers assign fields themselves),
    // hence InitializeIpForwardEntry is intentionally not imported.
    /// <summary>
    /// Adds the route row to the routing table. Returns NO_ERROR (0) on success, or a Win32
    /// error code (e.g. 87 ERROR_INVALID_PARAMETER on layout/field problems, 1168
    /// ERROR_NOT_FOUND when the interface does not exist).
    /// </summary>
    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint CreateIpForwardEntry2(ref MIB_IPFORWARD_ROW2 row);

    /// <summary>
    /// Deletes the route row (matched by destination prefix + interface) from the routing
    /// table.
    /// </summary>
    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint DeleteIpForwardEntry2(ref MIB_IPFORWARD_ROW2 row);

    /// <summary>
    /// Initializes an MIB_IPINTERFACE_ROW for the given address family; required before
    /// GetIpInterfaceEntry.
    /// </summary>
    [DllImport("iphlpapi.dll")]
    private static extern void InitializeIpInterfaceEntry(ref MIB_IPINTERFACE_ROW row);

    /// <summary>
    /// Fetches the current per-interface IP parameters into the row (located by
    /// LUID/index + family).
    /// </summary>
    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetIpInterfaceEntry(ref MIB_IPINTERFACE_ROW row);

    /// <summary>
    /// Writes the row back to the interface. The entire row is applied, so the row must come
    /// from GetIpInterfaceEntry with only the intended fields modified.
    /// </summary>
    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint SetIpInterfaceEntry(ref MIB_IPINTERFACE_ROW row);

    /// <summary>Converts an interface LUID into the current interface index.</summary>
    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint ConvertInterfaceLuidToIndex(ref NET_LUID luid, ref uint index);

    /// <summary>
    /// Waits until the given handle is signaled or the timeout (INFINITE = 0xFFFFFFFF)
    /// elapses; used by the read loop on the Wintun read-wait event.
    /// </summary>
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    #endregion
}
