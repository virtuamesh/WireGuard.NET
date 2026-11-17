using System.Runtime.InteropServices;

namespace WireGuard.NET.Tun;

/// <summary>
/// P/Invoke / Mach system-call interop layer for <see cref="MacOSUtunDevice"/> (partial-class
/// split). Centralizes the <c>ctl_info</c>/<c>sockaddr_ctl</c> native structures and the
/// libSystem.dylib wrappers so they are kept apart from the device lifecycle logic.
/// </summary>
public partial class MacOSUtunDevice
{
    #region Native Structs

    /// <summary>
    /// Kernel control information structure, used with the CTLIOCGINFO ioctl to resolve the
    /// utun kernel control by name. Byte layout: a 4-byte kernel-assigned control id
    /// (<c>ctl_id</c>, filled in by the ioctl) followed by a 96-byte NUL-terminated
    /// control-name buffer (<c>ctl_name</c>, ByValTStr with SizeConst = 96 to match the
    /// native MAX_KCTL_NAME). The fixed-size name buffer must match the native
    /// <c>struct ctl_info</c> byte for byte, or the kernel will read a truncated name.
    /// </summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    private struct ctl_info
    {
        public uint ctl_id;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 96)]
        public string ctl_name;
    }

    /// <summary>
    /// Kernel control socket address (AF_SYSTEM + SYSPROTO_CONTROL) used to connect() to the
    /// resolved utun control. Byte layout: <c>sc_len</c> (1 byte, total structure length),
    /// <c>sc_family</c> (1 byte, AF_SYSTEM = 32), <c>sc_sysaddr</c> (2 bytes,
    /// AF_SYS_CONTROL = 2), <c>sc_id</c> (4 bytes, control id from CTLIOCGINFO),
    /// <c>sc_unit</c> (4 bytes, 0 = let the kernel assign the unit) and a 5-uint reserved
    /// tail. The sequential layout must match the native <c>struct sockaddr_ctl</c> byte for
    /// byte, or connect() will fail.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct sockaddr_ctl
    {
        public byte sc_len;
        public byte sc_family;
        public ushort sc_sysaddr;
        public uint sc_id;
        public uint sc_unit;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 5)]
        public uint[] sc_reserved;
    }

    #endregion

    #region P/Invoke (libSystem.dylib)

    /// <summary>Creates a kernel control socket (AF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL).</summary>
    /// <param name="domain">Address family (AF_SYSTEM).</param>
    /// <param name="type">Socket type (SOCK_DGRAM).</param>
    /// <param name="protocol">Protocol (SYSPROTO_CONTROL).</param>
    /// <returns>The socket file descriptor, or -1 on error.</returns>
    [DllImport("libSystem.dylib", SetLastError = true)]
    private static extern int socket(int domain, int type, int protocol);

    /// <summary>Closes a file descriptor.</summary>
    /// <param name="fd">The file descriptor to close.</param>
    /// <returns>0 on success, or -1 on error.</returns>
    [DllImport("libSystem.dylib", SetLastError = true)]
    private static extern int close(int fd);

    /// <summary>
    /// Resolves the utun kernel control id for <paramref name="info"/> via the CTLIOCGINFO
    /// ioctl: pass the control name ("com.apple.net.utun_control") in and receive the
    /// kernel-assigned id back in <c>ctl_id</c>.
    /// </summary>
    /// <param name="fd">The kernel control socket.</param>
    /// <param name="request">The ioctl request code (CTLIOCGINFO).</param>
    /// <param name="info">The control info structure (modified in place by the kernel).</param>
    /// <returns>0 on success, or -1 on error.</returns>
    [DllImport("libSystem.dylib", SetLastError = true)]
    private static extern int ioctl(int fd, uint request, ref ctl_info info);

    /// <summary>Connects the control socket to the utun kernel control via its sockaddr_ctl address.</summary>
    /// <param name="fd">The kernel control socket.</param>
    /// <param name="addr">The resolved control address.</param>
    /// <param name="addrlen">Size of the address structure in bytes.</param>
    /// <returns>0 on success, or -1 on error.</returns>
    [DllImport("libSystem.dylib", SetLastError = true)]
    private static extern int connect(int fd, ref sockaddr_ctl addr, int addrlen);

    /// <summary>Reads a socket option (used to retrieve the actual utun interface name).</summary>
    /// <param name="fd">The utun file descriptor.</param>
    /// <param name="level">Option level.</param>
    /// <param name="optname">Option name.</param>
    /// <param name="optval">Buffer receiving the option value.</param>
    /// <param name="optlen">On input the buffer size; on output the written length.</param>
    /// <returns>0 on success, or -1 on error.</returns>
    [DllImport("libSystem.dylib", SetLastError = true)]
    private static extern int getsockopt(int fd, int level, int optname, byte[] optval, ref int optlen);

    /// <summary>Sets a socket option (used to set SO_NOSIGPIPE on the utun descriptor).</summary>
    /// <param name="fd">The utun file descriptor.</param>
    /// <param name="level">Option level (SOL_SOCKET).</param>
    /// <param name="optname">Option name (SO_NOSIGPIPE).</param>
    /// <param name="optval">Option value bytes.</param>
    /// <param name="optlen">Length of the option value bytes.</param>
    /// <returns>0 on success, or -1 on error.</returns>
    [DllImport("libSystem.dylib", SetLastError = true)]
    private static extern int setsockopt(int fd, int level, int optname, byte[] optval, int optlen);

    /// <summary>Reads up to <paramref name="count"/> bytes from the utun file descriptor into <paramref name="buf"/>.</summary>
    /// <param name="fd">The utun file descriptor.</param>
    /// <param name="buf">Buffer receiving the packet (4-byte family header + IP packet).</param>
    /// <param name="count">Buffer size in bytes.</param>
    /// <returns>Number of bytes read, 0 on EOF, or -1 on error.</returns>
    [DllImport("libSystem.dylib", SetLastError = true)]
    private static extern IntPtr read(int fd, byte[] buf, IntPtr count);

    /// <summary>Writes up to <paramref name="count"/> bytes from <paramref name="buf"/> to the utun file descriptor.</summary>
    /// <param name="fd">The utun file descriptor.</param>
    /// <param name="buf">Buffer containing the packet (4-byte family header + IP packet).</param>
    /// <param name="count">Number of bytes to write.</param>
    /// <returns>Number of bytes written, or -1 on error.</returns>
    [DllImport("libSystem.dylib", SetLastError = true)]
    private static extern IntPtr write(int fd, byte[] buf, IntPtr count);

    /// <summary>
    /// Polls the utun file descriptor for readiness with a millisecond timeout; drives the
    /// ReadPacketAsync loop so it can wake up for cancellation.
    /// </summary>
    /// <param name="fds">Poll descriptor structure (single element in this usage).</param>
    /// <param name="nfds">Number of poll descriptors.</param>
    /// <param name="timeout">Timeout in milliseconds.</param>
    /// <returns>Number of ready descriptors, 0 on timeout, or -1 on error.</returns>
    [DllImport("libSystem.dylib", SetLastError = true)]
    private static extern int poll(ref PollFd fds, uint nfds, int timeout);

    /// <summary>Manipulates file-descriptor flags (e.g. O_NONBLOCK via F_SETFL).</summary>
    /// <param name="fd">The file descriptor.</param>
    /// <param name="cmd">The fcntl command.</param>
    /// <param name="arg">Command argument.</param>
    /// <returns>Command-dependent result, or -1 on error.</returns>
    [DllImport("libSystem.dylib", SetLastError = true)]
    private static extern int fcntl(int fd, int cmd, int arg);

    #endregion
}
