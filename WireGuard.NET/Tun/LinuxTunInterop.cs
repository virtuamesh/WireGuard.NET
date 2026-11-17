using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace WireGuard.NET.Tun;

/// <summary>
/// P/Invoke / libc interop layer for <see cref="LinuxTunDevice"/> (partial-class split).
/// Centralizes the <c>IfReq</c>/<c>PollFd</c> native structures and the libc wrappers so they
/// are kept apart from the device lifecycle logic.
/// </summary>
public partial class LinuxTunDevice
{
    #region Native Structs

    /// <summary>
    /// Generic network interface request structure, shared by the TUNSETIFF and SIOCSIF* ioctls.
    /// Byte layout: a 16-byte NUL-terminated interface-name buffer (<c>ifrn_name</c>,
    /// ByValTStr with SizeConst = 16 to match the kernel's IFNAMSIZ) followed by the
    /// ioctl-specific union value carried in <c>ifru_flags</c>. The sequential layout and the
    /// fixed-size name buffer must match the native <c>struct ifreq</c> byte for byte, or the
    /// kernel will read a corrupted interface name or flags.
    /// </summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    private struct IfReq
    {
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 16)]
        public string ifrn_name;

        public IntPtr ifru_flags;
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

    #endregion

    #region P/Invoke (libc)

    /// <summary>Opens the TUN device node (/dev/net/tun) with the given file flags (O_RDWR).</summary>
    /// <param name="pathname">Device node path.</param>
    /// <param name="flags">Open flags (O_RDWR).</param>
    /// <returns>The file descriptor, or -1 on error (errno via Marshal.GetLastWin32Error).</returns>
    [DllImport("libc", SetLastError = true)]
    private static extern int open(string pathname, int flags);

    /// <summary>Closes a file descriptor.</summary>
    /// <param name="fd">The file descriptor to close.</param>
    /// <returns>0 on success, or -1 on error.</returns>
    [DllImport("libc", SetLastError = true)]
    private static extern int close(int fd);

    /// <summary>
    /// Performs an interface-request ioctl (TUNSETIFF to attach the fd to a TUN interface,
    /// SIOCSIFFLAGS to bring it up) with an <see cref="IfReq"/> payload.
    /// </summary>
    /// <param name="fd">The TUN or socket file descriptor.</param>
    /// <param name="request">The ioctl request code.</param>
    /// <param name="ifreq">The interface request structure (modified in place by the kernel).</param>
    /// <returns>0 on success, or -1 on error.</returns>
    [DllImport("libc", SetLastError = true)]
    private static extern int ioctl(int fd, int request, ref IfReq ifreq);

    /// <summary>Performs an ioctl with a raw pointer payload.</summary>
    /// <param name="fd">The file descriptor.</param>
    /// <param name="request">The ioctl request code.</param>
    /// <param name="ifreq">Raw pointer to the request payload.</param>
    /// <returns>0 on success, or -1 on error.</returns>
    [DllImport("libc", SetLastError = true)]
    private static extern int ioctl(int fd, int request, IntPtr ifreq);

    /// <summary>Creates a socket, used by the SIOCSIFFLAGS fallback path in BringInterfaceUp.</summary>
    /// <param name="domain">Address family (AF_INET).</param>
    /// <param name="type">Socket type (SOCK_DGRAM).</param>
    /// <param name="protocol">Protocol (IPPROTO_IP).</param>
    /// <returns>The socket file descriptor, or -1 on error.</returns>
    [DllImport("libc", SetLastError = true)]
    private static extern int socket(AddressFamily domain, SocketType type, ProtocolType protocol);

    /// <summary>Writes up to <paramref name="count"/> bytes from <paramref name="buf"/> to the TUN file descriptor.</summary>
    /// <param name="fd">The TUN file descriptor.</param>
    /// <param name="buf">Packet buffer to write.</param>
    /// <param name="count">Number of bytes to write.</param>
    /// <returns>Number of bytes written, or -1 on error.</returns>
    [DllImport("libc", SetLastError = true)]
    private static extern IntPtr write(int fd, byte[] buf, IntPtr count);

    /// <summary>Reads up to <paramref name="count"/> bytes from the TUN file descriptor into <paramref name="buf"/>.</summary>
    /// <param name="fd">The TUN file descriptor.</param>
    /// <param name="buf">Buffer receiving the packet.</param>
    /// <param name="count">Buffer size in bytes.</param>
    /// <returns>Number of bytes read, 0 on EOF, or -1 on error.</returns>
    [DllImport("libc", SetLastError = true)]
    private static extern IntPtr read(int fd, byte[] buf, IntPtr count);

    /// <summary>
    /// Polls the TUN file descriptor for readability with a millisecond timeout; drives the
    /// ReadPacketAsync loop so it can wake up for cancellation and error conditions.
    /// </summary>
    /// <param name="fds">Poll descriptor array (single element in this usage).</param>
    /// <param name="nfds">Number of poll descriptors.</param>
    /// <param name="timeout">Timeout in milliseconds.</param>
    /// <returns>Number of ready descriptors, 0 on timeout, or -1 on error.</returns>
    [DllImport("libc", SetLastError = true)]
    private static extern int poll(ref PollFd fds, uint nfds, int timeout);

    #endregion
}
