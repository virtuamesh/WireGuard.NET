using System.Runtime.InteropServices;

namespace WireGuard.NET.Tun;

/// <summary>
/// Creates the platform-appropriate <see cref="ITunDevice"/> implementation:
/// <see cref="WindowsWintunDevice"/> (wintun.dll ring buffer) on Windows,
/// <see cref="LinuxTunDevice"/> (/dev/net/tun ioctls) on Linux, and
/// <see cref="MacOSUtunDevice"/> (utun kernel control socket) on macOS — or a
/// <see cref="MockTunDevice"/> when requested for testing.
/// </summary>
public static class TunDeviceFactory
{
    /// <summary>
    /// Creates a TUN device for the current operating system.
    /// </summary>
    /// <param name="name">The requested interface name (ignored by <see cref="MockTunDevice"/>).</param>
    /// <param name="useMock">When true, returns a <see cref="MockTunDevice"/> regardless of platform.</param>
    /// <param name="mtu">The interface MTU (ignored by <see cref="WindowsWintunDevice"/>, which is fixed at 1420).</param>
    /// <returns>A new, not-yet-started TUN device.</returns>
    /// <exception cref="PlatformNotSupportedException">The operating system has no TUN implementation.</exception>
    public static ITunDevice Create(string name, bool useMock = false, int mtu = 1420)
    {
        if (useMock)
            return new MockTunDevice();

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return new WindowsWintunDevice(name);
        }

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            return new LinuxTunDevice(name, mtu);
        }

        if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            return new MacOSUtunDevice(name, mtu);
        }

        throw new PlatformNotSupportedException($"Unknown platform: {RuntimeInformation.OSDescription}");
    }

    /// <summary>
    /// Indicates whether the current operating system has a real TUN implementation
    /// (Windows, Linux or macOS).
    /// </summary>
    /// <returns>true when <see cref="Create"/> can create a real (non-mock) device on this platform.</returns>
    public static bool IsPlatformSupported()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return true;
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            return true;
        if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            return true;

        return false;
    }
}
