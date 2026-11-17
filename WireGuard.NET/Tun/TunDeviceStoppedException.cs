namespace WireGuard.NET.Tun;

/// <summary>
/// Thrown when a TUN device is stopped or becomes invalid while in use (the adapter was
/// disabled, its handle became invalid, etc.).
/// This dedicated type replaces the fragile practice of detecting this condition by matching
/// the "Device stopped" substring in exception messages.
/// </summary>
public class TunDeviceStoppedException : OperationCanceledException
{
    /// <summary>
    /// Initializes a new instance of the <see cref="TunDeviceStoppedException"/> class
    /// with the specified error message.
    /// </summary>
    /// <param name="message">The message describing why the device stopped.</param>
    public TunDeviceStoppedException(string message) : base(message)
    {
    }
}
