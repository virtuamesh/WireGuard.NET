namespace WireGuard.NET.Protocol.Noise;

/// <summary>
/// The handshake state has already been consumed: all message patterns have been read or
/// written, typically because a handshake response was processed twice.
/// This dedicated type replaces the fragile practice of detecting this condition by matching
/// the "No more message patterns" substring in exception messages.
/// </summary>
public class NoiseHandshakeConsumedException : InvalidOperationException
{
    /// <summary>
    /// Initializes a new instance of the <see cref="NoiseHandshakeConsumedException"/> class
    /// with the specified error message.
    /// </summary>
    /// <param name="message">The message describing the consumed handshake state.</param>
    public NoiseHandshakeConsumedException(string message) : base(message)
    {
    }
}
