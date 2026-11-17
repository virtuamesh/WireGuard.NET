namespace WireGuard.NET.Protocol.Noise;

/// <summary>
/// AEAD authentication of a Noise message failed: the remote public key candidate did not
/// match, or the message was tampered with in transit.
/// This dedicated type replaces the fragile practice of detecting this condition by matching
/// the "Authentication tag" substring in exception messages.
/// </summary>
public class NoiseAuthenticationException : System.Security.Cryptography.CryptographicException
{
    /// <summary>
    /// Initializes a new instance of the <see cref="NoiseAuthenticationException"/> class
    /// with the specified error message.
    /// </summary>
    /// <param name="message">The message describing the authentication failure.</param>
    public NoiseAuthenticationException(string message) : base(message)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="NoiseAuthenticationException"/> class
    /// with the specified error message and inner exception.
    /// </summary>
    /// <param name="message">The message describing the authentication failure.</param>
    /// <param name="innerException">The underlying AEAD exception (e.g. thrown by ChaCha20-Poly1305).</param>
    public NoiseAuthenticationException(string message, Exception innerException) : base(message, innerException)
    {
    }
}
