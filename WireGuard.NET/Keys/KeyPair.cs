using System.Security.Cryptography;
using WireGuard.NET.Crypto;

namespace WireGuard.NET.Keys;

/// <summary>
/// Represents an X25519 key pair used for the WireGuard handshake. The private key is
/// cloned on construction and zeroed when the instance is disposed.
/// </summary>
public class KeyPair : IDisposable
{
    /// <summary>Gets the raw 32-byte X25519 private key.</summary>
    public byte[] PrivateKey { get; }

    /// <summary>Gets the derived 32-byte X25519 public key.</summary>
    public byte[] PublicKey { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="KeyPair"/> class from an existing
    /// private key and derives the corresponding public key.
    /// </summary>
    /// <param name="privateKey">The raw 32-byte X25519 private key. The value is cloned, so the caller keeps ownership of the original array.</param>
    /// <exception cref="ArgumentException"><paramref name="privateKey"/> is not exactly 32 bytes long.</exception>
    public KeyPair(byte[] privateKey)
    {
        if (privateKey.Length != 32)
            throw new ArgumentException("Private key must be 32 bytes", nameof(privateKey));

        PrivateKey = (byte[])privateKey.Clone();
        PublicKey = X25519Crypto.GeneratePublicKey(PrivateKey);
    }

    /// <summary>
    /// Generates a new key pair with a fresh random private key.
    /// </summary>
    /// <returns>A newly generated <see cref="KeyPair"/> instance.</returns>
    public static KeyPair Generate()
    {
        var privateKey = X25519Crypto.GeneratePrivateKey();
        return new KeyPair(privateKey);
    }

    /// <summary>
    /// Computes the X25519 shared secret between this key pair's private key and the
    /// specified peer public key.
    /// </summary>
    /// <param name="peerPublicKey">The raw 32-byte public key of the remote peer.</param>
    /// <returns>The raw 32-byte shared secret.</returns>
    public byte[] ComputeSharedSecret(byte[] peerPublicKey)
    {
        return X25519Crypto.ScalarMult(PrivateKey, peerPublicKey);
    }

    /// <summary>
    /// Derives the public key corresponding to the specified private key.
    /// </summary>
    /// <param name="privateKey">The raw 32-byte X25519 private key.</param>
    /// <returns>The derived 32-byte public key.</returns>
    public static byte[] DerivePublicKey(byte[] privateKey)
    {
        return X25519Crypto.GeneratePublicKey(privateKey);
    }

    /// <summary>
    /// Zeroes the private key material in memory.
    /// </summary>
    /// <remarks>The public key is not considered secret and is not zeroed.</remarks>
    public void Dispose()
    {
        CryptographicOperations.ZeroMemory(PrivateKey);
    }
}
