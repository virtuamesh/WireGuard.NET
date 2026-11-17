using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

namespace WireGuard.NET.Crypto;

/// <summary>
/// X25519 Diffie-Hellman key exchange over Curve25519 (RFC 7748) — the DH primitive of
/// the WireGuard Noise protocol (whitepaper section 5.4).
/// </summary>
/// <remarks>
/// <para>
/// X25519 computes scalar multiplication on the Montgomery curve Curve25519. Private
/// and public keys are raw 32-byte arrays (little-endian encodings of the curve scalar
/// and u-coordinate), not base64 or any other textual format.
/// </para>
/// <para>
/// All members are static and thread-safe. Private keys and shared secrets returned by
/// this class are secret key material held in plain arrays; callers should zeroize them
/// (for example with
/// <see cref="System.Security.Cryptography.CryptographicOperations.ZeroMemory"/>) once
/// they are no longer needed.
/// </para>
/// </remarks>
public static class X25519Crypto
{

    /// <summary>
    /// Generates a new X25519 private key using a cryptographically secure random source.
    /// </summary>
    /// <returns>A new 32-byte private key.</returns>
    /// <remarks>
    /// The returned bytes are the raw encoded scalar and are secret. When consumed by
    /// <see cref="GeneratePublicKey(byte[])"/> or <see cref="ScalarMult(byte[],byte[])"/>,
    /// RFC 7748 clamping is applied automatically at scalar-multiplication time, so the
    /// stored value does not need to be pre-clamped.
    /// </remarks>
    public static byte[] GeneratePrivateKey()
    {
        var random = new Org.BouncyCastle.Security.SecureRandom();
        var keyGen = new X25519KeyPairGenerator();
        keyGen.Init(new X25519KeyGenerationParameters(random));
        var keyPair = keyGen.GenerateKeyPair();
        var privKey = (X25519PrivateKeyParameters)keyPair.Private;
        var encoded = new byte[X25519PrivateKeyParameters.KeySize];
        privKey.Encode(encoded, 0);
        return encoded;
    }

    /// <summary>
    /// Derives the public key that corresponds to an X25519 private key.
    /// </summary>
    /// <param name="privateKey">The 32-byte X25519 private key.</param>
    /// <returns>
    /// A new 32-byte public key: the Curve25519 base point multiplied by the private scalar.
    /// </returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="privateKey"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="privateKey"/> is not 32 bytes.
    /// </exception>
    /// <remarks>
    /// The public key can be shared freely; the peer feeds it into
    /// <see cref="ScalarMult(byte[],byte[])"/> to compute the shared secret. The input
    /// array is not modified.
    /// </remarks>
    public static byte[] GeneratePublicKey(byte[] privateKey)
    {
        if (privateKey == null)
            throw new ArgumentNullException(nameof(privateKey));
        if (privateKey.Length != 32)
            throw new ArgumentException("Private key must be 32 bytes", nameof(privateKey));

        var privKey = new X25519PrivateKeyParameters(privateKey, 0);
        var pubKey = privKey.GeneratePublicKey();
        var encoded = new byte[X25519PublicKeyParameters.KeySize];
        pubKey.Encode(encoded, 0);
        return encoded;
    }

    /// <summary>
    /// Computes the raw X25519 shared secret between a private key and a peer public key
    /// (RFC 7748 §5).
    /// </summary>
    /// <param name="privateKey">
    /// The 32-byte local private key; clamped internally on a copy, so the input array
    /// is not modified.
    /// </param>
    /// <param name="publicKey">The 32-byte peer public key.</param>
    /// <returns>A new 32-byte shared secret.</returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="privateKey"/> or <paramref name="publicKey"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="privateKey"/> or <paramref name="publicKey"/> is not 32 bytes.
    /// </exception>
    /// <remarks>
    /// <para>
    /// Before the multiplication, the private scalar is clamped per RFC 7748 §5: the
    /// three lowest bits of the first byte are cleared, the highest bit of the last byte
    /// is cleared, and the second-highest bit of the last byte is set.
    /// </para>
    /// <para>
    /// This returns the raw shared secret. In the Noise protocol used by WireGuard, every
    /// DH result is immediately fed into the hash/HMAC-based key derivation; do not use
    /// the raw output directly as an encryption key.
    /// </para>
    /// <para>
    /// The all-zero output check recommended by RFC 7748 §6.1 (which detects low-order
    /// input points) is not performed here.
    /// </para>
    /// </remarks>
    public static byte[] ScalarMult(byte[] privateKey, byte[] publicKey)
    {
        if (privateKey == null)
            throw new ArgumentNullException(nameof(privateKey));
        if (publicKey == null)
            throw new ArgumentNullException(nameof(publicKey));
        if (privateKey.Length != 32)
            throw new ArgumentException("Private key must be 32 bytes", nameof(privateKey));
        if (publicKey.Length != 32)
            throw new ArgumentException("Public key must be 32 bytes", nameof(publicKey));

        var clampedKey = (byte[])privateKey.Clone();
        clampedKey[0] &= 248;
        clampedKey[31] &= 127;
        clampedKey[31] |= 64;

        var privKey = new X25519PrivateKeyParameters(clampedKey, 0);
        var pubKey = new X25519PublicKeyParameters(publicKey, 0);
        var agreement = new X25519Agreement();
        agreement.Init(privKey);
        var sharedSecret = new byte[agreement.AgreementSize];
        agreement.CalculateAgreement(pubKey, sharedSecret, 0);
        return sharedSecret;
    }
}
