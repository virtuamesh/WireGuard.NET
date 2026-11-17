using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

namespace WireGuard.NET.Crypto;

/// <summary>
/// Provides one-shot BLAKE2s hashing, keyed BLAKE2s MAC computation, and HMAC-BLAKE2s —
/// the hash primitives required by the WireGuard Noise protocol (BLAKE2s-256 is the HASH
/// primitive of WireGuard whitepaper section 5.4).
/// </summary>
/// <remarks>
/// <para>
/// BLAKE2s (RFC 7693) is a cryptographic hash function designed for 32-bit platforms,
/// with a native keyed-MAC mode and a digest size of up to 256 bits. The WireGuard
/// protocol uses unkeyed BLAKE2s-256 for transcript hashing and cookie-key derivation,
/// keyed BLAKE2s with a 128-bit output for cookie MACs, and HMAC over BLAKE2s-256 inside
/// its key-derivation function (KDF).
/// </para>
/// <para>
/// All members are static and thread-safe: digest instances and scratch buffers are
/// cached per thread and reset on every call, so no state is shared between threads and
/// hot paths avoid allocations. Every method returns a fresh array owned by the caller
/// and unaffected by subsequent calls.
/// </para>
/// <para>
/// All operations are one-shot: the entire input must be supplied as a single buffer.
/// There is no streaming/incremental API.
/// </para>
/// </remarks>
public static class Blake2s
{
    /// <summary>
    /// The digest size, in bytes, of the full-length operations (<see cref="Hash(byte[])"/>
    /// and <see cref="HMAC(byte[],byte[])"/>): 32 bytes (256 bits, BLAKE2s-256).
    /// </summary>
    public const int HashSize = 32;

    /// <summary>
    /// The BLAKE2s internal block size, in bytes: 64 bytes (512 bits). Also used as the
    /// key-block length of <see cref="HMAC(byte[],byte[])"/>.
    /// </summary>
    public const int BlockSize = 64;

    [ThreadStatic]
    private static Blake2sDigest? _tsDigest;

    [ThreadStatic]
    private static Blake2sDigest? _tsDigest128;

    [ThreadStatic]
    private static byte[]? _tsOutput;

    [ThreadStatic]
    private static byte[]? _tsOutput128;

    private static byte[] GetOutput() => _tsOutput ??= new byte[HashSize];
    private static byte[] GetOutput128() => _tsOutput128 ??= new byte[16];

    /// <summary>
    /// Computes the unkeyed BLAKE2s-256 digest of the input.
    /// </summary>
    /// <param name="input">The bytes to hash; may be empty.</param>
    /// <returns>A new <see cref="HashSize"/>-byte (32-byte) array containing the digest.</returns>
    /// <remarks>
    /// This is the HASH function of the WireGuard Noise protocol (whitepaper section 5.4),
    /// used for transcript hashing and for deriving cookie MAC keys from public keys.
    /// </remarks>
    public static byte[] Hash(byte[] input)
    {
        var digest = _tsDigest;
        if (digest == null)
        {
            digest = new Blake2sDigest();
            _tsDigest = digest;
        }
        var output = GetOutput();
        digest.Reset();
        digest.BlockUpdate(input, 0, input.Length);
        digest.DoFinal(output, 0);
        return (byte[])output.Clone();
    }

    /// <summary>
    /// Computes a keyed BLAKE2s-256 digest (MAC) using the native BLAKE2s keying mechanism.
    /// </summary>
    /// <param name="input">The message to authenticate; may be empty.</param>
    /// <param name="key">
    /// The secret key, at most 32 bytes (the BLAKE2s maximum key length); it is
    /// zero-padded internally to a full 64-byte block per RFC 7693.
    /// </param>
    /// <returns>A new 32-byte array containing the keyed digest.</returns>
    /// <remarks>
    /// This is the built-in keyed mode of BLAKE2s (the key is mixed into the first
    /// compressed block), not the HMAC construction; for HMAC over BLAKE2s-256 use
    /// <see cref="HMAC(byte[],byte[])"/>. A fresh digest instance is created per call
    /// because the key is part of the digest state.
    /// </remarks>
    public static byte[] Hash(byte[] input, byte[] key)
    {
        var digest = new Blake2sDigest(key);
        var output = new byte[digest.GetDigestSize()];
        digest.BlockUpdate(input, 0, input.Length);
        digest.DoFinal(output, 0);
        return output;
    }

    /// <summary>
    /// Computes a truncated BLAKE2s digest with a 128-bit (16-byte) output, optionally keyed.
    /// </summary>
    /// <param name="input">The message to hash or authenticate; may be empty.</param>
    /// <param name="key">
    /// Optional secret key, at most 32 bytes, for keyed-MAC operation; pass
    /// <see langword="null"/> for unkeyed hashing.
    /// </param>
    /// <returns>A new 16-byte array containing the digest.</returns>
    /// <remarks>
    /// The 16-byte length matches the MAC1/MAC2 field size of the WireGuard cookie
    /// mechanism (whitepaper section 5.4), where keyed BLAKE2s MACs are computed over
    /// handshake messages.
    /// </remarks>
    public static byte[] Hash128(byte[] input, byte[]? key = null)
    {
        var digest = _tsDigest128;
        if (digest == null || (key == null && digest.GetDigestSize() != 16) || (key != null && digest.GetDigestSize() != 16))
        {
            digest = key != null
                ? new Blake2sDigest(key, 16, null, null)
                : new Blake2sDigest(16);
            _tsDigest128 = digest;
        }
        else
        {
            digest.Reset();
            if (key != null)
            {
                digest = new Blake2sDigest(key, 16, null, null);
                _tsDigest128 = digest;
            }
        }
        var output = GetOutput128();
        digest.BlockUpdate(input, 0, input.Length);
        digest.DoFinal(output, 0);
        return (byte[])output.Clone();
    }

    /// <summary>
    /// Computes the unkeyed BLAKE2s-256 digest of a segment of a buffer.
    /// </summary>
    /// <param name="input">The buffer containing the bytes to hash.</param>
    /// <param name="offset">The zero-based offset, in bytes, at which the hashed data starts.</param>
    /// <param name="length">The number of bytes to hash.</param>
    /// <returns>A new <see cref="HashSize"/>-byte (32-byte) array containing the digest.</returns>
    public static byte[] Hash(byte[] input, int offset, int length)
    {
        var digest = _tsDigest;
        if (digest == null)
        {
            digest = new Blake2sDigest();
            _tsDigest = digest;
        }
        var output = GetOutput();
        digest.Reset();
        digest.BlockUpdate(input, offset, length);
        digest.DoFinal(output, 0);
        return (byte[])output.Clone();
    }

    /// <summary>
    /// Computes HMAC over BLAKE2s-256 (RFC 2104) — the HMAC(HASH, key, data) construction
    /// used by the WireGuard key-derivation function.
    /// </summary>
    /// <param name="key">
    /// The secret key, of any length. Keys longer than <see cref="BlockSize"/> (64 bytes)
    /// are first hashed with BLAKE2s-256; all keys are then zero-padded to 64 bytes.
    /// </param>
    /// <param name="message">The data to authenticate; may be empty.</param>
    /// <returns>A new <see cref="HashSize"/>-byte (32-byte) array containing the HMAC tag.</returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="key"/> or <paramref name="message"/> is <see langword="null"/>.
    /// </exception>
    /// <remarks>
    /// Implements the generic HMAC construction: the padded key is XORed with the inner
    /// pad (0x36) and the outer pad (0x5C) to form the inner and outer hash preimages,
    /// with BLAKE2s-256 as both hashes. The WireGuard KDF chains this HMAC (whitepaper
    /// section 5.4) to derive chaining keys and transport keys from handshake secrets.
    /// </remarks>
    public static byte[] HMAC(byte[] key, byte[] message)
    {
        if (key == null) throw new ArgumentNullException(nameof(key));
        if (message == null) throw new ArgumentNullException(nameof(message));

        byte[] keyPrime;
        if (key.Length > BlockSize)
        {
            keyPrime = new byte[BlockSize];
            var hashedKey = Hash(key);
            Buffer.BlockCopy(hashedKey, 0, keyPrime, 0, hashedKey.Length);
        }
        else
        {
            keyPrime = new byte[BlockSize];
            Buffer.BlockCopy(key, 0, keyPrime, 0, key.Length);
        }

        var ipad = new byte[BlockSize];
        var opad = new byte[BlockSize];
        for (var i = 0; i < BlockSize; i++)
        {
            ipad[i] = (byte)(keyPrime[i] ^ 0x36);
            opad[i] = (byte)(keyPrime[i] ^ 0x5C);
        }

        var innerData = new byte[BlockSize + message.Length];
        Buffer.BlockCopy(ipad, 0, innerData, 0, BlockSize);
        Buffer.BlockCopy(message, 0, innerData, BlockSize, message.Length);
        var innerHash = Hash(innerData);

        var outerData = new byte[BlockSize + HashSize];
        Buffer.BlockCopy(opad, 0, outerData, 0, BlockSize);
        Buffer.BlockCopy(innerHash, 0, outerData, BlockSize, HashSize);
        return Hash(outerData);
    }
}
