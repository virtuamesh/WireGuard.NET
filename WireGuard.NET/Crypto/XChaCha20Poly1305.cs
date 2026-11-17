using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

namespace WireGuard.NET.Crypto;

/// <summary>
/// One-shot XChaCha20-Poly1305 AEAD encryption and decryption: the extended-nonce
/// variant of ChaCha20-Poly1305 defined in draft-irtf-cfrg-xchacha, used here to seal
/// WireGuard cookie values.
/// </summary>
/// <remarks>
/// <para>
/// XChaCha20-Poly1305 accepts a 192-bit (24-byte) nonce instead of ChaCha20-Poly1305's
/// 96-bit nonce, which makes random nonces safe to use. The first 16 nonce bytes are fed
/// through the HChaCha20 core to derive a 32-byte subkey; the remaining 8 bytes become
/// the low 64 bits of the 12-byte ChaCha20-Poly1305 subnonce (prefixed with four zero
/// bytes). The message is then processed by plain ChaCha20-Poly1305 (RFC 8439 §2.8)
/// under that subkey/subnonce pair.
/// </para>
/// <para>
/// All members are static and thread-safe. Encryption and decryption are one-shot over
/// whole buffers; see <see cref="ChaCha20Poly1305"/> for the tag layout and security
/// properties of the underlying AEAD.
/// </para>
/// </remarks>
public static class XChaCha20Poly1305
{
    [ThreadStatic]
    private static uint[]? _tsInput;

    [ThreadStatic]
    private static byte[]? _tsSubNonce;

    /// <summary>
    /// Encrypts and authenticates a plaintext with XChaCha20-Poly1305.
    /// </summary>
    /// <param name="key">The 32-byte (256-bit) symmetric key.</param>
    /// <param name="nonce">
    /// The 24-byte (192-bit) XChaCha20 nonce; may be random, but must never repeat under
    /// the same key.
    /// </param>
    /// <param name="plaintext">The bytes to encrypt; may be empty.</param>
    /// <param name="associatedData">
    /// Data that is authenticated but not encrypted (AAD); may be empty.
    /// </param>
    /// <returns>
    /// A new array of length <c>plaintext.Length + 16</c> containing the ciphertext
    /// followed by the 16-byte Poly1305 authentication tag.
    /// </returns>
    /// <exception cref="ArgumentException">
    /// <paramref name="key"/> is not 32 bytes, or <paramref name="nonce"/> is not 24 bytes.
    /// </exception>
    public static byte[] Encrypt(byte[] key, byte[] nonce, byte[] plaintext, byte[] associatedData)
    {
        if (key.Length != 32)
            throw new ArgumentException("Key must be 32 bytes", nameof(key));
        if (nonce.Length != 24)
            throw new ArgumentException("Nonce must be 24 bytes for XChaCha20", nameof(nonce));

        var (subKey, subNonce) = HChaCha20DeriveSubKeyAndNonce(key, nonce);

        return ChaCha20Poly1305.Encrypt(subKey, subNonce, plaintext, associatedData);
    }

    /// <summary>
    /// Verifies and decrypts an XChaCha20-Poly1305 ciphertext.
    /// </summary>
    /// <param name="key">The 32-byte (256-bit) symmetric key used for encryption.</param>
    /// <param name="nonce">The 24-byte (192-bit) nonce used for encryption.</param>
    /// <param name="ciphertextWithTag">
    /// The ciphertext with its trailing 16-byte Poly1305 tag; must be at least 16 bytes.
    /// </param>
    /// <param name="associatedData">The AAD that was used for encryption; may be empty.</param>
    /// <returns>
    /// A new array of length <c>ciphertextWithTag.Length - 16</c> containing the plaintext.
    /// </returns>
    /// <exception cref="ArgumentException">
    /// <paramref name="key"/> is not 32 bytes, or <paramref name="nonce"/> is not 24 bytes.
    /// </exception>
    /// <exception cref="System.Security.Cryptography.CryptographicException">
    /// The authentication tag did not verify — wrong key, wrong nonce, modified
    /// ciphertext, or mismatched associated data. Thrown by the underlying
    /// ChaCha20-Poly1305 call.
    /// </exception>
    public static byte[] Decrypt(byte[] key, byte[] nonce, byte[] ciphertextWithTag, byte[] associatedData)
    {
        if (key.Length != 32)
            throw new ArgumentException("Key must be 32 bytes", nameof(key));
        if (nonce.Length != 24)
            throw new ArgumentException("Nonce must be 24 bytes for XChaCha20", nameof(nonce));

        var (subKey, subNonce) = HChaCha20DeriveSubKeyAndNonce(key, nonce);

        return ChaCha20Poly1305.Decrypt(subKey, subNonce, ciphertextWithTag, associatedData);
    }

    /// <summary>
    /// Derives the ChaCha20-Poly1305 subkey and 12-byte subnonce from an XChaCha20 key
    /// and nonce (draft-irtf-cfrg-xchacha).
    /// </summary>
    /// <param name="key">The 32-byte XChaCha20 key.</param>
    /// <param name="nonce">The 24-byte XChaCha20 nonce.</param>
    /// <returns>
    /// The 32-byte HChaCha20 subkey and a 12-byte subnonce consisting of four zero bytes
    /// followed by nonce bytes 16-23.
    /// </returns>
    private static (byte[] subKey, byte[] subNonce) HChaCha20DeriveSubKeyAndNonce(byte[] key, byte[] nonce)
    {
        var subKey = HChaCha20(key, nonce);

        var subNonce = _tsSubNonce;
        if (subNonce == null)
        {
            subNonce = new byte[12];
            _tsSubNonce = subNonce;
        }
        subNonce.AsSpan().Clear();
        Buffer.BlockCopy(nonce, 16, subNonce, 4, 8);

        return (subKey, subNonce);
    }

    /// <summary>
    /// Computes the HChaCha20 core (draft-irtf-cfrg-xchacha §2.3): a 20-round ChaCha20
    /// permutation over the "expand 32-byte k" constants, the key, and the first 16 nonce
    /// bytes, without the final feed-forward addition.
    /// </summary>
    /// <param name="key">The 32-byte key.</param>
    /// <param name="nonce">The nonce; only the first 16 bytes are used.</param>
    /// <returns>A new 32-byte subkey assembled from state words 0-3 and 12-15.</returns>
    /// <remarks>
    /// State words are read and written little-endian via <see cref="BitConverter"/>, as
    /// required by the HChaCha20 definition. The 64-byte working state is cached per thread.
    /// </remarks>
    private static byte[] HChaCha20(byte[] key, byte[] nonce)
    {
        var input = _tsInput;
        if (input == null)
        {
            input = new uint[16];
            _tsInput = input;
        }

        input[0] = 0x61707865;
        input[1] = 0x3320646e;
        input[2] = 0x79622d32;
        input[3] = 0x6b206574;

        input[4] = BitConverter.ToUInt32(key, 0);
        input[5] = BitConverter.ToUInt32(key, 4);
        input[6] = BitConverter.ToUInt32(key, 8);
        input[7] = BitConverter.ToUInt32(key, 12);
        input[8] = BitConverter.ToUInt32(key, 16);
        input[9] = BitConverter.ToUInt32(key, 20);
        input[10] = BitConverter.ToUInt32(key, 24);
        input[11] = BitConverter.ToUInt32(key, 28);

        input[12] = BitConverter.ToUInt32(nonce, 0);
        input[13] = BitConverter.ToUInt32(nonce, 4);
        input[14] = BitConverter.ToUInt32(nonce, 8);
        input[15] = BitConverter.ToUInt32(nonce, 12);

        for (var i = 0; i < 10; i++)
        {
            QuarterRound(ref input[0], ref input[4], ref input[8], ref input[12]);
            QuarterRound(ref input[1], ref input[5], ref input[9], ref input[13]);
            QuarterRound(ref input[2], ref input[6], ref input[10], ref input[14]);
            QuarterRound(ref input[3], ref input[7], ref input[11], ref input[15]);
            QuarterRound(ref input[0], ref input[5], ref input[10], ref input[15]);
            QuarterRound(ref input[1], ref input[6], ref input[11], ref input[12]);
            QuarterRound(ref input[2], ref input[7], ref input[8], ref input[13]);
            QuarterRound(ref input[3], ref input[4], ref input[9], ref input[14]);
        }

        var output = new byte[32];
        BitConverter.GetBytes(input[0]).CopyTo(output, 0);
        BitConverter.GetBytes(input[1]).CopyTo(output, 4);
        BitConverter.GetBytes(input[2]).CopyTo(output, 8);
        BitConverter.GetBytes(input[3]).CopyTo(output, 12);
        BitConverter.GetBytes(input[12]).CopyTo(output, 16);
        BitConverter.GetBytes(input[13]).CopyTo(output, 20);
        BitConverter.GetBytes(input[14]).CopyTo(output, 24);
        BitConverter.GetBytes(input[15]).CopyTo(output, 28);

        return output;
    }

    /// <summary>
    /// Applies the ChaCha20 quarter-round to four state words (RFC 8439 §2.1).
    /// </summary>
    private static void QuarterRound(ref uint a, ref uint b, ref uint c, ref uint d)
    {
        a += b;
        d ^= a;
        d = RotateLeft(d, 16);
        c += d;
        b ^= c;
        b = RotateLeft(b, 12);
        a += b;
        d ^= a;
        d = RotateLeft(d, 8);
        c += d;
        b ^= c;
        b = RotateLeft(b, 7);
    }

    /// <summary>
    /// Rotates a 32-bit value left by the given number of bits.
    /// </summary>
    /// <param name="value">The value to rotate.</param>
    /// <param name="count">The rotation amount, in bits.</param>
    /// <returns>The rotated value.</returns>
    private static uint RotateLeft(uint value, int count)
    {
        return (value << count) | (value >> (32 - count));
    }
}
