using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using System.Buffers;
using System.Security.Cryptography;

namespace WireGuard.NET.Crypto;

/// <summary>
/// One-shot ChaCha20-Poly1305 AEAD encryption and decryption (RFC 8439 §2.8) — the
/// AEAD_CHACHA20_POLY1305 primitive of the WireGuard protocol (whitepaper section 5.4).
/// </summary>
/// <remarks>
/// <para>
/// ChaCha20-Poly1305 is an authenticated encryption with associated data (AEAD)
/// construction: the plaintext is encrypted with the ChaCha20 stream cipher (RFC 8439
/// §2.4) and the ciphertext is authenticated with a Poly1305 MAC (RFC 8439 §2.5). The
/// one-time Poly1305 key is the first 32 bytes of the ChaCha20 keystream block generated
/// with block counter 0 (RFC 8439 §2.6); the message keystream starts at block counter 1.
/// The tag is computed over
/// <c>AAD || pad16 || ciphertext || pad16 || len64(AAD) || len64(ciphertext)</c> per
/// RFC 8439 §2.8.
/// </para>
/// <para>
/// All members are static and thread-safe: the cipher and MAC instances are cached per
/// thread and re-initialized on every call. Encryption and decryption are one-shot over
/// whole buffers; there is no streaming API.
/// </para>
/// <para>
/// Security notes: reusing a nonce under the same key is catastrophic — it reveals the
/// Poly1305 one-time key and enables plaintext recovery and forgery. In WireGuard the
/// nonce is a monotonically increasing 64-bit counter, so a key/nonce pair never repeats
/// within a session. Tag verification compares all 16 bytes without early exit, and no
/// plaintext is released unless the tag is valid.
/// </para>
/// </remarks>
public static class ChaCha20Poly1305
{
    private static readonly byte[] EmptyPad = Array.Empty<byte>();
    private static readonly byte[] Pad16 = new byte[16];

    [ThreadStatic]
    private static byte[]? _tsFirstBlock;

    [ThreadStatic]
    private static byte[]? _tsLenBytes;

    [ThreadStatic]
    private static byte[]? _tsPolyKey;

    [ThreadStatic]
    private static byte[]? _tsTag;

    [ThreadStatic]
    private static ChaCha7539Engine? _tsCipher;

    [ThreadStatic]
    private static Poly1305? _tsMac;

    private static byte[] GetFirstBlock() => _tsFirstBlock ??= new byte[64];
    private static byte[] GetLenBytes() => _tsLenBytes ??= new byte[16];
    private static byte[] GetPolyKey() => _tsPolyKey ??= new byte[32];
    private static byte[] GetTag() => _tsTag ??= new byte[16];
    private static ChaCha7539Engine GetCipher() => _tsCipher ??= new ChaCha7539Engine();
    private static Poly1305 GetMac() => _tsMac ??= new Poly1305();

    /// <summary>
    /// Encrypts and authenticates a plaintext with ChaCha20-Poly1305.
    /// </summary>
    /// <param name="key">The 32-byte (256-bit) symmetric key.</param>
    /// <param name="nonce">
    /// The 12-byte (96-bit) nonce. In WireGuard this is four zero bytes followed by the
    /// 64-bit little-endian message counter. Must never repeat under the same key.
    /// </param>
    /// <param name="plaintext">The bytes to encrypt; may be empty.</param>
    /// <param name="associatedData">
    /// Data that is authenticated but not encrypted (AAD); may be empty. WireGuard data
    /// packets use empty AAD, while handshake messages use the transcript hash as AAD.
    /// </param>
    /// <returns>
    /// A new array of length <c>plaintext.Length + 16</c> containing the ciphertext
    /// followed by the 16-byte Poly1305 authentication tag.
    /// </returns>
    /// <exception cref="ArgumentException">
    /// <paramref name="key"/> is not 32 bytes, or <paramref name="nonce"/> is not 12 bytes.
    /// </exception>
    public static byte[] Encrypt(byte[] key, byte[] nonce, byte[] plaintext, byte[] associatedData)
    {
        if (key.Length != 32)
            throw new ArgumentException("Key must be 32 bytes", nameof(key));
        if (nonce.Length != 12)
            throw new ArgumentException("Nonce must be 12 bytes", nameof(nonce));

        var cipher = GetCipher();
        cipher.Init(true, new ParametersWithIV(new KeyParameter(key), nonce));

        var firstBlock = GetFirstBlock();
        Array.Clear(firstBlock, 0, 64);
        cipher.ProcessBytes(firstBlock, 0, firstBlock.Length, firstBlock, 0);

        var polyKey = GetPolyKey();
        Buffer.BlockCopy(firstBlock, 0, polyKey, 0, 32);

        var ciphertext = new byte[plaintext.Length];
        cipher.ProcessBytes(plaintext, 0, plaintext.Length, ciphertext, 0);

        var mac = GetMac();
        mac.Init(new KeyParameter(polyKey, 0, 32));
        mac.Reset();

        var adLen = (long)associatedData.Length;
        var ctLen = (long)ciphertext.Length;

        mac.BlockUpdate(associatedData, 0, associatedData.Length);
        WritePad(mac, adLen);

        mac.BlockUpdate(ciphertext, 0, ciphertext.Length);
        WritePad(mac, ctLen);

        var lenBytes = GetLenBytes();
        BitConverter.TryWriteBytes(lenBytes.AsSpan(0, 8), adLen);
        BitConverter.TryWriteBytes(lenBytes.AsSpan(8, 8), ctLen);
        mac.BlockUpdate(lenBytes, 0, 16);

        var tag = GetTag();
        mac.DoFinal(tag, 0);

        var result = new byte[ciphertext.Length + 16];
        Buffer.BlockCopy(ciphertext, 0, result, 0, ciphertext.Length);
        Buffer.BlockCopy(tag, 0, result, ciphertext.Length, 16);

        return result;
    }

    /// <summary>
    /// Verifies and decrypts a ChaCha20-Poly1305 ciphertext.
    /// </summary>
    /// <param name="key">The 32-byte (256-bit) symmetric key used for encryption.</param>
    /// <param name="nonce">The 12-byte (96-bit) nonce used for encryption.</param>
    /// <param name="ciphertextWithTag">
    /// The ciphertext with its trailing 16-byte Poly1305 tag; must be at least 16 bytes.
    /// </param>
    /// <param name="associatedData">The AAD that was used for encryption; may be empty.</param>
    /// <returns>
    /// A new array of length <c>ciphertextWithTag.Length - 16</c> containing the plaintext.
    /// </returns>
    /// <exception cref="ArgumentException">
    /// <paramref name="key"/> is not 32 bytes, <paramref name="nonce"/> is not 12 bytes,
    /// or <paramref name="ciphertextWithTag"/> is shorter than 16 bytes.
    /// </exception>
    /// <exception cref="CryptographicException">
    /// The authentication tag did not verify — wrong key, wrong nonce, modified
    /// ciphertext, or mismatched associated data.
    /// </exception>
    /// <remarks>
    /// Authentication happens before decryption: no plaintext is produced unless the tag
    /// is valid. The 16-byte tag comparison scans all bytes without short-circuiting
    /// (constant-time comparison), and the computed tag is zeroized on the failure path.
    /// </remarks>
    public static byte[] Decrypt(byte[] key, byte[] nonce, byte[] ciphertextWithTag, byte[] associatedData)
    {
        if (key.Length != 32)
            throw new ArgumentException("Key must be 32 bytes", nameof(key));
        if (nonce.Length != 12)
            throw new ArgumentException("Nonce must be 12 bytes", nameof(nonce));
        if (ciphertextWithTag.Length < 16)
            throw new ArgumentException("Ciphertext with tag must be at least 16 bytes", nameof(ciphertextWithTag));

        var ctLen = ciphertextWithTag.Length - 16;

        var cipher = GetCipher();
        cipher.Init(true, new ParametersWithIV(new KeyParameter(key), nonce));

        var firstBlock = GetFirstBlock();
        Array.Clear(firstBlock, 0, 64);
        cipher.ProcessBytes(firstBlock, 0, firstBlock.Length, firstBlock, 0);

        var polyKey = GetPolyKey();
        Buffer.BlockCopy(firstBlock, 0, polyKey, 0, 32);

        var mac = GetMac();
        mac.Init(new KeyParameter(polyKey, 0, 32));
        mac.Reset();

        var adLen = (long)associatedData.Length;

        mac.BlockUpdate(associatedData, 0, associatedData.Length);
        WritePad(mac, adLen);

        mac.BlockUpdate(ciphertextWithTag, 0, ctLen);
        WritePad(mac, (long)ctLen);

        var lenBytes = GetLenBytes();
        BitConverter.TryWriteBytes(lenBytes.AsSpan(0, 8), adLen);
        BitConverter.TryWriteBytes(lenBytes.AsSpan(8, 8), (long)ctLen);
        mac.BlockUpdate(lenBytes, 0, 16);

        var computedTag = GetTag();
        mac.DoFinal(computedTag, 0);

        var tagOffset = ctLen;
        bool tagValid = true;
        for (int i = 0; i < 16; i++)
        {
            if (computedTag[i] != ciphertextWithTag[tagOffset + i])
                tagValid = false;
        }

        if (!tagValid)
        {
            // Log only non-sensitive metadata; never dump keys, tags, or ciphertext material.
            System.Diagnostics.Debug.WriteLine($"[ChaCha20Poly1305] Decrypt failed: authentication tag mismatch (ctLen={ctLen}, totalLen={ciphertextWithTag.Length})");
            CryptographicOperations.ZeroMemory(computedTag);
            throw new System.Security.Cryptography.CryptographicException("Authentication tag verification failed");
        }

        var plaintext = new byte[ctLen];
        cipher.ProcessBytes(ciphertextWithTag, 0, ctLen, plaintext, 0);

        return plaintext;
    }

    /// <summary>
    /// Pads the Poly1305 input with zero bytes up to the next 16-byte boundary, as
    /// required by the AAD/ciphertext padding rule of RFC 8439 §2.8.
    /// </summary>
    /// <param name="mac">The Poly1305 instance to update.</param>
    /// <param name="len">The length, in bytes, of the data segment that was just absorbed.</param>
    private static void WritePad(Poly1305 mac, long len)
    {
        var remainder = (int)(len % 16);
        if (remainder > 0)
        {
            mac.BlockUpdate(Pad16, 0, 16 - remainder);
        }
    }
}
