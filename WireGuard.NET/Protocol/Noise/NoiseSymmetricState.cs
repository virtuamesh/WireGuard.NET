using System.Buffers.Binary;
using System.Threading;
using WireGuard.NET.Crypto;

namespace WireGuard.NET.Protocol.Noise;

/// <summary>
/// Symmetric cryptographic state of a Noise protocol handshake, as defined by the Noise
/// framework and used by the Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s handshake specified in the
/// WireGuard whitepaper. Holds the chaining key (<c>ck</c>), the running hash (<c>h</c>), the
/// current AEAD key (<c>k</c>) and the 64-bit nonce counter (<c>n</c>).
/// <para>
/// Key-derivation chain: <see cref="MixKey"/> and <see cref="MixKeyAndHash"/> run HKDF
/// (BLAKE2s-HMAC based, 2 or 3 outputs) over the chaining key and new input key material to
/// derive the next chaining key and AEAD key (and, for the pre-shared key, an intermediate
/// hash that is folded into the transcript), resetting the nonce counter.
/// <see cref="MixHash"/> binds handshake transcript data into the running hash.
/// <see cref="EncryptAndHash"/>/<see cref="DecryptAndHash"/> AEAD-protect the trailing message
/// payload with ChaCha20-Poly1305, using the running hash as associated data, and also mix
/// the ciphertext into the hash. <see cref="Split"/> closes the handshake by deriving the
/// two transport keys from the chaining key.
/// </para>
/// <para>
/// Thread-safety: the nonce counter is incremented atomically (see the Interlocked call in
/// <see cref="EncryptAndHash"/>), but the rest of the state mutates freely — drive one
/// instance from a single logical handshake flow only.
/// </para>
/// </summary>
public class NoiseSymmetricState : IDisposable
{
    private byte[] _ck;
    private byte[] _h;
    private byte[] _k;
    private ulong _n;
    private bool _hasKey;
    private bool _disposed;

    /// <summary>
    /// Initializes the symmetric state with the given initial chaining key and running hash
    /// (each 32 bytes) and no AEAD key set yet, so EncryptAndHash/DecryptAndHash pass data
    /// through unencrypted until the first MixKey/MixKeyAndHash call.
    /// </summary>
    /// <param name="ck">Initial chaining key (32 bytes).</param>
    /// <param name="h">Initial running hash (32 bytes).</param>
    public NoiseSymmetricState(byte[] ck, byte[] h)
    {
        _ck = ck;
        _h = h;
        _k = Array.Empty<byte>();
        _n = 0;
        _hasKey = false;
    }

    /// <summary>
    /// Mixes new input key material into the state: derives a new chaining key and a new AEAD
    /// key via HKDF (2 outputs) and resets the nonce counter. After this call, subsequent
    /// <see cref="EncryptAndHash"/>/<see cref="DecryptAndHash"/> operations are encrypted.
    /// </summary>
    /// <param name="inputKeyMaterial">New key material (e.g. an X25519 shared secret).</param>
    public void MixKey(byte[] inputKeyMaterial)
    {
        var (newCk, tempK, _) = HKDF(_ck, inputKeyMaterial, 2);
        _ck = newCk;
        _k = tempK;
        _n = 0;
        _hasKey = true;
    }

    /// <summary>
    /// Mixes new input key material into both the chaining key and the running hash (Noise
    /// "MixKeyAndHash", used for the WireGuard pre-shared key): derives a new chaining key, an
    /// intermediate hash and a new AEAD key via HKDF (3 outputs), folds the intermediate hash
    /// into the running hash and resets the nonce counter.
    /// </summary>
    /// <param name="inputKeyMaterial">New key material (the 32-byte pre-shared key).</param>
    public void MixKeyAndHash(byte[] inputKeyMaterial)
    {
        var (newCk, tempH, tempK) = HKDF(_ck, inputKeyMaterial, 3);
        _ck = newCk;
        MixHash(tempH);
        _k = tempK;
        _n = 0;
        _hasKey = true;
    }

    /// <summary>
    /// Folds <paramref name="data"/> into the running hash: h = BLAKE2s(h || data). Binds the
    /// handshake transcript (ephemeral/static public keys, ciphertexts) into the final keys.
    /// </summary>
    /// <param name="data">Transcript data to mix into the hash.</param>
    public void MixHash(byte[] data)
    {
        var combined = new byte[_h.Length + data.Length];
        Buffer.BlockCopy(_h, 0, combined, 0, _h.Length);
        Buffer.BlockCopy(data, 0, combined, _h.Length, data.Length);
        _h = Blake2s.Hash(combined);
    }

    /// <summary>
    /// Encrypts <paramref name="plaintext"/> with the current AEAD key — or passes it through
    /// unchanged when no key has been mixed in yet — using the running hash as associated
    /// data, then mixes the resulting ciphertext into the running hash. The Noise 96-bit nonce
    /// is a 4-byte zero prefix followed by the 64-bit little-endian counter.
    /// </summary>
    /// <param name="plaintext">Payload to encrypt and bind to the transcript.</param>
    /// <returns>The ciphertext (or the plaintext when no key is set).</returns>
    public byte[] EncryptAndHash(byte[] plaintext)
    {
        byte[] ciphertext;

        if (_hasKey)
        {
            // The Noise protocol mandates a 96-bit nonce = 4-byte zero prefix || 8-byte little-endian 64-bit counter.
            // BinaryPrimitives makes the byte order explicit, avoiding BitConverter's platform-dependent endianness.
            // A stackalloc Span avoids heap allocation for the nonce.
            Span<byte> nonce = stackalloc byte[12];
            BinaryPrimitives.WriteUInt64LittleEndian(nonce.Slice(4), Interlocked.Increment(ref _n) - 1UL);
            ciphertext = ChaCha20Poly1305.Encrypt(_k, nonce.ToArray(), plaintext, _h);
            MixHash(ciphertext);
        }
        else
        {
            ciphertext = plaintext;
            MixHash(ciphertext);
        }

        return ciphertext;
    }

    /// <summary>
    /// Decrypts <paramref name="ciphertext"/> with the current AEAD key — or passes it
    /// through unchanged when no key has been mixed in yet — using the running hash as
    /// associated data, then mixes the ciphertext into the running hash. AEAD authentication
    /// failures are wrapped in <see cref="NoiseAuthenticationException"/>.
    /// </summary>
    /// <param name="ciphertext">Payload to decrypt.</param>
    /// <returns>The plaintext (or the ciphertext when no key is set).</returns>
    /// <exception cref="NoiseAuthenticationException">AEAD authentication of the ciphertext failed.</exception>
    public byte[] DecryptAndHash(byte[] ciphertext)
    {
        byte[] plaintext;

        if (_hasKey)
        {
            Span<byte> nonce = stackalloc byte[12];
            BinaryPrimitives.WriteUInt64LittleEndian(nonce.Slice(4), Interlocked.Increment(ref _n) - 1UL);
            // AEAD authentication failures are uniformly wrapped in NoiseAuthenticationException,
            // letting callers distinguish a "remote public key candidate mismatch" from a genuine
            // protocol error without fragile exception-message string matching.
            try
            {
                plaintext = ChaCha20Poly1305.Decrypt(_k, nonce.ToArray(), ciphertext, _h);
            }
            catch (System.Security.Cryptography.CryptographicException ex)
            {
                throw new NoiseAuthenticationException(ex.Message, ex);
            }
            MixHash(ciphertext);
        }
        else
        {
            plaintext = ciphertext;
            MixHash(ciphertext);
        }

        return plaintext;
    }

    /// <summary>Returns a copy of the current running hash.</summary>
    public byte[] GetHash() => (byte[])_h.Clone();

    /// <summary>Returns a copy of the current chaining key.</summary>
    public byte[] GetChainingKey() => (byte[])_ck.Clone();

    /// <summary>Returns a copy of the current AEAD key (empty when no key has been mixed in).</summary>
    public byte[] GetEncryptionKey() => (byte[])_k.Clone();

    /// <summary>Returns the current 64-bit nonce counter value.</summary>
    public ulong GetNonce() => _n;

    /// <summary>Indicates whether an AEAD key has been mixed in (i.e. payloads are being encrypted).</summary>
    public bool HasKey => _hasKey;

    /// <summary>
    /// Splits the handshake into transport keys: derives two 32-byte keys (k1, k2) from the
    /// chaining key via HKDF (2 outputs, no further hash mixing) and returns the full final
    /// state (h, ck, k1, k2). The caller assigns the send/receive roles based on whether it
    /// acted as initiator or responder.
    /// </summary>
    public (byte[] h, byte[] ck, byte[] k1, byte[] k2) Split()
    {
        var (k1, k2, _) = HKDF(_ck, Array.Empty<byte>(), 2);
        return (_h, _ck, k1, k2);
    }

    /// <summary>
    /// WireGuard's HKDF construction built on BLAKE2s-HMAC: prk = HMAC(salt, ikm); each output
    /// block t(n+1) = HMAC(prk, t(n) || 0x(n+1)), with t(0) being the empty string. Yields one
    /// to three 32-byte outputs; unused outputs come back as empty arrays.
    /// </summary>
    /// <param name="salt">The HKDF salt (the current chaining key).</param>
    /// <param name="ikm">Input key material.</param>
    /// <param name="numOutputs">Number of output blocks to derive (1-3).</param>
    private static (byte[] output1, byte[] output2, byte[] output3) HKDF(byte[] salt, byte[] ikm, int numOutputs)
    {
        var prk = Blake2s.HMAC(salt, ikm);

        var t1 = Blake2s.HMAC(prk, new byte[] { 0x01 });

        if (numOutputs == 1)
        {
            return (t1, Array.Empty<byte>(), Array.Empty<byte>());
        }

        var t2Input = new byte[t1.Length + 1];
        Buffer.BlockCopy(t1, 0, t2Input, 0, t1.Length);
        t2Input[t1.Length] = 0x02;
        var t2 = Blake2s.HMAC(prk, t2Input);

        if (numOutputs == 2)
        {
            return (t1, t2, Array.Empty<byte>());
        }

        var t3Input = new byte[t2.Length + 1];
        Buffer.BlockCopy(t2, 0, t3Input, 0, t2.Length);
        t3Input[t2.Length] = 0x03;
        var t3 = Blake2s.HMAC(prk, t3Input);

        return (t1, t2, t3);
    }

    private static byte[] Combine(params byte[][] arrays)
    {
        var result = new byte[arrays.Sum(a => a.Length)];
        var offset = 0;
        foreach (var array in arrays)
        {
            Buffer.BlockCopy(array, 0, result, offset, array.Length);
            offset += array.Length;
        }
        return result;
    }

    /// <summary>
    /// Zeroes the chaining key, AEAD key and running hash buffers so no sensitive key material
    /// remains in memory. Idempotent.
    /// </summary>
    public void Dispose()
    {
        if (_disposed) return;

        System.Security.Cryptography.CryptographicOperations.ZeroMemory(_ck);
        System.Security.Cryptography.CryptographicOperations.ZeroMemory(_k);
        System.Security.Cryptography.CryptographicOperations.ZeroMemory(_h);
        _disposed = true;
    }
}
