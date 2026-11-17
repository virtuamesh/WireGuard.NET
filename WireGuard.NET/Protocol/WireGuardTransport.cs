using WireGuard.NET.Crypto;

namespace WireGuard.NET.Protocol;

/// <summary>
/// Encrypts and decrypts WireGuard transport data packets for one key generation
/// (one pair of ChaCha20Poly1305 send/receive keys derived from a completed
/// handshake): it maintains the monotonically increasing send counter used as the
/// packet nonce and a sliding receive replay window (see
/// <see cref="ReplayProtector"/>).
/// Thread-safety: <see cref="EncryptPacket"/> and <see cref="DecryptPacket"/> may be
/// called concurrently — the send counter is updated with <c>Interlocked</c> and the
/// replay window is internally locked. Disposing zeroes both key arrays in place.
/// </summary>
public class WireGuardTransport : IDisposable
{
    private byte[] _sendKey;
    private byte[] _recvKey;
    private ulong _sendCounter;
    private readonly ReplayProtector _replayProtector;
    private bool _disposed;

    // Per-thread scratch buffers for the nonce and packet header, avoiding
    // per-packet allocations on the encrypt/decrypt hot path.
    [ThreadStatic]
    private static byte[]? _tsNonce;

    [ThreadStatic]
    private static byte[]? _tsHeader;

    private static byte[] GetNonce() => _tsNonce ??= new byte[12];
    private static byte[] GetHeader() => _tsHeader ??= new byte[16];

    /// <summary>
    /// Creates a transport for one key generation. The key arrays are stored by
    /// reference (not cloned) and are zeroed in place by <see cref="Dispose"/>;
    /// callers must therefore not reuse or mutate them afterwards.
    /// </summary>
    /// <param name="sendKey">The 32-byte ChaCha20Poly1305 key for outbound packets.</param>
    /// <param name="recvKey">The 32-byte ChaCha20Poly1305 key for inbound packets.</param>
    /// <exception cref="ArgumentException">Thrown when either key is not 32 bytes.</exception>
    public WireGuardTransport(byte[] sendKey, byte[] recvKey)
    {
        if (sendKey.Length != 32)
            throw new ArgumentException("Send key must be 32 bytes", nameof(sendKey));
        if (recvKey.Length != 32)
            throw new ArgumentException("Receive key must be 32 bytes", nameof(recvKey));

        _sendKey = sendKey;
        _recvKey = recvKey;
        _sendCounter = 0;
        _replayProtector = new ReplayProtector();
    }

    /// <summary>
    /// Encrypts one plaintext packet into a WireGuard transport data message.
    /// Layout of the returned message: message type (LE u32 = 4) at offset 0,
    /// <paramref name="receiverIndex"/> (LE u32) at offset 4, the counter (LE u64) at
    /// offset 8, then the ChaCha20Poly1305 ciphertext with its 16-byte tag. The nonce
    /// is 12 zero bytes with the counter (LE u64) at offset 4; no AEAD associated
    /// data is used, matching the Linux kernel implementation.
    /// </summary>
    /// <param name="packet">The plaintext packet bytes (may be empty, e.g. a keepalive).</param>
    /// <param name="receiverIndex">The receiving peer's 4-byte session index for this key generation.</param>
    /// <returns>The encrypted data message: 16-byte header followed by ciphertext incl. tag.</returns>
    /// <exception cref="ObjectDisposedException">Thrown when the transport has been disposed.</exception>
    public byte[] EncryptPacket(byte[] packet, uint receiverIndex)
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(WireGuardTransport), "Transport key material has been zeroed");

        var currentCounter = Interlocked.Increment(ref _sendCounter) - 1;

        var nonce = GetNonce();
        Array.Clear(nonce, 0, 12);
        BitConverter.GetBytes(currentCounter).CopyTo(nonce, 4);

        var header = GetHeader();
        BitConverter.TryWriteBytes(header.AsSpan(0, 4), WireGuardConstants.TYPE_DATA);
        BitConverter.TryWriteBytes(header.AsSpan(4, 4), receiverIndex);
        BitConverter.TryWriteBytes(header.AsSpan(8, 8), currentCounter);

        // WireGuard transport data packets do NOT use AEAD associated data (AD).
        // Linux kernel WireGuard passes NULL/0 for AD: chacha20poly1305_encrypt_sg_inplace(sg, len, NULL, 0, nonce, key)
        var encrypted = ChaCha20Poly1305.Encrypt(_sendKey, nonce, packet, Array.Empty<byte>());

        var result = new byte[16 + encrypted.Length];
        Buffer.BlockCopy(header, 0, result, 0, 16);
        Buffer.BlockCopy(encrypted, 0, result, 16, encrypted.Length);

        return result;
    }

    /// <summary>
    /// Decrypts one inbound WireGuard transport data message. Expected layout:
    /// message type (LE u32 = 4) at offset 0, receiver index (LE u32) at offset 4,
    /// counter (LE u64) at offset 8, then the ChaCha20Poly1305 ciphertext with its
    /// 16-byte tag. The nonce mirrors encryption (12 zero bytes, counter at offset 4)
    /// and no AEAD associated data is used.
    /// </summary>
    /// <param name="encryptedPacket">The raw data message (at least 16 bytes).</param>
    /// <param name="receiverIndex">
    /// When this method returns, the 4-byte session index read from the packet header
    /// (offset 4) — the receiver index identifying which of the receiver's sessions
    /// the packet belongs to.
    /// </param>
    /// <returns>The decrypted plaintext packet bytes.</returns>
    /// <exception cref="ObjectDisposedException">Thrown when the transport has been disposed.</exception>
    /// <exception cref="ArgumentException">Thrown when the packet is too short or not a data packet.</exception>
    /// <exception cref="System.Security.Cryptography.CryptographicException">Thrown when AEAD authentication fails.</exception>
    /// <exception cref="InvalidOperationException">Thrown when a replay or invalid counter is detected.</exception>
    public byte[] DecryptPacket(byte[] encryptedPacket, out uint receiverIndex)
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(WireGuardTransport), "Transport key material has been zeroed");

        if (encryptedPacket.Length < WireGuardConstants.DATA_PACKET_MIN_LEN)
            throw new ArgumentException("Packet too short", nameof(encryptedPacket));

        var messageType = BitConverter.ToUInt32(encryptedPacket, 0) & 0xFF;
        if (messageType != WireGuardConstants.TYPE_DATA)
            throw new ArgumentException($"Not a data packet: type={messageType}", nameof(encryptedPacket));

        receiverIndex = BitConverter.ToUInt32(encryptedPacket, 4);
        var counter = BitConverter.ToUInt64(encryptedPacket, 8);

        var nonce = GetNonce();
        Array.Clear(nonce, 0, 12);
        BitConverter.GetBytes(counter).CopyTo(nonce, 4);

        var header = GetHeader();
        Buffer.BlockCopy(encryptedPacket, 0, header, 0, 16);

        var ciphertextLength = encryptedPacket.Length - 16;
        var ciphertextWithTag = new byte[ciphertextLength];
        Buffer.BlockCopy(encryptedPacket, 16, ciphertextWithTag, 0, ciphertextLength);

        // WireGuard transport data packets do NOT use AEAD associated data (AD).
        // Linux kernel WireGuard passes NULL/0 for AD: chacha20poly1305_decrypt_sg_inplace(sg, len, NULL, 0, nonce, key)
        var plaintext = ChaCha20Poly1305.Decrypt(_recvKey, nonce, ciphertextWithTag, Array.Empty<byte>());

        // Aligned with kernel WireGuard / wireguard-go: AEAD authentication first,
        // then the replay window commit. If the counter were committed before
        // decryption, a forged packet carrying a large counter could push the window
        // up and cause legitimate packets to be rejected (a remote DoS).
        if (!_replayProtector.ValidateCounter(counter))
        {
            throw new InvalidOperationException($"Replay attack detected or invalid counter (counter={counter}, windowLast={_replayProtector.LastCounter})");
        }

        return plaintext;
    }

    /// <summary>
    /// Returns the number of packets encrypted so far with this transport; the next
    /// outbound packet uses this counter value.
    /// </summary>
    /// <returns>The current send counter (atomic 64-bit read).</returns>
    public ulong GetCurrentSendCounter()
    {
        return Interlocked.Read(ref _sendCounter);
    }

    /// <summary>
    /// [VM-REPLAY-RECOVER-GATE 2026-10-31] Largest accepted receive counter (the
    /// replay window's high-water mark). Used by higher layers to distinguish a
    /// replay rejection caused by "the same packet delivered twice" (counter equal to
    /// this value) from one caused by "the peer rebuilt its session" (counter far
    /// below this value).
    /// </summary>
    public ulong LastReceivedCounter => _replayProtector.LastCounter;

    /// <summary>
    /// [VM-REPLAY-RECOVER 2026-10-21] Resets the receive replay window (used to
    /// realign after the peer rebuilt its session). Intended to be called only when a
    /// packet that already passed AEAD authentication was wrongly rejected by the
    /// window — forged packets cannot pass authentication, so resetting does not
    /// weaken replay protection (an attacker without the keys cannot construct a
    /// valid new packet).
    /// </summary>
    public void ResetReplayWindow()
    {
        _replayProtector.Reset();
    }

    /// <summary>
    /// Disposes the transport: securely zeroes the send and receive key arrays in
    /// place with <c>CryptographicOperations.ZeroMemory</c> — including the arrays
    /// originally passed to the constructor, which are stored by reference. Idempotent.
    /// </summary>
    public void Dispose()
    {
        if (_disposed) return;

        System.Security.Cryptography.CryptographicOperations.ZeroMemory(_sendKey);
        System.Security.Cryptography.CryptographicOperations.ZeroMemory(_recvKey);
        _disposed = true;
    }
}
