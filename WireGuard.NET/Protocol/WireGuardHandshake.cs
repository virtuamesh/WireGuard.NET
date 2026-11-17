using System.Security.Cryptography;
using WireGuard.NET.Crypto;
using WireGuard.NET.Protocol.Noise;

namespace WireGuard.NET.Protocol;

/// <summary>
/// Creates and parses WireGuard handshake messages (initiation and response) on top of
/// the Noise_IKpsk2 pattern implemented by <see cref="NoiseHandshakeState"/>: message
/// framing (type + session indices + Noise payload), MAC1/MAC2 computation and
/// validation, and TAI64N timestamp generation.
/// An instance holds the local private key and an optional preshared key for the
/// responder role. It performs no internal locking, so callers must serialize access
/// when it is shared across threads.
/// </summary>
public class WireGuardHandshake : IDisposable
{
    private byte[] _privateKey;
    private readonly byte[] _publicKey;
    private byte[]? _presharedKey;
    private bool _disposed;

    /// <summary>
    /// Optional per-peer-public-key token bucket (CPU-amplification protection for
    /// MAC1-valid initiations). When non-null, <see cref="ReadInitiation(byte[], IEnumerable{byte[]}?)"/>
    /// consumes one token per candidate public key before attempting to decrypt with
    /// it; candidates without a token are skipped, bounding the amplification surface
    /// (up to 3 X25519 operations per candidate per packet) to the token rate. Injected
    /// by WireGuardDevice, which also owns the StartCleanup/StopCleanup lifecycle.
    /// </summary>
    public RateLimiter? PeerRateLimiter { get; set; }

    // Domain-separation label for MAC1 key derivation per the WireGuard specification.
    private static readonly byte[] Mac1Label = System.Text.Encoding.UTF8.GetBytes("mac1----");

    /// <summary>
    /// Diagnostic event carrying human-readable handshake trace messages (e.g. matched
    /// peer keys, MAC validation results). Raised on the calling thread; may be
    /// <c>null</c> when no listener is attached.
    /// </summary>
    public event EventHandler<string>? OnDebugLog;

    /// <summary>Raises <see cref="OnDebugLog"/> with the given message, if a listener is attached.</summary>
    /// <param name="message">The diagnostic message to emit.</param>
    private void DebugLog(string message)
    {
        OnDebugLog?.Invoke(this, message);
    }

    /// <summary>
    /// Sets the preshared key mixed into Noise states created while processing inbound
    /// initiations (responder role). The array is cloned; passing <c>null</c> clears
    /// the key.
    /// </summary>
    /// <param name="presharedKey">32-byte preshared key, or <c>null</c> to clear.</param>
    public void SetPresharedKey(byte[]? presharedKey)
    {
        _presharedKey = presharedKey != null ? (byte[])presharedKey.Clone() : null;
    }

    /// <summary>
    /// Creates a handshake engine bound to the local key pair. The private key is
    /// cloned and the public key is derived from it; both are zeroed on
    /// <see cref="Dispose"/>.
    /// </summary>
    /// <param name="privateKey">The local 32-byte X25519 private key.</param>
    /// <exception cref="ArgumentException">Thrown when the private key is not 32 bytes.</exception>
    /// <remarks>
    /// Emits the derived public key (base64) through <see cref="OnDebugLog"/> for
    /// diagnostics.
    /// </remarks>
    public WireGuardHandshake(byte[] privateKey)
    {
        if (privateKey.Length != 32)
            throw new ArgumentException("Private key must be 32 bytes", nameof(privateKey));

        _privateKey = (byte[])privateKey.Clone();
        _publicKey = X25519Crypto.GeneratePublicKey(_privateKey);

        // [VM-S2] No longer logs a private-key hash (it could assist brute-force attacks);
        // only the public key is logged for debugging.
        OnDebugLog?.Invoke(this, $"WireGuardHandshake ctor: pubKey={Convert.ToBase64String(_publicKey)}");
    }

    /// <summary>
    /// Builds a handshake initiation message (WireGuard type 1) for the given peer.
    /// Message layout: type (LE u32) at offset 0, our sender index (LE u32) at offset
    /// 4, 108-byte Noise payload at offset 8, MAC1 (16 bytes) at offset 116, MAC2
    /// (16 bytes) at offset 132; total length 148 bytes.
    /// </summary>
    /// <param name="peerPublicKey">The peer's 32-byte X25519 public key.</param>
    /// <param name="presharedKey">
    /// Optional per-handshake 32-byte preshared key; when <c>null</c>, the handshake
    /// runs without a PSK.
    /// </param>
    /// <param name="cookie">
    /// Optional 16-byte cookie previously issued by the peer under load, used to key
    /// MAC2. When <c>null</c> (or not 16 bytes), MAC2 is emitted as all zeros.
    /// </param>
    /// <returns>
    /// A tuple of:
    /// <c>message</c> — the full 148-byte initiation message ready to send;
    /// <c>state</c> — the Noise handshake state; pass it to
    /// <see cref="ProcessResponse(byte[], NoiseHandshakeState)"/> when the peer
    /// answers;
    /// <c>localIndex</c> — the random 31-bit sender index embedded in the message.
    /// </returns>
    /// <exception cref="ArgumentException">Thrown when the peer public key is not 32 bytes.</exception>
    public (byte[] message, NoiseHandshakeState state, uint localIndex) CreateInitiation(
        byte[] peerPublicKey,
        byte[]? presharedKey = null,
        byte[]? cookie = null)
    {
        if (peerPublicKey == null || peerPublicKey.Length != 32)
            throw new ArgumentException("Peer public key must be 32 bytes", nameof(peerPublicKey));

        var localIndex = (uint)RandomNumberGenerator.GetInt32(int.MinValue, int.MaxValue) & 0x7FFFFFFF;

        var handshake = new NoiseHandshakeState(
            _privateKey,
            peerPublicKey,
            true,
            presharedKey
        );

        var timestamp = GenerateTimestamp();
        var noiseMessage = handshake.WriteMessage(timestamp);

        var messageWithoutMacs = BuildInitiationMessage(localIndex, noiseMessage);
        var (mac1, mac2) = ComputeMacs(peerPublicKey, messageWithoutMacs, cookie);

        var fullMessage = new byte[messageWithoutMacs.Length + 32];
        Buffer.BlockCopy(messageWithoutMacs, 0, fullMessage, 0, messageWithoutMacs.Length);
        Buffer.BlockCopy(mac1, 0, fullMessage, messageWithoutMacs.Length, 16);
        Buffer.BlockCopy(mac2, 0, fullMessage, messageWithoutMacs.Length + 16, 16);

        return (fullMessage, handshake, localIndex);
    }

    /// <summary>
    /// Not supported: the Noise_IKpsk2 responder requires the list of known peer
    /// public keys in order to perform the pre-message MixHash of the initiator's
    /// static key. Always throws; use
    /// <see cref="ProcessInitiation(byte[], IEnumerable{byte[]}, byte[])"/> instead.
    /// </summary>
    /// <param name="message">Not used.</param>
    /// <param name="presharedKey">Not used.</param>
    /// <exception cref="InvalidOperationException">Always thrown by this overload.</exception>
    public (NoiseHandshakeState state, uint senderIndex, byte[] peerPublicKey, byte[] message, uint localIndex, byte[] sendKey, byte[] recvKey) ProcessInitiation(
        byte[] message,
        byte[]? presharedKey = null)
    {
        throw new InvalidOperationException(
            "ProcessInitiation(message, psk) is not supported in Noise_IKpsk2 mode without known peer public keys. " +
            "Use the overload that takes knownPeerPublicKeys.");
    }

    /// <summary>
    /// Processes an inbound initiation message as the responder: authenticates it
    /// against the known peer public keys, applies the preshared key, builds the
    /// response and derives the transport keys.
    /// </summary>
    /// <param name="message">The raw 148-byte initiation message (WireGuard type 1).</param>
    /// <param name="knownPeerPublicKeys">
    /// Candidate peer public keys (32 bytes each) tried one by one until one
    /// authenticates; required by the Noise_IKpsk2 responder.
    /// </param>
    /// <param name="presharedKey">
    /// Optional 32-byte preshared key applied to the matched handshake state before
    /// the response is created; <c>null</c> to keep the state PSK-less.
    /// </param>
    /// <returns>
    /// A tuple of:
    /// <c>state</c> — the Noise handshake state of the matched peer;
    /// <c>senderIndex</c> — the initiator's session index (message offset 4);
    /// <c>peerPublicKey</c> — the matched initiator's public key;
    /// <c>message</c> — the 92-byte response message ready to send;
    /// <c>localIndex</c> — our freshly generated session index;
    /// <c>sendKey</c> / <c>recvKey</c> — the derived 32-byte transport keys.
    /// </returns>
    /// <exception cref="CryptographicException">
    /// Thrown when MAC1 validation fails or no known peer authenticates (see
    /// <see cref="ReadInitiation(byte[], IEnumerable{byte[]}?)"/>).
    /// </exception>
    public (NoiseHandshakeState state, uint senderIndex, byte[] peerPublicKey, byte[] message, uint localIndex, byte[] sendKey, byte[] recvKey) ProcessInitiation(
        byte[] message,
        IEnumerable<byte[]>? knownPeerPublicKeys,
        byte[]? presharedKey = null)
    {
        var (handshake, senderIndex, peerPublicKey, _) = ReadInitiation(message, knownPeerPublicKeys);

        if (presharedKey != null)
        {
            handshake.SetPresharedKey(presharedKey);
        }

        var (responseMessage, localIndex, sendKey, recvKey) = CreateResponse(handshake, senderIndex, peerPublicKey);

        return (handshake, senderIndex, peerPublicKey, responseMessage, localIndex, sendKey, recvKey);
    }

    /// <summary>
    /// Reads an initiation message without building a response. Delegates to
    /// <see cref="ReadInitiation(byte[], IEnumerable{byte[]}?)"/> with no known peer
    /// keys, which the Noise_IKpsk2 responder requires — so this overload always
    /// throws; use the two-argument overload instead.
    /// </summary>
    /// <param name="message">The raw initiation message.</param>
    /// <exception cref="CryptographicException">Always thrown, because the responder needs the known peer public keys.</exception>
    public (NoiseHandshakeState state, uint senderIndex, byte[] peerPublicKey) ReadInitiation(
        byte[] message)
    {
        var (state, senderIndex, peerPublicKey, _) = ReadInitiation(message, null);
        return (state, senderIndex, peerPublicKey);
    }

    /// <summary>
    /// Parses and authenticates an inbound initiation message: validates length, type
    /// and MAC1, then tries every known peer public key as the initiator's pre-message
    /// static key until one decrypts successfully.
    /// Message layout: type (LE u32) at offset 0, sender index (LE u32) at offset 4,
    /// 108-byte Noise payload at offset 8, MAC1 (16 bytes) at offset 116, MAC2
    /// (16 bytes) at offset 132.
    /// </summary>
    /// <param name="message">The raw 148-byte initiation message (WireGuard type 1).</param>
    /// <param name="knownPeerPublicKeys">
    /// Candidate peer public keys (32 bytes each); required — <c>null</c> throws,
    /// because the Noise_IKpsk2 responder must MixHash the initiator's static public
    /// key during the pre-message phase.
    /// </param>
    /// <returns>
    /// A tuple of:
    /// <c>state</c> — the Noise handshake state for the matched peer (ownership
    /// transfers to the caller, who must dispose it);
    /// <c>senderIndex</c> — the initiator's session index;
    /// <c>peerPublicKey</c> — the matched initiator's public key;
    /// <c>timestamp</c> — the 12-byte TAI64N handshake timestamp extracted from the
    /// Noise payload (empty array when the payload carried none).
    /// </returns>
    /// <exception cref="ArgumentException">Thrown on invalid message length or type.</exception>
    /// <exception cref="CryptographicException">
    /// Thrown when <paramref name="knownPeerPublicKeys"/> is <c>null</c>, when MAC1
    /// validation fails, or when every candidate fails authentication.
    /// </exception>
    public (NoiseHandshakeState state, uint senderIndex, byte[] peerPublicKey, byte[] timestamp) ReadInitiation(
        byte[] message, IEnumerable<byte[]>? knownPeerPublicKeys)
    {
        if (message.Length != WireGuardConstants.HANDSHAKE_INITIATION_LEN)
            throw new ArgumentException($"Invalid initiation message length: {message.Length}, expected {WireGuardConstants.HANDSHAKE_INITIATION_LEN}");

        var messageType = BitConverter.ToUInt32(message, 0) & 0xFF;
        if (messageType != WireGuardConstants.TYPE_INITIATION)
            throw new ArgumentException($"Invalid message type: {messageType}");

        var senderIndex = BitConverter.ToUInt32(message, 4);
        var noiseMessage = new byte[108];
        Buffer.BlockCopy(message, 8, noiseMessage, 0, 108);

        DebugLog($"ReadInitiation: senderIndex={senderIndex}, myPubKey={Convert.ToBase64String(_publicKey)}");
        DebugLog($"ReadInitiation: noiseMsg ephemeral={BitConverter.ToString(noiseMessage, 0, 16)}...");

        // Critical fix: in the Noise_IKpsk2 protocol the responder must MixHash the
        // initiator's static public key during the pre-message phase (the `<- s`
        // pattern). The responder therefore iterates over all known peer public keys
        // and attempts to decrypt the message with each one; the candidate that
        // decrypts successfully (i.e. whose authentication tag verifies) is the
        // matching peer. This matches the official wireguard-go implementation.
        if (knownPeerPublicKeys == null)
        {
            throw new CryptographicException(
                "Noise_IKpsk2 responder requires known peer public keys list to perform pre-message MixHash");
        }

        // 1) MAC1 must be keyed with the receiver's (responder's) own public key,
        //    so a quick MAC1 check first avoids unnecessary decryption attempts.
        //    Note: MAC1 covers the message with the trailing 32 MAC bytes removed.
        if (!ValidateMac1(_publicKey, message, message.Length - 32))
        {
            DebugLog($"ReadInitiation: MAC1 validation failed (responder={Convert.ToBase64String(_publicKey)})");
            throw new CryptographicException("MAC1 validation failed");
        }
        DebugLog($"ReadInitiation: MAC1 validated, attempting peer-key iterations");

        NoiseHandshakeState? handshake = null;
        byte[]? peerPublicKey = null;
        byte[]? timestamp = null;

        foreach (var candidatePub in knownPeerPublicKeys)
        {
            if (candidatePub == null || candidatePub.Length != 32) continue;

            // A MAC1-valid initiation can still be flooded (the MAC1 key is derived
            // publicly from this node's public key, so anyone can forge it). Consume a
            // token for the candidate public key before constructing a
            // NoiseHandshakeState (up to 3 X25519 operations per candidate); when the
            // limit is exceeded the candidate is skipped, converging the global rate
            // onto the token-bucket rate.
            if (PeerRateLimiter != null && !PeerRateLimiter.AllowPublicKey(candidatePub))
            {
                continue;
            }

            var tryHandshake = new NoiseHandshakeState(
                _privateKey,
                candidatePub,   // <-- In IK mode the responder must use the initiator's public key as the pre-message rs
                false,
                _presharedKey
            );
            tryHandshake.OnDebugLog += (sender, msg) => DebugLog($"[NoiseState candidate={Convert.ToBase64String(candidatePub).Substring(0, 12)}] {msg}");

            try
            {
                var ts = tryHandshake.ReadMessage(noiseMessage, senderIndex);
                var rs = tryHandshake.GetRemoteStaticKey();

                // Verify that the decrypted rs matches the candidate
                // [VM-S3] Use constant-time comparison to prevent timing side-channel attacks
                if (rs != null && rs.Length == 32 && CryptographicOperations.FixedTimeEquals(rs, candidatePub))
                {
                    handshake = tryHandshake;
                    peerPublicKey = candidatePub;
                    timestamp = ts;
                    break;
                }
                else
                {
                    tryHandshake.Dispose();
                    DebugLog($"ReadInitiation: candidate {Convert.ToBase64String(candidatePub)} decrypted but rs mismatch");
                }
            }
            catch (NoiseAuthenticationException)
            {
                tryHandshake.Dispose();
                // This public key is not the actual initiator; try the next candidate
            }
            catch (Exception ex)
            {
                tryHandshake.Dispose();
                DebugLog($"ReadInitiation: candidate {Convert.ToBase64String(candidatePub)} failed: {ex.Message}");
            }
        }

        if (handshake == null || peerPublicKey == null)
        {
            throw new CryptographicException("No matching peer found for initiation message (all candidates failed authentication tag verification)");
        }

        DebugLog($"ReadInitiation: matched peer {Convert.ToBase64String(peerPublicKey)}, timestamp={BitConverter.ToString(timestamp ?? Array.Empty<byte>())[..Math.Min(24, (timestamp?.Length ?? 0) * 3)]}...");

        return (handshake, senderIndex, peerPublicKey, timestamp ?? Array.Empty<byte>());
    }

    /// <summary>
    /// Builds a handshake response message (WireGuard type 2) using the handshake state
    /// produced by <see cref="ReadInitiation(byte[], IEnumerable{byte[]}?)"/>, then
    /// splits the Noise state into transport keys.
    /// Message layout: type (LE u32) at offset 0, our sender index (LE u32) at offset
    /// 4, the initiator's index echoed (LE u32) at offset 8, 48-byte Noise payload at
    /// offset 12, MAC1 (16 bytes) at offset 60, MAC2 (16 bytes) at offset 76; total
    /// length 92 bytes.
    /// </summary>
    /// <param name="handshake">The Noise state of the matched peer (responder role).</param>
    /// <param name="senderIndex">The initiator's session index to echo back.</param>
    /// <param name="peerPublicKey">The peer's 32-byte public key, used to derive the MAC1 key.</param>
    /// <param name="cookie">
    /// Optional 16-byte cookie previously issued by the peer under load, used to key
    /// MAC2. When <c>null</c> (or not 16 bytes), MAC2 is emitted as all zeros.
    /// </param>
    /// <returns>
    /// A tuple of:
    /// <c>message</c> — the full 92-byte response message ready to send;
    /// <c>localIndex</c> — the random 31-bit sender index embedded in the message;
    /// <c>sendKey</c> / <c>recvKey</c> — the 32-byte transport keys derived by
    /// splitting the Noise state.
    /// </returns>
    public (byte[] message, uint localIndex, byte[] sendKey, byte[] recvKey) CreateResponse(
        NoiseHandshakeState handshake,
        uint senderIndex,
        byte[] peerPublicKey,
        byte[]? cookie = null)
    {
        var localIndex = (uint)RandomNumberGenerator.GetInt32(int.MinValue, int.MaxValue) & 0x7FFFFFFF;

        var responseNoise = handshake.WriteMessage(Array.Empty<byte>());

        var responseWithoutMacs = BuildResponseMessage(localIndex, senderIndex, responseNoise);
        var (mac1, mac2) = ComputeMacs(peerPublicKey, responseWithoutMacs, cookie);

        var fullResponse = new byte[responseWithoutMacs.Length + 32];
        Buffer.BlockCopy(responseWithoutMacs, 0, fullResponse, 0, responseWithoutMacs.Length);
        Buffer.BlockCopy(mac1, 0, fullResponse, responseWithoutMacs.Length, 16);
        Buffer.BlockCopy(mac2, 0, fullResponse, responseWithoutMacs.Length + 16, 16);

        var (sendKey, recvKey) = handshake.Split();

        return (fullResponse, localIndex, sendKey, recvKey);
    }

    /// <summary>
    /// Processes an inbound response message (WireGuard type 2) as the initiator,
    /// completing the handshake and deriving the transport keys.
    /// Message layout: type (LE u32) at offset 0, sender index (LE u32) at offset 4,
    /// receiver index (LE u32) at offset 8, 48-byte Noise payload at offset 12, MAC1
    /// (16 bytes) at offset 60, MAC2 (16 bytes) at offset 76.
    /// </summary>
    /// <param name="message">The raw 92-byte response message.</param>
    /// <param name="state">
    /// The Noise state returned by <see cref="CreateInitiation(byte[], byte[], byte[])"/>
    /// for this handshake.
    /// </param>
    /// <returns>
    /// A tuple of:
    /// <c>senderIndex</c> — the responder's session index (message offset 4);
    /// <c>sendKey</c> / <c>recvKey</c> — the 32-byte transport keys derived by
    /// splitting the Noise state.
    /// </returns>
    /// <exception cref="ArgumentException">Thrown on invalid message length or type.</exception>
    public (uint senderIndex, byte[] sendKey, byte[] recvKey) ProcessResponse(
        byte[] message, NoiseHandshakeState state)
    {
        if (message.Length != WireGuardConstants.HANDSHAKE_RESPONSE_LEN)
            throw new ArgumentException($"Invalid response message length: {message.Length}, expected {WireGuardConstants.HANDSHAKE_RESPONSE_LEN}");

        var messageType = BitConverter.ToUInt32(message, 0) & 0xFF;
        if (messageType != WireGuardConstants.TYPE_RESPONSE)
            throw new ArgumentException($"Invalid message type: {messageType}");

        var senderIndex = BitConverter.ToUInt32(message, 4);
        var noiseMessage = new byte[48];
        Buffer.BlockCopy(message, 12, noiseMessage, 0, 48);

        var payload = state.ReadMessage(noiseMessage);
        var (sendKey, recvKey) = state.Split();

        return (senderIndex, sendKey, recvKey);
    }

    /// <summary>
    /// Assembles the initiation message header + Noise payload (without MACs):
    /// type (LE u32) at offset 0, sender index (LE u32) at offset 4, Noise payload at
    /// offset 8.
    /// </summary>
    /// <param name="senderIndex">Our 4-byte session index.</param>
    /// <param name="noiseContent">The Noise handshake payload bytes.</param>
    /// <returns>The initiation message body without the trailing MAC1/MAC2.</returns>
    private static byte[] BuildInitiationMessage(uint senderIndex, byte[] noiseContent)
    {
        var result = new byte[WireGuardConstants.MESSAGE_TYPE_LEN + WireGuardConstants.MESSAGE_INDEX_LEN + noiseContent.Length];

        BitConverter.GetBytes(WireGuardConstants.TYPE_INITIATION).CopyTo(result, 0);
        BitConverter.GetBytes(senderIndex).CopyTo(result, 4);
        Buffer.BlockCopy(noiseContent, 0, result, 8, noiseContent.Length);

        return result;
    }

    /// <summary>
    /// Assembles the response message header + Noise payload (without MACs):
    /// type (LE u32) at offset 0, sender index (LE u32) at offset 4, receiver index
    /// (LE u32) at offset 8, Noise payload at offset 12.
    /// </summary>
    /// <param name="senderIndex">Our 4-byte session index.</param>
    /// <param name="receiverIndex">The initiator's 4-byte session index to echo.</param>
    /// <param name="noiseContent">The Noise handshake payload bytes.</param>
    /// <returns>The response message body without the trailing MAC1/MAC2.</returns>
    private static byte[] BuildResponseMessage(uint senderIndex, uint receiverIndex, byte[] noiseContent)
    {
        var result = new byte[WireGuardConstants.MESSAGE_TYPE_LEN + WireGuardConstants.MESSAGE_INDEX_LEN * 2 + noiseContent.Length];

        BitConverter.GetBytes(WireGuardConstants.TYPE_RESPONSE).CopyTo(result, 0);
        BitConverter.GetBytes(senderIndex).CopyTo(result, 4);
        BitConverter.GetBytes(receiverIndex).CopyTo(result, 8);
        Buffer.BlockCopy(noiseContent, 0, result, 12, noiseContent.Length);

        return result;
    }

    // WireGuard spec: mac1 = MAC(HASH("mac1----" || responderPub), msg[0..-32]);
    // mac2 = MAC(cookie, msg[0..-16]) (i.e. the input includes mac1, and the key is
    // the 16-byte cookie itself issued by the peer). Without a cookie, mac2 must be
    // all zeros.
    private static (byte[] mac1, byte[] mac2) ComputeMacs(byte[] peerPublicKey, byte[] message, byte[]? cookie = null)
    {
        var mac1Key = Blake2s.Hash(Combine(Mac1Label, peerPublicKey));
        var mac1 = Blake2s.Hash128(message, mac1Key);

        byte[] mac2;
        if (cookie != null && cookie.Length == 16)
        {
            mac2 = Blake2s.Hash128(Combine(message, mac1), cookie);
        }
        else
        {
            mac2 = new byte[16];
        }

        return (mac1, mac2);
    }

    /// <summary>
    /// Validates the MAC1 field of a full handshake message in constant time.
    /// </summary>
    /// <param name="publicKey">
    /// The receiver's 32-byte public key; the MAC1 key is derived from it, so this
    /// must be our own key when validating inbound messages.
    /// </param>
    /// <param name="fullMessage">The complete handshake message including MAC1 and MAC2.</param>
    /// <param name="mac1Offset">
    /// Byte offset where MAC1 starts (message length − 32); MAC1 covers everything
    /// before it and MAC2 is the 16 bytes after it.
    /// </param>
    /// <returns><c>true</c> when the computed MAC1 matches the received one.</returns>
    public static bool ValidateMac1(byte[] publicKey, byte[] fullMessage, int mac1Offset)
    {
        var mac1Key = Blake2s.Hash(Combine(Mac1Label, publicKey));

        var messageWithoutMacs = fullMessage.Take(mac1Offset).ToArray();
        var receivedMac1 = fullMessage.Skip(mac1Offset).Take(16).ToArray();

        var computedMac1 = Blake2s.Hash128(messageWithoutMacs, mac1Key);

        return CryptographicOperations.FixedTimeEquals(computedMac1, receivedMac1);
    }

    /// <summary>
    /// Derives the 32-byte MAC1 key for a given public key:
    /// <c>HASH("mac1----" || publicKey)</c> per the WireGuard specification.
    /// </summary>
    /// <param name="publicKey">The 32-byte public key to derive the MAC1 key from.</param>
    /// <returns>The 32-byte MAC1 key.</returns>
    public static byte[] ComputeMac1Key(byte[] publicKey)
    {
        return Blake2s.Hash(Combine(Mac1Label, publicKey));
    }

    /// <summary>
    /// Generates the 12-byte TAI64N timestamp used as the initiation payload:
    /// big-endian 64-bit TAI64 seconds at offset 0 (Unix seconds + 2^62 + 10, the TAI64
    /// label plus the fixed TAI−UTC offset) and big-endian 32-bit nanoseconds within
    /// the current second at offset 8.
    /// </summary>
    /// <returns>A fresh 12-byte TAI64N timestamp.</returns>
    private static byte[] GenerateTimestamp()
    {
        var tai64n = new byte[12];

        var epochStart = new DateTimeOffset(1970, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var now = DateTimeOffset.UtcNow;
        var secondsSinceEpoch = (ulong)(now - epochStart).TotalSeconds;
        var taiSeconds = secondsSinceEpoch + 4611686018427387914UL;

        var nanoseconds = (uint)((now.Ticks % 10000000) * 100);

        var bigEndianSeconds = BitConverter.GetBytes(taiSeconds);
        if (BitConverter.IsLittleEndian)
            Array.Reverse(bigEndianSeconds);
        Buffer.BlockCopy(bigEndianSeconds, 0, tai64n, 0, 8);

        var bigEndianNano = BitConverter.GetBytes(nanoseconds);
        if (BitConverter.IsLittleEndian)
            Array.Reverse(bigEndianNano);
        Buffer.BlockCopy(bigEndianNano, 0, tai64n, 8, 4);

        return tai64n;
    }

    /// <summary>Concatenates the given byte arrays in order into a single new array.</summary>
    /// <param name="arrays">The arrays to concatenate.</param>
    /// <returns>A new array containing all input bytes in the given order.</returns>
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
    /// Disposes the engine: securely zeroes the local private key and the preshared
    /// key (if set) with <c>CryptographicOperations.ZeroMemory</c>. Idempotent.
    /// </summary>
    public void Dispose()
    {
        if (_disposed) return;

        CryptographicOperations.ZeroMemory(_privateKey);
        // [VM-S1] Securely zero the PSK to prevent sensitive key material lingering in memory
        if (_presharedKey != null) CryptographicOperations.ZeroMemory(_presharedKey);
        _disposed = true;
    }
}
