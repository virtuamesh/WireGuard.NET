using System.Security.Cryptography;
using WireGuard.NET.Crypto;

namespace WireGuard.NET.Protocol.Noise;

/// <summary>
/// State machine for a single Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s handshake, as specified in
/// the WireGuard whitepaper (Noise_IKpsk2). Holds the local/remote static and ephemeral X25519
/// key material, the pre-shared key, the message-token patterns and the underlying
/// <see cref="NoiseSymmetricState"/>.
/// <para>
/// State-machine transitions: pattern index 0 (handshake initiation) is e, es, s, ss; pattern
/// index 1 (handshake response) is e, ee, se, psk. The initiator writes message 1 via
/// <see cref="WriteMessage"/> and reads message 2 via <see cref="ReadMessage"/>; the responder
/// mirrors the order. Each token consumes key material from the message stream and advances the
/// <see cref="NoiseSymmetricState"/> key-derivation chain; the trailing payload is
/// AEAD-encrypted with the running hash as associated data. After both patterns are consumed,
/// <see cref="Split"/> derives the two ChaCha20-Poly1305 transport keys — the initiator sends
/// with k1 and receives with k2, the responder mirrors. Using the state after that throws
/// <see cref="NoiseHandshakeConsumedException"/>.
/// </para>
/// <para>
/// The MAC1/MAC2 fields and the cookie/under-load mechanics described in the WireGuard
/// whitepaper are applied at the WireGuard message-framing layer (WireGuardHandshake /
/// CookieProtector) and are outside the scope of this class.
/// </para>
/// <para>
/// Disposing the state zeroes all private key material and the pre-shared key. Instances are
/// not thread-safe: one handshake state drives exactly one message exchange.
/// </para>
/// </summary>
public class NoiseHandshakeState : IDisposable
{
    private const string Construction = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
    private const string Identifier = "WireGuard v1 zx2c4 Jason@zx2c4.com";

    private NoiseSymmetricState _symmetric;
    private byte[]? _s;
    private byte[]? _e;
    private byte[]? _rs;
    private byte[]? _re;
    private byte[] _psk;
    private bool _initiator;
    private int _messagePatternsIndex;
    private readonly List<List<Token>> _messagePatterns;
    private bool _disposed;

    /// <summary>
    /// Debug/tracing event fired at handshake state-machine transitions. Messages are redacted
    /// for safety: only public keys, truncated public-key fingerprints and high-level progress
    /// are emitted — private keys, DH shared secrets and intermediate hash/chaining-key values
    /// are never logged.
    /// </summary>
    public event EventHandler<string>? OnDebugLog;

    private void DebugLog(string message)
    {
        OnDebugLog?.Invoke(this, message);
    }

    /// <summary>
    /// Initializes a fresh Noise_IKpsk2 handshake state. Seeds the symmetric state from the
    /// protocol construction string (h = padded-or-hashed construction bytes, ck = h), mixes
    /// the WireGuard protocol identifier into h, pre-mixes the responder-side static public
    /// key into the hash — the initiator mixes the known remote static public key, the
    /// responder its own local static public key — and installs the two message patterns.
    /// </summary>
    /// <param name="localStaticPrivate">Local X25519 static private key (32 bytes).</param>
    /// <param name="remoteStaticPublic">Remote X25519 static public key (32 bytes); required for the initiator, optional for the responder.</param>
    /// <param name="initiator">True to act as handshake initiator, false as responder.</param>
    /// <param name="presharedKey">Optional 32-byte pre-shared key (all zeros when not supplied); mixed in by the response pattern's Token.Psk step.</param>
    public NoiseHandshakeState(
        byte[] localStaticPrivate,
        byte[]? remoteStaticPublic,
        bool initiator,
        byte[]? presharedKey = null)
    {
        _s = (byte[])localStaticPrivate.Clone();
        _rs = remoteStaticPublic != null ? (byte[])remoteStaticPublic.Clone() : null;
        _initiator = initiator;
        _messagePatternsIndex = 0;
        _psk = presharedKey != null ? (byte[])presharedKey.Clone() : new byte[32];

        var localPubFromS = X25519Crypto.GeneratePublicKey(_s);
        // [VM-S2] No longer emit privKeyHash (it could aid brute-force attacks); emit only the public key for debugging.
        DebugLog($"NoiseHandshakeState ctor: initiator={initiator}, pubKey={Convert.ToBase64String(localPubFromS)}");

        var protocolNameBytes = System.Text.Encoding.UTF8.GetBytes(Construction);
        byte[] h;
        if (protocolNameBytes.Length <= 32)
        {
            h = new byte[32];
            Buffer.BlockCopy(protocolNameBytes, 0, h, 0, protocolNameBytes.Length);
        }
        else
        {
            h = Blake2s.Hash(protocolNameBytes);
        }

        var ck = (byte[])h.Clone();

        _symmetric = new NoiseSymmetricState(ck, h);

        _symmetric.MixHash(System.Text.Encoding.UTF8.GetBytes(Identifier));

        if (_initiator)
        {
            if (_rs != null)
            {
                _symmetric.MixHash(_rs);
            }
        }
        else
        {
            _symmetric.MixHash(localPubFromS);
        }

        _messagePatterns = new List<List<Token>>
        {
            new() { Token.E, Token.DhEs, Token.S, Token.DhSs },
            new() { Token.E, Token.DhEe, Token.DhSe, Token.Psk }
        };
    }

    /// <summary>
    /// Serializes and encrypts the next outgoing handshake message for this side, following the
    /// current message pattern (initiation for the initiator: e, es, s, ss; response for the
    /// responder: e, ee, se, psk) and AEAD-encrypting the trailing payload. Advances the
    /// pattern index.
    /// </summary>
    /// <param name="payload">Handshake payload bytes (e.g. a timestamp for the initiation, empty for the response).</param>
    /// <returns>The serialized Noise handshake message body, without the WireGuard framing header and MAC1/MAC2 fields.</returns>
    /// <exception cref="NoiseHandshakeConsumedException">Both message patterns have already been written.</exception>
    public byte[] WriteMessage(byte[] payload)
    {
        if (_messagePatternsIndex >= _messagePatterns.Count)
            throw new NoiseHandshakeConsumedException("No more message patterns available");

        var buffer = new List<byte>();
        var pattern = _messagePatterns[_messagePatternsIndex];

        foreach (var token in pattern)
        {
            switch (token)
            {
                case Token.E:
                    if (_e == null)
                    {
                        var keyPair = Keys.KeyPair.Generate();
                        _e = keyPair.PrivateKey;
                    }
                    var ePub = X25519Crypto.GeneratePublicKey(_e);
                    buffer.AddRange(ePub);
                    _symmetric.MixHash(ePub);
                    _symmetric.MixKey(ePub);
                    break;

                case Token.S:
                    if (_s == null)
                        throw new InvalidOperationException("Static private key (_s) is null when processing Token.S");
                    var sPub = X25519Crypto.GeneratePublicKey(_s);
                    var encS = _symmetric.EncryptAndHash(sPub);
                    buffer.AddRange(encS);
                    break;

                case Token.DhEe:
                    if (_e == null) throw new InvalidOperationException("_e is null for DhEe");
                    if (_re == null) throw new InvalidOperationException("_re is null for DhEe");
                    var dhEe = X25519Crypto.ScalarMult(_e, _re);
                    _symmetric.MixKey(dhEe);
                    break;

                case Token.DhEs:
                    byte[] dhEs;
                    if (_initiator)
                    {
                        if (_e == null) throw new InvalidOperationException("_e is null for DhEs (initiator)");
                        if (_rs == null) throw new InvalidOperationException("_rs is null for DhEs (initiator)");
                        dhEs = X25519Crypto.ScalarMult(_e, _rs);
                    }
                    else
                    {
                        if (_s == null) throw new InvalidOperationException("_s is null for DhEs (responder)");
                        if (_re == null) throw new InvalidOperationException("_re is null for DhEs (responder)");
                        dhEs = X25519Crypto.ScalarMult(_s, _re);
                    }
                    _symmetric.MixKey(dhEs);
                    break;

                case Token.DhSe:
                    byte[] dhSe;
                    if (_initiator)
                    {
                        if (_s == null) throw new InvalidOperationException("_s is null for DhSe (initiator)");
                        if (_re == null) throw new InvalidOperationException("_re is null for DhSe (initiator)");
                        dhSe = X25519Crypto.ScalarMult(_s, _re);
                    }
                    else
                    {
                        if (_e == null) throw new InvalidOperationException("_e is null for DhSe (responder)");
                        if (_rs == null) throw new InvalidOperationException("_rs is null for DhSe (responder)");
                        dhSe = X25519Crypto.ScalarMult(_e, _rs);
                    }
                    _symmetric.MixKey(dhSe);
                    break;

                case Token.DhSs:
                    if (_s == null) throw new InvalidOperationException("_s is null for DhSs");
                    if (_rs == null) throw new InvalidOperationException("_rs is null for DhSs");
                    var dhSs = X25519Crypto.ScalarMult(_s, _rs);
                    _symmetric.MixKey(dhSs);
                    break;

                case Token.Psk:
                    _symmetric.MixKeyAndHash(_psk);
                    break;
            }
        }

        var encPayload = _symmetric.EncryptAndHash(payload);
        buffer.AddRange(encPayload);

        _messagePatternsIndex++;
        return buffer.ToArray();
    }

    /// <summary>
    /// Consumes and decrypts the next incoming handshake message for this side, following the
    /// current message pattern (initiation for the responder, response for the initiator) and
    /// decrypting the trailing AEAD payload. Advances the pattern index.
    /// </summary>
    /// <param name="message">The Noise handshake message body received from the peer (no WireGuard framing).</param>
    /// <param name="senderIndex">The WireGuard sender index from the framing header; used only for debug logging.</param>
    /// <returns>The decrypted handshake payload bytes.</returns>
    /// <exception cref="ObjectDisposedException">The state has been disposed.</exception>
    /// <exception cref="NoiseHandshakeConsumedException">Both message patterns have already been read.</exception>
    /// <exception cref="NoiseAuthenticationException">AEAD authentication failed — typically a remote public key candidate mismatch.</exception>
    public byte[] ReadMessage(byte[] message, uint senderIndex = 0)
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(NoiseHandshakeState));
        if (_messagePatternsIndex >= _messagePatterns.Count)
            throw new NoiseHandshakeConsumedException("No more message patterns available");

        var offset = 0;
        var pattern = _messagePatterns[_messagePatternsIndex];
        var myPubKey = _s != null ? X25519Crypto.GeneratePublicKey(_s) : null;
        var myPubKeyB64 = myPubKey != null ? Convert.ToBase64String(myPubKey) : "null";
        DebugLog($"ReadMessage: initiator={_initiator}, myPubKey={myPubKeyB64}, msgLen={message.Length}");

        foreach (var token in pattern)
        {
            switch (token)
            {
                case Token.E:
                    if (offset + 32 > message.Length)
                        throw new InvalidOperationException("Message too short for Token.E");
                    _re = message.Skip(offset).Take(32).ToArray();
                    offset += 32;
                    _symmetric.MixHash(_re);
                    _symmetric.MixKey(_re);
                    // [VM-S2] No longer emit intermediate cryptographic state such as hash/ck.
                    DebugLog($"Token.E: re={BitConverter.ToString(_re)[..Math.Min(24, _re.Length * 3)]}...");
                    break;

                case Token.S:
                    if (offset + 48 > message.Length)
                        throw new InvalidOperationException("Message too short for Token.S");
                    var temp = message.Skip(offset).Take(48).ToArray();
                    offset += 48;
                    // [VM-S2] Do not emit the full peer static public key, only a truncated fingerprint to correlate log lines.
                    _rs = _symmetric.DecryptAndHash(temp);
                    DebugLog($"Token.S: senderIndex={senderIndex}, rsFingerprint={Convert.ToBase64String(_rs)[..12]}...");
                    break;

                case Token.DhEe:
                    if (_e == null) throw new InvalidOperationException("_e is null for DhEe in ReadMessage");
                    if (_re == null) throw new InvalidOperationException("_re is null for DhEe in ReadMessage");
                    var dhEe = X25519Crypto.ScalarMult(_e, _re);
                    _symmetric.MixKey(dhEe);
                    // [VM-S2] No longer emit the DH shared secret (highest sensitivity level).
                    DebugLog("Token.DhEe: MixKey applied");
                    break;

                case Token.DhEs:
                    byte[] dhEs;
                    if (_initiator)
                    {
                        if (_e == null) throw new InvalidOperationException("_e is null for DhEs (initiator) in ReadMessage");
                        if (_rs == null) throw new InvalidOperationException("_rs is null for DhEs (initiator) in ReadMessage");
                        dhEs = X25519Crypto.ScalarMult(_e, _rs);
                    }
                    else
                    {
                        if (_s == null) throw new InvalidOperationException("_s is null for DhEs (responder) in ReadMessage");
                        if (_re == null) throw new InvalidOperationException("_re is null for DhEs (responder) in ReadMessage");
                        dhEs = X25519Crypto.ScalarMult(_s, _re);
                    }
                    _symmetric.MixKey(dhEs);
                    // [VM-S2] No longer emit the DH shared secret.
                    DebugLog("Token.DhEs: MixKey applied");
                    break;

                case Token.DhSe:
                    byte[] dhSe;
                    if (_initiator)
                    {
                        if (_s == null) throw new InvalidOperationException("_s is null for DhSe (initiator) in ReadMessage");
                        if (_re == null) throw new InvalidOperationException("_re is null for DhSe (initiator) in ReadMessage");
                        dhSe = X25519Crypto.ScalarMult(_s, _re);
                    }
                    else
                    {
                        if (_e == null) throw new InvalidOperationException("_e is null for DhSe (responder) in ReadMessage");
                        if (_rs == null) throw new InvalidOperationException("_rs is null for DhSe (responder) in ReadMessage");
                        dhSe = X25519Crypto.ScalarMult(_e, _rs);
                    }
                    _symmetric.MixKey(dhSe);
                    DebugLog("Token.DhSe: MixKey applied");
                    break;

                case Token.DhSs:
                    if (_s == null) throw new InvalidOperationException("_s is null for DhSs in ReadMessage");
                    if (_rs == null) throw new InvalidOperationException("_rs is null for DhSs in ReadMessage");
                    var dhSs = X25519Crypto.ScalarMult(_s, _rs);
                    _symmetric.MixKey(dhSs);
                    DebugLog("Token.DhSs: MixKey applied");
                    break;

                case Token.Psk:
                    _symmetric.MixKeyAndHash(_psk);
                    DebugLog("Token.Psk: MixKeyAndHash applied");
                    break;
            }
        }

        DebugLog($"Before DecryptAndHash (payload): remaining={message.Length - offset} bytes");
        var payload = _symmetric.DecryptAndHash(message.Skip(offset).ToArray());

        _messagePatternsIndex++;
        return payload;
    }

    /// <summary>
    /// Finalizes the handshake: splits the symmetric state into two transport keys and resolves
    /// them for this side's role — the initiator sends with k1 and receives with k2; the
    /// responder sends with k2 and receives with k1.
    /// </summary>
    /// <returns>A (sendKey, recvKey) tuple of 32-byte ChaCha20-Poly1305 transport keys.</returns>
    public (byte[] sendKey, byte[] recvKey) Split()
    {
        var (_, _, k1, k2) = _symmetric.Split();
        if (_initiator)
        {
            return (k1, k2);
        }
        else
        {
            return (k2, k1);
        }
    }

    /// <summary>
    /// Gets the remote static public key: the pre-provisioned value for an initiator, or the
    /// value decrypted from the peer's initiation message for a responder (null until message 1
    /// has been read). Returns the internal array without cloning; callers must not modify it.
    /// </summary>
    public byte[]? GetRemoteStaticKey()
    {
        return _rs;
    }

    /// <summary>
    /// Replaces the pre-shared key that the response pattern's Token.Psk step mixes into the
    /// handshake. Must be called before that step executes (i.e. before the response message is
    /// written or read).
    /// </summary>
    /// <param name="psk">The new 32-byte pre-shared key.</param>
    /// <exception cref="ArgumentException"><paramref name="psk"/> is not exactly 32 bytes.</exception>
    public void SetPresharedKey(byte[] psk)
    {
        if (psk == null || psk.Length != 32)
            throw new ArgumentException("PSK must be 32 bytes", nameof(psk));
        // [VM-S1] Clone the PSK so external mutation cannot affect internal state; zero the old PSK before replacing it to prevent residue.
        CryptographicOperations.ZeroMemory(_psk);
        _psk = (byte[])psk.Clone();
    }

    /// <summary>Gets a copy of the current running handshake hash (the WireGuard handshake hash).</summary>
    public byte[] GetHash()
    {
        return _symmetric.GetHash();
    }

    /// <summary>
    /// Noise message-pattern tokens, processed in order by WriteMessage/ReadMessage.
    /// </summary>
    private enum Token
    {
        /// <summary>Ephemeral key: append/absorb the 32-byte ephemeral public key into the message, hash and key chain.</summary>
        E,
        /// <summary>Static key: append/absorb the 48-byte AEAD-encrypted static public key (32 bytes + 16-byte tag).</summary>
        S,
        /// <summary>DH between the local and remote ephemeral keys; result mixed into the key chain.</summary>
        DhEe,
        /// <summary>DH between local ephemeral × remote static (initiator) or local static × remote ephemeral (responder); result mixed into the key chain.</summary>
        DhEs,
        /// <summary>Mirror of DhEs: local static × remote ephemeral (initiator) or local ephemeral × remote static (responder); result mixed into the key chain.</summary>
        DhSe,
        /// <summary>DH between the local and remote static keys; result mixed into the key chain.</summary>
        DhSs,
        /// <summary>Mix the 32-byte pre-shared key into both the key chain and the hash.</summary>
        Psk
    }

    /// <summary>
    /// Zeroes all sensitive key material: the local static and ephemeral private keys, the
    /// remote ephemeral public key, the remote static public key and the pre-shared key.
    /// Idempotent.
    /// </summary>
    public void Dispose()
    {
        if (_disposed) return;

        if (_s != null) CryptographicOperations.ZeroMemory(_s);
        if (_e != null) CryptographicOperations.ZeroMemory(_e);
        if (_re != null) CryptographicOperations.ZeroMemory(_re);
        // [VM-S1] Zero the peer static public key and the PSK to prevent sensitive key material from lingering in memory.
        if (_rs != null) CryptographicOperations.ZeroMemory(_rs);
        CryptographicOperations.ZeroMemory(_psk);
        _disposed = true;
    }
}
