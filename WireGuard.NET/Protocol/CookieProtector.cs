using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using WireGuard.NET.Crypto;

namespace WireGuard.NET.Protocol;

/// <summary>
/// Implements the WireGuard cookie mechanism for denial-of-service mitigation (WireGuard
/// whitepaper): under load, a responder can require initiators to echo a cookie in mac2 before
/// performing expensive handshake cryptography.
/// </summary>
/// <remarks>
/// <para>
/// The class serves both roles: as a responder it validates incoming mac1/mac2, manages the
/// locally issued cookie, and produces cookie replies; as an initiator it computes mac1/mac2 for
/// outgoing handshake messages and stores per-endpoint cookies received from remote peers.
/// </para>
/// <para>
/// Key derivation follows the protocol: the mac1 key is HASH("mac1----" || local public key) and
/// the cookie-encryption key is HASH("cookie--" || local public key), both keyed BLAKE2s. MAC
/// comparisons are constant time. Instances are thread-safe: the local cookie is guarded by a
/// lock, per-endpoint maps are concurrent dictionaries, and the derived keys are volatile.
/// </para>
/// </remarks>
public class CookieProtector : IDisposable
{
    /// <summary>The 16-byte cookie currently issued by this endpoint; <c>null</c> until first generated.</summary>
    private byte[]? _cookie;
    /// <summary>mac1 key (HASH("mac1----" || public key)); volatile, assigned once by <see cref="Initialize"/>.</summary>
    private volatile byte[]? _mac1Key;
    /// <summary>Cookie-encryption key (HASH("cookie--" || public key)); volatile, assigned once by <see cref="Initialize"/>.</summary>
    private volatile byte[]? _mac2Key;
    /// <summary>Cookies issued by remote peers, keyed by endpoint.</summary>
    private readonly ConcurrentDictionary<IPEndPoint, byte[]> _remoteCookies = new();
    /// <summary>Receive time (UtcNow) of each remote cookie, keyed by endpoint; used for lifetime checks.</summary>
    private readonly ConcurrentDictionary<IPEndPoint, DateTime> _remoteCookieTimes = new();
    /// <summary>The mac1 most recently sent to each endpoint; needed as AEAD associated data when decrypting that endpoint's cookie reply.</summary>
    private readonly ConcurrentDictionary<IPEndPoint, byte[]> _lastSentMac1 = new();
    /// <summary>Guards generation, validation, and zeroing of the locally issued cookie.</summary>
    private readonly object _cookieLock = new();
    /// <summary>Birth time (UtcNow) of the locally issued cookie.</summary>
    private DateTime _cookieBirthTime;
    /// <summary>Validity period of a cookie (120 s, per the whitepaper's cookie rotation).</summary>
    private static readonly TimeSpan CookieLifetime = TimeSpan.FromSeconds(120);
    /// <summary>Periodic cleanup timer for expired remote cookies; <c>null</c> when cleanup is stopped.</summary>
    private Timer? _cleanupTimer;
    /// <summary>Interval between expired-cookie cleanup passes (2 minutes).</summary>
    private static readonly TimeSpan CleanupInterval = TimeSpan.FromMinutes(2);
    /// <summary>Disposal flag.</summary>
    private bool _disposed;

    /// <summary>Domain-separation label for the mac1 key derivation.</summary>
    private static readonly byte[] Mac1Label = System.Text.Encoding.UTF8.GetBytes("mac1----");
    /// <summary>Domain-separation label for the cookie-encryption key derivation.</summary>
    // WireGuard spec: the cookie reply encryption key is HASH("cookie--" || responderStaticPublic).
    // An earlier implementation wrongly used the "mac2----" label, which was incompatible with
    // official WireGuard implementations.
    private static readonly byte[] CookieLabel = System.Text.Encoding.UTF8.GetBytes("cookie--");

    /// <summary>
    /// Derives the mac1 and cookie-encryption keys from the local public key.
    /// </summary>
    /// <param name="publicKey">The local 32-byte static public key.</param>
    /// <remarks>Must be called before computing or validating any MAC or cookie reply.</remarks>
    public void Initialize(byte[] publicKey)
    {
        _mac1Key = Blake2s.Hash(Combine(Mac1Label, publicKey));
        _mac2Key = Blake2s.Hash(Combine(CookieLabel, publicKey));
    }

    /// <summary>
    /// Validates the mac1 field of an incoming handshake message.
    /// </summary>
    /// <param name="packet">
    /// The complete message including both MACs: mac1 occupies the 16 bytes at offset
    /// Length - 32, mac2 the final 16 bytes.
    /// </param>
    /// <returns>
    /// <c>true</c> if mac1 equals keyed-BLAKE2s(128-bit, mac1 key) over the message preceding both
    /// MACs (compared in constant time); <c>false</c> if the protector is not initialized, the
    /// packet is too short, or the MAC mismatches.
    /// </returns>
    public bool ValidateMac1(byte[] packet)
    {
        var mac1Key = _mac1Key;
        if (mac1Key == null)
            return false;

        if (packet.Length < 32)
            return false;

        var mac1Offset = packet.Length - 32;
        var messageWithoutMacs = packet.Take(mac1Offset).ToArray();
        var receivedMac1 = packet.Skip(mac1Offset).Take(16).ToArray();

        var computedMac1 = Blake2s.Hash128(messageWithoutMacs, mac1Key);

        return ConstantTimeEquals(computedMac1, receivedMac1);
    }

    /// <summary>
    /// Validates the mac2 field of an incoming handshake message.
    /// </summary>
    /// <param name="packet">The complete message including both MACs (see <see cref="ValidateMac1"/>).</param>
    /// <returns>
    /// <c>true</c> if mac2 equals keyed-BLAKE2s(128-bit, current cookie) over the message
    /// preceding mac2 and is not all zeros; <c>false</c> if no valid local cookie exists, mac2 is
    /// all zeros (the initiator has no cookie yet), or the MAC mismatches.
    /// </returns>
    public bool ValidateMac2(byte[] packet)
    {
        // Spec: mac2 = MAC(cookie, msg[0..-16]), keyed with the cookie this endpoint currently issues.
        if (packet.Length < 16)
            return false;

        byte[]? cookie;
        lock (_cookieLock)
        {
            cookie = IsCookieValid() ? _cookie : null;
        }
        if (cookie == null)
            return false;

        var mac2Offset = packet.Length - 16;
        var messageWithoutMac2 = packet.Take(mac2Offset).ToArray();
        var receivedMac2 = packet.Skip(mac2Offset).Take(16).ToArray();

        if (receivedMac2.All(b => b == 0))
            return false;

        var computedMac2 = Blake2s.Hash128(messageWithoutMac2, cookie);

        return ConstantTimeEquals(computedMac2, receivedMac2);
    }

    /// <summary>
    /// Computes the mac1/mac2 pair for an outgoing handshake message.
    /// </summary>
    /// <param name="messageWithoutMacs">The message body preceding the two trailing 16-byte MAC fields.</param>
    /// <param name="endpoint">
    /// Destination endpoint, used to record the sent mac1 and to look up the peer's cookie; may be <c>null</c>.
    /// </param>
    /// <returns>
    /// mac1 is keyed-BLAKE2s(128-bit, mac1 key) over <paramref name="messageWithoutMacs"/>; mac2 is
    /// keyed-BLAKE2s(128-bit, peer-issued cookie) over the message plus mac1, or 16 zero bytes when
    /// no unexpired cookie is known for the endpoint — signaling the responder to send a cookie reply.
    /// </returns>
    /// <exception cref="InvalidOperationException">Thrown when <see cref="Initialize"/> has not been called.</exception>
    public (byte[] mac1, byte[] mac2) ComputeMacs(byte[] messageWithoutMacs, IPEndPoint? endpoint)
    {
        var currentMac1Key = _mac1Key;
        if (currentMac1Key == null)
            throw new InvalidOperationException("CookieProtector not initialized");

        var mac1 = Blake2s.Hash128(messageWithoutMacs, currentMac1Key);

        if (endpoint != null)
        {
            // Record the mac1 of the most recently sent message: it is the AEAD associated data
            // required for decrypting the peer's cookie reply (per spec).
            _lastSentMac1[endpoint] = mac1;
        }

        byte[] mac2;
        // Spec: the mac2 key is the 16-byte cookie issued by the peer; the input includes mac1.
        if (endpoint != null &&
            _remoteCookies.TryGetValue(endpoint, out var cookie) &&
            _remoteCookieTimes.TryGetValue(endpoint, out var cookieTime) &&
            DateTime.UtcNow - cookieTime < CookieLifetime)
        {
            mac2 = Blake2s.Hash128(Combine(messageWithoutMacs, mac1), cookie);
        }
        else
        {
            mac2 = new byte[16];
        }

        return (mac1, mac2);
    }

    /// <summary>
    /// Builds a cookie reply responding to a handshake initiation received under load.
    /// </summary>
    /// <param name="initiationPacket">
    /// The triggering handshake message including both MACs: its receiver index (bytes 4–7) is
    /// echoed into the reply, and its mac1 (the 16 bytes at Length - 32) is used as AEAD
    /// associated data.
    /// </param>
    /// <param name="endpoint">The initiator's endpoint from which the packet arrived.</param>
    /// <returns>
    /// A 64-byte cookie reply: type (4) | receiver index (4) | nonce (24) | encrypted cookie
    /// (16 + 16-byte tag), encrypted with XChaCha20Poly1305 under HASH("cookie--" || local public key).
    /// </returns>
    /// <exception cref="InvalidOperationException">Thrown when <see cref="Initialize"/> has not been called.</exception>
    /// <remarks>Regenerates the local cookie if it is missing or expired (120 s rotation).</remarks>
    public byte[] CreateCookieReply(byte[] initiationPacket, IPEndPoint endpoint)
    {
        var currentMac2Key = _mac2Key;
        if (currentMac2Key == null)
            throw new InvalidOperationException("CookieProtector not initialized");

        lock (_cookieLock)
        {
            if (_cookie == null || !IsCookieValid())
            {
                _cookie = new byte[16];
                RandomNumberGenerator.Fill(_cookie);
                _cookieBirthTime = DateTime.UtcNow;
            }

            var reply = new byte[WireGuardConstants.COOKIE_REPLY_LEN];

            BitConverter.GetBytes(WireGuardConstants.TYPE_COOKIE).CopyTo(reply, 0);

            var receiverIndex = BitConverter.ToUInt32(initiationPacket, 4);
            BitConverter.GetBytes(receiverIndex).CopyTo(reply, 4);

            var nonce = new byte[WireGuardConstants.WG_COOKIE_NONCE_LEN];
            RandomNumberGenerator.Fill(nonce);
            Buffer.BlockCopy(nonce, 0, reply, 8, WireGuardConstants.WG_COOKIE_NONCE_LEN);

            // Spec: the AEAD associated data of a cookie reply is the mac1 of the triggering
            // message (the 16 bytes following msg[0..-32]).
            byte[] ad = Array.Empty<byte>();
            if (initiationPacket.Length >= 32)
            {
                ad = new byte[16];
                Buffer.BlockCopy(initiationPacket, initiationPacket.Length - 32, ad, 0, 16);
            }

            var encryptedCookie = XChaCha20Poly1305.Encrypt(
                currentMac2Key,
                nonce,
                _cookie,
                ad);

            Buffer.BlockCopy(encryptedCookie, 0, reply, 8 + WireGuardConstants.WG_COOKIE_NONCE_LEN, encryptedCookie.Length);

            return reply;
        }
    }

    /// <summary>
    /// Decrypts and stores a cookie reply received from a peer.
    /// </summary>
    /// <param name="packet">
    /// The 64-byte cookie reply: type (4) | receiver index (4) | nonce (24) | encrypted cookie
    /// (16 + 16-byte tag).
    /// </param>
    /// <param name="endpoint">The endpoint the reply came from; the cookie is stored for it.</param>
    /// <remarks>
    /// Decryption uses XChaCha20Poly1305 with HASH("cookie--" || local public key). Per spec the
    /// AEAD associated data is the mac1 of our most recent message to that endpoint; if no mac1
    /// was recorded, decryption is retried with empty associated data. Malformed or undecryptable
    /// replies are silently ignored (no-op).
    /// </remarks>
    public void ProcessCookieReply(byte[] packet, IPEndPoint endpoint)
    {
        var currentMac2Key = _mac2Key;
        if (currentMac2Key == null)
            return;

        if (packet.Length != WireGuardConstants.COOKIE_REPLY_LEN)
            return;

        var messageType = BitConverter.ToUInt32(packet, 0) & 0xFF;
        if (messageType != WireGuardConstants.TYPE_COOKIE)
            return;

        var nonce = packet.Skip(8).Take(WireGuardConstants.WG_COOKIE_NONCE_LEN).ToArray();
        var encryptedCookie = packet.Skip(8 + WireGuardConstants.WG_COOKIE_NONCE_LEN).Take(WireGuardConstants.WG_COOKIE_LEN + WireGuardConstants.WG_AEAD_TAG_LEN).ToArray();

        // Spec: the decryption AD is "the mac1 of our most recent message to that endpoint";
        // fall back to empty AD when none is recorded.
        var ads = new List<byte[]>(2);
        if (_lastSentMac1.TryGetValue(endpoint, out var sentMac1))
            ads.Add(sentMac1);
        ads.Add(Array.Empty<byte>());

        foreach (var ad in ads)
        {
            try
            {
                var decryptedCookie = XChaCha20Poly1305.Decrypt(
                    currentMac2Key,
                    nonce,
                    encryptedCookie,
                    ad);

                if (decryptedCookie.Length == WireGuardConstants.WG_COOKIE_LEN)
                {
                    _remoteCookies[endpoint] = decryptedCookie;
                    _remoteCookieTimes[endpoint] = DateTime.UtcNow;
                }
                return;
            }
            catch (Exception)
            {
            }
        }
    }

    /// <summary>
    /// Records the mac1 of a message sent to an endpoint (the first 16 of the final 32 bytes),
    /// for use as AEAD associated data when decrypting a cookie reply from that endpoint.
    /// </summary>
    /// <param name="endpoint">Destination endpoint.</param>
    /// <param name="messageWithMacs">The sent message including both MACs; ignored if shorter than 32 bytes.</param>
    public void TrackSentMac1(IPEndPoint endpoint, byte[] messageWithMacs)
    {
        if (messageWithMacs == null || messageWithMacs.Length < 32)
            return;

        var mac1 = new byte[16];
        Buffer.BlockCopy(messageWithMacs, messageWithMacs.Length - 32, mac1, 0, 16);
        _lastSentMac1[endpoint] = mac1;
    }

    /// <summary>
    /// Determines whether an unexpired peer-issued cookie is stored for an endpoint.
    /// </summary>
    /// <param name="endpoint">The remote endpoint.</param>
    /// <returns><c>true</c> if a cookie received within the last 120 s exists for the endpoint.</returns>
    public bool HasCookieForEndpoint(IPEndPoint endpoint)
    {
        if (!_remoteCookies.ContainsKey(endpoint))
            return false;

        if (_remoteCookieTimes.TryGetValue(endpoint, out var cookieTime))
        {
            return DateTime.UtcNow - cookieTime < CookieLifetime;
        }

        return false;
    }

    /// <summary>
    /// Returns a copy of the cookie issued by the peer for the given endpoint.
    /// </summary>
    /// <param name="endpoint">The remote endpoint.</param>
    /// <returns>A 16-byte clone of the cookie, or <c>null</c> if none is stored or it has expired.</returns>
    public byte[]? GetCookieForEndpoint(IPEndPoint endpoint)
    {
        // This checks the freshness of the peer-issued cookie (_remoteCookieTimes), not the
        // validity of the locally issued cookie.
        if (_remoteCookies.TryGetValue(endpoint, out var cookie) &&
            _remoteCookieTimes.TryGetValue(endpoint, out var cookieTime) &&
            DateTime.UtcNow - cookieTime < CookieLifetime)
        {
            return (byte[])cookie.Clone();
        }
        return null;
    }

    /// <summary>
    /// Installs a locally issued cookie, resetting its birth time to now.
    /// </summary>
    /// <param name="cookie">The 16-byte cookie value.</param>
    public void SetCookie(byte[] cookie)
    {
        lock (_cookieLock)
        {
            _cookie = cookie;
            _cookieBirthTime = DateTime.UtcNow;
        }
    }

    /// <summary>
    /// Discards all per-endpoint cookies and recorded mac1 values (local cookie is kept).
    /// </summary>
    public void ClearCookies()
    {
        _remoteCookies.Clear();
        _remoteCookieTimes.Clear();
        _lastSentMac1.Clear();
    }

    /// <summary>
    /// Starts the periodic cleanup of expired remote cookies (every 2 minutes).
    /// No-op if already running.
    /// </summary>
    public void StartCleanup()
    {
        _cleanupTimer ??= new Timer(CleanupExpiredCookies, null, CleanupInterval, CleanupInterval);
    }

    /// <summary>Stops the periodic cookie cleanup.</summary>
    public void StopCleanup()
    {
        _cleanupTimer?.Dispose();
        _cleanupTimer = null;
    }

    /// <summary>
    /// Timer callback: removes remote cookies older than the cookie lifetime, along with their
    /// recorded receive times and mac1 values.
    /// </summary>
    /// <param name="state">Unused timer state.</param>
    private void CleanupExpiredCookies(object? state)
    {
        var cutoff = DateTime.UtcNow - CookieLifetime;
        var expired = _remoteCookieTimes
            .Where(kvp => kvp.Value < cutoff)
            .Select(kvp => kvp.Key)
            .ToList();

        foreach (var key in expired)
        {
            _remoteCookies.TryRemove(key, out _);
            _remoteCookieTimes.TryRemove(key, out _);
            _lastSentMac1.TryRemove(key, out _);
        }
    }

    /// <summary>
    /// Checks whether the locally issued cookie exists and is within its 120 s lifetime.
    /// The caller must hold <c>_cookieLock</c>.
    /// </summary>
    private bool IsCookieValid()
    {
        if (_cookie == null || _cookieBirthTime == default)
            return false;

        return DateTime.UtcNow - _cookieBirthTime < CookieLifetime;
    }

    /// <summary>
    /// Length-checked constant-time byte comparison (delegates to
    /// <see cref="CryptographicOperations.FixedTimeEquals"/>).
    /// </summary>
    private static bool ConstantTimeEquals(byte[] a, byte[] b)
    {
        if (a.Length != b.Length)
            return false;

        return CryptographicOperations.FixedTimeEquals(a, b);
    }

    /// <summary>Concatenates the given arrays into a newly allocated buffer.</summary>
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
    /// Zeroes all key material (mac1/mac2 keys, the local cookie, and every remote cookie), clears
    /// the per-endpoint maps, and stops the cleanup timer. No-op if already disposed.
    /// </summary>
    public void Dispose()
    {
        if (_disposed) return;

        lock (_cookieLock)
        {
            if (_cookie != null) CryptographicOperations.ZeroMemory(_cookie);
        }
        if (_mac1Key != null) CryptographicOperations.ZeroMemory(_mac1Key);
        if (_mac2Key != null) CryptographicOperations.ZeroMemory(_mac2Key);

        foreach (var cookie in _remoteCookies.Values)
        {
            CryptographicOperations.ZeroMemory(cookie);
        }
        _remoteCookies.Clear();
        _remoteCookieTimes.Clear();
        _lastSentMac1.Clear();

        _cleanupTimer?.Dispose();
        _cleanupTimer = null;
        _disposed = true;
    }
}
