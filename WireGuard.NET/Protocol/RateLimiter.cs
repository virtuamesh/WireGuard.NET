using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;

namespace WireGuard.NET.Protocol;

/// <summary>
/// Token-bucket rate limiter used for WireGuard-style denial-of-service mitigation.
/// </summary>
/// <remarks>
/// <para>
/// Limits are applied per source IP address (separate IPv4 and IPv6 tables) and per peer public
/// key, at a sustained rate of 20 packets/second with a burst of 5 (the bucket refills one token
/// per 50 ms and holds at most 250 ms worth of tokens). Entries idle for 10 minutes are evicted
/// by a periodic cleanup pass.
/// </para>
/// <para>
/// Buckets are updated with Interlocked compare-exchange loops and the tables are concurrent
/// dictionaries, so all methods are thread-safe and may be called concurrently.
/// </para>
/// </remarks>
public class RateLimiter
{
    /// <summary>Sustained rate: packets allowed per second per key.</summary>
    private const int PacketsPerSecond = 20;
    /// <summary>Burst size: maximum number of packets allowed back to back.</summary>
    private const int PacketsBurstable = 5;
    /// <summary>Nanoseconds per second.</summary>
    private const long NsecPerSecond = 1000000000L;
    /// <summary>Token cost of one packet in nanoseconds (50 ms).</summary>
    private const long PacketCost = NsecPerSecond / PacketsPerSecond;
    /// <summary>Maximum token balance in nanoseconds (250 ms, i.e. a burst of 5 packets).</summary>
    private const long TokenMax = PacketCost * PacketsBurstable;
    
    /// <summary>Token-bucket state per IPv4 source address (key: the 4 address bytes reinterpreted as an integer).</summary>
    private readonly ConcurrentDictionary<ulong, RateLimiterEntry> _ipv4Table = new();
    /// <summary>Token-bucket state per IPv6 source address (key: folded 64-bit hash of the 16 address bytes).</summary>
    private readonly ConcurrentDictionary<ulong, RateLimiterEntry> _ipv6Table = new();
    /// <summary>Token-bucket state per peer public key (key: Base64 string of the key).</summary>
    private readonly ConcurrentDictionary<string, RateLimiterEntry> _publicKeyTable = new(StringComparer.Ordinal);
    /// <summary>Periodic eviction timer; <c>null</c> when cleanup is stopped.</summary>
    private Timer? _cleanupTimer;
    /// <summary>Interval between eviction passes (5 minutes).</summary>
    private static readonly TimeSpan CleanupInterval = TimeSpan.FromMinutes(5);
    /// <summary>Idle time after which an entry is evicted (10 minutes).</summary>
    private static readonly TimeSpan EntryExpiry = TimeSpan.FromMinutes(10);

    /// <summary>Mutable token-bucket state for one rate-limit key.</summary>
    private class RateLimiterEntry
    {
        /// <summary>Timestamp (nanoseconds) of the last bucket refill; updated via Interlocked.</summary>
        public long LastTimeNs;
        /// <summary>Current token balance in nanoseconds; updated via Interlocked.</summary>
        public long Tokens;
        /// <summary>Last-access time (UtcNow ticks), used to evict idle entries.</summary>
        public long LastAccessTimeTicks;
    }

    /// <summary>
    /// Consumes one token from the bucket of the given source address.
    /// </summary>
    /// <param name="address">The IPv4 or IPv6 source address.</param>
    /// <returns>
    /// <c>true</c> if a token was available and consumed; <c>false</c> if the bucket is exhausted
    /// or the address family is neither IPv4 nor IPv6.
    /// </returns>
    public bool Allow(IPAddress address)
    {
        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            return AllowIPv4(address);
        }
        else if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            return AllowIPv6(address);
        }
        return false;
    }

    /// <summary>
    /// Consumes one token from the IPv4 source address's bucket; a new entry starts with a full bucket.
    /// </summary>
    /// <param name="address">The IPv4 source address.</param>
    /// <returns><c>true</c> if a token was available and consumed.</returns>
    private bool AllowIPv4(IPAddress address)
    {
        var addressBytes = address.GetAddressBytes();
        var key = BitConverter.ToUInt32(addressBytes, 0);
        
        var entry = _ipv4Table.GetOrAdd(key, _ => new RateLimiterEntry
        {
            LastTimeNs = GetCurrentTimeNs(),
            Tokens = TokenMax,
            LastAccessTimeTicks = DateTime.UtcNow.Ticks
        });
        
        return CheckTokens(entry);
    }

    /// <summary>
    /// Consumes one token from the IPv6 source address's bucket; a new entry starts with a full bucket.
    /// </summary>
    /// <param name="address">The IPv6 source address.</param>
    /// <returns><c>true</c> if a token was available and consumed.</returns>
    private bool AllowIPv6(IPAddress address)
    {
        var addressBytes = address.GetAddressBytes();
        var key = GenerateIPv6Key(addressBytes);
        
        var entry = _ipv6Table.GetOrAdd(key, _ => new RateLimiterEntry
        {
            LastTimeNs = GetCurrentTimeNs(),
            Tokens = TokenMax,
            LastAccessTimeTicks = DateTime.UtcNow.Ticks
        });
        
        return CheckTokens(entry);
    }

    /// <summary>
    /// Folds a 128-bit IPv6 address into a 64-bit hash key: reads the address as four 32-bit
    /// little-endian words, XORs words 1^2 into h1 and words 3^4 into h2, rotates h1 left by 13
    /// and h2 left by 7 bits, cross-XORs them, multiplies both by the Murmur3 constant
    /// 0x5bd1e995, and combines them as (h1 &lt;&lt; 32) | h2.
    /// </summary>
    /// <param name="addressBytes">The 16 address bytes.</param>
    /// <returns>The 64-bit bucket key; hash collisions may merge two addresses into one bucket.</returns>
    private static ulong GenerateIPv6Key(byte[] addressBytes)
    {
        var h1 = (uint)(addressBytes[0] | (addressBytes[1] << 8) | (addressBytes[2] << 16) | (addressBytes[3] << 24));
        h1 ^= (uint)(addressBytes[4] | (addressBytes[5] << 8) | (addressBytes[6] << 16) | (addressBytes[7] << 24));
        var h2 = (uint)(addressBytes[8] | (addressBytes[9] << 8) | (addressBytes[10] << 16) | (addressBytes[11] << 24));
        h2 ^= (uint)(addressBytes[12] | (addressBytes[13] << 8) | (addressBytes[14] << 16) | (addressBytes[15] << 24));
        h1 = (h1 << 13) | (h1 >> 19);
        h2 = (h2 << 7) | (h2 >> 25);
        h1 ^= h2;
        h2 ^= h1;
        h1 = h1 * 0x5bd1e995;
        h2 = h2 * 0x5bd1e995;
        return ((ulong)h1 << 32) | h2;
    }

    /// <summary>
    /// Refills the bucket with tokens accrued since the last update (capped at TokenMax) and,
    /// when affordable, deducts one packet cost. Uses an Interlocked compare-exchange loop on the
    /// last-update timestamp to serialize competing updates, so it is safe under concurrent calls
    /// on the same entry; also refreshes the entry's last-access time used by eviction.
    /// </summary>
    /// <param name="entry">The bucket state.</param>
    /// <returns><c>true</c> if a token was consumed; <c>false</c> if the balance was under one packet cost.</returns>
    private bool CheckTokens(RateLimiterEntry entry)
    {
        var now = GetCurrentTimeNs();
        Interlocked.Exchange(ref entry.LastAccessTimeTicks, DateTime.UtcNow.Ticks);

        while (true)
        {
            var lastTime = Interlocked.Read(ref entry.LastTimeNs);
            var currentTokens = Math.Min(TokenMax, Interlocked.Read(ref entry.Tokens) + (now - lastTime));

            if (currentTokens < PacketCost)
            {
                var oldLastTime = Interlocked.CompareExchange(ref entry.LastTimeNs, now, lastTime);
                if (oldLastTime != lastTime) continue;
                Interlocked.Exchange(ref entry.Tokens, currentTokens);
                return false;
            }

            var newTokens = currentTokens - PacketCost;
            var oldLastTime2 = Interlocked.CompareExchange(ref entry.LastTimeNs, now, lastTime);
            if (oldLastTime2 != lastTime) continue;
            Interlocked.Exchange(ref entry.Tokens, newTokens);
            return true;
        }
    }

    /// <summary>
    /// Token bucket per peer public key, guarding against CPU amplification from MAC1-valid
    /// initiations. The MAC1 key is publicly derivable from this node's public key, so an attacker
    /// can flood forged "MAC1-valid" initiations, forcing the responder to perform up to 3 X25519
    /// attempts for each of the N known peer public keys per packet. Tokens are consumed per
    /// candidate public key after MAC1 validation passes but before the Noise decryption attempts,
    /// converging the attacker's cost to the token rate.
    /// </summary>
    /// <param name="publicKey">The 32-byte candidate peer public key.</param>
    /// <returns><c>true</c> if a token was available and consumed; <c>false</c> if the bucket is exhausted.</returns>
    public bool AllowPublicKey(byte[] publicKey)
    {
        var key = Convert.ToBase64String(publicKey);

        var entry = _publicKeyTable.GetOrAdd(key, _ => new RateLimiterEntry
        {
            LastTimeNs = GetCurrentTimeNs(),
            Tokens = TokenMax,
            LastAccessTimeTicks = DateTime.UtcNow.Ticks
        });

        return CheckTokens(entry);
    }

    /// <summary>
    /// Consumes one token from the bucket of a raw IP packet's source address.
    /// </summary>
    /// <param name="packet">
    /// Raw IP packet starting with the IP header. The IP version is read from the high nibble of
    /// byte 0; an IPv4 packet requires at least 20 bytes with the source address at offset 12
    /// (4 bytes), an IPv6 packet at least 40 bytes with the source address at offset 8 (16 bytes).
    /// </param>
    /// <returns>
    /// <c>true</c> if a token was available and consumed; <c>false</c> for packets that are too
    /// short, use an unknown IP version, or have an exhausted bucket.
    /// </returns>
    public bool AllowPacket(byte[] packet)
    {
        if (packet.Length < 20)
            return false;

        var version = (packet[0] >> 4) & 0x0F;
        
        if (version == 4)
        {
            if (packet.Length < 20)
                return false;
            
            var srcAddress = new IPAddress(packet.Skip(12).Take(4).ToArray());
            return Allow(srcAddress);
        }
        else if (version == 6)
        {
            if (packet.Length < 40)
                return false;
            
            var srcAddress = new IPAddress(packet.Skip(8).Take(16).ToArray());
            return Allow(srcAddress);
        }
        
        return false;
    }

    /// <summary>Returns the current UTC time in nanoseconds (1 tick = 100 ns).</summary>
    private long GetCurrentTimeNs()
    {
        return DateTime.UtcNow.Ticks * 100;
    }

    /// <summary>
    /// Drops all rate-limit state (IPv4, IPv6, and public-key buckets).
    /// </summary>
    public void Clear()
    {
        _ipv4Table.Clear();
        _ipv6Table.Clear();
        _publicKeyTable.Clear();
    }

    /// <summary>
    /// Starts the periodic eviction of idle entries (every 5 minutes). No-op if already running.
    /// </summary>
    public void StartCleanup()
    {
        _cleanupTimer ??= new Timer(CleanupExpiredEntries, null, CleanupInterval, CleanupInterval);
    }

    /// <summary>Stops the periodic eviction.</summary>
    public void StopCleanup()
    {
        _cleanupTimer?.Dispose();
        _cleanupTimer = null;
    }

    /// <summary>
    /// Timer callback: removes entries whose last access is older than 10 minutes from the IPv4,
    /// IPv6, and public-key tables.
    /// </summary>
    /// <param name="state">Unused timer state.</param>
    private void CleanupExpiredEntries(object? state)
    {
        var cutoffTicks = (DateTime.UtcNow - EntryExpiry).Ticks;

        var expiredV4 = _ipv4Table
            .Where(kvp => Interlocked.Read(ref kvp.Value.LastAccessTimeTicks) < cutoffTicks)
            .Select(kvp => kvp.Key)
            .ToList();

        foreach (var key in expiredV4)
        {
            _ipv4Table.TryRemove(key, out _);
        }

        var expiredV6 = _ipv6Table
            .Where(kvp => Interlocked.Read(ref kvp.Value.LastAccessTimeTicks) < cutoffTicks)
            .Select(kvp => kvp.Key)
            .ToList();

        foreach (var key in expiredV6)
        {
            _ipv6Table.TryRemove(key, out _);
        }

        var expiredKeys = _publicKeyTable
            .Where(kvp => Interlocked.Read(ref kvp.Value.LastAccessTimeTicks) < cutoffTicks)
            .Select(kvp => kvp.Key)
            .ToList();

        foreach (var key in expiredKeys)
        {
            _publicKeyTable.TryRemove(key, out _);
        }
    }
}
