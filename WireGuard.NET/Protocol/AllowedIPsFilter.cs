using System.Net;
using System.Net.Sockets;

namespace WireGuard.NET.Protocol;

/// <summary>
/// Manages the AllowedIPs network set of a WireGuard interface and answers membership and
/// longest-prefix-match queries for both <see cref="IPAddress"/> values and raw IP packets.
/// </summary>
/// <remarks>
/// <para>
/// Matching implements the AllowedIPs semantics of the WireGuard whitepaper: an address or packet
/// belongs to a peer only if it falls within one of the peer's configured CIDR networks, and when
/// several networks match, the most specific one (longest prefix) wins.
/// </para>
/// <para>
/// Thread-safety: the current network set is held in an immutable snapshot that is replaced
/// wholesale on every mutation (copy-on-write) and published via a volatile field, so readers run
/// lock-free and never observe a partially updated set. Mutating operations serialize on a writer lock.
/// </para>
/// </remarks>
public partial class AllowedIPsFilter
{
    /// <summary>
    /// Immutable point-in-time snapshot of the allowed-IP network set (copy-on-write): the raw
    /// network lists plus prefix-length bucketed indexes used for longest-prefix matching.
    /// </summary>
    private sealed class NetworkSnapshot
    {
        /// <summary>IPv4 CIDR networks in this snapshot.</summary>
        public readonly IPNetworkEntry[] Ipv4Networks;
        /// <summary>IPv6 CIDR networks in this snapshot.</summary>
        public readonly IPNetworkEntry[] Ipv6Networks;
        /// <summary>Whether an IPv4 default route (0.0.0.0/0) is present.</summary>
        public readonly bool HasDefaultRouteV4;
        /// <summary>Whether an IPv6 default route (::/0) is present.</summary>
        public readonly bool HasDefaultRouteV6;
        /// <summary>IPv4 networks bucketed by prefix length for longest-prefix matching.</summary>
        public readonly Dictionary<int, List<IPNetworkEntry>> Ipv4ByPrefix;
        /// <summary>IPv6 networks bucketed by prefix length for longest-prefix matching.</summary>
        public readonly Dictionary<int, List<IPNetworkEntry>> Ipv6ByPrefix;

        /// <summary>
        /// Creates a snapshot from the given network lists, building the prefix-length indexes.
        /// </summary>
        /// <param name="ipv4">IPv4 CIDR networks.</param>
        /// <param name="ipv6">IPv6 CIDR networks.</param>
        /// <param name="hasDefV4">Whether an IPv4 default route is present.</param>
        /// <param name="hasDefV6">Whether an IPv6 default route is present.</param>
        public NetworkSnapshot(IPNetworkEntry[] ipv4, IPNetworkEntry[] ipv6, bool hasDefV4, bool hasDefV6)
        {
            Ipv4Networks = ipv4;
            Ipv6Networks = ipv6;
            HasDefaultRouteV4 = hasDefV4;
            HasDefaultRouteV6 = hasDefV6;

            Ipv4ByPrefix = new Dictionary<int, List<IPNetworkEntry>>();
            foreach (var entry in ipv4)
            {
                if (!Ipv4ByPrefix.TryGetValue(entry.PrefixLength, out var list))
                {
                    list = new List<IPNetworkEntry>();
                    Ipv4ByPrefix[entry.PrefixLength] = list;
                }
                list.Add(entry);
            }

            Ipv6ByPrefix = new Dictionary<int, List<IPNetworkEntry>>();
            foreach (var entry in ipv6)
            {
                if (!Ipv6ByPrefix.TryGetValue(entry.PrefixLength, out var list))
                {
                    list = new List<IPNetworkEntry>();
                    Ipv6ByPrefix[entry.PrefixLength] = list;
                }
                list.Add(entry);
            }
        }

        /// <summary>The shared empty snapshot used before any allowed IP is configured.</summary>
        public static readonly NetworkSnapshot Empty = new(Array.Empty<IPNetworkEntry>(), Array.Empty<IPNetworkEntry>(), false, false);
    }

    /// <summary>Current immutable snapshot; readers access it lock-free via volatile semantics.</summary>
    private volatile NetworkSnapshot _snapshot = NetworkSnapshot.Empty;
    /// <summary>Serializes mutating operations so snapshot publication is atomic.</summary>
    private readonly object _writeLock = new();

    /// <summary>
    /// Adds a single CIDR network to the allowed-IPs set.
    /// </summary>
    /// <param name="address">An address inside the network; host bits beyond the prefix are masked off.</param>
    /// <param name="prefixLength">Prefix length in bits (0–32 for IPv4, 0–128 for IPv6).</param>
    /// <remarks>
    /// Thread-safe: builds a new snapshot from the current one under the writer lock and publishes
    /// it atomically, so lock-free readers see either the old or the new set, never a mix.
    /// </remarks>
    public void AddAllowedIP(IPAddress address, int prefixLength)
    {
        lock (_writeLock)
        {
            var entry = new IPNetworkEntry(address, prefixLength);
            var isV4 = address.AddressFamily == AddressFamily.InterNetwork;

            var current = _snapshot;
            IPNetworkEntry[] newV4, newV6;
            bool hasDefV4 = current.HasDefaultRouteV4, hasDefV6 = current.HasDefaultRouteV6;

            if (isV4)
            {
                newV4 = new IPNetworkEntry[current.Ipv4Networks.Length + 1];
                Array.Copy(current.Ipv4Networks, newV4, current.Ipv4Networks.Length);
                newV4[^1] = entry;
                newV6 = current.Ipv6Networks;
                if (prefixLength == 0) hasDefV4 = true;
            }
            else
            {
                newV6 = new IPNetworkEntry[current.Ipv6Networks.Length + 1];
                Array.Copy(current.Ipv6Networks, newV6, current.Ipv6Networks.Length);
                newV6[^1] = entry;
                newV4 = current.Ipv4Networks;
                if (prefixLength == 0) hasDefV6 = true;
            }

            _snapshot = new NetworkSnapshot(newV4, newV6, hasDefV4, hasDefV6);
        }
    }

    /// <summary>
    /// Adds multiple CIDR networks in a single snapshot replacement.
    /// </summary>
    /// <param name="entries">(address, prefixLength) tuples describing the networks to add.</param>
    /// <remarks>
    /// Equivalent to repeated <see cref="AddAllowedIP"/> calls, but performs only one snapshot
    /// publication. Thread-safe (see <see cref="AddAllowedIP"/>).
    /// </remarks>
    public void AddAllowedIPsBatch(IEnumerable<(IPAddress address, int prefixLength)> entries)
    {
        lock (_writeLock)
        {
            var current = _snapshot;
            var v4List = new List<IPNetworkEntry>(current.Ipv4Networks);
            var v6List = new List<IPNetworkEntry>(current.Ipv6Networks);
            bool hasDefV4 = current.HasDefaultRouteV4, hasDefV6 = current.HasDefaultRouteV6;

            foreach (var (address, prefixLength) in entries)
            {
                var entry = new IPNetworkEntry(address, prefixLength);
                if (address.AddressFamily == AddressFamily.InterNetwork)
                {
                    v4List.Add(entry);
                    if (prefixLength == 0) hasDefV4 = true;
                }
                else
                {
                    v6List.Add(entry);
                    if (prefixLength == 0) hasDefV6 = true;
                }
            }

            _snapshot = new NetworkSnapshot(v4List.ToArray(), v6List.ToArray(), hasDefV4, hasDefV6);
        }
    }

    /// <summary>
    /// Removes the CIDR network identified by <paramref name="address"/> and
    /// <paramref name="prefixLength"/> from the allowed-IPs set.
    /// </summary>
    /// <param name="address">Base address of the network to remove.</param>
    /// <param name="prefixLength">Prefix length in bits of the network to remove.</param>
    /// <remarks>
    /// No-op if no identical network exists. The default-route flag of the affected address family
    /// is recomputed from the remaining networks. Thread-safe (see <see cref="AddAllowedIP"/>).
    /// </remarks>
    public void RemoveAllowedIP(IPAddress address, int prefixLength)
    {
        lock (_writeLock)
        {
            var entry = new IPNetworkEntry(address, prefixLength);
            var isV4 = address.AddressFamily == AddressFamily.InterNetwork;
            var current = _snapshot;

            IPNetworkEntry[] newV4, newV6;
            bool hasDefV4 = current.HasDefaultRouteV4, hasDefV6 = current.HasDefaultRouteV6;

            if (isV4)
            {
                var list = new List<IPNetworkEntry>(current.Ipv4Networks);
                list.Remove(entry);
                newV4 = list.ToArray();
                newV6 = current.Ipv6Networks;
                hasDefV4 = newV4.Any(n => n.PrefixLength == 0);
            }
            else
            {
                var list = new List<IPNetworkEntry>(current.Ipv6Networks);
                list.Remove(entry);
                newV6 = list.ToArray();
                newV4 = current.Ipv4Networks;
                hasDefV6 = newV6.Any(n => n.PrefixLength == 0);
            }

            _snapshot = new NetworkSnapshot(newV4, newV6, hasDefV4, hasDefV6);
        }
    }

    /// <summary>
    /// Removes all allowed-IP networks, resetting the filter to the empty snapshot.
    /// Thread-safe (see <see cref="AddAllowedIP"/>).
    /// </summary>
    public void Clear()
    {
        lock (_writeLock)
        {
            _snapshot = NetworkSnapshot.Empty;
        }
    }

    /// <summary>
    /// Returns the length of the longest configured network prefix that contains
    /// <paramref name="address"/> (longest-prefix match).
    /// </summary>
    /// <param name="address">The address to test (IPv4 or IPv6).</param>
    /// <returns>
    /// The longest matching prefix length in bits, or <c>-1</c> when no configured network
    /// contains the address.
    /// </returns>
    public int GetMatchingPrefixLength(IPAddress address)
    {
        var snap = _snapshot;
        var byPrefix = address.AddressFamily == AddressFamily.InterNetwork ? snap.Ipv4ByPrefix
            : address.AddressFamily == AddressFamily.InterNetworkV6 ? snap.Ipv6ByPrefix
            : null;

        if (byPrefix == null) return -1;

        var bestPrefix = -1;
        foreach (var kvp in byPrefix)
        {
            if (kvp.Key <= bestPrefix) continue;
            foreach (var network in kvp.Value)
            {
                if (network.Contains(address))
                {
                    bestPrefix = kvp.Key;
                    break;
                }
            }
        }
        return bestPrefix;
    }

    /// <summary>
    /// Extracts the destination address from a raw IP packet and performs longest-prefix
    /// matching on it.
    /// </summary>
    /// <param name="packet">
    /// Raw IP packet starting with the IP header. The IP version is read from the high nibble of
    /// byte 0; an IPv4 packet requires at least 20 bytes with the destination address at offset 16
    /// (4 bytes), an IPv6 packet at least 40 bytes with the destination address at offset 24
    /// (16 bytes).
    /// </param>
    /// <returns>
    /// The longest matching prefix length in bits, or <c>-1</c> for packets that are too short,
    /// use an unknown IP version, or match no configured network.
    /// </returns>
    public int GetPacketMatchingPrefixLength(byte[] packet)
    {
        if (packet.Length < 20) return -1;
        var version = (packet[0] >> 4) & 0x0F;

        if (version == 4 && packet.Length >= 20)
        {
            var dstAddress = new IPAddress(packet.Skip(16).Take(4).ToArray());
            return GetMatchingPrefixLength(dstAddress);
        }
        else if (version == 6 && packet.Length >= 40)
        {
            var dstAddress = new IPAddress(packet.Skip(24).Take(16).ToArray());
            return GetMatchingPrefixLength(dstAddress);
        }

        return -1;
    }

    /// <summary>
    /// Determines whether any configured network contains <paramref name="address"/>.
    /// </summary>
    /// <param name="address">The address to test (IPv4 or IPv6).</param>
    /// <returns>
    /// <c>true</c> if the address falls inside at least one allowed network; <c>false</c>
    /// otherwise, including for unsupported address families.
    /// </returns>
    public bool IsAllowed(IPAddress address)
    {
        var snap = _snapshot;
        var networks = address.AddressFamily == AddressFamily.InterNetwork ? snap.Ipv4Networks
            : address.AddressFamily == AddressFamily.InterNetworkV6 ? snap.Ipv6Networks
            : null;

        if (networks == null) return false;

        for (int i = 0; i < networks.Length; i++)
        {
            if (networks[i].Contains(address)) return true;
        }
        return false;
    }

    /// <summary>
    /// Determines whether the destination address of a raw IP packet falls inside any configured
    /// network.
    /// </summary>
    /// <param name="packet">
    /// Raw IP packet (see <see cref="GetPacketMatchingPrefixLength"/> for the expected byte layout).
    /// </param>
    /// <returns>
    /// <c>true</c> if the packet's destination address is allowed; <c>false</c> for malformed
    /// packets, unknown IP versions, or non-matching destinations.
    /// </returns>
    public bool IsPacketAllowed(byte[] packet)
    {
        if (packet.Length < 20) return false;
        var version = (packet[0] >> 4) & 0x0F;

        if (version == 4 && packet.Length >= 20)
        {
            var dstAddress = new IPAddress(packet.Skip(16).Take(4).ToArray());
            return IsAllowed(dstAddress);
        }
        else if (version == 6 && packet.Length >= 40)
        {
            var dstAddress = new IPAddress(packet.Skip(24).Take(16).ToArray());
            return IsAllowed(dstAddress);
        }

        return false;
    }

    /// <summary>
    /// Matches a raw IP packet against the allowed-IPs set and returns detailed match information.
    /// </summary>
    /// <param name="packet">
    /// Raw IP packet (see <see cref="GetPacketMatchingPrefixLength"/> for the expected byte layout).
    /// </param>
    /// <returns>
    /// A <see cref="PacketMatchResult"/> describing the matched prefix length or default-route
    /// match; <see cref="PacketMatchResult.NoMatch"/> for malformed packets, unknown IP versions,
    /// or when no configured network matches.
    /// </returns>
    public PacketMatchResult MatchPacket(byte[] packet)
    {
        if (packet.Length < 20) return PacketMatchResult.NoMatch;
        var version = (packet[0] >> 4) & 0x0F;

        var snap = _snapshot;
        if (version == 4 && packet.Length >= 20)
        {
            return MatchPacketCore(packet, 16, 4, snap.Ipv4ByPrefix, snap.HasDefaultRouteV4);
        }
        else if (version == 6 && packet.Length >= 40)
        {
            return MatchPacketCore(packet, 24, 16, snap.Ipv6ByPrefix, snap.HasDefaultRouteV6);
        }

        return PacketMatchResult.NoMatch;
    }

    /// <summary>
    /// Longest-prefix match over prefix-bucketed networks, operating directly on the packet bytes.
    /// </summary>
    /// <param name="packet">Raw IP packet whose destination address lies at <paramref name="dstOffset"/>.</param>
    /// <param name="dstOffset">Byte offset of the destination address within the packet.</param>
    /// <param name="addrLen">Length in bytes of the destination address (4 for IPv4, 16 for IPv6).</param>
    /// <param name="byPrefix">Networks bucketed by prefix length.</param>
    /// <param name="hasDefaultRoute">Whether the address family has an explicit default route configured.</param>
    /// <returns>
    /// <see cref="PacketMatchResult.DefaultRoute"/> when only the default route matches (including
    /// the empty-network case with a default route), a specific prefix match when a network
    /// contains the destination, otherwise <see cref="PacketMatchResult.NoMatch"/>.
    /// </returns>
    private static PacketMatchResult MatchPacketCore(byte[] packet, int dstOffset, int addrLen,
        Dictionary<int, List<IPNetworkEntry>> byPrefix, bool hasDefaultRoute)
    {
        if (byPrefix.Count == 0)
            return hasDefaultRoute ? PacketMatchResult.DefaultRoute : PacketMatchResult.NoMatch;

        int bestPrefix = -1;
        IPNetworkEntry? bestNetwork = null;

        foreach (var kvp in byPrefix)
        {
            if (kvp.Key <= bestPrefix) continue;
            foreach (var network in kvp.Value)
            {
                if (network.ContainsPacket(packet, dstOffset, addrLen))
                {
                    bestPrefix = kvp.Key;
                    bestNetwork = network;
                    break;
                }
            }
        }

        if (bestNetwork != null)
        {
            return bestPrefix == 0 ? PacketMatchResult.DefaultRoute : new PacketMatchResult(true, bestPrefix);
        }

        return hasDefaultRoute ? PacketMatchResult.DefaultRoute : PacketMatchResult.NoMatch;
    }

    /// <summary>
    /// Determines whether the allowed-IPs set effectively covers all addresses of an address
    /// family (a "catch-all" set).
    /// </summary>
    /// <returns>
    /// <c>true</c> if a /0 network exists in either family, or if both /1 halves of a family are
    /// present (0.0.0.0/1 + 128.0.0.0/1 for IPv4, ::/1 + 8000::/1 for IPv6).
    /// </returns>
    public bool HasDefaultRoute()
    {
        var snap = _snapshot;
        if (snap.HasDefaultRouteV4 || snap.HasDefaultRouteV6) return true;

        for (int i = 0; i < snap.Ipv4Networks.Length; i++)
        {
            if (snap.Ipv4Networks[i].PrefixLength == 0) return true;
        }

        var hasFirstHalf = false;
        var hasSecondHalf = false;
        for (int i = 0; i < snap.Ipv4Networks.Length; i++)
        {
            if (snap.Ipv4Networks[i].PrefixLength == 1)
            {
                if (snap.Ipv4Networks[i].NetworkAddress[0] == 0) hasFirstHalf = true;
                if (snap.Ipv4Networks[i].NetworkAddress[0] == 128) hasSecondHalf = true;
            }
        }
        if (hasFirstHalf && hasSecondHalf) return true;

        for (int i = 0; i < snap.Ipv6Networks.Length; i++)
        {
            if (snap.Ipv6Networks[i].PrefixLength == 0) return true;
        }

        var hasV6FirstHalf = false;
        var hasV6SecondHalf = false;
        for (int i = 0; i < snap.Ipv6Networks.Length; i++)
        {
            if (snap.Ipv6Networks[i].PrefixLength == 1)
            {
                if (snap.Ipv6Networks[i].NetworkAddress[0] == 0) hasV6FirstHalf = true;
                if (snap.Ipv6Networks[i].NetworkAddress[0] == 0x80) hasV6SecondHalf = true;
            }
        }
        return hasV6FirstHalf && hasV6SecondHalf;
    }

    /// <summary>
    /// Returns all configured networks in CIDR notation ("address/prefixLength").
    /// </summary>
    /// <returns>A new list containing every IPv4 and IPv6 network currently configured.</returns>
    public List<string> GetAll()
    {
        var snap = _snapshot;
        var result = new List<string>(snap.Ipv4Networks.Length + snap.Ipv6Networks.Length);

        foreach (var network in snap.Ipv4Networks)
        {
            var address = new IPAddress(network.NetworkAddress);
            result.Add($"{address}/{network.PrefixLength}");
        }

        foreach (var network in snap.Ipv6Networks)
        {
            var address = new IPAddress(network.NetworkAddress);
            result.Add($"{address}/{network.PrefixLength}");
        }

        return result;
    }
}
