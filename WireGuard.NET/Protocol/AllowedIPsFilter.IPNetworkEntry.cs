using System.Net;
using System.Net.Sockets;

namespace WireGuard.NET.Protocol;

// Partial class file for AllowedIPsFilter: contains the internal IPNetworkEntry CIDR entry type.
// Immutable value: network address + netmask + prefix length. Provides two matching modes,
// Contains(IPAddress) and ContainsPacket(byte[]).
public partial class AllowedIPsFilter
{
    /// <summary>
    /// A single immutable CIDR network entry. Value equality is defined by the
    /// (AddressFamily, PrefixLength, NetworkAddress) triple.
    /// </summary>
    private class IPNetworkEntry : IEquatable<IPNetworkEntry>
    {
        /// <summary>Network base address bytes with host bits masked to zero (network byte order).</summary>
        public byte[] NetworkAddress { get; }
        /// <summary>Subnet mask bytes derived from the prefix length.</summary>
        public byte[] Netmask { get; }
        /// <summary>Address family of the network (IPv4 or IPv6).</summary>
        public AddressFamily AddressFamily { get; }
        /// <summary>Prefix length in bits (0–32 for IPv4, 0–128 for IPv6).</summary>
        public int PrefixLength { get; }

        /// <summary>
        /// Creates a network entry, computing the masked network address and the subnet mask
        /// from <paramref name="address"/> and <paramref name="prefixLength"/>.
        /// </summary>
        /// <param name="address">Any address inside the network; host bits beyond the prefix are discarded.</param>
        /// <param name="prefixLength">Prefix length in bits.</param>
        public IPNetworkEntry(IPAddress address, int prefixLength)
        {
            AddressFamily = address.AddressFamily;
            PrefixLength = prefixLength;

            var addressBytes = address.GetAddressBytes();
            NetworkAddress = new byte[addressBytes.Length];
            Netmask = new byte[addressBytes.Length];

            CalculateNetworkAndMask(addressBytes, prefixLength, NetworkAddress, Netmask);
        }

        /// <summary>
        /// Checks whether <paramref name="address"/> falls within this network: address families
        /// must match, and the address AND-ed with the netmask must equal the network address.
        /// </summary>
        /// <param name="address">The address to test.</param>
        /// <returns><c>true</c> if the address belongs to this CIDR network.</returns>
        public bool Contains(IPAddress address)
        {
            if (address.AddressFamily != AddressFamily)
                return false;

            var addressBytes = address.GetAddressBytes();
            var maskedAddress = new byte[addressBytes.Length];

            for (var i = 0; i < addressBytes.Length; i++)
            {
                maskedAddress[i] = (byte)(addressBytes[i] & Netmask[i]);
            }

            return maskedAddress.SequenceEqual(NetworkAddress);
        }

        /// <summary>
        /// Matches the network directly against the destination-address bytes of a raw IP packet,
        /// avoiding IPAddress/byte[] allocations on the data path (4 bytes for IPv4, 16 for IPv6).
        /// </summary>
        /// <param name="packet">Raw IP packet.</param>
        /// <param name="dstOffset">Byte offset of the destination address within the packet.</param>
        /// <param name="addrLen">Length in bytes of the destination address.</param>
        /// <returns><c>true</c> if the destination address belongs to this CIDR network.</returns>
        public bool ContainsPacket(byte[] packet, int dstOffset, int addrLen)
        {
            for (var i = 0; i < addrLen; i++)
            {
                if ((byte)(packet[dstOffset + i] & Netmask[i]) != NetworkAddress[i])
                    return false;
            }
            return true;
        }

        /// <summary>
        /// Computes the network address (address AND mask) and the subnet mask for a prefix length:
        /// full bytes (prefixLength / 8) become 0xFF, a partial byte becomes 0xFF left-shifted by
        /// (8 - remainingBits), and all trailing bytes become zero.
        /// </summary>
        /// <param name="address">Address bytes to mask.</param>
        /// <param name="prefixLength">Prefix length in bits.</param>
        /// <param name="network">Output buffer receiving the masked network address.</param>
        /// <param name="mask">Output buffer receiving the subnet mask.</param>
        private static void CalculateNetworkAndMask(byte[] address, int prefixLength, byte[] network, byte[] mask)
        {
            var fullBytes = prefixLength / 8;
            var remainingBits = prefixLength % 8;

            for (var i = 0; i < fullBytes; i++)
            {
                mask[i] = 0xFF;
                network[i] = address[i];
            }

            if (remainingBits > 0 && fullBytes < address.Length)
            {
                mask[fullBytes] = (byte)(0xFF << (8 - remainingBits));
                network[fullBytes] = (byte)(address[fullBytes] & mask[fullBytes]);
            }

            for (var i = fullBytes + (remainingBits > 0 ? 1 : 0); i < address.Length; i++)
            {
                mask[i] = 0x00;
                network[i] = 0x00;
            }
        }

        /// <summary>
        /// Value equality on the (AddressFamily, PrefixLength, NetworkAddress) triple.
        /// </summary>
        /// <param name="other">The entry to compare with.</param>
        /// <returns><c>true</c> if both entries describe the same CIDR network.</returns>
        public bool Equals(IPNetworkEntry? other)
        {
            if (other == null) return false;
            return AddressFamily == other.AddressFamily &&
                   PrefixLength == other.PrefixLength &&
                   NetworkAddress.SequenceEqual(other.NetworkAddress);
        }

        /// <summary>Delegates to the typed <see cref="Equals(IPNetworkEntry)"/> overload.</summary>
        public override bool Equals(object? obj)
        {
            return Equals(obj as IPNetworkEntry);
        }

        /// <summary>Hash code combining family, prefix length, and network address bytes.</summary>
        public override int GetHashCode()
        {
            var hash = AddressFamily.GetHashCode() ^ PrefixLength.GetHashCode();
            foreach (var b in NetworkAddress)
            {
                hash ^= b.GetHashCode();
            }
            return hash;
        }
    }
}
