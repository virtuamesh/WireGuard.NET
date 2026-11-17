using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;

namespace WireGuard.NET;

/// <summary>
/// [VM-STUN-ON-WG-SOCKET 2026-11-05] Performs STUN Binding on **WireGuard's own UDP socket**.
///
/// Why the same socket must be reused: NATs (especially CGNAT / symmetric NAT) allocate a
/// different external port for each 5-tuple. A STUN probe from a side-channel temporary
/// socket only yields the mapping of *that temporary port*, which is meaningless for the
/// WireGuard data plane — this was exactly the root cause of the earlier symptom where
/// "the public endpoint reported by the server was unreachable by peers, so connectivity
/// fell back to DERP" (2026-11-05 production: u24 reported 124.89.103.222:32931~32942,
/// all unreachable for direct connection).
///
/// This class is responsible only for building/parsing datagrams (pure functions, easy
/// to unit-test); actual send/receive is performed by <see cref="WireGuardDevice"/> inside
/// its existing receive loop: STUN responses are recognized and extracted before they
/// enter WireGuard parsing.
/// </summary>
public static class StunEndpointDiscovery
{
    /// <summary>The RFC 5389 magic cookie.</summary>
    public const uint MagicCookie = 0x2112A442;

    private const ushort BindingRequest = 0x0001;
    private const ushort BindingSuccessResponse = 0x0101;
    private const ushort AttributeMappedAddress = 0x0001;
    private const ushort AttributeXorMappedAddress = 0x0020;

    /// <summary>
    /// Builds a Binding Request and outputs the 12-byte transaction ID (used for response matching).
    /// </summary>
    /// <param name="transactionId">When this method returns, contains the randomly generated 12-byte transaction ID used to match the corresponding response.</param>
    /// <returns>A 20-byte STUN Binding Request datagram.</returns>
    public static byte[] BuildBindingRequest(out byte[] transactionId)
    {
        transactionId = RandomNumberGenerator.GetBytes(12);
        var packet = new byte[20];
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(0, 2), BindingRequest);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2, 2), 0);
        BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(4, 4), MagicCookie);
        transactionId.CopyTo(packet, 8);
        return packet;
    }

    /// <summary>
    /// Quickly determines whether a datagram looks like STUN (used to intercept it before WireGuard parsing).
    /// WireGuard packets have a first byte of 1/2/3/4, while the STUN first byte is the high bits
    /// of the message length, so checking the cookie is the more reliable discriminator.
    /// </summary>
    /// <param name="packet">The received datagram.</param>
    /// <returns><c>true</c> if the datagram carries the STUN magic cookie; otherwise, <c>false</c>.</returns>
    public static bool LooksLikeStun(ReadOnlySpan<byte> packet)
    {
        if (packet.Length < 20) return false;
        return BinaryPrimitives.ReadUInt32BigEndian(packet.Slice(4, 4)) == MagicCookie;
    }

    /// <summary>
    /// Parses the mapped address out of a Binding Success Response.
    /// </summary>
    /// <param name="packet">The received datagram.</param>
    /// <param name="transactionId">When this method returns, contains the transaction ID carried by the response (the caller matches it against its own outgoing request).</param>
    /// <param name="mapped">When this method returns, contains the NAT-mapped public endpoint, or <c>null</c> if no mapped address could be parsed.</param>
    /// <returns><c>true</c> if a MAPPED-ADDRESS or XOR-MAPPED-ADDRESS attribute was successfully parsed; otherwise, <c>false</c>.</returns>
    public static bool TryParseBindingResponse(ReadOnlySpan<byte> packet, out byte[] transactionId, out IPEndPoint? mapped)
    {
        transactionId = Array.Empty<byte>();
        mapped = null;

        if (packet.Length < 20) return false;
        if (BinaryPrimitives.ReadUInt32BigEndian(packet.Slice(4, 4)) != MagicCookie) return false;
        if (BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(0, 2)) != BindingSuccessResponse) return false;

        var bodyLength = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(2, 2));
        if (20 + bodyLength > packet.Length) bodyLength = (ushort)(packet.Length - 20);

        transactionId = packet.Slice(8, 12).ToArray();

        var offset = 20;
        var end = 20 + bodyLength;
        while (offset + 4 <= end)
        {
            var attrType = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(offset, 2));
            var attrLen = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(offset + 2, 2));
            var valueOffset = offset + 4;
            if (valueOffset + attrLen > end) break;

            if ((attrType == AttributeXorMappedAddress || attrType == AttributeMappedAddress) && attrLen >= 8)
            {
                var family = packet[valueOffset + 1];
                var port = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(valueOffset + 2, 2));
                if (attrType == AttributeXorMappedAddress)
                {
                    // XOR-MAPPED-ADDRESS: the port is XOR-ed with the high 16 bits of the cookie
                    port ^= (ushort)(MagicCookie >> 16);
                }

                if (family == 0x01 && attrLen >= 8) // IPv4
                {
                    var ipBytes = packet.Slice(valueOffset + 4, 4).ToArray();
                    if (attrType == AttributeXorMappedAddress)
                    {
                        var cookieBytes = BitConverter.GetBytes(MagicCookie);
                        if (BitConverter.IsLittleEndian) Array.Reverse(cookieBytes);
                        for (var i = 0; i < 4; i++) ipBytes[i] ^= cookieBytes[i];
                    }
                    mapped = new IPEndPoint(new IPAddress(ipBytes), port);
                    return true;
                }

                if (family == 0x02 && attrLen >= 20) // IPv6
                {
                    var ipBytes = packet.Slice(valueOffset + 4, 16).ToArray();
                    if (attrType == AttributeXorMappedAddress)
                    {
                        var cookieBytes = BitConverter.GetBytes(MagicCookie);
                        if (BitConverter.IsLittleEndian) Array.Reverse(cookieBytes);
                        for (var i = 0; i < 4; i++) ipBytes[i] ^= cookieBytes[i];
                        // The last 12 bytes of the transaction ID participate in the XOR
                        for (var i = 0; i < 12; i++) ipBytes[4 + i] ^= transactionId[i];
                    }
                    mapped = new IPEndPoint(new IPAddress(ipBytes), port);
                    return true;
                }
            }

            offset = valueOffset + ((attrLen + 3) & ~3);
        }

        return false;
    }
}
