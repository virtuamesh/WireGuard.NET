using System.Net;
using Xunit;
using WireGuard.NET.Protocol;

namespace WireGuard.NET.Tests.Protocol;

/// <summary>
/// Tests for the allowed-IPs filter, covering IPv4 and IPv6 network matching, removal, clearing, and packet-level checks.
/// </summary>
public class AllowedIPsFilterTests
{
    /// <summary>
    /// Verifies that a /32 entry allows exactly one IPv4 address.
    /// </summary>
    [Fact]
    public void AddAndCheckIPv4Network_SingleIP_IsAllowed()
    {
        var filter = new AllowedIPsFilter();
        filter.AddAllowedIP(IPAddress.Parse("192.168.4.4"), 32);
        
        Assert.True(filter.IsAllowed(IPAddress.Parse("192.168.4.4")));
        Assert.False(filter.IsAllowed(IPAddress.Parse("192.168.4.5")));
    }

    /// <summary>
    /// Verifies that a /24 entry allows addresses inside the network and rejects addresses outside it.
    /// </summary>
    [Fact]
    public void AddAndCheckIPv4Network_Prefix_IsAllowed()
    {
        var filter = new AllowedIPsFilter();
        filter.AddAllowedIP(IPAddress.Parse("192.168.4.0"), 24);
        
        Assert.True(filter.IsAllowed(IPAddress.Parse("192.168.4.20")));
        Assert.True(filter.IsAllowed(IPAddress.Parse("192.168.4.0")));
        Assert.False(filter.IsAllowed(IPAddress.Parse("192.168.5.0")));
    }

    /// <summary>
    /// Verifies that overlapping networks with different prefix lengths all match the addresses they contain.
    /// </summary>
    [Fact]
    public void AddAndCheckIPv4Network_MultipleNetworks_PrioritizesSpecific()
    {
        var filter = new AllowedIPsFilter();
        filter.AddAllowedIP(IPAddress.Parse("192.168.0.0"), 16);
        filter.AddAllowedIP(IPAddress.Parse("192.168.4.0"), 24);
        filter.AddAllowedIP(IPAddress.Parse("192.168.4.4"), 32);
        
        Assert.True(filter.IsAllowed(IPAddress.Parse("192.168.4.4")));
        Assert.True(filter.IsAllowed(IPAddress.Parse("192.168.4.20")));
        Assert.True(filter.IsAllowed(IPAddress.Parse("192.168.200.182")));
    }

    /// <summary>
    /// Verifies that IPv6 /128 and /64 entries match addresses inside their ranges.
    /// </summary>
    [Fact]
    public void AddAndCheckIPv6Network_IsAllowed()
    {
        var filter = new AllowedIPsFilter();
        filter.AddAllowedIP(IPAddress.Parse("2607:5300:6000:6b00::c05f:0543"), 128);
        filter.AddAllowedIP(IPAddress.Parse("2607:5300:6000:6b00::"), 64);
        
        Assert.True(filter.IsAllowed(IPAddress.Parse("2607:5300:6000:6b00::c05f:0543")));
        Assert.True(filter.IsAllowed(IPAddress.Parse("2607:5300:6000:6b00::c02e:01ee")));
    }

    /// <summary>
    /// Verifies that removing a network stops it from matching addresses.
    /// </summary>
    [Fact]
    public void RemoveAllowedIP_NetworkIsRemoved()
    {
        var filter = new AllowedIPsFilter();
        filter.AddAllowedIP(IPAddress.Parse("192.168.4.0"), 24);
        
        Assert.True(filter.IsAllowed(IPAddress.Parse("192.168.4.20")));
        
        filter.RemoveAllowedIP(IPAddress.Parse("192.168.4.0"), 24);
        
        Assert.False(filter.IsAllowed(IPAddress.Parse("192.168.4.20")));
    }

    /// <summary>
    /// Verifies that clearing the filter removes every allowed network.
    /// </summary>
    [Fact]
    public void Clear_AllNetworksAreRemoved()
    {
        var filter = new AllowedIPsFilter();
        filter.AddAllowedIP(IPAddress.Parse("192.168.4.0"), 24);
        filter.AddAllowedIP(IPAddress.Parse("10.0.0.0"), 8);
        
        Assert.True(filter.IsAllowed(IPAddress.Parse("192.168.4.20")));
        Assert.True(filter.IsAllowed(IPAddress.Parse("10.1.2.3")));
        
        filter.Clear();
        
        Assert.False(filter.IsAllowed(IPAddress.Parse("192.168.4.20")));
        Assert.False(filter.IsAllowed(IPAddress.Parse("10.1.2.3")));
    }

    /// <summary>
    /// Verifies that GetAll returns the string form of every added IPv4 and IPv6 network.
    /// </summary>
    [Fact]
    public void GetAll_ReturnsAllNetworks()
    {
        var filter = new AllowedIPsFilter();
        filter.AddAllowedIP(IPAddress.Parse("192.168.4.0"), 24);
        filter.AddAllowedIP(IPAddress.Parse("10.0.0.0"), 8);
        filter.AddAllowedIP(IPAddress.Parse("2607:5300:6000:6b00::"), 64);
        
        var all = filter.GetAll();
        
        Assert.Equal(3, all.Count);
        Assert.Contains("192.168.4.0/24", all);
        Assert.Contains("10.0.0.0/8", all);
        Assert.Contains("2607:5300:6000:6b00::/64", all);
    }

    /// <summary>
    /// Verifies that IPv4 packets are classified by destination address against the allowed networks.
    /// </summary>
    [Fact]
    public void IsPacketAllowed_IPv4Packet_CorrectlyChecksDestinationIP()
    {
        var filter = new AllowedIPsFilter();
        filter.AddAllowedIP(IPAddress.Parse("192.168.4.0"), 24);
        
        var ipv4Packet = new byte[]
        {
            0x45, 0x00, 0x00, 0x3c, 0x1e, 0x46, 0x40, 0x00,
            0x40, 0x06, 0xb1, 0xe6, 0x0a, 0x00, 0x00, 0x01,
            0xc0, 0xa8, 0x04, 0x14
        };
        
        Assert.True(filter.IsPacketAllowed(ipv4Packet));
        
        var ipv4PacketOther = new byte[]
        {
            0x45, 0x00, 0x00, 0x3c, 0x1e, 0x46, 0x40, 0x00,
            0x40, 0x06, 0xb1, 0xe6, 0xc0, 0xa8, 0x04, 0x14,
            0x0a, 0x00, 0x00, 0x01
        };
        
        Assert.False(filter.IsPacketAllowed(ipv4PacketOther));
    }

    /// <summary>
    /// Verifies that IPv6 packets are classified by destination address against the allowed networks.
    /// </summary>
    [Fact]
    public void IsPacketAllowed_IPv6Packet_CorrectlyChecksDestinationIP()
    {
        var filter = new AllowedIPsFilter();
        filter.AddAllowedIP(IPAddress.Parse("2607:5300:6000:6b00::"), 64);
        
        var ipv6Packet = new byte[40];
        ipv6Packet[0] = 0x60;
        var srcAddr = IPAddress.Parse("2001:db8::1").GetAddressBytes();
        Array.Copy(srcAddr, 0, ipv6Packet, 8, 16);
        var dstAddr = IPAddress.Parse("2607:5300:6000:6b00::c05f:0543").GetAddressBytes();
        Array.Copy(dstAddr, 0, ipv6Packet, 24, 16);
        
        Assert.True(filter.IsPacketAllowed(ipv6Packet));
        
        var ipv6PacketOther = new byte[40];
        ipv6PacketOther[0] = 0x60;
        var srcAddrOther = IPAddress.Parse("2607:5300:6000:6b00::1").GetAddressBytes();
        Array.Copy(srcAddrOther, 0, ipv6PacketOther, 8, 16);
        var dstAddrOther = IPAddress.Parse("2001:db8::1").GetAddressBytes();
        Array.Copy(dstAddrOther, 0, ipv6PacketOther, 24, 16);
        
        Assert.False(filter.IsPacketAllowed(ipv6PacketOther));
    }
}
