using System.Net;
using Xunit;
using WireGuard.NET.Protocol;

namespace WireGuard.NET.Tests.Protocol;

/// <summary>
/// Tests for the per-IP rate limiter, covering burst allowance, per-address independence, IPv6 handling, packet checks, and reset.
/// </summary>
public class RateLimiterTests
{
    /// <summary>
    /// Verifies that up to the five-packet burst from one IPv4 address is allowed.
    /// </summary>
    [Fact]
    public void Allow_BurstPackets_AllAllowed()
    {
        var limiter = new RateLimiter();
        var ip = IPAddress.Parse("192.168.1.1");
        
        for (var i = 0; i < 5; i++)
        {
            Assert.True(limiter.Allow(ip), $"Packet {i + 1} should be allowed");
        }
    }

    /// <summary>
    /// Verifies that the sixth packet from the same address is denied.
    /// </summary>
    [Fact]
    public void Allow_ExceedsBurst_NotAllowed()
    {
        var limiter = new RateLimiter();
        var ip = IPAddress.Parse("192.168.1.1");
        
        for (var i = 0; i < 5; i++)
        {
            Assert.True(limiter.Allow(ip));
        }
        
        Assert.False(limiter.Allow(ip), "6th packet should be rate limited");
    }

    /// <summary>
    /// Verifies that two addresses each receive their own burst allowance.
    /// </summary>
    [Fact]
    public void Allow_DifferentIPs_IndependentLimiting()
    {
        var limiter = new RateLimiter();
        var ip1 = IPAddress.Parse("192.168.1.1");
        var ip2 = IPAddress.Parse("192.168.1.2");
        
        for (var i = 0; i < 5; i++)
        {
            Assert.True(limiter.Allow(ip1));
            Assert.True(limiter.Allow(ip2));
        }
        
        Assert.False(limiter.Allow(ip1));
        Assert.False(limiter.Allow(ip2));
    }

    /// <summary>
    /// Verifies that IPv6 addresses are limited with the same burst behavior.
    /// </summary>
    [Fact]
    public void Allow_IPv6Address_IsAllowed()
    {
        var limiter = new RateLimiter();
        var ip = IPAddress.Parse("2001:db8::1");
        
        for (var i = 0; i < 5; i++)
        {
            Assert.True(limiter.Allow(ip));
        }
        
        Assert.False(limiter.Allow(ip));
    }

    /// <summary>
    /// Verifies that AllowPacket classifies IPv4 packets by source address and enforces the burst limit.
    /// </summary>
    [Fact]
    public void AllowPacket_IPv4Packet_CorrectlyChecks()
    {
        var limiter = new RateLimiter();
        
        var ipv4Packet = new byte[]
        {
            0x45, 0x00, 0x00, 0x3c, 0x1e, 0x46, 0x40, 0x00,
            0x40, 0x06, 0xb1, 0xe6, 0xc0, 0xa8, 0x01, 0x01,
            0xc0, 0xa8, 0x00, 0x01
        };
        
        for (var i = 0; i < 5; i++)
        {
            Assert.True(limiter.AllowPacket(ipv4Packet));
        }
        
        Assert.False(limiter.AllowPacket(ipv4Packet));
    }

    /// <summary>
    /// Verifies that Clear resets the limiter so the full burst is allowed again.
    /// </summary>
    [Fact]
    public void Clear_AllEntriesCleared()
    {
        var limiter = new RateLimiter();
        var ip = IPAddress.Parse("192.168.1.1");
        
        for (var i = 0; i < 5; i++)
        {
            Assert.True(limiter.Allow(ip));
        }
        
        Assert.False(limiter.Allow(ip));
        
        limiter.Clear();
        
        for (var i = 0; i < 5; i++)
        {
            Assert.True(limiter.Allow(ip));
        }
    }
}
