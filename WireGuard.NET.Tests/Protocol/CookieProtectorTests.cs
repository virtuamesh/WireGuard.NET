using System.Net;
using WireGuard.NET.Protocol;
using Xunit;

namespace WireGuard.NET.Tests.Protocol;

/// <summary>
/// Tests for the cookie protector, covering MAC computation, MAC validation, cookie replies, and cookie storage.
/// </summary>
public class CookieProtectorTests
{
    /// <summary>
    /// Verifies that initializing with a public key leaves the protector without a cookie for a new endpoint.
    /// </summary>
    [Fact]
    public void Initialize_ShouldSetMacKeys()
    {
        var protector = new CookieProtector();
        var publicKey = new byte[32];
        new Random(42).NextBytes(publicKey);

        protector.Initialize(publicKey);

        Assert.True(protector.HasCookieForEndpoint(new IPEndPoint(IPAddress.Loopback, 1234)) == false);
    }

    /// <summary>
    /// Verifies that ComputeMacs returns 16-byte mac1 and mac2 values.
    /// </summary>
    [Fact]
    public void ComputeMacs_ShouldReturn16ByteMacs()
    {
        var protector = new CookieProtector();
        var publicKey = new byte[32];
        new Random(42).NextBytes(publicKey);
        protector.Initialize(publicKey);

        var message = new byte[100];
        new Random(43).NextBytes(message);
        var endpoint = new IPEndPoint(IPAddress.Loopback, 1234);

        var (mac1, mac2) = protector.ComputeMacs(message, endpoint);

        Assert.Equal(16, mac1.Length);
        Assert.Equal(16, mac2.Length);
    }

    /// <summary>
    /// Verifies that mac2 is all zeros when no cookie is held for the endpoint.
    /// </summary>
    [Fact]
    public void ComputeMacs_WithoutCookie_Mac2ShouldBeZero()
    {
        var protector = new CookieProtector();
        var publicKey = new byte[32];
        new Random(42).NextBytes(publicKey);
        protector.Initialize(publicKey);

        var message = new byte[100];
        var endpoint = new IPEndPoint(IPAddress.Loopback, 1234);

        var (_, mac2) = protector.ComputeMacs(message, endpoint);

        Assert.True(mac2.All(b => b == 0));
    }

    /// <summary>
    /// Verifies that mac2 is all zeros when no endpoint is supplied.
    /// </summary>
    [Fact]
    public void ComputeMacs_WithNullEndpoint_Mac2ShouldBeZero()
    {
        var protector = new CookieProtector();
        var publicKey = new byte[32];
        new Random(42).NextBytes(publicKey);
        protector.Initialize(publicKey);

        var message = new byte[100];

        var (_, mac2) = protector.ComputeMacs(message, null);

        Assert.True(mac2.All(b => b == 0));
    }

    /// <summary>
    /// Verifies that ValidateMac1 accepts a packet carrying a correctly computed mac1.
    /// </summary>
    [Fact]
    public void ValidateMac1_ValidMac_ShouldReturnTrue()
    {
        var protector = new CookieProtector();
        var publicKey = new byte[32];
        new Random(42).NextBytes(publicKey);
        protector.Initialize(publicKey);

        var messageWithoutMacs = new byte[100];
        new Random(43).NextBytes(messageWithoutMacs);
        var endpoint = new IPEndPoint(IPAddress.Loopback, 1234);

        var (mac1, mac2) = protector.ComputeMacs(messageWithoutMacs, endpoint);

        var fullPacket = new byte[messageWithoutMacs.Length + 32];
        Buffer.BlockCopy(messageWithoutMacs, 0, fullPacket, 0, messageWithoutMacs.Length);
        Buffer.BlockCopy(mac1, 0, fullPacket, messageWithoutMacs.Length, 16);
        Buffer.BlockCopy(mac2, 0, fullPacket, messageWithoutMacs.Length + 16, 16);

        var result = protector.ValidateMac1(fullPacket);

        Assert.True(result);
    }

    /// <summary>
    /// Verifies that ValidateMac1 rejects a packet whose MAC fields are random.
    /// </summary>
    [Fact]
    public void ValidateMac1_InvalidMac_ShouldReturnFalse()
    {
        var protector = new CookieProtector();
        var publicKey = new byte[32];
        new Random(42).NextBytes(publicKey);
        protector.Initialize(publicKey);

        var packet = new byte[132];
        new Random(43).NextBytes(packet);

        var result = protector.ValidateMac1(packet);

        Assert.False(result);
    }

    /// <summary>
    /// Verifies that a cookie reply has the length defined by the protocol constants.
    /// </summary>
    [Fact]
    public void CreateCookieReply_ShouldReturnCorrectLength()
    {
        var protector = new CookieProtector();
        var publicKey = new byte[32];
        new Random(42).NextBytes(publicKey);
        protector.Initialize(publicKey);

        var initiationPacket = new byte[WireGuardConstants.HANDSHAKE_INITIATION_LEN];
        BitConverter.GetBytes(WireGuardConstants.TYPE_INITIATION).CopyTo(initiationPacket, 0);
        BitConverter.GetBytes((uint)12345).CopyTo(initiationPacket, 4);
        var endpoint = new IPEndPoint(IPAddress.Loopback, 51820);

        var reply = protector.CreateCookieReply(initiationPacket, endpoint);

        Assert.Equal(WireGuardConstants.COOKIE_REPLY_LEN, reply.Length);
    }

    /// <summary>
    /// Verifies that the cookie reply header carries the cookie message type.
    /// </summary>
    [Fact]
    public void CreateCookieReply_MessageTypeShouldBe3()
    {
        var protector = new CookieProtector();
        var publicKey = new byte[32];
        new Random(42).NextBytes(publicKey);
        protector.Initialize(publicKey);

        var initiationPacket = new byte[WireGuardConstants.HANDSHAKE_INITIATION_LEN];
        BitConverter.GetBytes(WireGuardConstants.TYPE_INITIATION).CopyTo(initiationPacket, 0);
        BitConverter.GetBytes((uint)12345).CopyTo(initiationPacket, 4);
        var endpoint = new IPEndPoint(IPAddress.Loopback, 51820);

        var reply = protector.CreateCookieReply(initiationPacket, endpoint);

        var messageType = BitConverter.ToUInt32(reply, 0);
        Assert.Equal(WireGuardConstants.TYPE_COOKIE, messageType);
    }

    /// <summary>
    /// Verifies that a client that tracked its sent mac1 stores the cookie after processing a matching reply.
    /// </summary>
    [Fact]
    public void ProcessCookieReply_And_ValidateMac2_ShouldWork()
    {
        var serverProtector = new CookieProtector();
        var clientProtector = new CookieProtector();
        var serverPubKey = new byte[32];
        new Random(42).NextBytes(serverPubKey);
        serverProtector.Initialize(serverPubKey);
        clientProtector.Initialize(serverPubKey);

        var initiationPacket = new byte[WireGuardConstants.HANDSHAKE_INITIATION_LEN];
        BitConverter.GetBytes(WireGuardConstants.TYPE_INITIATION).CopyTo(initiationPacket, 0);
        BitConverter.GetBytes((uint)12345).CopyTo(initiationPacket, 4);
        var endpoint = new IPEndPoint(IPAddress.Loopback, 51820);

        // cookie reply 的 AEAD AD 为触发报文的 mac1，客户端需先记录已发报文的 mac1
        clientProtector.TrackSentMac1(endpoint, initiationPacket);

        var cookieReply = serverProtector.CreateCookieReply(initiationPacket, endpoint);

        clientProtector.ProcessCookieReply(cookieReply, endpoint);

        Assert.True(clientProtector.HasCookieForEndpoint(endpoint));
    }

    /// <summary>
    /// Verifies that a reply whose associated data does not match a tracked mac1 does not store a cookie.
    /// </summary>
    [Fact]
    public void ProcessCookieReply_WithoutTrackedMac1_ShouldNotStoreCookie()
    {
        // 规范要求 AD = 我方已发报文的 mac1；未记录（AD 不匹配）时解密必须失败
        var serverProtector = new CookieProtector();
        var clientProtector = new CookieProtector();
        var serverPubKey = new byte[32];
        new Random(42).NextBytes(serverPubKey);
        serverProtector.Initialize(serverPubKey);
        clientProtector.Initialize(serverPubKey);

        var initiationPacket = new byte[WireGuardConstants.HANDSHAKE_INITIATION_LEN];
        BitConverter.GetBytes(WireGuardConstants.TYPE_INITIATION).CopyTo(initiationPacket, 0);
        BitConverter.GetBytes((uint)12345).CopyTo(initiationPacket, 4);
        // mac1 非零，确保 AD 与空 AD 不同
        for (int i = initiationPacket.Length - 32; i < initiationPacket.Length - 16; i++)
            initiationPacket[i] = 0xAB;
        var endpoint = new IPEndPoint(IPAddress.Loopback, 51820);

        var cookieReply = serverProtector.CreateCookieReply(initiationPacket, endpoint);

        clientProtector.ProcessCookieReply(cookieReply, endpoint);

        Assert.False(clientProtector.HasCookieForEndpoint(endpoint));
    }

    /// <summary>
    /// Verifies that once a cookie is stored, ComputeMacs attaches a non-zero mac2.
    /// </summary>
    [Fact]
    public void ComputeMacs_WithCookieFromReply_ShouldAttachNonZeroMac2()
    {
        var serverProtector = new CookieProtector();
        var clientProtector = new CookieProtector();
        var serverPubKey = new byte[32];
        new Random(42).NextBytes(serverPubKey);
        serverProtector.Initialize(serverPubKey);
        clientProtector.Initialize(serverPubKey);

        var initiationPacket = new byte[WireGuardConstants.HANDSHAKE_INITIATION_LEN];
        BitConverter.GetBytes(WireGuardConstants.TYPE_INITIATION).CopyTo(initiationPacket, 0);
        BitConverter.GetBytes((uint)12345).CopyTo(initiationPacket, 4);
        var endpoint = new IPEndPoint(IPAddress.Loopback, 51820);

        clientProtector.TrackSentMac1(endpoint, initiationPacket);
        var cookieReply = serverProtector.CreateCookieReply(initiationPacket, endpoint);
        clientProtector.ProcessCookieReply(cookieReply, endpoint);

        var message = new byte[100];
        new Random(43).NextBytes(message);
        var (_, mac2) = clientProtector.ComputeMacs(message, endpoint);

        Assert.False(mac2.All(b => b == 0), "持有对端 cookie 时 mac2 必须非零（规范要求附带）");
    }

    /// <summary>
    /// Verifies that processing an all-zero cookie reply does not throw.
    /// </summary>
    [Fact]
    public void ProcessCookieReply_InvalidMessage_ShouldNotCrash()
    {
        var protector = new CookieProtector();
        var publicKey = new byte[32];
        new Random(42).NextBytes(publicKey);
        protector.Initialize(publicKey);

        var invalidPacket = new byte[WireGuardConstants.COOKIE_REPLY_LEN];
        var endpoint = new IPEndPoint(IPAddress.Loopback, 51820);

        protector.ProcessCookieReply(invalidPacket, endpoint);
    }

    /// <summary>
    /// Verifies that ClearCookies removes stored cookies.
    /// </summary>
    [Fact]
    public void ClearCookies_ShouldRemoveAllCookies()
    {
        var protector = new CookieProtector();
        var publicKey = new byte[32];
        new Random(42).NextBytes(publicKey);
        protector.Initialize(publicKey);

        protector.SetCookie(new byte[16]);
        protector.ClearCookies();

        Assert.False(protector.HasCookieForEndpoint(new IPEndPoint(IPAddress.Loopback, 1234)));
    }

    /// <summary>
    /// Verifies that two protectors initialized with the same key produce the same mac1 for the same message.
    /// </summary>
    [Fact]
    public void ComputeMacs_SameMessageSameKey_ShouldReturnSameMac1()
    {
        var protector1 = new CookieProtector();
        var protector2 = new CookieProtector();
        var publicKey = new byte[32];
        new Random(42).NextBytes(publicKey);
        protector1.Initialize(publicKey);
        protector2.Initialize(publicKey);

        var message = new byte[100];
        new Random(43).NextBytes(message);
        var endpoint = new IPEndPoint(IPAddress.Loopback, 1234);

        var (mac1_a, _) = protector1.ComputeMacs(message, endpoint);
        var (mac1_b, _) = protector2.ComputeMacs(message, endpoint);

        Assert.Equal(mac1_a, mac1_b);
    }

    /// <summary>
    /// Verifies that different messages produce different mac1 values.
    /// </summary>
    [Fact]
    public void ComputeMacs_DifferentMessages_ShouldReturnDifferentMac1()
    {
        var protector = new CookieProtector();
        var publicKey = new byte[32];
        new Random(42).NextBytes(publicKey);
        protector.Initialize(publicKey);

        var message1 = new byte[100];
        var message2 = new byte[100];
        new Random(43).NextBytes(message1);
        new Random(44).NextBytes(message2);
        var endpoint = new IPEndPoint(IPAddress.Loopback, 1234);

        var (mac1_a, _) = protector.ComputeMacs(message1, endpoint);
        var (mac1_b, _) = protector.ComputeMacs(message2, endpoint);

        Assert.NotEqual(mac1_a, mac1_b);
    }
}
