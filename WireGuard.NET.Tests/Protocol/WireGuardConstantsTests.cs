using WireGuard.NET.Protocol;
using Xunit;

namespace WireGuard.NET.Tests.Protocol;

/// <summary>
/// Tests that WireGuard protocol constants match the specification, including key sizes, message types and lengths, and timers.
/// </summary>
public class WireGuardConstantsTests
{
    /// <summary>
    /// Verifies that the key, public key, hash, and cookie key lengths are 32 bytes.
    /// </summary>
    [Fact]
    public void KeyLengths_ShouldBe32()
    {
        Assert.Equal(32, WireGuardConstants.WG_KEY_LEN);
        Assert.Equal(32, WireGuardConstants.NOISE_PUBLIC_KEY_LEN);
        Assert.Equal(32, WireGuardConstants.NOISE_HASH_LEN);
        Assert.Equal(32, WireGuardConstants.WG_COOKIE_KEY_LEN);
    }

    /// <summary>
    /// Verifies that the AEAD nonce length is 12 and tag lengths are 16.
    /// </summary>
    [Fact]
    public void AEAD_Parameters_ShouldMatchWireGuardSpec()
    {
        Assert.Equal(12, WireGuardConstants.WG_AEAD_NONCE_LEN);
        Assert.Equal(16, WireGuardConstants.WG_AEAD_TAG_LEN);
        Assert.Equal(16, WireGuardConstants.NOISE_AUTHTAG_LEN);
    }

    /// <summary>
    /// Verifies that the cookie nonce, cookie, and MAC lengths match the specification.
    /// </summary>
    [Fact]
    public void Cookie_Parameters_ShouldMatchWireGuardSpec()
    {
        Assert.Equal(24, WireGuardConstants.WG_COOKIE_NONCE_LEN);
        Assert.Equal(16, WireGuardConstants.WG_COOKIE_LEN);
        Assert.Equal(16, WireGuardConstants.WG_COOKIE_MAC_LEN);
    }

    /// <summary>
    /// Verifies that message types are initiation 1, response 2, cookie 3, and data 4.
    /// </summary>
    [Fact]
    public void MessageTypes_ShouldMatchWireGuardSpec()
    {
        Assert.Equal(1u, WireGuardConstants.TYPE_INITIATION);
        Assert.Equal(2u, WireGuardConstants.TYPE_RESPONSE);
        Assert.Equal(3u, WireGuardConstants.TYPE_COOKIE);
        Assert.Equal(4u, WireGuardConstants.TYPE_DATA);
    }

    /// <summary>
    /// Verifies that initiation, response, and cookie reply message lengths match the specification.
    /// </summary>
    [Fact]
    public void MessageLengths_ShouldMatchWireGuardSpec()
    {
        Assert.Equal(148, WireGuardConstants.HANDSHAKE_INITIATION_LEN);
        Assert.Equal(92, WireGuardConstants.HANDSHAKE_RESPONSE_LEN);
        Assert.Equal(64, WireGuardConstants.COOKIE_REPLY_LEN);
    }

    /// <summary>
    /// Verifies that the rekey-after-time constant is 180 seconds.
    /// </summary>
    [Fact]
    public void RekeyAfterTime_ShouldBe180Seconds()
    {
        Assert.Equal(180, WireGuardConstants.REKEY_AFTER_TIME);
    }

    /// <summary>
    /// Verifies that the reject-after-time constant is 600 seconds.
    /// </summary>
    [Fact]
    public void RejectAfterTime_ShouldBe600Seconds()
    {
        Assert.Equal(600, WireGuardConstants.REJECT_AFTER_TIME);
    }

    /// <summary>
    /// Verifies that the rekey-attempt-time constant is 90 seconds.
    /// </summary>
    [Fact]
    public void RekeyAttemptTime_ShouldBe90Seconds()
    {
        Assert.Equal(90, WireGuardConstants.REKEY_ATTEMPT_TIME);
    }

    /// <summary>
    /// Verifies that the rekey-after-messages constant is 2 to the power of 60.
    /// </summary>
    [Fact]
    public void RekeyAfterMessages_ShouldBe2ToThe60()
    {
        Assert.Equal(1UL << 60, WireGuardConstants.REKEY_AFTER_MESSAGES);
    }

    /// <summary>
    /// Verifies that the reject-after-messages constant is 2 to the power of 64 minus 2 to the power of 4 minus 1.
    /// </summary>
    [Fact]
    public void RejectAfterMessages_ShouldBeNearMax()
    {
        Assert.Equal(WireGuardConstants.REJECT_AFTER_MESSAGES, unchecked((1UL << 64) - (1UL << 4) - 1));
    }

    /// <summary>
    /// Verifies that the TAI64N timestamp length is 12 bytes.
    /// </summary>
    [Fact]
    public void TimestampLength_ShouldBe12()
    {
        Assert.Equal(12, WireGuardConstants.NOISE_TAI64N_LEN);
    }

    /// <summary>
    /// Verifies that the message type, index, counter, and header lengths are correct.
    /// </summary>
    [Fact]
    public void MessageHeaderLengths_ShouldBeCorrect()
    {
        Assert.Equal(4, WireGuardConstants.MESSAGE_TYPE_LEN);
        Assert.Equal(4, WireGuardConstants.MESSAGE_INDEX_LEN);
        Assert.Equal(8, WireGuardConstants.MESSAGE_COUNTER_LEN);
        Assert.Equal(4, WireGuardConstants.MESSAGE_HEADER_LEN);
    }

    /// <summary>
    /// Verifies that the initiation header length is 8 bytes.
    /// </summary>
    [Fact]
    public void InitiationHeaderLen_ShouldBe8()
    {
        Assert.Equal(8, WireGuardConstants.INITIATION_HEADER_LEN);
    }

    /// <summary>
    /// Verifies that the response header length is 12 bytes.
    /// </summary>
    [Fact]
    public void ResponseHeaderLen_ShouldBe12()
    {
        Assert.Equal(12, WireGuardConstants.RESPONSE_HEADER_LEN);
    }

    /// <summary>
    /// Verifies that the minimum data packet length is 16 bytes.
    /// </summary>
    [Fact]
    public void DataPacketMinLen_ShouldBe16()
    {
        Assert.Equal(16, WireGuardConstants.DATA_PACKET_MIN_LEN);
    }

    /// <summary>
    /// Verifies that the keepalive timeout constant is 10 seconds.
    /// </summary>
    [Fact]
    public void KeepaliveTimeout_ShouldBe10()
    {
        Assert.Equal(10, WireGuardConstants.KEEPALIVE_TIMEOUT);
    }

    /// <summary>
    /// Verifies that the cookie secret rotation time is 120 seconds.
    /// </summary>
    [Fact]
    public void CookieSecretTime_ShouldBe120()
    {
        Assert.Equal(120, WireGuardConstants.COOKIE_SECRET_TIME);
    }
}
