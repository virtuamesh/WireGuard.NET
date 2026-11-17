using WireGuard.NET.Protocol;
using WireGuard.NET.Crypto;
using Xunit;

namespace WireGuard.NET.Tests.Protocol;

/// <summary>
/// Tests for the WireGuard handshake message layer, covering initiation and response construction, MAC1 validation, timestamp reading, cookie handling, and end-to-end key agreement.
/// </summary>
public class WireGuardHandshakeTests
{
    private static (byte[] privateKey, byte[] publicKey) GenerateKeyPair()
    {
        var privateKey = X25519Crypto.GeneratePrivateKey();
        var publicKey = X25519Crypto.GeneratePublicKey(privateKey);
        return (privateKey, publicKey);
    }

    /// <summary>
    /// Verifies that an initiation message has the protocol-defined handshake initiation length.
    /// </summary>
    [Fact]
    public void CreateInitiation_ShouldReturnCorrectMessageSize()
    {
        var (initPriv, _) = GenerateKeyPair();
        var (_, respPub) = GenerateKeyPair();

        var handshake = new WireGuardHandshake(initPriv);
        var (message, _, _) = handshake.CreateInitiation(respPub);

        Assert.Equal(WireGuardConstants.HANDSHAKE_INITIATION_LEN, message.Length);
    }

    /// <summary>
    /// Verifies that the initiation header carries the initiation message type.
    /// </summary>
    [Fact]
    public void CreateInitiation_MessageTypeShouldBe1()
    {
        var (initPriv, _) = GenerateKeyPair();
        var (_, respPub) = GenerateKeyPair();

        var handshake = new WireGuardHandshake(initPriv);
        var (message, _, _) = handshake.CreateInitiation(respPub);

        var messageType = BitConverter.ToUInt32(message, 0);
        Assert.Equal(WireGuardConstants.TYPE_INITIATION, messageType);
    }

    /// <summary>
    /// Verifies that a peer key of the wrong length or null is rejected with ArgumentException.
    /// </summary>
    [Fact]
    public void CreateInitiation_InvalidPeerKey_ShouldThrow()
    {
        var (initPriv, _) = GenerateKeyPair();

        var handshake = new WireGuardHandshake(initPriv);

        Assert.Throws<ArgumentException>(() => handshake.CreateInitiation(new byte[16]));
        Assert.Throws<ArgumentException>(() => handshake.CreateInitiation(null!));
    }

    /// <summary>
    /// Verifies that processing a valid initiation yields a response, non-zero indices, the peer public key, and 32-byte session keys.
    /// </summary>
    [Fact]
    public void ProcessInitiation_ValidMessage_ShouldReturnResponse()
    {
        var (initPriv, initPub) = GenerateKeyPair();
        var (respPriv, respPub) = GenerateKeyPair();

        var initiator = new WireGuardHandshake(initPriv);
        var responder = new WireGuardHandshake(respPriv);

        var (initMessage, _, _) = initiator.CreateInitiation(respPub);
        var (state, senderIndex, peerPublicKey, response, localIndex, sendKey, recvKey) =
            responder.ProcessInitiation(initMessage, new[] { initPub });

        Assert.Equal(WireGuardConstants.HANDSHAKE_RESPONSE_LEN, response.Length);
        Assert.NotEqual(0u, senderIndex);
        Assert.NotEqual(0u, localIndex);
        Assert.NotNull(peerPublicKey);
        Assert.Equal(32, peerPublicKey.Length);
        Assert.NotNull(sendKey);
        Assert.Equal(32, sendKey.Length);
        Assert.NotNull(recvKey);
        Assert.Equal(32, recvKey.Length);
    }

    /// <summary>
    /// Verifies that the response header carries the response message type.
    /// </summary>
    [Fact]
    public void ProcessInitiation_ResponseMessageTypeShouldBe2()
    {
        var (initPriv, initPub) = GenerateKeyPair();
        var (respPriv, respPub) = GenerateKeyPair();

        var initiator = new WireGuardHandshake(initPriv);
        var responder = new WireGuardHandshake(respPriv);

        var (initMessage, _, _) = initiator.CreateInitiation(respPub);
        var (_, _, _, response, _, _, _) = responder.ProcessInitiation(initMessage, new[] { initPub });

        var messageType = BitConverter.ToUInt32(response, 0);
        Assert.Equal(WireGuardConstants.TYPE_RESPONSE, messageType);
    }

    /// <summary>
    /// Verifies that an initiation message with an invalid length throws ArgumentException.
    /// </summary>
    [Fact]
    public void ProcessInitiation_InvalidLength_ShouldThrow()
    {
        var (respPriv, _) = GenerateKeyPair();

        var handshake = new WireGuardHandshake(respPriv);

        Assert.Throws<ArgumentException>(() => handshake.ProcessInitiation(new byte[50], Array.Empty<byte[]>()));
    }

    /// <summary>
    /// Verifies that an initiation message with the wrong message type throws ArgumentException.
    /// </summary>
    [Fact]
    public void ProcessInitiation_WrongType_ShouldThrow()
    {
        var (respPriv, _) = GenerateKeyPair();

        var handshake = new WireGuardHandshake(respPriv);
        var message = new byte[WireGuardConstants.HANDSHAKE_INITIATION_LEN];
        BitConverter.GetBytes(WireGuardConstants.TYPE_RESPONSE).CopyTo(message, 0);

        Assert.Throws<ArgumentException>(() => handshake.ProcessInitiation(message, Array.Empty<byte[]>()));
    }

    /// <summary>
    /// Verifies that a full handshake derives mirrored transport keys and identifies the initiator public key.
    /// </summary>
    [Fact]
    public void FullHandshake_BothSidesShouldDeriveSameTransportKeys()
    {
        var (initPriv, initPub) = GenerateKeyPair();
        var (respPriv, respPub) = GenerateKeyPair();

        var initiator = new WireGuardHandshake(initPriv);
        var responder = new WireGuardHandshake(respPriv);

        var (initMessage, initState, _) = initiator.CreateInitiation(respPub);

        var (_, _, peerPubKey, response, _, respSendKey, respRecvKey) =
            responder.ProcessInitiation(initMessage, new[] { initPub });

        var expectedInitPub = X25519Crypto.GeneratePublicKey(initPriv);
        Assert.Equal(expectedInitPub, peerPubKey);

        var (_, initSendKey, initRecvKey) = initiator.ProcessResponse(response, initState);

        Assert.Equal(respSendKey, initRecvKey);
        Assert.Equal(respRecvKey, initSendKey);
    }

    /// <summary>
    /// Verifies that two independent handshakes between the same static keys derive different session keys.
    /// </summary>
    [Fact]
    public void FullHandshake_DifferentHandshakes_ShouldDeriveDifferentKeys()
    {
        var (initPriv, initPub) = GenerateKeyPair();
        var (respPriv, respPub) = GenerateKeyPair();

        var initiator1 = new WireGuardHandshake(initPriv);
        var responder1 = new WireGuardHandshake(respPriv);
        var (initMsg1, initState1, _) = initiator1.CreateInitiation(respPub);
        var (_, _, _, resp1, _, sendKey1, _) = responder1.ProcessInitiation(initMsg1, new[] { initPub });
        var (_, initSend1, _) = initiator1.ProcessResponse(resp1, initState1);

        var initiator2 = new WireGuardHandshake(initPriv);
        var responder2 = new WireGuardHandshake(respPriv);
        var (initMsg2, initState2, _) = initiator2.CreateInitiation(respPub);
        var (_, _, _, resp2, _, sendKey2, _) = responder2.ProcessInitiation(initMsg2, new[] { initPub });
        var (_, initSend2, _) = initiator2.ProcessResponse(resp2, initState2);

        Assert.NotEqual(sendKey1, sendKey2);
        Assert.NotEqual(initSend1, initSend2);
    }

    /// <summary>
    /// Verifies that separate handshakes with fresh ephemeral keys derive different initiator send keys.
    /// </summary>
    [Fact]
    public void FullHandshake_DifferentEphemeralKeys_ShouldDeriveDifferentKeys()
    {
        var (initPriv, initPub) = GenerateKeyPair();
        var (respPriv, respPub) = GenerateKeyPair();

        var initiator1 = new WireGuardHandshake(initPriv);
        var responder1 = new WireGuardHandshake(respPriv);
        var (initMsg1, initState1, _) = initiator1.CreateInitiation(respPub);
        var (_, _, _, resp1, _, sendKey1, _) = responder1.ProcessInitiation(initMsg1, new[] { initPub });
        var (_, initSend1, _) = initiator1.ProcessResponse(resp1, initState1);

        var initiator2 = new WireGuardHandshake(initPriv);
        var responder2 = new WireGuardHandshake(respPriv);
        var (initMsg2, initState2, _) = initiator2.CreateInitiation(respPub);
        var (_, _, _, resp2, _, sendKey2, _) = responder2.ProcessInitiation(initMsg2, new[] { initPub });
        var (_, initSend2, _) = initiator2.ProcessResponse(resp2, initState2);

        Assert.NotEqual(initSend1, initSend2);
    }

    /// <summary>
    /// Verifies that ValidateMac1 accepts an initiation whose MAC was computed for the correct public key.
    /// </summary>
    [Fact]
    public void ValidateMac1_ValidMessage_ShouldReturnTrue()
    {
        var (initPriv, _) = GenerateKeyPair();
        var (_, respPub) = GenerateKeyPair();

        var initiator = new WireGuardHandshake(initPriv);
        var (message, _, _) = initiator.CreateInitiation(respPub);

        var result = WireGuardHandshake.ValidateMac1(respPub, message, message.Length - 32);

        Assert.True(result);
    }

    /// <summary>
    /// Verifies that ValidateMac1 rejects an initiation when validated with a different public key.
    /// </summary>
    [Fact]
    public void ValidateMac1_WrongPublicKey_ShouldReturnFalse()
    {
        var (initPriv, _) = GenerateKeyPair();
        var (_, respPub) = GenerateKeyPair();
        var (_, wrongPub) = GenerateKeyPair();

        var initiator = new WireGuardHandshake(initPriv);
        var (message, _, _) = initiator.CreateInitiation(respPub);

        var result = WireGuardHandshake.ValidateMac1(wrongPub, message, message.Length - 32);

        Assert.False(result);
    }

    /// <summary>
    /// Verifies that the MAC1 key derived from a public key is 32 bytes.
    /// </summary>
    [Fact]
    public void ComputeMac1Key_ShouldReturn32Bytes()
    {
        var (_, pub) = GenerateKeyPair();

        var mac1Key = WireGuardHandshake.ComputeMac1Key(pub);

        Assert.Equal(32, mac1Key.Length);
    }

    /// <summary>
    /// Verifies that a response message with an invalid length throws ArgumentException.
    /// </summary>
    [Fact]
    public void ProcessResponse_InvalidLength_ShouldThrow()
    {
        var (initPriv, _) = GenerateKeyPair();
        var (_, respPub) = GenerateKeyPair();

        var initiator = new WireGuardHandshake(initPriv);
        var (_, state, _) = initiator.CreateInitiation(respPub);

        Assert.Throws<ArgumentException>(() => initiator.ProcessResponse(new byte[50], state));
    }

    /// <summary>
    /// Verifies that CreateInitiation returns a non-zero local sender index.
    /// </summary>
    [Fact]
    public void CreateInitiation_SenderIndexShouldBeNonZero()
    {
        var (initPriv, _) = GenerateKeyPair();
        var (_, respPub) = GenerateKeyPair();

        var handshake = new WireGuardHandshake(initPriv);
        var (_, _, localIndex) = handshake.CreateInitiation(respPub);

        Assert.NotEqual(0u, localIndex);
    }

    /// <summary>
    /// Verifies that initiator transport keys are each 32 bytes and differ from one another.
    /// </summary>
    [Fact]
    public void FullHandshake_InitiatorTransportKeysShouldBeValid()
    {
        var (initPriv, initPub) = GenerateKeyPair();
        var (respPriv, respPub) = GenerateKeyPair();

        var initiator = new WireGuardHandshake(initPriv);
        var responder = new WireGuardHandshake(respPriv);

        var (initMessage, initState, _) = initiator.CreateInitiation(respPub);
        var (_, _, _, response, _, _, _) = responder.ProcessInitiation(initMessage, new[] { initPub });
        var (_, initSendKey, initRecvKey) = initiator.ProcessResponse(response, initState);

        Assert.NotNull(initSendKey);
        Assert.Equal(32, initSendKey.Length);
        Assert.NotNull(initRecvKey);
        Assert.Equal(32, initRecvKey.Length);
        Assert.NotEqual(initSendKey, initRecvKey);
    }

    /// <summary>
    /// Verifies a full handshake using the Linux server key, including message lengths, types, and mirrored session keys.
    /// </summary>
    [Fact]
    public void FullHandshake_WithLinuxServerKey_ShouldSucceed()
    {
        var serverPrivBase64 = "sB6dEZ1xbAd3dntgK0MKWXnC+sEugmOk/M9uRgNZPWE=";
        var serverPubBase64 = "N7E5R38PCXtkUTMtdz4BpHikZORr/xfZ563W0dosyVw=";

        var serverPriv = Convert.FromBase64String(serverPrivBase64);
        var serverPub = X25519Crypto.GeneratePublicKey(serverPriv);
        Assert.Equal(serverPubBase64, Convert.ToBase64String(serverPub));

        var (clientPriv, clientPub) = GenerateKeyPair();

        var serverHandshake = new WireGuardHandshake(serverPriv);
        var clientHandshake = new WireGuardHandshake(clientPriv);

        var (initMessage, initState, _) = serverHandshake.CreateInitiation(clientPub);
        Assert.Equal(WireGuardConstants.HANDSHAKE_INITIATION_LEN, initMessage.Length);

        var messageType = BitConverter.ToUInt32(initMessage, 0) & 0xFF;
        Assert.Equal(WireGuardConstants.TYPE_INITIATION, messageType);

        var (state, senderIndex, peerPublicKey, response, localIndex, sendKey, recvKey) =
            clientHandshake.ProcessInitiation(initMessage, new[] { serverPub });

        Assert.Equal(WireGuardConstants.HANDSHAKE_RESPONSE_LEN, response.Length);
        Assert.Equal(serverPub, peerPublicKey);

        var (_, initSendKey, initRecvKey) = serverHandshake.ProcessResponse(response, initState);

        Assert.Equal(initSendKey, recvKey);
        Assert.Equal(initRecvKey, sendKey);

        Console.WriteLine($"Server send key: {Convert.ToBase64String(initSendKey)}");
        Console.WriteLine($"Client send key: {Convert.ToBase64String(sendKey)}");
        Console.WriteLine("Linux server key WireGuard handshake succeeded!");
    }

    /// <summary>
    /// Verifies that after a handshake, transport packets encrypt and decrypt end to end with correct headers, indices, and payloads.
    /// </summary>
    [Fact]
    public void FullHandshake_EndToEndEncryptDecrypt_ShouldSucceed()
    {
        // Simulate a full WireGuard handshake and data packet exchange
        var (initPriv, initPub) = GenerateKeyPair();
        var (respPriv, respPub) = GenerateKeyPair();

        var initiator = new WireGuardHandshake(initPriv);
        var responder = new WireGuardHandshake(respPriv);

        // Step 1: Initiator creates initiation
        var (initMessage, initState, initLocalIndex) = initiator.CreateInitiation(respPub);

        // Step 2: Responder processes initiation and creates response
        var (state, senderIndex, peerPublicKey, response, respLocalIndex, respSendKey, respRecvKey) =
            responder.ProcessInitiation(initMessage, new[] { initPub });

        // Step 3: Initiator processes response
        var (initSenderIndex, initSendKey, initRecvKey) = initiator.ProcessResponse(response, initState);

        // Verify key correspondence
        Assert.Equal(initSendKey, respRecvKey);  // Initiator's send key = Responder's recv key
        Assert.Equal(initRecvKey, respSendKey);  // Initiator's recv key = Responder's send key

        // Step 4: Create transport objects
        var initiatorTransport = new WireGuardTransport(initSendKey, initRecvKey);
        var responderTransport = new WireGuardTransport(respSendKey, respRecvKey);

        // Step 5: Initiator encrypts a data packet (keepalive = empty payload)
        var keepalive = Array.Empty<byte>();
        var encryptedPacket = initiatorTransport.EncryptPacket(keepalive, respLocalIndex);

        // Verify packet format
        Assert.True(encryptedPacket.Length >= 32);  // 16 header + 16 tag minimum
        var msgType = BitConverter.ToUInt32(encryptedPacket, 0) & 0xFF;
        Assert.Equal(WireGuardConstants.TYPE_DATA, msgType);
        var recvIdx = BitConverter.ToUInt32(encryptedPacket, 4);
        Assert.Equal(respLocalIndex, recvIdx);

        // Step 6: Responder decrypts the packet
        var decrypted = responderTransport.DecryptPacket(encryptedPacket, out var decryptedReceiverIndex);
        Assert.Equal(respLocalIndex, decryptedReceiverIndex);
        Assert.Empty(decrypted);  // Keepalive has empty payload

        // Step 7: Responder sends a data packet back
        var responseData = new byte[] { 0x01, 0x02, 0x03, 0x04 };
        var responseEncrypted = responderTransport.EncryptPacket(responseData, initLocalIndex);

        // Step 8: Initiator decrypts the response
        var responseDecrypted = initiatorTransport.DecryptPacket(responseEncrypted, out var respDecryptedIdx);
        Assert.Equal(initLocalIndex, respDecryptedIdx);
        Assert.Equal(responseData, responseDecrypted);

        Console.WriteLine("End-to-end encrypt/decrypt test passed!");
    }

    /// <summary>
    /// Verifies that ReadInitiation returns the initiator public key and a 12-byte TAI64N timestamp close to the current time.
    /// </summary>
    [Fact]
    public void ReadInitiation_ShouldReturnTai64nTimestamp()
    {
        var (initPriv, initPub) = GenerateKeyPair();
        var (respPriv, respPub) = GenerateKeyPair();

        var initiator = new WireGuardHandshake(initPriv);
        var responder = new WireGuardHandshake(respPriv);

        var (initMessage, _, _) = initiator.CreateInitiation(respPub);

        var (_, _, peerPublicKey, timestamp) = responder.ReadInitiation(initMessage, new[] { initPub });

        Assert.Equal(initPub, peerPublicKey);
        // TAI64N 为 12 字节（8 字节大端秒 + 4 字节大端纳秒）
        Assert.Equal(12, timestamp.Length);

        // 秒部分应为 TAI 当前时间（unix + 4611686018427387914），验证合理性
        var secBytes = timestamp[..8];
        if (BitConverter.IsLittleEndian) secBytes = secBytes.Reverse().ToArray();
        var taiSeconds = BitConverter.ToUInt64(secBytes);
        var unixSeconds = (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var expectedTai = unixSeconds + 4611686018427387914UL;
        Assert.InRange(taiSeconds, expectedTai - 60, expectedTai + 60);
    }

    /// <summary>
    /// Verifies that mac2 in a newly created initiation is all zeros when no cookie is supplied.
    /// </summary>
    [Fact]
    public void CreateInitiation_WithoutCookie_Mac2ShouldBeZero()
    {
        var (initPriv, _) = GenerateKeyPair();
        var (_, respPub) = GenerateKeyPair();

        var initiator = new WireGuardHandshake(initPriv);
        var (message, _, _) = initiator.CreateInitiation(respPub);

        var mac2 = message[^16..];
        Assert.True(mac2.All(b => b == 0));
    }

    /// <summary>
    /// Verifies that a supplied cookie produces a non-zero mac2 equal to the specified BLAKE2s128 computation.
    /// </summary>
    [Fact]
    public void CreateInitiation_WithCookie_Mac2ShouldMatchSpec()
    {
        // 规范：mac2 = BLAKE2s(msg[0..-32] || mac1, key=cookie)
        var (initPriv, _) = GenerateKeyPair();
        var (_, respPub) = GenerateKeyPair();
        var cookie = new byte[16];
        new Random(99).NextBytes(cookie);

        var initiator = new WireGuardHandshake(initPriv);
        var (message, _, _) = initiator.CreateInitiation(respPub, cookie: cookie);

        var mac2 = message[^16..];
        Assert.False(mac2.All(b => b == 0), "mac2 should be attached when a cookie is held");

        var messageWithoutMacs = message[..^32];
        var mac1 = message[^32..^16];
        var expected = Blake2s.Hash128(
            messageWithoutMacs.Concat(mac1).ToArray(), cookie);
        Assert.Equal(expected, mac2);
    }
}
