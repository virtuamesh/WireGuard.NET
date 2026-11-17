using WireGuard.NET.Protocol.Noise;
using WireGuard.NET.Crypto;
using Xunit;

namespace WireGuard.NET.Tests.Protocol;

/// <summary>
/// Tests for the Noise IKpsk2 handshake state, covering message construction, timestamp transfer, key derivation, replay behavior, and known-answer vectors.
/// </summary>
public class NoiseHandshakeStateTests
{
    private static (byte[] privateKey, byte[] publicKey) GenerateKeyPair()
    {
        var privateKey = X25519Crypto.GeneratePrivateKey();
        var publicKey = X25519Crypto.GeneratePublicKey(privateKey);
        return (privateKey, publicKey);
    }

    /// <summary>
    /// Verifies that an initiator can be constructed with a remote static public key.
    /// </summary>
    [Fact]
    public void Constructor_InitiatorWithRemoteKey_ShouldSucceed()
    {
        var (localPriv, _) = GenerateKeyPair();
        var (_, remotePub) = GenerateKeyPair();

        var state = new NoiseHandshakeState(localPriv, remotePub, true);

        Assert.NotNull(state);
    }

    /// <summary>
    /// Verifies that a responder can be constructed without a remote static public key.
    /// </summary>
    [Fact]
    public void Constructor_ResponderWithoutRemoteKey_ShouldSucceed()
    {
        var (localPriv, _) = GenerateKeyPair();

        var state = new NoiseHandshakeState(localPriv, null, false);

        Assert.NotNull(state);
    }

    /// <summary>
    /// Verifies that the initiator first message is non-empty and longer than an ephemeral public key.
    /// </summary>
    [Fact]
    public void WriteMessage_InitiatorFirstMessage_ShouldReturnNonEmptyBuffer()
    {
        var (initPriv, _) = GenerateKeyPair();
        var (_, respPub) = GenerateKeyPair();

        var initiator = new NoiseHandshakeState(initPriv, respPub, true);
        var timestamp = new byte[12];
        var message = initiator.WriteMessage(timestamp);

        Assert.NotEmpty(message);
        Assert.True(message.Length > 32);
    }

    /// <summary>
    /// Verifies that the responder reading the initiation recovers the initiator timestamp.
    /// </summary>
    [Fact]
    public void ReadMessage_ResponderAfterInitiator_ShouldExtractTimestamp()
    {
        var (initPriv, initPub) = GenerateKeyPair();
        var (respPriv, respPub) = GenerateKeyPair();

        var initiator = new NoiseHandshakeState(initPriv, respPub, true);
        var responder = new NoiseHandshakeState(respPriv, null, false);

        var timestamp = new byte[12];
        new Random(42).NextBytes(timestamp);
        var initMessage = initiator.WriteMessage(timestamp);

        var receivedTimestamp = responder.ReadMessage(initMessage);

        Assert.Equal(timestamp, receivedTimestamp);
    }

    /// <summary>
    /// Verifies that a complete handshake yields send and receive keys mirrored between initiator and responder.
    /// </summary>
    [Fact]
    public void FullHandshake_BothSidesShouldDeriveSameKeys()
    {
        var (initPriv, initPub) = GenerateKeyPair();
        var (respPriv, respPub) = GenerateKeyPair();

        var initiator = new NoiseHandshakeState(initPriv, respPub, true);
        var responder = new NoiseHandshakeState(respPriv, null, false);

        var timestamp = new byte[12];
        var initMessage = initiator.WriteMessage(timestamp);
        responder.ReadMessage(initMessage);

        var responseMessage = responder.WriteMessage(Array.Empty<byte>());
        initiator.ReadMessage(responseMessage);

        var (initSend, initRecv) = initiator.Split();
        var (respSend, respRecv) = responder.Split();

        Assert.Equal(initSend, respRecv);
        Assert.Equal(initRecv, respSend);
    }

    /// <summary>
    /// Verifies that two handshakes with fresh ephemeral keys derive different transport keys.
    /// </summary>
    [Fact]
    public void FullHandshake_DifferentEphemeralKeys_ShouldDeriveDifferentKeys()
    {
        var (initPriv, initPub) = GenerateKeyPair();
        var (respPriv, respPub) = GenerateKeyPair();

        var initiator1 = new NoiseHandshakeState(initPriv, respPub, true);
        var responder1 = new NoiseHandshakeState(respPriv, null, false);

        var timestamp = new byte[12];
        var initMessage1 = initiator1.WriteMessage(timestamp);
        responder1.ReadMessage(initMessage1);
        var responseMessage1 = responder1.WriteMessage(Array.Empty<byte>());
        initiator1.ReadMessage(responseMessage1);
        var (initSend1, _) = initiator1.Split();

        var initiator2 = new NoiseHandshakeState(initPriv, respPub, true);
        var responder2 = new NoiseHandshakeState(respPriv, null, false);

        var initMessage2 = initiator2.WriteMessage(timestamp);
        responder2.ReadMessage(initMessage2);
        var responseMessage2 = responder2.WriteMessage(Array.Empty<byte>());
        initiator2.ReadMessage(responseMessage2);
        var (initSend2, _) = initiator2.Split();

        Assert.NotEqual(initSend1, initSend2);
    }

    /// <summary>
    /// Verifies that after reading the initiation the responder knows the initiator static public key.
    /// </summary>
    [Fact]
    public void GetRemoteStaticKey_AfterHandshake_ShouldReturnPeerPublicKey()
    {
        var (initPriv, initPub) = GenerateKeyPair();
        var (respPriv, respPub) = GenerateKeyPair();

        var initiator = new NoiseHandshakeState(initPriv, respPub, true);
        var responder = new NoiseHandshakeState(respPriv, null, false);

        var timestamp = new byte[12];
        var initMessage = initiator.WriteMessage(timestamp);
        responder.ReadMessage(initMessage);

        var remoteKey = responder.GetRemoteStaticKey();

        Assert.NotNull(remoteKey);
        var expectedInitPub = X25519Crypto.GeneratePublicKey(initPriv);
        Assert.Equal(expectedInitPub, remoteKey);
    }

    /// <summary>
    /// Verifies that calling WriteMessage a second time in the same step throws InvalidOperationException.
    /// </summary>
    [Fact]
    public void WriteMessage_CalledTwice_ShouldThrow()
    {
        var (initPriv, _) = GenerateKeyPair();
        var (_, respPub) = GenerateKeyPair();

        var initiator = new NoiseHandshakeState(initPriv, respPub, true);

        initiator.WriteMessage(new byte[12]);

        Assert.Throws<InvalidOperationException>(() => initiator.WriteMessage(new byte[12]));
    }

    /// <summary>
    /// Verifies that Split returns mirrored keys after the handshake completes.
    /// </summary>
    [Fact]
    public void Split_AfterHandshakeComplete_ShouldReturnMatchingKeys()
    {
        var (initPriv, initPub) = GenerateKeyPair();
        var (respPriv, respPub) = GenerateKeyPair();

        var initiator = new NoiseHandshakeState(initPriv, respPub, true);
        var responder = new NoiseHandshakeState(respPriv, null, false);

        var timestamp = new byte[12];
        var initMessage = initiator.WriteMessage(timestamp);
        responder.ReadMessage(initMessage);

        var responseMessage = responder.WriteMessage(Array.Empty<byte>());
        initiator.ReadMessage(responseMessage);

        var (respSend, respRecv) = responder.Split();
        var (initSend, initRecv) = initiator.Split();

        Assert.Equal(initSend, respRecv);
        Assert.Equal(initRecv, respSend);
    }

    /// <summary>
    /// Verifies that repeated sessions between the same static keys derive different send keys.
    /// </summary>
    [Fact]
    public void FullHandshake_MultipleSessions_ShouldDeriveDifferentKeys()
    {
        var (initPriv, initPub) = GenerateKeyPair();
        var (respPriv, respPub) = GenerateKeyPair();

        byte[]? prevSendKey = null;

        for (int i = 0; i < 3; i++)
        {
            var initiator = new NoiseHandshakeState(initPriv, respPub, true);
            var responder = new NoiseHandshakeState(respPriv, null, false);

            var timestamp = new byte[12];
            var initMessage = initiator.WriteMessage(timestamp);
            responder.ReadMessage(initMessage);

            var responseMessage = responder.WriteMessage(Array.Empty<byte>());
            initiator.ReadMessage(responseMessage);

            var (initSend, _) = initiator.Split();

            if (prevSendKey != null)
            {
                Assert.NotEqual(prevSendKey, initSend);
            }
            prevSendKey = initSend;
        }
    }

    /// <summary>
    /// Verifies that a known WireGuard private key derives the expected public key.
    /// </summary>
    [Fact]
    public void X25519Crypto_KnownKeyPair_ShouldMatchWireGuard()
    {
        var serverPrivBase64 = "iLNj0hOlQY4ftnxtN8SUt+M4+MKEQiGtwlyh1dB/wV8=";
        var expectedPubBase64 = "2TCaCRYzC6Va7oiCW8Rhnh4a18Ft6LMvBb8FtJLXjnE=";

        var serverPriv = Convert.FromBase64String(serverPrivBase64);
        var derivedPub = X25519Crypto.GeneratePublicKey(serverPriv);

        Assert.Equal(expectedPubBase64, Convert.ToBase64String(derivedPub));
    }

    /// <summary>
    /// Verifies that a full handshake succeeds with known WireGuard key pairs.
    /// </summary>
    [Fact]
    public void FullHandshake_WithKnownWireGuardKeys_ShouldSucceed()
    {
        var serverPrivBase64 = "iLNj0hOlQY4ftnxtN8SUt+M4+MKEQiGtwlyh1dB/wV8=";
        var serverPubBase64 = "2TCaCRYzC6Va7oiCW8Rhnh4a18Ft6LMvBb8FtJLXjnE=";

        var serverPriv = Convert.FromBase64String(serverPrivBase64);
        var serverPub = Convert.FromBase64String(serverPubBase64);

        var (clientPriv, clientPub) = GenerateKeyPair();

        var initiator = new NoiseHandshakeState(clientPriv, serverPub, true);
        var responder = new NoiseHandshakeState(serverPriv, null, false);

        var timestamp = new byte[12];
        var initMessage = initiator.WriteMessage(timestamp);
        var receivedTimestamp = responder.ReadMessage(initMessage);

        Assert.Equal(timestamp, receivedTimestamp);

        var responseMessage = responder.WriteMessage(Array.Empty<byte>());
        initiator.ReadMessage(responseMessage);

        var (initSend, initRecv) = initiator.Split();
        var (respSend, respRecv) = responder.Split();

        Assert.Equal(initSend, respRecv);
        Assert.Equal(initRecv, respSend);
    }

    /// <summary>
    /// Verifies a full handshake with the server as initiator, including remote key identification and mirrored session keys.
    /// </summary>
    [Fact]
    public void ServerAsInitiator_HandshakeShouldSucceed()
    {
        var serverPrivBase64 = "iLNj0hOlQY4ftnxtN8SUt+M4+MKEQiGtwlyh1dB/wV8=";
        var serverPubBase64 = "2TCaCRYzC6Va7oiCW8Rhnh4a18Ft6LMvBb8FtJLXjnE=";
        var serverPriv = Convert.FromBase64String(serverPrivBase64);
        var serverPub = Convert.FromBase64String(serverPubBase64);

        var (clientPriv, clientPub) = GenerateKeyPair();

        var initiator = new NoiseHandshakeState(serverPriv, clientPub, true);
        initiator.OnDebugLog += (s, msg) => Console.WriteLine($"[Initiator] {msg}");

        var responder = new NoiseHandshakeState(clientPriv, null, false);
        responder.OnDebugLog += (s, msg) => Console.WriteLine($"[Responder] {msg}");

        var timestamp = new byte[12];
        new Random(42).NextBytes(timestamp);
        var initMessage = initiator.WriteMessage(timestamp);

        Console.WriteLine($"Initiation message length: {initMessage.Length}");
        Console.WriteLine($"  Ephemeral key: {BitConverter.ToString(initMessage, 0, 32)}");
        Console.WriteLine($"  Encrypted static: {BitConverter.ToString(initMessage, 32, 48)}");
        Console.WriteLine($"  Encrypted timestamp: {BitConverter.ToString(initMessage, 80, 28)}");

        var receivedTimestamp = responder.ReadMessage(initMessage);

        Assert.Equal(timestamp, receivedTimestamp);

        var remoteStaticKey = responder.GetRemoteStaticKey();
        Assert.NotNull(remoteStaticKey);
        Assert.Equal(serverPub, remoteStaticKey);

        var responseMessage = responder.WriteMessage(Array.Empty<byte>());
        initiator.ReadMessage(responseMessage);

        var (initSend, initRecv) = initiator.Split();
        var (respSend, respRecv) = responder.Split();

        Assert.Equal(initSend, respRecv);
        Assert.Equal(initRecv, respSend);
    }

    /// <summary>
    /// Verifies that a handshake succeeds when the initiator supplies a preshared key and the responder installs the same one.
    /// </summary>
    [Fact]
    public void FullHandshake_WithPSK_ShouldSucceed()
    {
        var (initPriv, initPub) = GenerateKeyPair();
        var (respPriv, respPub) = GenerateKeyPair();
        var psk = new byte[32];
        new Random(123).NextBytes(psk);

        var initiator = new NoiseHandshakeState(initPriv, respPub, true, psk);
        var responder = new NoiseHandshakeState(respPriv, null, false);

        var timestamp = new byte[12];
        var initMessage = initiator.WriteMessage(timestamp);
        responder.ReadMessage(initMessage);

        responder.SetPresharedKey(psk);

        var responseMessage = responder.WriteMessage(Array.Empty<byte>());
        initiator.ReadMessage(responseMessage);

        var (initSend, initRecv) = initiator.Split();
        var (respSend, respRecv) = responder.Split();

        Assert.Equal(initSend, respRecv);
        Assert.Equal(initRecv, respSend);
    }

    /// <summary>
    /// Verifies the RFC 7748 X25519 public key and shared secret test vector.
    /// </summary>
    [Fact]
    public void X25519_RFC7748_TestVector()
    {
        var alicePriv = Convert.FromHexString(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        var alicePub = Convert.FromHexString(
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        var bobPriv = Convert.FromHexString(
            "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        var bobPub = Convert.FromHexString(
            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");

        var derivedAlicePub = X25519Crypto.GeneratePublicKey(alicePriv);
        Assert.Equal(alicePub, derivedAlicePub);

        var derivedBobPub = X25519Crypto.GeneratePublicKey(bobPriv);
        Assert.Equal(bobPub, derivedBobPub);

        var sharedAlice = X25519Crypto.ScalarMult(alicePriv, bobPub);
        var sharedBob = X25519Crypto.ScalarMult(bobPriv, alicePub);
        var expectedShared = Convert.FromHexString(
            "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

        Assert.Equal(sharedAlice, sharedBob);
        Assert.Equal(expectedShared, sharedAlice);
    }

    /// <summary>
    /// Verifies that ScalarMult with the base point equals GeneratePublicKey for random private keys.
    /// </summary>
    [Fact]
    public void X25519_ScalarMult_MatchesGeneratePublicKey_WithBasePoint()
    {
        var basePoint = new byte[32];
        basePoint[0] = 9;

        for (int i = 0; i < 5; i++)
        {
            var privKey = X25519Crypto.GeneratePrivateKey();
            var pubViaGenerate = X25519Crypto.GeneratePublicKey(privKey);
            var pubViaScalarMult = X25519Crypto.ScalarMult(privKey, basePoint);

            Console.WriteLine($"Test {i}: Generate={Convert.ToHexString(pubViaGenerate)[..16]}... ScalarMult={Convert.ToHexString(pubViaScalarMult)[..16]}... Match={pubViaGenerate.SequenceEqual(pubViaScalarMult)}");

            Assert.Equal(pubViaGenerate, pubViaScalarMult);
        }
    }

    /// <summary>
    /// Prints the BouncyCastle private key encoding and clamping result for the RFC 7748 private key; no assertions.
    /// </summary>
    [Fact]
    public void X25519_PrivateKeyEncoding_ClampingCheck()
    {
        var alicePrivRaw = Convert.FromHexString(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");

        var privKeyParams = new Org.BouncyCastle.Crypto.Parameters.X25519PrivateKeyParameters(alicePrivRaw, 0);
        var encoded = new byte[32];
        privKeyParams.Encode(encoded, 0);

        Console.WriteLine($"Raw priv:    {Convert.ToHexString(alicePrivRaw)}");
        Console.WriteLine($"Encoded priv: {Convert.ToHexString(encoded)}");
        Console.WriteLine($"Same: {alicePrivRaw.SequenceEqual(encoded)}");

        var clamped = (byte[])alicePrivRaw.Clone();
        clamped[0] &= 248;
        clamped[31] &= 127;
        clamped[31] |= 64;
        Console.WriteLine($"Clamped priv: {Convert.ToHexString(clamped)}");

        if (!alicePrivRaw.SequenceEqual(encoded))
        {
            Console.WriteLine("BouncyCastle APPLIES clamping in constructor - encoded differs from raw");
            Console.WriteLine($"Encoded matches clamped: {encoded.SequenceEqual(clamped)}");
        }
        else
        {
            Console.WriteLine("BouncyCastle does NOT apply clamping in constructor - encoded same as raw");
        }
    }

    /// <summary>
    /// Verifies the hash chain by completing an initiation against a known server key and checking the timestamp and remote key.
    /// </summary>
    [Fact]
    public void StepByStep_HashChainVerification()
    {
        var serverPrivBase64 = "iLNj0hOlQY4ftnxtN8SUt+M4+MKEQiGtwlyh1dB/wV8=";
        var serverPriv = Convert.FromBase64String(serverPrivBase64);
        var serverPub = X25519Crypto.GeneratePublicKey(serverPriv);

        var (clientPriv, clientPub) = GenerateKeyPair();

        Console.WriteLine($"=== Initiator (Server) ===");
        Console.WriteLine($"Server private key: {serverPrivBase64}");
        Console.WriteLine($"Server public key: {Convert.ToBase64String(serverPub)}");
        Console.WriteLine($"Client public key: {Convert.ToBase64String(clientPub)}");

        var initiator = new NoiseHandshakeState(serverPriv, clientPub, true);
        initiator.OnDebugLog += (s, msg) => Console.WriteLine($"[I] {msg}");

        Console.WriteLine($"\n=== Responder (Client) ===");
        Console.WriteLine($"Client private key: {Convert.ToBase64String(clientPriv)}");
        Console.WriteLine($"Client public key: {Convert.ToBase64String(clientPub)}");

        var responder = new NoiseHandshakeState(clientPriv, null, false);
        responder.OnDebugLog += (s, msg) => Console.WriteLine($"[R] {msg}");

        var timestamp = new byte[12];
        new Random(99).NextBytes(timestamp);

        Console.WriteLine($"\n=== Writing Initiation ===");
        var initMessage = initiator.WriteMessage(timestamp);

        Console.WriteLine($"\n=== Reading Initiation ===");
        var receivedTimestamp = responder.ReadMessage(initMessage);

        Assert.Equal(timestamp, receivedTimestamp);

        var remoteStaticKey = responder.GetRemoteStaticKey();
        Assert.NotNull(remoteStaticKey);
        Assert.Equal(serverPub, remoteStaticKey);

        Console.WriteLine($"\n=== Responder identified initiator as: {Convert.ToBase64String(remoteStaticKey)} ===");
    }

    /// <summary>
    /// Skipped test that parses a captured kernel initiation packet once a matching initiator public key is supplied.
    /// </summary>
    [Fact(Skip = "Requires captured packet with matching responder private key")]
    public void ParseKernelWireGuardInitiationPacket_WithKnownKeys()
    {
        var serverPrivBase64 = "iLNj0hOlQY4ftnxtN8SUt+M4+MKEQiGtwlyh1dB/wV8=";
        var serverPriv = Convert.FromBase64String(serverPrivBase64);

        var packetHex =
            "01000000be4970c2c3561f8bf284345b239f3c45" +
            "5542831b192993b6474dfa0a48d098aefcf5ab7d" +
            "2cc2b59954777263f17f76a8bce8a50c232c59c9" +
            "5b09a64e3df312beae891ab593e5211ba4f245f8" +
            "13735feb91d661d0f22c1733fa5b0dfda69ef6de" +
            "a53b9ad13b4e874e04e6a8204169a0c81a9afee5" +
            "bca26809872a5c1989fccaba0000000000000000" +
            "0000000000000000";

        var packet = Convert.FromHexString(packetHex);
        Assert.Equal(148, packet.Length);

        var noiseMessage = new byte[108];
        Buffer.BlockCopy(packet, 8, noiseMessage, 0, 108);

        // TODO: Replace with the actual initiator public key that matches the captured packet
        var initiatorPubBase64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        var initiatorPub = Convert.FromBase64String(initiatorPubBase64);

        var responder = new NoiseHandshakeState(serverPriv, null, false);
        responder.OnDebugLog += (s, msg) => Console.WriteLine($"[Noise] {msg}");

        byte[] timestamp;
        try
        {
            timestamp = responder.ReadMessage(noiseMessage);
            Console.WriteLine($"Timestamp: {BitConverter.ToString(timestamp)}");
            var remoteStaticKey = responder.GetRemoteStaticKey();
            Console.WriteLine($"Remote static key: {Convert.ToBase64String(remoteStaticKey!)}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"FAILED: {ex.Message}");
            throw;
        }
    }

    /// <summary>
    /// Verifies that the real server private key derives the expected public key.
    /// </summary>
    [Fact]
    public void RealServerKey_DerivesCorrectPublicKey()
    {
        var serverPrivBase64 = "iDiUpisHHRBEQ7J1Q3+ZDx4g9d4jRqPYu13aUlvdc2c=";
        var expectedPubBase64 = "2w72+AUiZA0NX3UicBQrTPc1LoSIqtoW96KLQUBFAF0=";

        var serverPriv = Convert.FromBase64String(serverPrivBase64);
        var derivedPub = X25519Crypto.GeneratePublicKey(serverPriv);
        var derivedPubBase64 = Convert.ToBase64String(derivedPub);

        Console.WriteLine($"Server private key: {serverPrivBase64}");
        Console.WriteLine($"Derived public key: {derivedPubBase64}");
        Console.WriteLine($"Expected public key: {expectedPubBase64}");
        Console.WriteLine($"Match: {derivedPubBase64 == expectedPubBase64}");

        Assert.Equal(expectedPubBase64, derivedPubBase64);
    }

    /// <summary>
    /// Verifies a full handshake with the real server key as responder, including remote key identification and mirrored session keys.
    /// </summary>
    [Fact]
    public void RealServerKey_FullHandshakeAsResponder_ShouldSucceed()
    {
        var serverPrivBase64 = "iDiUpisHHRBEQ7J1Q3+ZDx4g9d4jRqPYu13aUlvdc2c=";
        var serverPubBase64 = "2w72+AUiZA0NX3UicBQrTPc1LoSIqtoW96KLQUBFAF0=";

        var serverPriv = Convert.FromBase64String(serverPrivBase64);
        var serverPub = Convert.FromBase64String(serverPubBase64);

        Assert.Equal(serverPub, X25519Crypto.GeneratePublicKey(serverPriv));

        var (clientPriv, clientPub) = GenerateKeyPair();

        var initiator = new NoiseHandshakeState(clientPriv, serverPub, true);
        initiator.OnDebugLog += (s, msg) => Console.WriteLine($"[Initiator] {msg}");

        var responder = new NoiseHandshakeState(serverPriv, null, false);
        responder.OnDebugLog += (s, msg) => Console.WriteLine($"[Responder] {msg}");

        var timestamp = new byte[12];
        new Random(42).NextBytes(timestamp);

        var initMessage = initiator.WriteMessage(timestamp);
        Console.WriteLine($"Initiation message length: {initMessage.Length}");

        var receivedTimestamp = responder.ReadMessage(initMessage);
        Assert.Equal(timestamp, receivedTimestamp);

        var remoteStaticKey = responder.GetRemoteStaticKey();
        Assert.NotNull(remoteStaticKey);
        Assert.Equal(clientPub, remoteStaticKey);

        var responseMessage = responder.WriteMessage(Array.Empty<byte>());
        Console.WriteLine($"Response message length: {responseMessage.Length}");

        initiator.ReadMessage(responseMessage);

        var (initSend, initRecv) = initiator.Split();
        var (respSend, respRecv) = responder.Split();

        Assert.Equal(initSend, respRecv);
        Assert.Equal(initRecv, respSend);

        Console.WriteLine("Handshake succeeded with real server key!");
    }

    /// <summary>
    /// Verifies a full handshake with the real server key as initiator, including remote key identification and mirrored session keys.
    /// </summary>
    [Fact]
    public void RealServerKey_ServerAsInitiator_ShouldSucceed()
    {
        var serverPrivBase64 = "iDiUpisHHRBEQ7J1Q3+ZDx4g9d4jRqPYu13aUlvdc2c=";
        var serverPubBase64 = "2w72+AUiZA0NX3UicBQrTPc1LoSIqtoW96KLQUBFAF0=";

        var serverPriv = Convert.FromBase64String(serverPrivBase64);
        var serverPub = Convert.FromBase64String(serverPubBase64);

        Assert.Equal(serverPub, X25519Crypto.GeneratePublicKey(serverPriv));

        var (clientPriv, clientPub) = GenerateKeyPair();

        var initiator = new NoiseHandshakeState(serverPriv, clientPub, true);
        initiator.OnDebugLog += (s, msg) => Console.WriteLine($"[Initiator(Server)] {msg}");

        var responder = new NoiseHandshakeState(clientPriv, null, false);
        responder.OnDebugLog += (s, msg) => Console.WriteLine($"[Responder(Client)] {msg}");

        var timestamp = new byte[12];
        new Random(42).NextBytes(timestamp);

        var initMessage = initiator.WriteMessage(timestamp);
        Console.WriteLine($"Initiation message length: {initMessage.Length}");

        var receivedTimestamp = responder.ReadMessage(initMessage);
        Assert.Equal(timestamp, receivedTimestamp);

        var remoteStaticKey = responder.GetRemoteStaticKey();
        Assert.NotNull(remoteStaticKey);
        Assert.Equal(serverPub, remoteStaticKey);

        var responseMessage = responder.WriteMessage(Array.Empty<byte>());
        Console.WriteLine($"Response message length: {responseMessage.Length}");

        initiator.ReadMessage(responseMessage);

        var (initSend, initRecv) = initiator.Split();
        var (respSend, respRecv) = responder.Split();

        Assert.Equal(initSend, respRecv);
        Assert.Equal(initRecv, respSend);

        Console.WriteLine("Server-as-initiator handshake succeeded with real server key!");
    }

    /// <summary>
    /// Verifies a full handshake with the current Linux server key as initiator, including remote key identification and mirrored session keys.
    /// </summary>
    [Fact]
    public void CurrentLinuxServerKey_ServerAsInitiator_ShouldSucceed()
    {
        var serverPrivBase64 = "sB6dEZ1xbAd3dntgK0MKWXnC+sEugmOk/M9uRgNZPWE=";
        var serverPubBase64 = "N7E5R38PCXtkUTMtdz4BpHikZORr/xfZ563W0dosyVw=";

        var serverPriv = Convert.FromBase64String(serverPrivBase64);
        var serverPub = Convert.FromBase64String(serverPrivBase64);
        serverPub = X25519Crypto.GeneratePublicKey(serverPriv);

        Console.WriteLine($"Server private key: {serverPrivBase64}");
        Console.WriteLine($"Derived public key: {Convert.ToBase64String(serverPub)}");
        Console.WriteLine($"Expected public key: {serverPubBase64}");
        Assert.Equal(serverPubBase64, Convert.ToBase64String(serverPub));

        var (clientPriv, clientPub) = GenerateKeyPair();

        var initiator = new NoiseHandshakeState(serverPriv, clientPub, true);
        initiator.OnDebugLog += (s, msg) => Console.WriteLine($"[Initiator(Server)] {msg}");

        var responder = new NoiseHandshakeState(clientPriv, null, false);
        responder.OnDebugLog += (s, msg) => Console.WriteLine($"[Responder(Client)] {msg}");

        var timestamp = new byte[12];
        new Random(42).NextBytes(timestamp);

        var initMessage = initiator.WriteMessage(timestamp);
        Console.WriteLine($"Initiation message length: {initMessage.Length}");

        var receivedTimestamp = responder.ReadMessage(initMessage);
        Assert.Equal(timestamp, receivedTimestamp);

        var remoteStaticKey = responder.GetRemoteStaticKey();
        Assert.NotNull(remoteStaticKey);
        Assert.Equal(serverPub, remoteStaticKey);

        var responseMessage = responder.WriteMessage(Array.Empty<byte>());
        Console.WriteLine($"Response message length: {responseMessage.Length}");

        initiator.ReadMessage(responseMessage);

        var (initSend, initRecv) = initiator.Split();
        var (respSend, respRecv) = responder.Split();

        Assert.Equal(initSend, respRecv);
        Assert.Equal(initRecv, respSend);

        Console.WriteLine("Current Linux server key handshake succeeded!");
    }
}
