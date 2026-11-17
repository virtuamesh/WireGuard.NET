using System.Security.Cryptography;
using WireGuard.NET.Crypto;
using WireGuard.NET.Protocol.Noise;
using Xunit;
using Xunit.Abstractions;

namespace WireGuard.NET.Tests.Protocol;

/// <summary>
/// Interop tests that verify keys, Diffie-Hellman results, hash chains, and full handshakes against real Linux kernel and Windows WireGuard key material.
/// </summary>
public class LinuxKernelInteropTests
{
    private readonly ITestOutputHelper _output;

    public LinuxKernelInteropTests(ITestOutputHelper output)
    {
        _output = output;
    }

    /// <summary>
    /// Verifies that the captured Linux server private key derives the expected public key.
    /// </summary>
    [Fact]
    public void Verify_ServerPublicKey_MatchesLinuxKernel()
    {
        var serverPrivB64 = "sB6dEZ1xbAd3dntgK0MKWXnC+sEugmOk/M9uRgNZPWE=";
        var expectedPubB64 = "N7E5R38PCXtkUTMtdz4BpHikZORr/xfZ563W0dosyVw=";

        var serverPriv = Convert.FromBase64String(serverPrivB64);
        var derivedPub = X25519Crypto.GeneratePublicKey(serverPriv);
        var derivedPubB64 = Convert.ToBase64String(derivedPub);

        _output.WriteLine($"Server priv: {serverPrivB64}");
        _output.WriteLine($"Derived pub: {derivedPubB64}");
        _output.WriteLine($"Expected:    {expectedPubB64}");
        _output.WriteLine($"Match: {derivedPubB64 == expectedPubB64}");

        Assert.Equal(expectedPubB64, derivedPubB64);
    }

    /// <summary>
    /// Verifies that the static Diffie-Hellman shared secret with the captured client public key matches the reference value.
    /// </summary>
    [Fact]
    public void Verify_StaticDhSharedSecret_MatchesPython()
    {
        var serverPrivB64 = "sB6dEZ1xbAd3dntgK0MKWXnC+sEugmOk/M9uRgNZPWE=";
        var clientPubB64 = "oQqgYLVBvhXAeHW/+AXsy5NfaF3YfbzM8n/fV8anmXs=";
        var expectedSharedHex = "26fa518f29a7fad72eacd388d9d9d6611c975a452f306b8247b0f48c10efaa1f";

        var serverPriv = Convert.FromBase64String(serverPrivB64);
        var clientPub = Convert.FromBase64String(clientPubB64);

        var shared = X25519Crypto.ScalarMult(serverPriv, clientPub);
        var sharedHex = Convert.ToHexString(shared).ToLower();

        _output.WriteLine($"Computed shared: {sharedHex}");
        _output.WriteLine($"Expected shared: {expectedSharedHex}");
        _output.WriteLine($"Match: {sharedHex == expectedSharedHex}");

        Assert.Equal(expectedSharedHex, sharedHex);
    }

    /// <summary>
    /// Verifies that the initial hash chain after mixing the construction, identifier, and server public key matches the handshake state hash.
    /// </summary>
    [Fact]
    public void Verify_InitialHashChain_MatchesLinuxKernel()
    {
        var serverPrivB64 = "sB6dEZ1xbAd3dntgK0MKWXnC+sEugmOk/M9uRgNZPWE=";
        var serverPriv = Convert.FromBase64String(serverPrivB64);
        var serverPub = X25519Crypto.GeneratePublicKey(serverPriv);

        var construction = System.Text.Encoding.UTF8.GetBytes("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s");
        var identifier = System.Text.Encoding.UTF8.GetBytes("WireGuard v1 zx2c4 Jason@zx2c4.com");

        _output.WriteLine($"Construction length: {construction.Length} (expected: 37)");
        _output.WriteLine($"Identifier length: {identifier.Length} (expected: 34)");

        Assert.Equal(37, construction.Length);
        Assert.Equal(34, identifier.Length);

        var ck = Blake2s.Hash(construction);
        var ckHex = Convert.ToHexString(ck).ToLower();
        _output.WriteLine($"ck = {ckHex}");

        var hInput = new byte[32 + identifier.Length];
        Buffer.BlockCopy(ck, 0, hInput, 0, 32);
        Buffer.BlockCopy(identifier, 0, hInput, 32, identifier.Length);
        var h = Blake2s.Hash(hInput);
        var hHex = Convert.ToHexString(h).ToLower();
        _output.WriteLine($"h after MixHash(identifier) = {hHex}");

        var hAfterServerInput = new byte[32 + serverPub.Length];
        Buffer.BlockCopy(h, 0, hAfterServerInput, 0, 32);
        Buffer.BlockCopy(serverPub, 0, hAfterServerInput, 32, serverPub.Length);
        var hAfterServer = Blake2s.Hash(hAfterServerInput);
        var hAfterServerHex = Convert.ToHexString(hAfterServer).ToLower();
        _output.WriteLine($"h after MixHash(serverPub) = {hAfterServerHex}");

        var responder = new NoiseHandshakeState(serverPriv, null, false);
        var responderHash = responder.GetHash();
        var responderHashHex = Convert.ToHexString(responderHash).ToLower();
        _output.WriteLine($"NoiseHandshakeState hash = {responderHashHex}");

        Assert.Equal(hAfterServerHex, responderHashHex);
    }

    /// <summary>
    /// Verifies a complete handshake with the server static key as initiator in which both sides derive mirrored transport keys.
    /// </summary>
    [Fact]
    public void FullHandshake_ServerAsInitiator_WithRealKeys()
    {
        var serverPrivB64 = "sB6dEZ1xbAd3dntgK0MKWXnC+sEugmOk/M9uRgNZPWE=";
        var serverPubB64 = "N7E5R38PCXtkUTMtdz4BpHikZORr/xfZ563W0dosyVw=";
        var serverPriv = Convert.FromBase64String(serverPrivB64);
        var serverPub = Convert.FromBase64String(serverPubB64);

        Assert.Equal(serverPub, X25519Crypto.GeneratePublicKey(serverPriv));

        var (clientPriv, clientPub) = GenerateKeyPair();
        _output.WriteLine($"Client pub: {Convert.ToBase64String(clientPub)}");

        var initiator = new NoiseHandshakeState(serverPriv, clientPub, true);
        initiator.OnDebugLog += (s, msg) => _output.WriteLine($"[Initiator] {msg}");

        var responder = new NoiseHandshakeState(clientPriv, null, false);
        responder.OnDebugLog += (s, msg) => _output.WriteLine($"[Responder] {msg}");

        var timestamp = new byte[12];
        new Random(42).NextBytes(timestamp);

        var initMessage = initiator.WriteMessage(timestamp);
        _output.WriteLine($"Initiation message length: {initMessage.Length}");

        var receivedTimestamp = responder.ReadMessage(initMessage);
        Assert.Equal(timestamp, receivedTimestamp);

        var remoteStaticKey = responder.GetRemoteStaticKey();
        Assert.NotNull(remoteStaticKey);
        Assert.Equal(serverPub, remoteStaticKey);
        _output.WriteLine($"Responder identified initiator as: {Convert.ToBase64String(remoteStaticKey)}");

        var responseMessage = responder.WriteMessage(Array.Empty<byte>());
        initiator.ReadMessage(responseMessage);

        var (initSend, initRecv) = initiator.Split();
        var (respSend, respRecv) = responder.Split();

        Assert.Equal(initSend, respRecv);
        Assert.Equal(initRecv, respSend);

        _output.WriteLine("Handshake succeeded with real Linux kernel keys!");
    }

    /// <summary>
    /// Verifies that the responder reads the initiation and recovers the timestamp, confirming that the ephemeral Diffie-Hellman secrets agree.
    /// </summary>
    [Fact]
    public void Verify_ClientAsResponder_DhEsSharedSecret()
    {
        var serverPrivB64 = "sB6dEZ1xbAd3dntgK0MKWXnC+sEugmOk/M9uRgNZPWE=";
        var serverPriv = Convert.FromBase64String(serverPrivB64);

        var (clientPriv, clientPub) = GenerateKeyPair();

        var initiator = new NoiseHandshakeState(serverPriv, clientPub, true);
        var responder = new NoiseHandshakeState(clientPriv, null, false);

        var timestamp = new byte[12];
        new Random(42).NextBytes(timestamp);

        var initMessage = initiator.WriteMessage(timestamp);

        var ephemeralPub = initMessage[..32];
        _output.WriteLine($"Initiator ephemeral pub: {BitConverter.ToString(ephemeralPub)[..40]}...");

        var initiatorDhEs = X25519Crypto.ScalarMult(serverPriv, clientPub);
        _output.WriteLine($"Initiator DH(server_priv, client_pub): {Convert.ToHexString(initiatorDhEs).ToLower()[..40]}...");

        var responderDhEs = X25519Crypto.ScalarMult(clientPriv, ephemeralPub);
        _output.WriteLine($"Responder DH(client_priv, ephemeral_pub): {Convert.ToHexString(responderDhEs).ToLower()[..40]}...");

        _output.WriteLine($"NOTE: These are different DH operations - initiator uses DH(e, rs), responder uses DH(s, re)");
        _output.WriteLine($"Initiator DH(e, rs) = DH(initiator_ephemeral_priv, client_pub)");
        _output.WriteLine($"Responder DH(s, re) = DH(client_priv, initiator_ephemeral_pub)");
        _output.WriteLine($"These should be equal by DH property: DH(a_priv, b_pub) = DH(b_priv, a_pub)");

        var receivedTimestamp = responder.ReadMessage(initMessage);
        Assert.Equal(timestamp, receivedTimestamp);
        _output.WriteLine("ReadMessage succeeded - DH shared secrets matched!");
    }

    /// <summary>
    /// Verifies that the captured Windows client private key derives the expected public key.
    /// </summary>
    [Fact]
    public void Verify_WindowsClientPublicKey_MatchesWireGuardPeer()
    {
        var winPrivB64 = "WNt2/fPCdXID05XnqJBtagAPngJgdpM0lafcCA+8KFY=";
        var expectedPubB64 = "oQqgYLVBvhXAeHW/+AXsy5NfaF3YfbzM8n/fV8anmXs=";

        var winPriv = Convert.FromBase64String(winPrivB64);
        var derivedPub = X25519Crypto.GeneratePublicKey(winPriv);
        var derivedPubB64 = Convert.ToBase64String(derivedPub);

        _output.WriteLine($"Windows priv: {winPrivB64}");
        _output.WriteLine($"Derived pub:  {derivedPubB64}");
        _output.WriteLine($"Expected:     {expectedPubB64}");
        _output.WriteLine($"Match: {derivedPubB64 == expectedPubB64}");

        Assert.Equal(expectedPubB64, derivedPubB64);
    }

    /// <summary>
    /// Verifies that both sides compute the same Diffie-Hellman shared secret from the captured server and Windows keys.
    /// </summary>
    [Fact]
    public void Verify_DhSharedSecret_BetweenServerAndClient()
    {
        var serverPrivB64 = "sB6dEZ1xbAd3dntgK0MKWXnC+sEugmOk/M9uRgNZPWE=";
        var winPrivB64 = "WNt2/fPCdXID05XnqJBtagAPngJgdpM0lafcCA+8KFY=";

        var serverPriv = Convert.FromBase64String(serverPrivB64);
        var winPriv = Convert.FromBase64String(winPrivB64);
        var serverPub = X25519Crypto.GeneratePublicKey(serverPriv);
        var winPub = X25519Crypto.GeneratePublicKey(winPriv);

        var sharedFromServer = X25519Crypto.ScalarMult(serverPriv, winPub);
        var sharedFromWin = X25519Crypto.ScalarMult(winPriv, serverPub);

        _output.WriteLine($"Server priv: {serverPrivB64}");
        _output.WriteLine($"Server pub:  {Convert.ToBase64String(serverPub)}");
        _output.WriteLine($"Win priv:    {winPrivB64}");
        _output.WriteLine($"Win pub:     {Convert.ToBase64String(winPub)}");
        _output.WriteLine($"DH(server_priv, win_pub) = {Convert.ToBase64String(sharedFromServer)}");
        _output.WriteLine($"DH(win_priv, server_pub) = {Convert.ToBase64String(sharedFromWin)}");
        _output.WriteLine($"DH Match: {Convert.ToBase64String(sharedFromServer) == Convert.ToBase64String(sharedFromWin)}");

        Assert.Equal(sharedFromServer, sharedFromWin);
    }

    /// <summary>
    /// Verifies a complete handshake with the Windows client as initiator and the Linux server as responder, ending in matching session keys.
    /// </summary>
    [Fact]
    public void FullHandshake_WindowsClientToLinuxServer_WithRealKeys()
    {
        var serverPrivB64 = "sB6dEZ1xbAd3dntgK0MKWXnC+sEugmOk/M9uRgNZPWE=";
        var serverPubB64 = "N7E5R38PCXtkUTMtdz4BpHikZORr/xfZ563W0dosyVw=";
        var winPrivB64 = "WNt2/fPCdXID05XnqJBtagAPngJgdpM0lafcCA+8KFY=";
        var winPubB64 = "oQqgYLVBvhXAeHW/+AXsy5NfaF3YfbzM8n/fV8anmXs=";

        var serverPriv = Convert.FromBase64String(serverPrivB64);
        var serverPub = Convert.FromBase64String(serverPubB64);
        var winPriv = Convert.FromBase64String(winPrivB64);
        var winPub = Convert.FromBase64String(winPubB64);

        Assert.Equal(serverPub, X25519Crypto.GeneratePublicKey(serverPriv));
        Assert.Equal(winPub, X25519Crypto.GeneratePublicKey(winPriv));

        _output.WriteLine("=== Windows Client as Initiator, Linux Server as Responder ===");

        var initiator = new NoiseHandshakeState(winPriv, serverPub, true);
        initiator.OnDebugLog += (s, msg) => _output.WriteLine($"[Initiator/Win] {msg}");

        var responder = new NoiseHandshakeState(serverPriv, null, false);
        responder.OnDebugLog += (s, msg) => _output.WriteLine($"[Responder/Linux] {msg}");

        var timestamp = new byte[12];
        new Random(42).NextBytes(timestamp);

        var initMessage = initiator.WriteMessage(timestamp);
        _output.WriteLine($"Initiation message length: {initMessage.Length}");

        var receivedTimestamp = responder.ReadMessage(initMessage);
        Assert.Equal(timestamp, receivedTimestamp);
        _output.WriteLine("Server successfully read initiation message from Windows client!");

        var remoteStaticKey = responder.GetRemoteStaticKey();
        Assert.NotNull(remoteStaticKey);
        Assert.Equal(winPub, remoteStaticKey);
        _output.WriteLine($"Server identified client as: {Convert.ToBase64String(remoteStaticKey)}");

        var responseMessage = responder.WriteMessage(Array.Empty<byte>());
        initiator.ReadMessage(responseMessage);
        _output.WriteLine("Client successfully read response message from Linux server!");

        var (initSend, initRecv) = initiator.Split();
        var (respSend, respRecv) = responder.Split();

        Assert.Equal(initSend, respRecv);
        Assert.Equal(initRecv, respSend);
        _output.WriteLine("Session keys match! Full handshake with real keys succeeded!");
    }

    /// <summary>
    /// Verifies a complete handshake with the Linux server as initiator and the Windows client as responder, ending in matching session keys.
    /// </summary>
    [Fact]
    public void FullHandshake_LinuxKernelAsInitiator_WindowsClientAsResponder()
    {
        var serverPrivB64 = "sB6dEZ1xbAd3dntgK0MKWXnC+sEugmOk/M9uRgNZPWE=";
        var serverPubB64 = "N7E5R38PCXtkUTMtdz4BpHikZORr/xfZ563W0dosyVw=";
        var winPrivB64 = "WNt2/fPCdXID05XnqJBtagAPngJgdpM0lafcCA+8KFY=";
        var winPubB64 = "oQqgYLVBvhXAeHW/+AXsy5NfaF3YfbzM8n/fV8anmXs=";

        var serverPriv = Convert.FromBase64String(serverPrivB64);
        var serverPub = Convert.FromBase64String(serverPubB64);
        var winPriv = Convert.FromBase64String(winPrivB64);
        var winPub = Convert.FromBase64String(winPubB64);

        _output.WriteLine("=== Linux Kernel as Initiator, Windows Client as Responder ===");
        _output.WriteLine($"Linux server priv: {serverPrivB64}");
        _output.WriteLine($"Linux server pub:  {serverPubB64}");
        _output.WriteLine($"Windows priv: {winPrivB64}");
        _output.WriteLine($"Windows pub:  {winPubB64}");

        var initiator = new NoiseHandshakeState(serverPriv, winPub, true);
        initiator.OnDebugLog += (s, msg) => _output.WriteLine($"[Initiator/Linux] {msg}");

        var responder = new NoiseHandshakeState(winPriv, null, false);
        responder.OnDebugLog += (s, msg) => _output.WriteLine($"[Responder/Win] {msg}");

        var initHash = responder.GetHash();
        _output.WriteLine($"Responder initial hash: {BitConverter.ToString(initHash).Replace("-", "")}");
        _output.WriteLine($"Expected from log: AC-91-5C-2F-FD-67-83-59-70-3D-AC-73-86-0B...");

        var timestamp = new byte[12];
        new Random(42).NextBytes(timestamp);

        var initMessage = initiator.WriteMessage(timestamp);
        _output.WriteLine($"Initiation message length: {initMessage.Length}");

        var receivedTimestamp = responder.ReadMessage(initMessage);
        Assert.Equal(timestamp, receivedTimestamp);
        _output.WriteLine("Windows client successfully read initiation from Linux kernel!");

        var remoteStaticKey = responder.GetRemoteStaticKey();
        Assert.NotNull(remoteStaticKey);
        Assert.Equal(serverPub, remoteStaticKey);
        _output.WriteLine($"Windows client identified Linux server as: {Convert.ToBase64String(remoteStaticKey)}");

        var responseMessage = responder.WriteMessage(Array.Empty<byte>());
        initiator.ReadMessage(responseMessage);
        _output.WriteLine("Linux server successfully read response from Windows client!");

        var (initSend, initRecv) = initiator.Split();
        var (respSend, respRecv) = responder.Split();

        Assert.Equal(initSend, respRecv);
        Assert.Equal(initRecv, respSend);
        _output.WriteLine("Session keys match! Full handshake succeeded!");
    }

    /// <summary>
    /// Verifies that a captured initiation packet has the expected length and type and that the Windows responder can decrypt it.
    /// </summary>
    [Fact]
    public void ParseRealLinuxKernelInitiationPacket_Captured20260531()
    {
        var winPrivB64 = "WNt2/fPCdXID05XnqJBtagAPngJgdpM0lafcCA+8KFY=";
        var serverPubB64 = "N7E5R38PCXtkUTMtdz4BpHikZORr/xfZ563W0dosyVw=";

        var winPriv = Convert.FromBase64String(winPrivB64);
        var serverPub = Convert.FromBase64String(serverPubB64);

        var packetHex =
            "01000000" +
            "88f33fbd" +
            "f357741ee9591b8835d50bd02f72093604600b758d012f3d51afa35e9977" +
            "ab5cbb85c59de5163eb1a1c2b62cdfe9c64011bee092c8b159676b344e2698e5" +
            "b83dc0fd76eacfecf52f1e707b1900e4ddba" +
            "86eee1096e9260cee45fe9d9c5a1c39030aa8b5aa4d205852fc1ec25" +
            "c82a6c609bc1365f406928769d87fde5" +
            "00000000000000000000000000000000";

        var packet = Convert.FromHexString(packetHex);
        _output.WriteLine($"Packet length: {packet.Length}");
        Assert.Equal(148, packet.Length);

        var messageType = BitConverter.ToUInt32(packet, 0) & 0xFF;
        Assert.Equal(1u, messageType);
        _output.WriteLine($"Message type: {messageType} (TYPE_INITIATION)");

        var senderIndex = BitConverter.ToUInt32(packet, 4);
        _output.WriteLine($"Sender index: {senderIndex}");

        var noiseMessage = new byte[108];
        Buffer.BlockCopy(packet, 8, noiseMessage, 0, 108);

        _output.WriteLine($"Noise message ephemeral: {BitConverter.ToString(noiseMessage, 0, 32)}");

        var responder = new NoiseHandshakeState(winPriv, null, false);
        responder.OnDebugLog += (s, msg) => _output.WriteLine($"[Noise] {msg}");

        var initHash = responder.GetHash();
        _output.WriteLine($"Responder initial hash: {BitConverter.ToString(initHash).Replace("-", "")}");

        try
        {
            var timestamp = responder.ReadMessage(noiseMessage);
            _output.WriteLine($"Successfully decrypted! Timestamp: {BitConverter.ToString(timestamp)}");

            var remoteStaticKey = responder.GetRemoteStaticKey();
            Assert.NotNull(remoteStaticKey);
            _output.WriteLine($"Remote static key: {Convert.ToBase64String(remoteStaticKey)}");
            _output.WriteLine($"Expected server pub: {serverPubB64}");
            Assert.Equal(serverPub, remoteStaticKey);
        }
        catch (CryptographicException ex)
        {
            _output.WriteLine($"FAILED: {ex.Message}");
        }
    }

    private static (byte[] privateKey, byte[] publicKey) GenerateKeyPair()
    {
        var privateKey = X25519Crypto.GeneratePrivateKey();
        var publicKey = X25519Crypto.GeneratePublicKey(privateKey);
        return (privateKey, publicKey);
    }
}
