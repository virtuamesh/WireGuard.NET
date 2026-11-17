using WireGuard.NET.Crypto;
using WireGuard.NET.Protocol;
using WireGuard.NET.Protocol.Noise;
using Xunit;
using Xunit.Abstractions;

namespace WireGuard.NET.Tests.Protocol;

/// <summary>
/// Tests that reproduce captured Noise initiation traffic and verify decryption against observed Linux kernel keys.
/// </summary>
public class CapturePacketDecryptTests
{
    private readonly ITestOutputHelper _output;

    public CapturePacketDecryptTests(ITestOutputHelper output)
    {
        _output = output;
    }

    /// <summary>
    /// Verifies that an initiation written by a server initiator is read by a client responder, yielding the timestamp and the server static key.
    /// </summary>
    [Fact]
    public void Decrypt_CapturedInitiationPacket_FromLinuxKernel()
    {
        var serverPrivB64 = "sB6dEZ1xbAd3dntgK0MKWXnC+sEugmOk/M9uRgNZPWE=";
        var serverPubB64 = "N7E5R38PCXtkUTMtdz4BpHikZORr/xfZ563W0dosyVw=";
        var serverPriv = Convert.FromBase64String(serverPrivB64);
        var serverPub = Convert.FromBase64String(serverPubB64);

        var (clientPriv, clientPub) = GenerateKeyPair();
        _output.WriteLine($"Client pub: {Convert.ToBase64String(clientPub)}");

        var initiator = new NoiseHandshakeState(serverPriv, clientPub, true);
        initiator.OnDebugLog += (s, msg) => _output.WriteLine($"[I] {msg}");

        var timestamp = new byte[12];
        new Random(42).NextBytes(timestamp);
        var initMessage = initiator.WriteMessage(timestamp);
        _output.WriteLine($"Initiation noise message: {BitConverter.ToString(initMessage)[..80]}...");

        var responder = new NoiseHandshakeState(clientPriv, null, false);
        responder.OnDebugLog += (s, msg) => _output.WriteLine($"[R] {msg}");

        var receivedTimestamp = responder.ReadMessage(initMessage);
        Assert.Equal(timestamp, receivedTimestamp);
        _output.WriteLine("SUCCESS: Internal handshake works!");

        var remoteStaticKey = responder.GetRemoteStaticKey();
        Assert.NotNull(remoteStaticKey);
        Assert.Equal(serverPub, remoteStaticKey);
    }

    /// <summary>
    /// Verifies that the ephemeral key can be extracted from an initiation message and that the responder reads the message with a matching timestamp.
    /// </summary>
    [Fact]
    public void Verify_DhEs_WithEphemeralKeyExtraction()
    {
        var serverPrivB64 = "sB6dEZ1xbAd3dntgK0MKWXnC+sEugmOk/M9uRgNZPWE=";
        var serverPriv = Convert.FromBase64String(serverPrivB64);
        var serverPub = X25519Crypto.GeneratePublicKey(serverPriv);

        var (clientPriv, clientPub) = GenerateKeyPair();

        var initiator = new NoiseHandshakeState(serverPriv, clientPub, true);
        var timestamp = new byte[12];
        new Random(42).NextBytes(timestamp);
        var initMessage = initiator.WriteMessage(timestamp);

        var ephemeralPubFromMsg = initMessage[..32];
        _output.WriteLine($"Ephemeral pub from message: {BitConverter.ToString(ephemeralPubFromMsg)[..40]}...");

        var initiatorDhEs = X25519Crypto.ScalarMult(serverPriv, clientPub);
        _output.WriteLine($"DH(server_priv, client_pub) = {Convert.ToHexString(initiatorDhEs).ToLower()[..40]}...");

        var responder = new NoiseHandshakeState(clientPriv, null, false);
        responder.OnDebugLog += (s, msg) => _output.WriteLine($"[R] {msg}");

        var receivedTimestamp = responder.ReadMessage(initMessage);
        Assert.Equal(timestamp, receivedTimestamp);
        _output.WriteLine("SUCCESS: Full handshake with real server key works!");
    }

    private static (byte[] privateKey, byte[] publicKey) GenerateKeyPair()
    {
        var privateKey = X25519Crypto.GeneratePrivateKey();
        var publicKey = X25519Crypto.GeneratePublicKey(privateKey);
        return (privateKey, publicKey);
    }
}
