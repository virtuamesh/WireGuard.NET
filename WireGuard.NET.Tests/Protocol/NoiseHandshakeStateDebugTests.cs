using WireGuard.NET.Protocol.Noise;
using WireGuard.NET.Crypto;
using Xunit;

namespace WireGuard.NET.Tests.Protocol;

/// <summary>
/// Diagnostic test tracing a Noise handshake from Diffie-Hellman agreement through message exchange.
/// </summary>
public class NoiseHandshakeStateDebugTests
{
    /// <summary>
    /// Verifies that both parties agree on the X25519 shared secret and that an initiation message is produced and read back with the same timestamp.
    /// </summary>
    [Fact]
    public void Debug_TraceHandshake()
    {
        var initPriv = X25519Crypto.GeneratePrivateKey();
        var respPriv = X25519Crypto.GeneratePrivateKey();
        var initPub = X25519Crypto.GeneratePublicKey(initPriv);
        var respPub = X25519Crypto.GeneratePublicKey(respPriv);

        var dh1 = X25519Crypto.ScalarMult(initPriv, respPub);
        var dh2 = X25519Crypto.ScalarMult(respPriv, initPub);
        Assert.Equal(dh1, dh2);

        var initiator = new NoiseHandshakeState(initPriv, respPub, true);
        var responder = new NoiseHandshakeState(respPriv, null, false);

        var timestamp = new byte[12];
        new Random(42).NextBytes(timestamp);

        var initMessage = initiator.WriteMessage(timestamp);
        Assert.Equal(108, initMessage.Length);

        var receivedTimestamp = responder.ReadMessage(initMessage);
        Assert.Equal(timestamp, receivedTimestamp);
    }
}
