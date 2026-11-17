using WireGuard.NET.Protocol;
using WireGuard.NET.Crypto;
using Xunit;

namespace WireGuard.NET.Tests.Protocol;

/// <summary>
/// Tests for the session manager that tracks per-peer handshake state, local indices, and transport keys.
/// </summary>
public class WireGuardSessionTests
{
    private static byte[] GenerateKey()
    {
        var key = new byte[32];
        new Random(42).NextBytes(key);
        return key;
    }

    private static WireGuardConfig CreateConfig()
    {
        return new WireGuardConfig
        {
            PrivateKey = X25519Crypto.GeneratePrivateKey()
        };
    }

    /// <summary>
    /// Verifies that creating an initiation returns a non-empty message, a handshake state, and a non-zero local index.
    /// </summary>
    [Fact]
    public void CreateInitiation_ShouldReturnMessageAndState()
    {
        var config = CreateConfig();
        var session = new WireGuardSession(config);
        var peerPubKey = X25519Crypto.GeneratePublicKey(X25519Crypto.GeneratePrivateKey());

        var (message, state, localIndex) = session.CreateInitiation(peerPubKey);

        Assert.NotEmpty(message);
        Assert.NotNull(state);
        Assert.NotEqual(0u, localIndex);
    }

    /// <summary>
    /// Verifies that processing an initiation returns a response, indices, the peer key, and 32-byte send and receive keys.
    /// </summary>
    [Fact]
    public void ProcessInitiation_ShouldReturnResponseAndKeys()
    {
        var initConfig = CreateConfig();
        var respConfig = CreateConfig();
        var initSession = new WireGuardSession(initConfig);
        var respSession = new WireGuardSession(respConfig);

        var respPubKey = X25519Crypto.GeneratePublicKey(respConfig.PrivateKey);
        var initPubKey = X25519Crypto.GeneratePublicKey(initConfig.PrivateKey);
        var (initMessage, _, _) = initSession.CreateInitiation(respPubKey);

        var (response, senderIndex, localIndex, peerPubKey, state, sendKey, recvKey) =
            respSession.ProcessInitiation(initMessage, new[] { initPubKey });

        Assert.NotEmpty(response);
        Assert.NotEqual(0u, senderIndex);
        Assert.NotEqual(0u, localIndex);
        Assert.NotNull(peerPubKey);
        Assert.NotNull(sendKey);
        Assert.NotNull(recvKey);
        Assert.Equal(32, sendKey.Length);
        Assert.Equal(32, recvKey.Length);
    }

    /// <summary>
    /// Verifies that a session established on both sides produces mirrored send and receive keys.
    /// </summary>
    [Fact]
    public void FullSession_BothSidesShouldEstablishSession()
    {
        var initConfig = CreateConfig();
        var respConfig = CreateConfig();
        var initSession = new WireGuardSession(initConfig);
        var respSession = new WireGuardSession(respConfig);

        var respPubKey = X25519Crypto.GeneratePublicKey(respConfig.PrivateKey);
        var initPubKey = X25519Crypto.GeneratePublicKey(initConfig.PrivateKey);
        var (initMessage, initState, _) = initSession.CreateInitiation(respPubKey);

        var (response, _, _, peerPubKey, _, respSendKey, respRecvKey) =
            respSession.ProcessInitiation(initMessage, new[] { initPubKey });

        var (_, _, initSendKey, initRecvKey) =
            initSession.ProcessResponse(respPubKey, response, initState);

        Assert.Equal(respSendKey, initRecvKey);
        Assert.Equal(respRecvKey, initSendKey);
    }

    /// <summary>
    /// Verifies that the initiator reports an established session after processing the response while the responder does not.
    /// </summary>
    [Fact]
    public void IsSessionEstablished_AfterFullHandshake_ShouldReturnTrue()
    {
        var initConfig = CreateConfig();
        var respConfig = CreateConfig();
        var initSession = new WireGuardSession(initConfig);
        var respSession = new WireGuardSession(respConfig);

        var respPubKey = X25519Crypto.GeneratePublicKey(respConfig.PrivateKey);
        var initPubKey = X25519Crypto.GeneratePublicKey(initConfig.PrivateKey);
        var (initMessage, initState, _) = initSession.CreateInitiation(respPubKey);

        var (response, _, _, peerPubKey, _, _, _) = respSession.ProcessInitiation(initMessage, new[] { initPubKey });

        initSession.ProcessResponse(respPubKey, response, initState);

        Assert.True(initSession.IsSessionEstablished(respPubKey));
        Assert.False(respSession.IsSessionEstablished(peerPubKey));
    }

    /// <summary>
    /// Verifies that an unknown peer has no established session.
    /// </summary>
    [Fact]
    public void IsSessionEstablished_BeforeHandshake_ShouldReturnFalse()
    {
        var config = CreateConfig();
        var session = new WireGuardSession(config);
        var peerPubKey = GenerateKey();

        Assert.False(session.IsSessionEstablished(peerPubKey));
    }

    /// <summary>
    /// Verifies that GetSession returns the peer session in the initiating state after CreateInitiation.
    /// </summary>
    [Fact]
    public void GetSession_AfterCreateInitiation_ShouldReturnSession()
    {
        var config = CreateConfig();
        var session = new WireGuardSession(config);
        var peerPubKey = GenerateKey();

        session.CreateInitiation(peerPubKey);

        var peerSession = session.GetSession(peerPubKey);
        Assert.NotNull(peerSession);
        Assert.Equal(SessionState.Initiating, peerSession.State);
    }

    /// <summary>
    /// Verifies that GetSessionByLocalIndex finds the session created for that index.
    /// </summary>
    [Fact]
    public void GetSessionByLocalIndex_ShouldReturnSession()
    {
        var config = CreateConfig();
        var session = new WireGuardSession(config);
        var peerPubKey = X25519Crypto.GeneratePublicKey(X25519Crypto.GeneratePrivateKey());

        var (_, _, localIndex) = session.CreateInitiation(peerPubKey);

        var peerSession = session.GetSessionByLocalIndex(localIndex);
        Assert.NotNull(peerSession);
        Assert.Equal(localIndex, peerSession.LocalIndex);
    }

    /// <summary>
    /// Verifies that UpdateSessionKeys replaces the keys and marks the session established.
    /// </summary>
    [Fact]
    public void UpdateSessionKeys_ShouldUpdateKeys()
    {
        var config = CreateConfig();
        var session = new WireGuardSession(config);
        var peerPubKey = GenerateKey();
        var newSendKey = new byte[32];
        var newRecvKey = new byte[32];
        new Random(44).NextBytes(newSendKey);
        new Random(45).NextBytes(newRecvKey);

        session.CreateInitiation(peerPubKey);
        session.UpdateSessionKeys(peerPubKey, newSendKey, newRecvKey);

        var peerSession = session.GetSession(peerPubKey);
        Assert.NotNull(peerSession);
        Assert.Equal(newSendKey, peerSession.SendKey);
        Assert.Equal(newRecvKey, peerSession.RecvKey);
        Assert.Equal(SessionState.Established, peerSession.State);
    }

    /// <summary>
    /// Verifies that ClearSession removes the peer session.
    /// </summary>
    [Fact]
    public void ClearSession_ShouldRemoveSession()
    {
        var config = CreateConfig();
        var session = new WireGuardSession(config);
        var peerPubKey = GenerateKey();

        session.CreateInitiation(peerPubKey);
        session.ClearSession(peerPubKey);

        Assert.Null(session.GetSession(peerPubKey));
    }

    /// <summary>
    /// Verifies that ClearAllSessions removes every peer session.
    /// </summary>
    [Fact]
    public void ClearAllSessions_ShouldRemoveAllSessions()
    {
        var config = CreateConfig();
        var session = new WireGuardSession(config);
        var peer1 = GenerateKey();
        var peer2 = GenerateKey();

        session.CreateInitiation(peer1);
        session.CreateInitiation(peer2);
        session.ClearAllSessions();

        Assert.Null(session.GetSession(peer1));
        Assert.Null(session.GetSession(peer2));
    }
}
