using System.Reflection;
using WireGuard.NET.Protocol;
using WireGuard.NET.Protocol.Noise;
using WireGuard.NET.Crypto;
using Xunit;

namespace WireGuard.NET.Tests.Protocol;

/// <summary>
/// Regression tests for NoiseHandshakeState key material disposal: cloned private keys, preshared keys, and remote static key copies must be zeroed when a state is disposed or removed by the HandshakeManager.
/// </summary>
public class NoiseHandshakeStateDisposalTests
{
    private static (byte[] privateKey, byte[] publicKey) GenerateKeyPair()
    {
        var privateKey = X25519Crypto.GeneratePrivateKey();
        var publicKey = X25519Crypto.GeneratePublicKey(privateKey);
        return (privateKey, publicKey);
    }

    private static byte[]? GetField(NoiseHandshakeState state, string name)
    {
        var field = typeof(NoiseHandshakeState).GetField(name,
            BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(field);
        return field!.GetValue(state) as byte[];
    }

    /// <summary>
    /// Verifies that Dispose zeroes the static, preshared, remote static, and ephemeral key buffers.
    /// </summary>
    [Fact]
    public void Dispose_ZeroesAllKeyMaterialIncludingRemoteStaticKey()
    {
        var (localPriv, _) = GenerateKeyPair();
        var (_, remotePub) = GenerateKeyPair();
        var psk = X25519Crypto.GeneratePrivateKey();

        var state = new NoiseHandshakeState(localPriv, remotePub, true, psk);

        // 制造 _e/_re：走一条真实握手路径
        var timestamp = new byte[12];
        var message = state.WriteMessage(timestamp);
        Assert.NotEmpty(message);

        var sBefore = GetField(state, "_s");
        var pskBefore = GetField(state, "_psk");
        var rsBefore = GetField(state, "_rs");
        Assert.NotNull(sBefore);
        Assert.NotNull(pskBefore);
        Assert.NotNull(rsBefore);

        state.Dispose();

        Assert.All(sBefore!, b => Assert.Equal(0, b));
        Assert.All(pskBefore!, b => Assert.Equal(0, b));
        Assert.All(rsBefore!, b => Assert.Equal(0, b));
        var eAfter = GetField(state, "_e");
        if (eAfter != null)
            Assert.All(eAfter, b => Assert.Equal(0, b));
    }

    /// <summary>
    /// Verifies that calling Dispose more than once does not throw.
    /// </summary>
    [Fact]
    public void Dispose_IsIdempotent()
    {
        var (localPriv, _) = GenerateKeyPair();
        var state = new NoiseHandshakeState(localPriv, null, false);

        state.Dispose();
        var ex = Record.Exception(() => state.Dispose());
        Assert.Null(ex);
    }

    /// <summary>
    /// Verifies that reading a message after disposal throws ObjectDisposedException.
    /// </summary>
    [Fact]
    public void ReadMessage_AfterDispose_ThrowsObjectDisposedException()
    {
        var (initPriv, _) = GenerateKeyPair();
        var (respPriv, respPub) = GenerateKeyPair();

        var initiator = new NoiseHandshakeState(initPriv, respPub, true);
        var message = initiator.WriteMessage(new byte[12]);

        var responder = new NoiseHandshakeState(respPriv, null, false);
        responder.Dispose();

        Assert.Throws<ObjectDisposedException>(() => responder.ReadMessage(message[8..]));
    }

    /// <summary>
    /// Verifies that replacing the preshared key zeroes the previous buffer and installs the new key.
    /// </summary>
    [Fact]
    public void SetPresharedKey_Replacement_ZeroesOldPsk()
    {
        var (localPriv, _) = GenerateKeyPair();
        var oldPsk = X25519Crypto.GeneratePrivateKey();
        var newPsk = X25519Crypto.GeneratePrivateKey();
        // 克隆一份以便在 Dispose 后置零时比对内容
        var oldPskClone = (byte[])oldPsk.Clone();

        var state = new NoiseHandshakeState(localPriv, null, false, oldPsk);
        var oldPskRef = GetField(state, "_psk")!;
        Assert.Equal(oldPsk, oldPskRef);

        state.SetPresharedKey(newPsk);

        // 旧 PSK 数组应已被清零（SetPresharedKey 内部 ZeroMemory），新 PSK 已装入
        Assert.All(oldPskClone, (b, i) => Assert.Equal(0, oldPskRef[i]));
        Assert.Equal(newPsk, GetField(state, "_psk"));
    }

    /// <summary>
    /// Verifies that clearing a pending handshake disposes its state and zeroes the static key.
    /// </summary>
    [Fact]
    public void HandshakeManager_ClearHandshake_DisposesPendingState()
    {
        var (localPriv, _) = GenerateKeyPair();
        var (_, peerPub) = GenerateKeyPair();
        var manager = new HandshakeManager();

        var state = new NoiseHandshakeState(localPriv, peerPub, true);
        var sRef = GetField(state, "_s")!;
        manager.InitiateHandshake(peerPub, Array.Empty<byte>(), state, localIndex: 123);

        manager.ClearHandshake(peerPub);

        // 被移除的 pending 状态必须随 ClearHandshake 一并 Dispose（_s 清零）
        Assert.All(sRef, b => Assert.Equal(0, b));
    }

    /// <summary>
    /// Verifies that clearing all pending handshakes disposes every state.
    /// </summary>
    [Fact]
    public void HandshakeManager_ClearAllHandshakes_DisposesAllPendingStates()
    {
        var (localPriv, _) = GenerateKeyPair();
        var (_, peerPub) = GenerateKeyPair();
        var manager = new HandshakeManager();

        var state = new NoiseHandshakeState(localPriv, peerPub, true);
        var sRef = GetField(state, "_s")!;
        manager.InitiateHandshake(peerPub, Array.Empty<byte>(), state, localIndex: 456);

        manager.ClearAllHandshakes();

        Assert.All(sRef, b => Assert.Equal(0, b));
    }

    /// <summary>
    /// Verifies that replacing a pending handshake disposes the previous state.
    /// </summary>
    [Fact]
    public void HandshakeManager_UpdateHandshakeMessage_DisposesReplacedState()
    {
        var (localPriv, _) = GenerateKeyPair();
        var (_, peerPub) = GenerateKeyPair();
        var manager = new HandshakeManager();

        var oldState = new NoiseHandshakeState(localPriv, peerPub, true);
        var oldSRef = GetField(oldState, "_s")!;
        manager.InitiateHandshake(peerPub, Array.Empty<byte>(), oldState, localIndex: 1);

        var newState = new NoiseHandshakeState(localPriv, peerPub, true);
        manager.UpdateHandshakeMessage(peerPub, Array.Empty<byte>(), newState, localIndex: 2);

        // 被替换的旧状态必须 Dispose
        Assert.All(oldSRef, b => Assert.Equal(0, b));
    }

    /// <summary>
    /// Verifies that stopping the handshake manager disposes pending states.
    /// </summary>
    [Fact]
    public void HandshakeManager_Stop_DisposesPendingStates()
    {
        var (localPriv, _) = GenerateKeyPair();
        var (_, peerPub) = GenerateKeyPair();
        var manager = new HandshakeManager();
        manager.Start();

        var state = new NoiseHandshakeState(localPriv, peerPub, true);
        var sRef = GetField(state, "_s")!;
        manager.InitiateHandshake(peerPub, Array.Empty<byte>(), state, localIndex: 789);

        manager.Stop();

        Assert.All(sRef, b => Assert.Equal(0, b));
    }
}
