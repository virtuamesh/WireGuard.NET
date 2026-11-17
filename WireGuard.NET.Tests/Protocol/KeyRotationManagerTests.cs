using WireGuard.NET.Protocol;
using Xunit;

namespace WireGuard.NET.Tests.Protocol;

/// <summary>
/// Tests for the key rotation manager, covering peer state lifecycle, rekey decisions, counters, and rotation events.
/// </summary>
public class KeyRotationManagerTests
{
    private static byte[] GeneratePeerKey()
    {
        var key = new byte[32];
        new Random(42).NextBytes(key);
        return key;
    }

    /// <summary>
    /// Verifies that starting and stopping the manager does not throw.
    /// </summary>
    [Fact]
    public void Start_And_Stop_ShouldNotThrow()
    {
        var manager = new KeyRotationManager();

        manager.Start();
        manager.Stop();
    }

    /// <summary>
    /// Verifies that initializing a peer with send and receive keys completes without error.
    /// </summary>
    [Fact]
    public void InitializePeer_ShouldNotThrow()
    {
        var manager = new KeyRotationManager();
        var peerKey = GeneratePeerKey();
        var sendKey = new byte[32];
        var recvKey = new byte[32];

        manager.InitializePeer(peerKey, sendKey, recvKey);
    }

    /// <summary>
    /// Verifies that a freshly initialized peer does not require a rekey.
    /// </summary>
    [Fact]
    public void ShouldInitiateRekey_ImmediatelyAfterInit_ShouldReturnFalse()
    {
        var manager = new KeyRotationManager();
        var peerKey = GeneratePeerKey();
        var sendKey = new byte[32];
        var recvKey = new byte[32];

        manager.InitializePeer(peerKey, sendKey, recvKey);

        Assert.False(manager.ShouldInitiateRekey(peerKey));
    }

    /// <summary>
    /// Verifies that an unknown peer never requires a rekey.
    /// </summary>
    [Fact]
    public void ShouldInitiateRekey_UnknownPeer_ShouldReturnFalse()
    {
        var manager = new KeyRotationManager();
        var unknownKey = GeneratePeerKey();

        Assert.False(manager.ShouldInitiateRekey(unknownKey));
    }

    /// <summary>
    /// Verifies that packets from an unknown peer are rejected.
    /// </summary>
    [Fact]
    public void ShouldReject_UnknownPeer_ShouldReturnTrue()
    {
        var manager = new KeyRotationManager();
        var unknownKey = GeneratePeerKey();

        Assert.True(manager.ShouldReject(unknownKey));
    }

    /// <summary>
    /// Verifies that a freshly initialized peer is not rejected.
    /// </summary>
    [Fact]
    public void ShouldReject_ImmediatelyAfterInit_ShouldReturnFalse()
    {
        var manager = new KeyRotationManager();
        var peerKey = GeneratePeerKey();
        var sendKey = new byte[32];
        var recvKey = new byte[32];

        manager.InitializePeer(peerKey, sendKey, recvKey);

        Assert.False(manager.ShouldReject(peerKey));
    }

    /// <summary>
    /// Verifies that marking a peer for rotation makes ShouldInitiateRekey return true.
    /// </summary>
    [Fact]
    public void MarkForRotation_ShouldTriggerRekey()
    {
        var manager = new KeyRotationManager();
        var peerKey = GeneratePeerKey();
        var sendKey = new byte[32];
        var recvKey = new byte[32];

        manager.InitializePeer(peerKey, sendKey, recvKey);
        manager.MarkForRotation(peerKey);

        Assert.True(manager.ShouldInitiateRekey(peerKey));
    }

    /// <summary>
    /// Verifies that rotating keys clears the pending rekey state.
    /// </summary>
    [Fact]
    public void RotateKeys_ShouldResetRekeyState()
    {
        var manager = new KeyRotationManager();
        var peerKey = GeneratePeerKey();
        var sendKey = new byte[32];
        var recvKey = new byte[32];

        manager.InitializePeer(peerKey, sendKey, recvKey);
        manager.MarkForRotation(peerKey);
        Assert.True(manager.ShouldInitiateRekey(peerKey));

        var newSendKey = new byte[32];
        var newRecvKey = new byte[32];
        new Random(44).NextBytes(newSendKey);
        new Random(45).NextBytes(newRecvKey);
        manager.RotateKeys(peerKey, newSendKey, newRecvKey);

        Assert.False(manager.ShouldInitiateRekey(peerKey));
    }

    /// <summary>
    /// Verifies that one hundred RecordSend calls increment the send count to 100.
    /// </summary>
    [Fact]
    public void RecordSend_ShouldIncrementSendCount()
    {
        var manager = new KeyRotationManager();
        var peerKey = GeneratePeerKey();
        var sendKey = new byte[32];
        var recvKey = new byte[32];

        manager.InitializePeer(peerKey, sendKey, recvKey);

        for (int i = 0; i < 100; i++)
        {
            manager.RecordSend(peerKey);
        }

        var state = manager.GetPeerState(peerKey);
        Assert.NotNull(state);
        Assert.Equal(100L, state.SendCount);
    }

    /// <summary>
    /// Verifies that fifty RecordRecv calls increment the receive count to 50.
    /// </summary>
    [Fact]
    public void RecordRecv_ShouldIncrementRecvCount()
    {
        var manager = new KeyRotationManager();
        var peerKey = GeneratePeerKey();
        var sendKey = new byte[32];
        var recvKey = new byte[32];

        manager.InitializePeer(peerKey, sendKey, recvKey);

        for (int i = 0; i < 50; i++)
        {
            manager.RecordRecv(peerKey);
        }

        var state = manager.GetPeerState(peerKey);
        Assert.NotNull(state);
        Assert.Equal(50L, state.RecvCount);
    }

    /// <summary>
    /// Verifies that ClearPeer removes the peer state and its rekey flag.
    /// </summary>
    [Fact]
    public void ClearPeer_ShouldRemovePeer()
    {
        var manager = new KeyRotationManager();
        var peerKey = GeneratePeerKey();
        var sendKey = new byte[32];
        var recvKey = new byte[32];

        manager.InitializePeer(peerKey, sendKey, recvKey);
        manager.ClearPeer(peerKey);

        Assert.Null(manager.GetPeerState(peerKey));
        Assert.False(manager.ShouldInitiateRekey(peerKey));
    }

    /// <summary>
    /// Verifies that ClearAllPeers removes the state of every peer.
    /// </summary>
    [Fact]
    public void ClearAllPeers_ShouldRemoveAllPeers()
    {
        var manager = new KeyRotationManager();
        var key1 = GeneratePeerKey();
        var key2 = GeneratePeerKey();

        manager.InitializePeer(key1, new byte[32], new byte[32]);
        manager.InitializePeer(key2, new byte[32], new byte[32]);

        manager.ClearAllPeers();

        Assert.Null(manager.GetPeerState(key1));
        Assert.Null(manager.GetPeerState(key2));
    }

    /// <summary>
    /// Verifies that GetPeerState returns a copy whose key buffer cannot mutate the stored state.
    /// </summary>
    [Fact]
    public void GetPeerState_ShouldReturnClone()
    {
        var manager = new KeyRotationManager();
        var peerKey = GeneratePeerKey();
        var sendKey = new byte[32];
        sendKey[0] = 42;

        manager.InitializePeer(peerKey, sendKey, new byte[32]);

        var state = manager.GetPeerState(peerKey);
        Assert.NotNull(state);
        Assert.Equal(42, state.SendKey[0]);

        state.SendKey[0] = 99;
        var state2 = manager.GetPeerState(peerKey);
        Assert.NotNull(state2);
        Assert.Equal(42, state2.SendKey[0]);
    }

    /// <summary>
    /// Verifies that the KeyRotationNeeded event fires with the marked peer key after the manager starts.
    /// </summary>
    [Fact]
    public void KeyRotationNeeded_ShouldFireWhenRekeyNeeded()
    {
        var manager = new KeyRotationManager();
        var peerKey = GeneratePeerKey();
        var sendKey = new byte[32];
        var recvKey = new byte[32];

        manager.InitializePeer(peerKey, sendKey, recvKey);
        manager.MarkForRotation(peerKey);

        byte[]? rotatedKey = null;
        manager.KeyRotationNeeded += (_, key) => rotatedKey = key;
        manager.Start();

        Thread.Sleep(200);
        manager.Stop();

        Assert.Equal(peerKey, rotatedKey);
    }
}
