using WireGuard.NET.Protocol;
using Xunit;

namespace WireGuard.NET.Tests.Protocol;

/// <summary>
/// Tests for WireGuardPeer timestamp replay protection and transport rotation handling.
/// </summary>
public class WireGuardPeerTests
{
    private static (byte[] sendKey, byte[] recvKey) GenerateTransportKeys(int seed)
    {
        var sendKey = new byte[32];
        var recvKey = new byte[32];
        new Random(seed).NextBytes(sendKey);
        new Random(seed + 1).NextBytes(recvKey);
        return (sendKey, recvKey);
    }

    private static byte[] MakeTai64n(ulong seconds, uint nanos)
    {
        // TAI64N：8 字节大端秒 + 4 字节大端纳秒
        var result = new byte[12];
        var secBytes = BitConverter.GetBytes(seconds);
        if (BitConverter.IsLittleEndian) Array.Reverse(secBytes);
        Buffer.BlockCopy(secBytes, 0, result, 0, 8);
        var nanoBytes = BitConverter.GetBytes(nanos);
        if (BitConverter.IsLittleEndian) Array.Reverse(nanoBytes);
        Buffer.BlockCopy(nanoBytes, 0, result, 8, 4);
        return result;
    }

    /// <summary>
    /// Verifies that the first TAI64N initiation timestamp is always accepted.
    /// </summary>
    [Fact]
    public void TryUpdateLastInitiationTimestamp_FirstTimestamp_ShouldAccept()
    {
        var peer = new WireGuardPeer(new byte[32]);

        Assert.True(peer.TryUpdateLastInitiationTimestamp(MakeTai64n(1000, 500)));
    }

    /// <summary>
    /// Verifies that strictly newer nanosecond and second values are accepted.
    /// </summary>
    [Fact]
    public void TryUpdateLastInitiationTimestamp_NewerTimestamp_ShouldAccept()
    {
        var peer = new WireGuardPeer(new byte[32]);

        Assert.True(peer.TryUpdateLastInitiationTimestamp(MakeTai64n(1000, 500)));
        Assert.True(peer.TryUpdateLastInitiationTimestamp(MakeTai64n(1000, 501)));
        Assert.True(peer.TryUpdateLastInitiationTimestamp(MakeTai64n(1001, 0)));
    }

    /// <summary>
    /// Verifies that identical, nanosecond-regressed, and second-regressed timestamps are rejected.
    /// </summary>
    [Fact]
    public void TryUpdateLastInitiationTimestamp_ReplayedOrStaleTimestamp_ShouldReject()
    {
        var peer = new WireGuardPeer(new byte[32]);

        Assert.True(peer.TryUpdateLastInitiationTimestamp(MakeTai64n(1000, 500)));
        // 完全重放
        Assert.False(peer.TryUpdateLastInitiationTimestamp(MakeTai64n(1000, 500)));
        // 纳秒回退
        Assert.False(peer.TryUpdateLastInitiationTimestamp(MakeTai64n(1000, 499)));
        // 秒回退
        Assert.False(peer.TryUpdateLastInitiationTimestamp(MakeTai64n(999, 999)));
    }

    /// <summary>
    /// Verifies that timestamps shorter than 12 bytes are rejected.
    /// </summary>
    [Fact]
    public void TryUpdateLastInitiationTimestamp_InvalidLength_ShouldReject()
    {
        var peer = new WireGuardPeer(new byte[32]);

        Assert.False(peer.TryUpdateLastInitiationTimestamp(new byte[8]));
        Assert.False(peer.TryUpdateLastInitiationTimestamp(ReadOnlySpan<byte>.Empty));
    }

    /// <summary>
    /// Verifies that the previous transport rejects already-seen counters after rotation while still decrypting unseen counters.
    /// </summary>
    [Fact]
    public void SetTransport_PreviousTransportRetainsReplayWindow()
    {
        // 轮换传输层后，previous transport 必须保留旧重放窗口（30s TTL 内）：
        // 旧密钥的新计数器包仍可解密，但已见计数器的旧包必须仍被拒绝。
        var peer = new WireGuardPeer(new byte[32]);
        var (sendA, recvA) = GenerateTransportKeys(100);
        var (sendB, recvB) = GenerateTransportKeys(200);

        // 对端视角：用 recvA 加密发给我们（我们以 recvA 解密）
        var remoteTransportA = new WireGuardTransport(recvA, sendA);
        peer.SetTransport(sendA, recvA);

        var pkt0 = remoteTransportA.EncryptPacket(System.Text.Encoding.UTF8.GetBytes("old-0"), 1u);
        var pkt1 = remoteTransportA.EncryptPacket(System.Text.Encoding.UTF8.GetBytes("old-1"), 1u);

        // 正常解密两个包（counter 0 和 1 均已见）
        Assert.NotNull(peer.DecryptPacket(pkt0, out _));
        Assert.NotNull(peer.DecryptPacket(pkt1, out _));

        // 轮换传输层（previous = A）
        peer.SetTransport(sendB, recvB);

        // 重放旧会话已见计数器（counter=0）的包：必须被拒绝（窗口未清零）
        Assert.Null(peer.TryDecryptWithPreviousTransport(pkt0, out _));

        // 旧会话未见过的新计数器（counter=2）的包：仍应可解密
        var pkt2 = remoteTransportA.EncryptPacket(System.Text.Encoding.UTF8.GetBytes("old-2"), 1u);
        var decrypted = peer.TryDecryptWithPreviousTransport(pkt2, out _);
        Assert.NotNull(decrypted);
        Assert.Equal("old-2", System.Text.Encoding.UTF8.GetString(decrypted));
    }

    /// <summary>
    /// Verifies that two retained previous generations still decrypt packets from the second-oldest session.
    /// </summary>
    [Fact]
    public void TryDecryptWithPreviousTransport_TwoRapidRotations_StillDecryptsSecondGeneration()
    {
        // [VM-SESSION-COLLAPSE-GRACE 2026-11-08] 两侧同时发起握手时，7 秒内可能连续建立 3 个会话。
        // 只保留 1 代 previous 时，倒数第二代的密钥会被挤掉，对端在途数据包全部解不出来
        // （实测出口节点 380 次/日会话塌缩 + 25 次丢包）。这里断言保留 2 代仍能解密。
        var peer = new WireGuardPeer(new byte[32]);
        var (sendA, recvA) = GenerateTransportKeys(300);
        var (sendB, recvB) = GenerateTransportKeys(400);
        var (sendC, recvC) = GenerateTransportKeys(500);

        var remoteTransportA = new WireGuardTransport(recvA, sendA);

        peer.SetTransport(sendA, recvA);   // 第 1 代
        peer.SetTransport(sendB, recvB);   // 第 2 代（A 退役）
        peer.SetTransport(sendC, recvC);   // 第 3 代（B 退役，A 仍应在保留队列里）

        var pktFromA = remoteTransportA.EncryptPacket(System.Text.Encoding.UTF8.GetBytes("gen-A"), 1u);

        var decrypted = peer.TryDecryptWithPreviousTransport(pktFromA, out _);
        Assert.NotNull(decrypted);
        Assert.Equal("gen-A", System.Text.Encoding.UTF8.GetString(decrypted));
    }

    /// <summary>
    /// Verifies that the oldest generation is evicted once more than two previous transports have accumulated.
    /// </summary>
    [Fact]
    public void TryDecryptWithPreviousTransport_ThirdRotation_EvictsOldestGeneration()
    {
        // 队列上限 2 代：第 4 次轮换后，第 1 代必须已被淘汰（不能无限堆积旧密钥）。
        var peer = new WireGuardPeer(new byte[32]);
        var (sendA, recvA) = GenerateTransportKeys(600);
        var (sendB, recvB) = GenerateTransportKeys(700);
        var (sendC, recvC) = GenerateTransportKeys(800);
        var (sendD, recvD) = GenerateTransportKeys(900);

        var remoteTransportA = new WireGuardTransport(recvA, sendA);

        peer.SetTransport(sendA, recvA);
        peer.SetTransport(sendB, recvB);
        peer.SetTransport(sendC, recvC);
        peer.SetTransport(sendD, recvD);

        var pktFromA = remoteTransportA.EncryptPacket(System.Text.Encoding.UTF8.GetBytes("gen-A"), 1u);

        Assert.Null(peer.TryDecryptWithPreviousTransport(pktFromA, out _));
    }
}
