using System.Reflection;
using WireGuard.NET.Crypto;
using WireGuard.NET.Protocol;
using WireGuard.NET.Tun;
using Xunit;

namespace WireGuard.NET.Tests.Protocol;

/// <summary>
/// Regression test for UDP dead-link detection (2026-10-08): after the peer restarts and drops its session, active sending must switch to DERP and re-handshake instead of blackholing until the upper-layer timeout.
/// </summary>
public class WireGuardUdpDeadLinkTests
{
    private int _derpDataPacketsSent;

    private static object GetPeerDict(object device)
    {
        var field = device.GetType().GetField("_peers", BindingFlags.NonPublic | BindingFlags.Instance)
            ?? throw new InvalidOperationException("_peers field not found");
        return field.GetValue(device)!;
    }

    private static WireGuardPeer? GetPeer(object device, byte[] publicKey)
    {
        var dict = (System.Collections.Concurrent.ConcurrentDictionary<byte[], WireGuardPeer>)GetPeerDict(device);
        return dict.TryGetValue(publicKey, out var p) ? p : null;
    }

    private static void ResetPeerSession(object device, byte[] peerPublicKey)
    {
        var field = device.GetType().GetField("_connectionManager", BindingFlags.NonPublic | BindingFlags.Instance)
            ?? throw new InvalidOperationException("_connectionManager field not found");
        var manager = field.GetValue(device)!;
        manager.GetType().GetMethod("ResetPeer")!.Invoke(manager, new object?[] { peerPublicKey });
    }

    /// <summary>
    /// Verifies that a dead UDP link triggers DERP forwarding and a fast session re-establishment with data still reaching the peer TUN.
    /// </summary>
    [Fact]
    public async Task UdpDeadLink_ShouldSwitchToDerpAndReinitiateHandshake()
    {
        var privA = X25519Crypto.GeneratePrivateKey();
        var pubA = X25519Crypto.GeneratePublicKey(privA);
        var privB = X25519Crypto.GeneratePrivateKey();
        var pubB = X25519Crypto.GeneratePublicKey(privB);

        var mockA = new MockTunDevice();
        var mockB = new MockTunDevice();

        var configA = new WireGuardConfig
        {
            PrivateKey = privA,
            ListenPort = 40031,
            Address = System.Net.IPAddress.Parse("10.99.2.1"),
            AddressPrefixLength = 24,
            Peers =
            [
                new PeerConfig
                {
                    PublicKey = pubB,
                    Endpoint = new System.Net.IPEndPoint(System.Net.IPAddress.Loopback, 40032),
                    AllowedIPs = [new WireGuard.NET.Protocol.IPNetwork { Address = System.Net.IPAddress.Parse("10.99.2.2"), PrefixLength = 32 }]
                }
            ]
        };
        var configB = new WireGuardConfig
        {
            PrivateKey = privB,
            ListenPort = 40032,
            Address = System.Net.IPAddress.Parse("10.99.2.2"),
            AddressPrefixLength = 24,
            Peers =
            [
                new PeerConfig
                {
                    PublicKey = pubA,
                    AllowedIPs = [new WireGuard.NET.Protocol.IPNetwork { Address = System.Net.IPAddress.Parse("10.99.2.1"), PrefixLength = 32 }]
                }
            ]
        };

        using var deviceA = new WireGuardDevice(configA, useMockTunDevice: true);
        using var deviceB = new WireGuardDevice(configB, useMockTunDevice: true);
        deviceA.SetTunDevice(mockA);
        deviceB.SetTunDevice(mockB);
        deviceA.UdpDeadLinkTimeout = TimeSpan.FromSeconds(2);

        // 接线 DERP 虚拟回环（无真实 DERP 服务器），并统计 A 发往 B 的 DERP 数据包：
        // 死链检测触发时数据路径会瞬时切到 DERP；随后若重握手经 UDP 完成（UDP 被证明存活），
        // ProcessResponseAsync 会合法地把 IsDerpConnected 复位为 false——瞬态标志位轮询不可靠，
        // 因此以 DERP 发包计数作为"路径切换已发生"的确定性证据。
        deviceA.SendPacketViaDerp += (_, e) =>
        {
            if (e.PeerPublicKey.SequenceEqual(pubB))
            {
                Interlocked.Increment(ref _derpDataPacketsSent);
            }
            deviceB.InjectPacketFromDerp(pubA, e.Packet);
        };
        deviceB.SendPacketViaDerp += (_, e) => deviceA.InjectPacketFromDerp(pubB, e.Packet);

        await deviceA.StartAsync();
        await deviceB.StartAsync();

        try
        {
            // 等待 UDP 直连握手完成
            var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(10);
            while (DateTime.UtcNow < deadline &&
                   (GetPeer(deviceA, pubB)?.IsEstablished != true || GetPeer(deviceB, pubA)?.IsEstablished != true))
            {
                await Task.Delay(100);
            }
            Assert.True(GetPeer(deviceA, pubB)?.IsEstablished == true, "A->B handshake should establish");

            // 模拟 B 重启丢会话：B 丢弃 A 的会话（UDP 端口仍在收包，A 的包将被 B 静默丢弃）
            var bResetAt = DateTime.UtcNow;
            ResetPeerSession(deviceB, pubA);

            // A 持续活跃发送（模拟 ping：合法 IPv4 头 dst=10.99.2.2 以命中 B 的 AllowedIPs）
            var payload = new byte[52];
            payload[0] = 0x45; // IPv4, IHL=5
            payload[2] = 0x00; payload[3] = 52; // total length
            payload[8] = 64;   // TTL
            payload[9] = 1;    // protocol = ICMP
            payload[12] = 10; payload[13] = 99; payload[14] = 2; payload[15] = 1; // src
            payload[16] = 10; payload[17] = 99; payload[18] = 2; payload[19] = 2; // dst
            var sendDeadline = DateTime.UtcNow + TimeSpan.FromSeconds(15);
            bool derpPathUsed = false;
            bool sessionReestablished = false;
            DateTime? reestablishedAt = null;
            var lastDiag = "no-diag";
            while (DateTime.UtcNow < sendDeadline && !(derpPathUsed && sessionReestablished))
            {
                mockA.EnqueueReceivedPacket(payload);
                await Task.Delay(300);
                var peerA = GetPeer(deviceA, pubB);
                var peerB = GetPeer(deviceB, pubA);
                derpPathUsed = Volatile.Read(ref _derpDataPacketsSent) > 0;
                sessionReestablished = peerB is { IsEstablished: true, LastHandshake: var lh } && lh > bResetAt;
                if (sessionReestablished && reestablishedAt == null)
                {
                    reestablishedAt = DateTime.UtcNow;
                }
                if (peerA != null)
                {
                    var now = DateTime.UtcNow;
                    lastDiag = $"established={peerA.IsEstablished} txAge={(peerA.LastTxTime == DateTime.MinValue ? -1 : (now - peerA.LastTxTime).TotalSeconds):F1}s rxAge={(peerA.LastRxTime == DateTime.MinValue ? -1 : (now - peerA.LastRxTime).TotalSeconds):F1}s hsAge={(peerA.LastHandshake == DateTime.MinValue ? -1 : (now - peerA.LastHandshake).TotalSeconds):F1}s derpPackets={Volatile.Read(ref _derpDataPacketsSent)}";
                }
            }

            Assert.True(derpPathUsed, $"A should route data via DERP after dead-link detection (transient switch), diag: {lastDiag}");
            Assert.True(sessionReestablished, "B should re-establish the session after A's re-handshake");

            // 核心优化目标：会话在 UdpDeadLinkTimeout(2s) + 握手往返量级内重建，而非等待 150s 上层超时
            Assert.True(reestablishedAt!.Value - bResetAt < TimeSpan.FromSeconds(8),
                $"Session should re-establish quickly, took {(reestablishedAt.Value - bResetAt).TotalSeconds:F1}s");

            // 端到端：B 重建会话后，A 的数据包应能经 DERP 路径解密并出现在 B 的 TUN 上
            mockA.EnqueueReceivedPacket(payload);
            mockB.ClearSentPackets();
            var rxDeadline = DateTime.UtcNow + TimeSpan.FromSeconds(5);
            while (DateTime.UtcNow < rxDeadline && mockB.GetSentPackets().Length == 0)
            {
                await Task.Delay(100);
            }
            Assert.True(mockB.GetSentPackets().Length > 0, "A's data packets should be decrypted on B's TUN after recovery");
        }
        finally
        {
            deviceA.Stop();
            deviceB.Stop();
        }
    }
}
