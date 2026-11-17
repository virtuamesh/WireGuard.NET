using System.Reflection;
using WireGuard.NET.Crypto;
using WireGuard.NET.Protocol;
using WireGuard.NET.Tun;
using Xunit;

namespace WireGuard.NET.Tests.Protocol;

/// <summary>
/// Regression test for zombie peers claiming the same /32 route (2026-10-09): when two peers match the same prefix, traffic must go to the peer with an established session and transport instead of an unhandshaken zombie peer.
/// </summary>
public class WireGuardDeviceRouteTieBreakTests
{
    private static WireGuardPeer? GetPeer(object device, byte[] publicKey)
    {
        var field = device.GetType().GetField("_peers", BindingFlags.NonPublic | BindingFlags.Instance)
            ?? throw new InvalidOperationException("_peers field not found");
        var dict = (System.Collections.Concurrent.ConcurrentDictionary<byte[], WireGuardPeer>)field.GetValue(device)!;
        return dict.TryGetValue(publicKey, out var p) ? p : null;
    }

    /// <summary>
    /// Verifies that a packet destined for an address claimed by both a live peer and a zombie peer is routed to the established peer.
    /// </summary>
    [Fact]
    public async Task SamePrefixPeers_TrafficShouldGoToEstablishedPeerNotZombie()
    {
        var privA = X25519Crypto.GeneratePrivateKey();
        var pubA = X25519Crypto.GeneratePublicKey(privA);
        var privB = X25519Crypto.GeneratePrivateKey();
        var pubB = X25519Crypto.GeneratePublicKey(privB);
        var privZ = X25519Crypto.GeneratePrivateKey();
        var pubZ = X25519Crypto.GeneratePublicKey(privZ);

        var mockA = new MockTunDevice();
        var mockB = new MockTunDevice();

        // 设备 A：僵尸 peerZ（回环无监听端口、永不握手成功）与真 peerB（回环可达、会话可建立）
        // 认领同一 /32（10.99.3.2）。僵尸放在配置前面，最大化复刻"字典迭代先命中僵尸"的现场。
        var configA = new WireGuardConfig
        {
            PrivateKey = privA,
            ListenPort = 40111,
            Address = System.Net.IPAddress.Parse("10.99.3.1"),
            AddressPrefixLength = 24,
            Peers =
            [
                new PeerConfig
                {
                    PublicKey = pubZ,
                    Endpoint = new System.Net.IPEndPoint(System.Net.IPAddress.Loopback, 40113),
                    AllowedIPs = [new WireGuard.NET.Protocol.IPNetwork { Address = System.Net.IPAddress.Parse("10.99.3.2"), PrefixLength = 32 }]
                },
                new PeerConfig
                {
                    PublicKey = pubB,
                    Endpoint = new System.Net.IPEndPoint(System.Net.IPAddress.Loopback, 40112),
                    AllowedIPs = [new WireGuard.NET.Protocol.IPNetwork { Address = System.Net.IPAddress.Parse("10.99.3.2"), PrefixLength = 32 }]
                }
            ]
        };
        var configB = new WireGuardConfig
        {
            PrivateKey = privB,
            ListenPort = 40112,
            Address = System.Net.IPAddress.Parse("10.99.3.2"),
            AddressPrefixLength = 24,
            Peers =
            [
                new PeerConfig
                {
                    PublicKey = pubA,
                    AllowedIPs = [new WireGuard.NET.Protocol.IPNetwork { Address = System.Net.IPAddress.Parse("10.99.3.1"), PrefixLength = 32 }]
                }
            ]
        };

        using var deviceA = new WireGuardDevice(configA, useMockTunDevice: true);
        using var deviceB = new WireGuardDevice(configB, useMockTunDevice: true);
        deviceA.SetTunDevice(mockA);
        deviceB.SetTunDevice(mockB);

        await deviceA.StartAsync();
        await deviceB.StartAsync();

        try
        {
            // 等待 A-B 经 UDP 直连建立会话（僵尸 peerZ 同期持续向死端口发 initiation，永不建立）
            var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(10);
            while (DateTime.UtcNow < deadline)
            {
                var p = GetPeer(deviceA, pubB);
                if (p is { IsEstablished: true, HasTransport: true })
                {
                    break;
                }
                await Task.Delay(100);
            }
            Assert.True(GetPeer(deviceA, pubB) is { IsEstablished: true, HasTransport: true },
                "A->B handshake should establish");

            mockB.ClearSentPackets();

            // 模拟本机发出的 ping（合法 IPv4 头，dst=10.99.3.2 命中两个 peer 的同前缀 AllowedIPs）
            var payload = new byte[52];
            payload[0] = 0x45; // IPv4, IHL=5
            payload[2] = 0x00; payload[3] = 52; // total length
            payload[8] = 64;   // TTL
            payload[9] = 1;    // protocol = ICMP
            payload[12] = 10; payload[13] = 99; payload[14] = 3; payload[15] = 1; // src
            payload[16] = 10; payload[17] = 99; payload[18] = 3; payload[19] = 2; // dst
            mockA.EnqueueReceivedPacket(payload);

            // 断言：数据包必须到达健康的 peerB（B 的 mock TUN 收到解密后明文），
            // 而不是被路由给从未握手的僵尸 peerZ（修复前可能因字典迭代顺序输给僵尸）。
            var received = false;
            var recvDeadline = DateTime.UtcNow + TimeSpan.FromSeconds(5);
            while (DateTime.UtcNow < recvDeadline)
            {
                if (mockB.GetSentPackets().Any(p => p.AsSpan().SequenceEqual(payload)))
                {
                    received = true;
                    break;
                }
                await Task.Delay(50);
            }
            Assert.True(received,
                "packet should be routed to the established peer, not the zombie claiming the same /32");
        }
        finally
        {
            deviceA.Stop();
            deviceB.Stop();
        }
    }
}
