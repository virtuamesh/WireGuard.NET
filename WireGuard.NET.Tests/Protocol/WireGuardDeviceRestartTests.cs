using System.Collections.Concurrent;
using System.Net;
using WireGuard.NET.Crypto;
using WireGuard.NET.Protocol;
using WireGuard.NET.Tun;
using Xunit;

namespace WireGuard.NET.Tests.Protocol;

/// <summary>
/// Regression test ensuring that stopping and restarting the same WireGuardDevice instance recreates its TUN and UDP packet channels so packet delivery keeps working after restart.
/// </summary>
public class WireGuardDeviceRestartTests
{
    private static readonly (byte[] privA, byte[] pubA, byte[] privB, byte[] pubB) Keys = GenerateKeys();

    private static (byte[], byte[], byte[], byte[]) GenerateKeys()
    {
        var privA = X25519Crypto.GeneratePrivateKey();
        var privB = X25519Crypto.GeneratePrivateKey();
        return (privA, X25519Crypto.GeneratePublicKey(privA), privB, X25519Crypto.GeneratePublicKey(privB));
    }

    private static byte[] MakeIPv4Packet(byte dstLastOctet, byte tag)
    {
        var packet = new byte[28];
        packet[0] = 0x45;
        // [FIX] IPv4 TotalLength 必须与缓冲区长度一致：设备层 TUN 写入前的畸形包校验
        // 会丢弃 TotalLength 与实际长度不一致的包（此前未填该字段导致 phase 1/2 数据
        // 投递全部被静默丢弃、测试超时）
        packet[2] = (byte)(packet.Length >> 8);
        packet[3] = (byte)(packet.Length & 0xFF);
        packet[16] = 10; packet[17] = 99; packet[18] = 0; packet[19] = dstLastOctet;
        packet[24] = tag;
        return packet;
    }

    private static async Task WaitForAsync(Func<bool> condition, TimeSpan timeout, string what,
        ConcurrentQueue<string> logsA, ConcurrentQueue<string> logsB)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            if (condition()) return;
            await Task.Delay(100);
        }
        if (!condition())
        {
            var dumpA = string.Join("\n", logsA.Reverse().Take(40));
            var dumpB = string.Join("\n", logsB.Reverse().Take(40));
            throw new Xunit.Sdk.XunitException(
                $"Timed out waiting for: {what}\n--- deviceA logs ---\n{dumpA}\n--- deviceB logs ---\n{dumpB}");
        }
    }

    /// <summary>
    /// Verifies that after Stop followed by StartAsync on the same instance, handshakes, inbound data delivery, and the TUN send path still work.
    /// </summary>
    [Fact]
    public async Task StopThenStart_SameInstance_ShouldStillExchangePackets()
    {
        var (privA, pubA, privB, pubB) = Keys;
        const int portA = 39181;
        const int portB = 39182;

        var receivedByA = new ConcurrentBag<byte>();
        var tcsPhase1 = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var tcsPhase2 = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        var configA = new WireGuardConfig
        {
            PrivateKey = privA,
            ListenPort = portA,
            Address = IPAddress.Parse("10.99.0.1"),
            AddressPrefixLength = 24,
            Peers =
            [
                new PeerConfig
                {
                    PublicKey = pubB,
                    AllowedIPs = [new WireGuard.NET.Protocol.IPNetwork { Address = IPAddress.Parse("10.99.0.2"), PrefixLength = 32 }]
                }
            ]
        };

        var configB = new WireGuardConfig
        {
            PrivateKey = privB,
            ListenPort = portB,
            Address = IPAddress.Parse("10.99.0.2"),
            AddressPrefixLength = 24,
            Peers =
            [
                new PeerConfig
                {
                    PublicKey = pubA,
                    Endpoint = new IPEndPoint(IPAddress.Loopback, portA),
                    AllowedIPs = [new WireGuard.NET.Protocol.IPNetwork { Address = IPAddress.Parse("10.99.0.1"), PrefixLength = 32 }]
                }
            ]
        };

        using var deviceA = new WireGuardDevice(configA, useMockTunDevice: true);
        using var deviceB = new WireGuardDevice(configB, useMockTunDevice: true);
        var tunA = new MockTunDevice();
        var tunB = new MockTunDevice();
        deviceA.SetTunDevice(tunA);
        deviceB.SetTunDevice(tunB);

        // TEMP 诊断：采集两端设备日志，超时断言时输出
        var logsA = new ConcurrentQueue<string>();
        var logsB = new ConcurrentQueue<string>();
        deviceA.OnLog += (_, log) => logsA.Enqueue($"{DateTime.UtcNow:HH:mm:ss.fff} [{log.Level}] {log.Message}");
        deviceB.OnLog += (_, log) => logsB.Enqueue($"{DateTime.UtcNow:HH:mm:ss.fff} [{log.Level}] {log.Message}");

        deviceA.OnPacketReceived += (_, packet) =>
        {
            if (packet.Length > 0)
            {
                receivedByA.Add(packet[24]);
                if (packet[24] == 0x01) tcsPhase1.TrySetResult();
                if (packet[24] == 0x02) tcsPhase2.TrySetResult();
            }
        };

        // ---- Phase 1：正常启动，B 主动向 A 发起握手并传数据 ----
        await deviceA.StartAsync();
        await deviceB.StartAsync();

        await WaitForAsync(() => deviceB.GetPeer(pubA)?.IsEstablished == true,
            TimeSpan.FromSeconds(10), "phase 1 handshake B->A", logsA, logsB);

        tunB.EnqueueReceivedPacket(MakeIPv4Packet(1, 0x01));
        await WaitForAsync(() => tcsPhase1.Task.IsCompleted, TimeSpan.FromSeconds(10), "phase 1 data delivery", logsA, logsB);
        Assert.Contains((byte)0x01, receivedByA);

        // ---- Phase 2：同实例 Stop→Start，然后验证握手与数据收发仍然工作 ----
        deviceA.Stop();
        await deviceA.StartAsync();

        // B 侧旧会话对重启后的 A 已无意义，重置后触发新握手
        deviceB.ResetPeerSession(pubA);
        _ = deviceB.InjectPacketToPeerAsync(pubA, MakeIPv4Packet(1, 0x03));

        await WaitForAsync(() => deviceA.GetPeer(pubB)?.IsEstablished == true,
            TimeSpan.FromSeconds(15), "phase 2 handshake with restarted A", logsA, logsB);

        // 数据路径：B 的 TUN → 加密 → UDP → A 的 UDP channel → 解密 → OnPacketReceived
        tunB.EnqueueReceivedPacket(MakeIPv4Packet(1, 0x02));
        await WaitForAsync(() => tcsPhase2.Task.IsCompleted, TimeSpan.FromSeconds(10), "phase 2 data delivery after restart", logsA, logsB);
        Assert.Contains((byte)0x02, receivedByA);

        // TUN 读路径在 A 重启后也必须存活：A 的 TUN 注入包应被加密并发往 B（TxBytes 增长）
        var txBefore = deviceA.GetPeer(pubB)?.TxBytes ?? 0;
        tunA.EnqueueReceivedPacket(MakeIPv4Packet(2, 0x04));
        await WaitForAsync(() => (deviceA.GetPeer(pubB)?.TxBytes ?? 0) > txBefore,
            TimeSpan.FromSeconds(10), "phase 2 TUN read path after restart", logsA, logsB);
    }
}
