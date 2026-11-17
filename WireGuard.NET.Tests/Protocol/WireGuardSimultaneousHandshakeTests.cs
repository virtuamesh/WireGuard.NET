using System.Collections.Concurrent;
using System.Net;
using WireGuard.NET.Crypto;
using WireGuard.NET.Protocol;
using WireGuard.NET.Tun;
using Xunit;

namespace WireGuard.NET.Tests.Protocol;

/// <summary>
/// Regression test for simultaneous handshake convergence: when both sides initiate at once, the tie-break winner must ignore the peer initiation and the loser must yield so both converge on a single session without replay attack storms.
/// </summary>
public class WireGuardSimultaneousHandshakeTests
{
    private static byte[] MakeIPv4Packet(byte dstLastOctet, byte tag)
    {
        var packet = new byte[28];
        packet[0] = 0x45;
        // [FIX] IPv4 TotalLength 必须与缓冲区长度一致：设备层 TUN 写入前的畸形包校验
        // 会丢弃 TotalLength 与实际长度不一致的包
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
            await Task.Delay(50);
        }
        var dumpA = string.Join("\n", logsA.Reverse().Take(60));
        var dumpB = string.Join("\n", logsB.Reverse().Take(60));
        throw new Xunit.Sdk.XunitException($"Timed out waiting for: {what}\n--- deviceA logs ---\n{dumpA}\n--- deviceB logs ---\n{dumpB}");
    }

    /// <summary>
    /// Verifies that simultaneous initiations converge to one established session with bidirectional data and no replay attack logs, retrying up to four rounds when the race is not hit.
    /// </summary>
    [Fact]
    public async Task SimultaneousInitiations_ShouldConvergeToSingleSessionWithBidirectionalData()
    {
        var simultaneousSeen = false;

        // 多轮循环：同时握手依赖双方在对方 initiation 到达前完成 pending 注册，
        // 线程调度毫秒级抖动可能使个别轮次退化为普通握手，故跑多轮直到命中一次。
        for (var round = 0; round < 4; round++)
        {
            var portA = 39401 + round * 10;
            var portB = portA + 1;

            var privA = X25519Crypto.GeneratePrivateKey();
            var pubA = X25519Crypto.GeneratePublicKey(privA);
            var privB = X25519Crypto.GeneratePrivateKey();
            var pubB = X25519Crypto.GeneratePublicKey(privB);
            var aWins = pubA.AsSpan().SequenceCompareTo(pubB) > 0;

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
                        Endpoint = new IPEndPoint(IPAddress.Loopback, portB),
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

            var logsA = new ConcurrentQueue<string>();
            var logsB = new ConcurrentQueue<string>();
            deviceA.OnLog += (_, log) => logsA.Enqueue($"[{log.Level}] {log.Message}");
            deviceB.OnLog += (_, log) => logsB.Enqueue($"[{log.Level}] {log.Message}");

            var tcsAtoB = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var tcsBtoA = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            deviceB.OnPacketReceived += (_, packet) =>
            {
                if (packet.Length > 24 && packet[24] == 0x01) tcsAtoB.TrySetResult();
            };
            deviceA.OnPacketReceived += (_, packet) =>
            {
                if (packet.Length > 24 && packet[24] == 0x02) tcsBtoA.TrySetResult();
            };

            await deviceA.StartAsync();
            await deviceB.StartAsync();

            // 双方并发 InjectPacketToPeerAsync（无 transport → 触发握手 initiation），
            // 各自的 pending 注册为同步路径，构造"同时握手"场景。
            var injectA = deviceA.InjectPacketToPeerAsync(pubB, MakeIPv4Packet(2, 0x01));
            var injectB = deviceB.InjectPacketToPeerAsync(pubA, MakeIPv4Packet(1, 0x02));
            await Task.WhenAll(injectA, injectB);

            await WaitForAsync(() =>
                    deviceA.GetPeer(pubB)?.IsEstablished == true &&
                    deviceB.GetPeer(pubA)?.IsEstablished == true,
                TimeSpan.FromSeconds(10), "simultaneous handshake convergence", logsA, logsB);

            // 双向数据互通 = 双向都通过 replay 窗口与 counter 校验（旧逻辑在此双向全灭）
            tunA.EnqueueReceivedPacket(MakeIPv4Packet(2, 0x01));
            tunB.EnqueueReceivedPacket(MakeIPv4Packet(1, 0x02));

            await WaitForAsync(() => tcsAtoB.Task.IsCompleted && tcsBtoA.Task.IsCompleted,
                TimeSpan.FromSeconds(10), "bidirectional data after simultaneous handshake", logsA, logsB);

            // 建立后再等 3 秒：旧 bug 的握手风暴表现为持续 "Replay attack detected" WRN
            await Task.Delay(3000);
            foreach (var logs in new[] { logsA, logsB })
            {
                var replayLogs = logs.Where(l => l.Contains("Replay attack")).ToList();
                Assert.True(replayLogs.Count == 0,
                    $"Round {round}: replay attack logs after convergence!\n{string.Join("\n", replayLogs)}");
            }

            // 收敛角色断言：命中同时握手的那一轮，获胜方必须 ignore，退让方必须 yield
            var winnerLogs = aWins ? logsA : logsB;
            var loserLogs = aWins ? logsB : logsA;
            if (winnerLogs.Any(l => l.Contains("ignoring peer's initiation")))
            {
                simultaneousSeen = true;
                Assert.True(
                    loserLogs.Any(l => l.Contains("yielded to peer's initiation")),
                    $"Round {round}: winner ignored peer initiation but loser did not yield (tie-break roles inconsistent).\n" +
                    $"aWins={aWins}\n--- loser logs ---\n{string.Join("\n", loserLogs.Reverse().Take(40))}");
            }

            deviceA.Stop();
            deviceB.Stop();
        }

        Assert.True(simultaneousSeen,
            "None of 4 rounds hit the simultaneous handshake path (no 'ignoring peer's initiation' log) - test cannot verify tie-break convergence");
    }
}
