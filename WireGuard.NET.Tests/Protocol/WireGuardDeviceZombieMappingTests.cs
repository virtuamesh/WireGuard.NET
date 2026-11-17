using System.Reflection;
using WireGuard.NET.Crypto;
using WireGuard.NET.Protocol;
using Xunit;

namespace WireGuard.NET.Tests.Protocol;

/// <summary>
/// Regression test for stale pending index mappings after a handshake timeout (2026-10-08): the device must remove incomplete index-to-peer mappings when a handshake times out so later re-handshakes are not blocked.
/// </summary>
public class WireGuardDeviceZombieMappingTests
{
    private static readonly (byte[] privA, byte[] pubA, byte[] privB, byte[] pubB) Keys = GenerateKeys();

    private static (byte[], byte[], byte[], byte[]) GenerateKeys()
    {
        var privA = X25519Crypto.GeneratePrivateKey();
        var privB = X25519Crypto.GeneratePrivateKey();
        return (privA, X25519Crypto.GeneratePublicKey(privA), privB, X25519Crypto.GeneratePublicKey(privB));
    }

    private static IReadOnlyList<object> GetPeerMappings(object device)
    {
        var field = device.GetType().GetField("_indexToPeer", BindingFlags.NonPublic | BindingFlags.Instance)
            ?? throw new InvalidOperationException("_indexToPeer field not found");
        var dict = field.GetValue(device) as System.Collections.IDictionary
            ?? throw new InvalidOperationException("_indexToPeer is not IDictionary");
        var result = new List<object>();
        foreach (var value in dict.Values)
        {
            result.Add(value);
        }
        return result;
    }

    private static bool IsIncompleteMappingFor(object mapping, byte[] peerPublicKey)
    {
        var type = mapping.GetType();
        var isCompleted = (bool)(type.GetProperty("IsCompleted")?.GetValue(mapping) ?? throw new InvalidOperationException("IsCompleted not found"));
        var peerKey = (byte[])(type.GetProperty("PeerPublicKey")?.GetValue(mapping) ?? throw new InvalidOperationException("PeerPublicKey not found"));
        return !isCompleted && peerKey.AsSpan().SequenceEqual(peerPublicKey);
    }

    /// <summary>
    /// Verifies that an incomplete pending index mapping is removed after the handshake timeout callback runs.
    /// </summary>
    [Fact]
    public async Task HandshakeTimedOut_ShouldRemoveZombiePendingIndexMapping()
    {
        var (privA, pubA, privB, pubB) = Keys;

        // 对端端点指向无监听的回环端口：initiation 发出后永远收不到 response，
        // 复现"握手 pending 挂起"的现场（不必等待 90s 真实超时，直接触发回调）。
        var configA = new WireGuardConfig
        {
            PrivateKey = privA,
            ListenPort = 39291,
            Address = System.Net.IPAddress.Parse("10.99.1.1"),
            AddressPrefixLength = 24,
            Peers =
            [
                new PeerConfig
                {
                    PublicKey = pubB,
                    Endpoint = new System.Net.IPEndPoint(System.Net.IPAddress.Loopback, 39292),
                    AllowedIPs = [new WireGuard.NET.Protocol.IPNetwork { Address = System.Net.IPAddress.Parse("10.99.1.2"), PrefixLength = 32 }]
                }
            ]
        };

        using var deviceA = new WireGuardDevice(configA, useMockTunDevice: true);
        await deviceA.StartAsync();
        try
        {
            // 等待 initiation 落入索引映射（StartAsync 同步发起，通常立即出现）
            IReadOnlyList<object> mappings = GetPeerMappings(deviceA);
            var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(5);
            while (DateTime.UtcNow < deadline && !mappings.Any(m => IsIncompleteMappingFor(m, pubB)))
            {
                await Task.Delay(100);
                mappings = GetPeerMappings(deviceA);
            }
            Assert.True(mappings.Any(m => IsIncompleteMappingFor(m, pubB)),
                "expected an incomplete (pending) index mapping for pubB after handshake initiation");

            // 模拟 HandshakeManager 超时路径：先移除 pending（生产代码超时时先移除再触发事件），
            // 再触发设备的 OnHandshakeTimedOut。
            var managerField = deviceA.GetType().GetField("_handshakeManager", BindingFlags.NonPublic | BindingFlags.Instance)
                ?? throw new InvalidOperationException("_handshakeManager field not found");
            var manager = managerField.GetValue(deviceA)!;
            manager.GetType().GetMethod("ClearHandshake")!.Invoke(manager, new object?[] { pubB });

            var onTimedOut = deviceA.GetType().GetMethod("OnHandshakeTimedOut", BindingFlags.NonPublic | BindingFlags.Instance)
                ?? throw new InvalidOperationException("OnHandshakeTimedOut method not found");
            onTimedOut.Invoke(deviceA, new object?[] { null, pubB });

            // 断言：僵尸 incomplete 映射已被清理（修复前会滞留最长 5 分钟并阻塞重握手）
            mappings = GetPeerMappings(deviceA);
            Assert.DoesNotContain(mappings, m => IsIncompleteMappingFor(m, pubB));
        }
        finally
        {
            deviceA.Stop();
        }
    }
}
