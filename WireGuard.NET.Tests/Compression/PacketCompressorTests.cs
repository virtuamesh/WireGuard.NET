using WireGuard.NET.Compression;
using Xunit;

namespace WireGuard.NET.Tests.Compression;

/// <summary>
/// Tests for the packet compressor, covering compression round trips, frame flag handling, plain IP packet pass-through, and decompressed-size limits.
/// </summary>
public class PacketCompressorTests
{
    /// <summary>
    /// Verifies that compressible data survives a compress/decompress round trip unchanged.
    /// </summary>
    [Fact]
    public void CompressDecompress_ShouldRoundTrip()
    {
        var compressor = new PacketCompressor();
        var data = new byte[2000];
        new Random(42).NextBytes(data);
        // 制造可压缩内容
        for (int i = 0; i < data.Length; i++) data[i] = (byte)(i % 7);

        var compressed = compressor.Compress(data);
        Assert.NotNull(compressed);

        var decompressed = compressor.Decompress(compressed);
        Assert.NotNull(decompressed);
        Assert.Equal(data, decompressed);
    }

    /// <summary>
    /// Verifies that a receiver with IsEnabled false can still decompress frames produced by a peer that enabled compression.
    /// </summary>
    [Fact]
    public void Decompress_WhenIsEnabledFalse_ShouldStillDecompress()
    {
        // [FIX 2026-10-15 回归] 解压能力不得 gate IsEnabled：对端（如 Linux WireGuardNETService）
        // 可能启用压缩而本端（如未 override EnablePacketCompression 的 Android 服务）
        // IsEnabled=false，此时必须仍能解压，否则 [0x01] 帧会被当 IP 包写 TUN →
        // 内核 EINVAL → ubuntuserver24→Android 方向 TCP 数据全丢（线上 RDP 0x7 / SSH 断连根因）。
        var sender = new PacketCompressor { IsEnabled = true };
        var data = new byte[2000];
        for (int i = 0; i < data.Length; i++) data[i] = (byte)(i % 7);
        var compressed = sender.Compress(data);
        Assert.NotNull(compressed);

        var receiver = new PacketCompressor { IsEnabled = false };
        var decompressed = receiver.Decompress(compressed);
        Assert.NotNull(decompressed);
        Assert.Equal(data, decompressed);
    }

    /// <summary>
    /// Verifies that plain IPv4 and IPv6 packets are not mistaken for compressed frames and return null.
    /// </summary>
    [Fact]
    public void Decompress_PlainIpPacket_ShouldReturnNull()
    {
        // 明文 IP 包（首字节 0x45=IPv4 / 0x60=IPv6）不是压缩帧，Decompress 必须返回 null，
        // 由调用方按原样写 TUN。
        var compressor = new PacketCompressor();
        var ipv4 = new byte[] { 0x45, 0x00, 0x05, 0xDC };
        Assert.Null(compressor.Decompress(ipv4));
        var ipv6 = new byte[] { 0x60, 0x00, 0x00, 0x00 };
        Assert.Null(compressor.Decompress(ipv6));
    }

    /// <summary>
    /// Verifies that an explicitly marked uncompressed frame is returned with its flag byte stripped.
    /// </summary>
    [Fact]
    public void Decompress_UncompressedFlag_ShouldStripFlag()
    {
        // [0x00] 前缀帧（发送方显式标记未压缩）必须剥离标志位还原数据。
        var compressor = new PacketCompressor();
        var payload = new byte[] { 0x45, 0x00, 0x00, 0x01 };
        var framed = new byte[] { PacketCompressor.FlagUncompressed, payload[0], payload[1], payload[2], payload[3] };
        var result = compressor.Decompress(framed);
        Assert.NotNull(result);
        Assert.Equal(payload, result);
    }

    /// <summary>
    /// Verifies that a highly compressible payload expanding past MaxDecompressedSize is rejected as a decompression bomb.
    /// </summary>
    [Fact]
    public void Decompress_BombExceedingMaxSize_ShouldReturnNull()
    {
        // 压缩炸弹防护：128KB 高可压缩数据压完很小，解压超过 64KB 上限必须丢弃
        var compressor = new PacketCompressor();
        var bomb = new byte[PacketCompressor.MaxDecompressedSize * 2]; // 128KB 全零

        var compressed = compressor.Compress(bomb);
        Assert.NotNull(compressed);
        Assert.True(compressed.Length < 4096, $"sanity: bomb compressed to {compressed.Length} bytes");

        var result = compressor.Decompress(compressed);
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that a payload exactly at MaxDecompressedSize round trips, skipping the check when compression yields no benefit.
    /// </summary>
    [Fact]
    public void Decompress_ExactlyAtLimit_ShouldSucceed()
    {
        var compressor = new PacketCompressor();
        // 刚好等于上限的数据（低压缩率内容，确保不是全零）
        var data = new byte[PacketCompressor.MaxDecompressedSize];
        for (int i = 0; i < data.Length; i++) data[i] = (byte)(i % 251);

        var compressed = compressor.Compress(data);
        if (compressed == null)
        {
            // 压缩无收益时 Compress 返回 null，属正常路径，不在本测试范围
            return;
        }

        var result = compressor.Decompress(compressed);
        Assert.NotNull(result);
        Assert.Equal(data, result);
    }
}
