using System.IO.Compression;

namespace WireGuard.NET.Compression;

/// <summary>
/// Packet compressor implementation based on <see cref="System.IO.Compression"/>.
/// Frame format: [1-byte flag: 0x00 = uncompressed, 0x01 = compressed][data].
/// </summary>
public class PacketCompressor : IPacketCompressor
{
    /// <summary>
    /// Only packets larger than this threshold are compressed. Small packets gain little
    /// from compression and may even grow.
    /// </summary>
    public const int CompressionThreshold = 256;

    /// <summary>Flag byte: payload is uncompressed.</summary>
    public const byte FlagUncompressed = 0x00;

    /// <summary>Flag byte: payload is compressed.</summary>
    public const byte FlagCompressed = 0x01;

    /// <summary>
    /// The maximum allowed decompressed size (64 KiB). A single TUN packet is at most
    /// ~64 KB; anything above this limit is treated as a compression bomb or corrupted
    /// data and dropped (<see cref="Decompress"/> returns null).
    /// </summary>
    public const int MaxDecompressedSize = 64 * 1024;

    private long _totalPackets;
    private long _compressedPackets;
    private long _bytesSaved;

    /// <summary>
    /// The total number of packets processed (only packets above the threshold,
    /// i.e. those for which compression was attempted, are counted).
    /// </summary>
    public long TotalPackets => Interlocked.Read(ref _totalPackets);

    /// <summary>
    /// The number of packets that were actually compressed.
    /// </summary>
    public long CompressedPackets => Interlocked.Read(ref _compressedPackets);

    /// <summary>
    /// The number of bytes saved through compression (original size minus compressed
    /// size, including the 1-byte flag overhead).
    /// </summary>
    public long BytesSaved => Interlocked.Read(ref _bytesSaved);

    /// <summary>
    /// Gets or sets a value indicating whether compression is enabled.
    /// </summary>
    public bool IsEnabled { get; set; } = true;

    /// <summary>
    /// Compresses the specified data using Deflate at the fastest level. Returns
    /// <c>null</c> when compression is disabled, the input is empty or not larger than
    /// <see cref="CompressionThreshold"/>, compression fails, or the compressed output
    /// (including the 1-byte flag overhead) would not be smaller than the original.
    /// </summary>
    /// <param name="data">The plaintext packet payload to compress.</param>
    /// <returns>The framed payload [0x01][compressed data], or <c>null</c> when no compression was applied.</returns>
    /// <remarks>Updates the <see cref="TotalPackets"/>, <see cref="CompressedPackets"/>, and <see cref="BytesSaved"/> counters; safe to call from multiple threads.</remarks>
    public byte[]? Compress(byte[] data)
    {
        if (!IsEnabled || data == null || data.Length == 0)
        {
            return null;
        }

        // Only compress packets larger than the threshold
        if (data.Length <= CompressionThreshold)
        {
            return null;
        }

        Interlocked.Increment(ref _totalPackets);

        byte[] compressed;
        try
        {
            compressed = Deflate(data, CompressionLevel.Fastest);
        }
        catch (Exception)
        {
            // Compression failed; treat as uncompressed
            return null;
        }

        // Compressed output is not smaller than the original (including the 1-byte flag overhead); skip compression
        if (compressed.Length + 1 >= data.Length)
        {
            return null;
        }

        Interlocked.Increment(ref _compressedPackets);
        Interlocked.Add(ref _bytesSaved, data.Length - (compressed.Length + 1));

        // Frame format: [0x01][compressed data]
        var result = new byte[1 + compressed.Length];
        result[0] = FlagCompressed;
        Buffer.BlockCopy(compressed, 0, result, 1, compressed.Length);
        return result;
    }

    /// <summary>
    /// Decompresses the specified data. The leading flag byte determines whether the
    /// payload needs to be inflated. Returns <c>null</c> when the data is not compressed
    /// (the first byte is neither the 0x01 nor the 0x00 flag).
    /// Note: this method deliberately does NOT check <see cref="IsEnabled"/> — IsEnabled
    /// only controls whether the local end actively compresses its own outgoing traffic,
    /// while decompression is driven purely by the self-describing flag byte: the remote
    /// peer (which may run a different platform/version/configuration) is free to compress
    /// its outgoing traffic, so the local end must always be able to decompress it. If
    /// this method were gated on IsEnabled, a protocol asymmetry would cause compressed
    /// frames to be written to TUN as if they were IP packets, which the kernel rejects
    /// with EINVAL → all TCP data silently dropped (root cause of the 2026-10-15
    /// production RDP failure (0x7) / SSH disconnects: the Linux-side
    /// WireGuardNETService had compression enabled while the Android-side
    /// AndroidWireGuardService did not override the empty EnablePacketCompression
    /// implementation, so received [0x01] frames went into TUN verbatim).
    /// </summary>
    /// <param name="data">The received payload, possibly prefixed with a compression flag byte.</param>
    /// <returns>The decompressed plaintext payload, <c>null</c> when the input does not carry a compression flag, or <c>null</c> when the payload would exceed <see cref="MaxDecompressedSize"/> or fails to inflate (the packet is dropped).</returns>
    public byte[]? Decompress(byte[] data)
    {
        if (data == null || data.Length == 0)
        {
            return null;
        }

        var flag = data[0];
        if (flag == FlagCompressed)
        {
            try
            {
                var payload = new byte[data.Length - 1];
                Buffer.BlockCopy(data, 1, payload, 0, payload.Length);
                // Returns null (packet dropped) when the decompressed size exceeds MaxDecompressedSize
                return Inflate(payload);
            }
            catch (Exception)
            {
                // Decompression failed: the data may be corrupted or not actually compressed
                return null;
            }
        }

        if (flag == FlagUncompressed)
        {
            // Frame format [0x00][raw data]; strip the flag byte
            var payload = new byte[data.Length - 1];
            Buffer.BlockCopy(data, 1, payload, 0, payload.Length);
            return payload;
        }

        // First byte is not a flag (e.g. IP packets start with 0x40/0x60): raw uncompressed packet
        return null;
    }

    private static byte[] Deflate(byte[] data, CompressionLevel level)
    {
        using var output = new MemoryStream(data.Length);
        using (var deflate = new DeflateStream(output, level, leaveOpen: true))
        {
            deflate.Write(data, 0, data.Length);
        }

        return output.ToArray();
    }

    private static byte[]? Inflate(byte[] data)
    {
        using var input = new MemoryStream(data);
        using var deflate = new DeflateStream(input, CompressionMode.Decompress);
        using var output = new MemoryStream(Math.Min(data.Length * 2, MaxDecompressedSize));

        var buffer = new byte[8192];
        var total = 0;
        int read;
        while ((read = deflate.Read(buffer, 0, buffer.Length)) > 0)
        {
            total += read;
            if (total > MaxDecompressedSize)
            {
                // Compression-bomb protection: decompressed size exceeds the limit, drop the packet
                return null;
            }
            output.Write(buffer, 0, read);
        }

        return output.ToArray();
    }
}
