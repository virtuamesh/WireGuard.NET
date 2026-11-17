namespace WireGuard.NET.Compression;

/// <summary>
/// Packet compressor contract for the WireGuard data path. Compression is applied after
/// an IP packet is read from the TUN layer and before it is encrypted by WireGuard;
/// decompression is applied after decryption and before the packet is written to TUN.
/// </summary>
public interface IPacketCompressor
{
    /// <summary>
    /// Compresses the specified data. Returns <c>null</c> to indicate that the data should
    /// not be compressed (it is too small, or compression would not shrink it).
    /// The returned array already includes the 1-byte flag prefix.
    /// </summary>
    /// <param name="data">The plaintext packet payload to compress.</param>
    /// <returns>The compressed framed payload (flag byte + compressed data), or <c>null</c> when compression was not applied.</returns>
    byte[]? Compress(byte[] data);

    /// <summary>
    /// Decompresses the specified data. The leading flag byte determines whether the
    /// payload needs to be inflated. Returns <c>null</c> when the data is not compressed
    /// (the first byte is neither the 0x01 nor the 0x00 flag).
    /// </summary>
    /// <param name="data">The received payload, possibly prefixed with a compression flag byte.</param>
    /// <returns>The decompressed plaintext payload, or <c>null</c> when the input does not carry a compression flag.</returns>
    byte[]? Decompress(byte[] data);

    /// <summary>
    /// Gets or sets a value indicating whether compression is enabled.
    /// </summary>
    bool IsEnabled { get; set; }
}
