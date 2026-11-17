using WireGuard.NET.Protocol;
using Xunit;

namespace WireGuard.NET.Tests.Protocol;

/// <summary>
/// Tests for the WireGuard transport data packet layer, covering header format, counters, replay protection, and encryption round trips.
/// </summary>
public class WireGuardTransportTests
{
    private static (byte[] keyA, byte[] keyB) GenerateKeyPair()
    {
        var keyA = new byte[32];
        var keyB = new byte[32];
        new Random(42).NextBytes(keyA);
        new Random(43).NextBytes(keyB);
        return (keyA, keyB);
    }

    /// <summary>
    /// Verifies that a transport packet encrypts and decrypts to the same plaintext with the receiver index preserved.
    /// </summary>
    [Fact]
    public void EncryptPacket_And_DecryptPacket_ShouldRoundTrip()
    {
        var (keyA, keyB) = GenerateKeyPair();
        var transportA = new WireGuardTransport(keyA, keyB);
        var transportB = new WireGuardTransport(keyB, keyA);
        var plaintext = System.Text.Encoding.UTF8.GetBytes("Hello, WireGuard Transport!");
        var receiverIndex = 12345u;

        var encrypted = transportA.EncryptPacket(plaintext, receiverIndex);
        var decrypted = transportB.DecryptPacket(encrypted, out var recvIndex);

        Assert.Equal(plaintext, decrypted);
        Assert.Equal(receiverIndex, recvIndex);
    }

    /// <summary>
    /// Verifies that the encrypted length equals the plaintext plus a 16-byte header and 16-byte tag.
    /// </summary>
    [Fact]
    public void EncryptPacket_ShouldAddHeaderAndTag()
    {
        var (keyA, keyB) = GenerateKeyPair();
        var transport = new WireGuardTransport(keyA, keyB);
        var plaintext = new byte[100];
        var receiverIndex = 12345u;

        var encrypted = transport.EncryptPacket(plaintext, receiverIndex);

        Assert.Equal(16 + 100 + 16, encrypted.Length);
    }

    /// <summary>
    /// Verifies that the transport packet header carries the data message type.
    /// </summary>
    [Fact]
    public void EncryptPacket_MessageTypeShouldBe4()
    {
        var (keyA, keyB) = GenerateKeyPair();
        var transport = new WireGuardTransport(keyA, keyB);
        var plaintext = new byte[50];
        var receiverIndex = 12345u;

        var encrypted = transport.EncryptPacket(plaintext, receiverIndex);

        var messageType = BitConverter.ToUInt32(encrypted, 0);
        Assert.Equal(WireGuardConstants.TYPE_DATA, messageType);
    }

    /// <summary>
    /// Verifies that the receiver index is written into the packet header.
    /// </summary>
    [Fact]
    public void EncryptPacket_ReceiverIndexShouldBeSet()
    {
        var (keyA, keyB) = GenerateKeyPair();
        var transport = new WireGuardTransport(keyA, keyB);
        var plaintext = new byte[50];
        var receiverIndex = 0xDEADBEEFu;

        var encrypted = transport.EncryptPacket(plaintext, receiverIndex);

        var recvIdx = BitConverter.ToUInt32(encrypted, 4);
        Assert.Equal(receiverIndex, recvIdx);
    }

    /// <summary>
    /// Verifies that each encrypted packet carries a counter incremented by one.
    /// </summary>
    [Fact]
    public void EncryptPacket_CounterShouldIncrement()
    {
        var (keyA, keyB) = GenerateKeyPair();
        var transport = new WireGuardTransport(keyA, keyB);
        var plaintext = new byte[50];
        var receiverIndex = 12345u;

        var encrypted1 = transport.EncryptPacket(plaintext, receiverIndex);
        var counter1 = BitConverter.ToUInt64(encrypted1, 8);

        var encrypted2 = transport.EncryptPacket(plaintext, receiverIndex);
        var counter2 = BitConverter.ToUInt64(encrypted2, 8);

        Assert.Equal(counter1 + 1, counter2);
    }

    /// <summary>
    /// Verifies that decryption with a mismatched key throws CryptographicException.
    /// </summary>
    [Fact]
    public void DecryptPacket_WithWrongKey_ShouldThrow()
    {
        var (keyA, keyB) = GenerateKeyPair();
        var wrongKey = new byte[32];
        var transportA = new WireGuardTransport(keyA, keyB);
        var transportB = new WireGuardTransport(keyB, wrongKey);
        var plaintext = System.Text.Encoding.UTF8.GetBytes("Test");
        var receiverIndex = 12345u;

        var encrypted = transportA.EncryptPacket(plaintext, receiverIndex);

        Assert.Throws<System.Security.Cryptography.CryptographicException>(() =>
            transportB.DecryptPacket(encrypted, out _));
    }

    /// <summary>
    /// Verifies that a packet shorter than the minimum length throws ArgumentException.
    /// </summary>
    [Fact]
    public void DecryptPacket_TooShort_ShouldThrow()
    {
        var (keyA, keyB) = GenerateKeyPair();
        var transport = new WireGuardTransport(keyA, keyB);

        Assert.Throws<ArgumentException>(() => transport.DecryptPacket(new byte[10], out _));
    }

    /// <summary>
    /// Verifies that decrypting the same valid packet twice throws InvalidOperationException.
    /// </summary>
    [Fact]
    public void DecryptPacket_ReplayAttack_ShouldThrow()
    {
        var (keyA, keyB) = GenerateKeyPair();
        var transportA = new WireGuardTransport(keyA, keyB);
        var transportB = new WireGuardTransport(keyB, keyA);
        var plaintext = new byte[50];
        var receiverIndex = 12345u;

        var encrypted = transportA.EncryptPacket(plaintext, receiverIndex);
        transportB.DecryptPacket(encrypted, out _);

        Assert.Throws<InvalidOperationException>(() => transportB.DecryptPacket(encrypted, out _));
    }

    /// <summary>
    /// Verifies that an empty plaintext, as used by keepalives, encrypts and decrypts successfully.
    /// </summary>
    [Fact]
    public void EncryptPacket_EmptyPlaintext_ShouldWork()
    {
        var (keyA, keyB) = GenerateKeyPair();
        var transportA = new WireGuardTransport(keyA, keyB);
        var transportB = new WireGuardTransport(keyB, keyA);
        var plaintext = Array.Empty<byte>();
        var receiverIndex = 12345u;

        var encrypted = transportA.EncryptPacket(plaintext, receiverIndex);
        var decrypted = transportB.DecryptPacket(encrypted, out var recvIndex);

        Assert.Equal(plaintext, decrypted);
        Assert.Equal(receiverIndex, recvIndex);
    }

    /// <summary>
    /// Verifies that the reported send counter starts at zero and increments after each encryption.
    /// </summary>
    [Fact]
    public void GetCurrentSendCounter_ShouldIncrement()
    {
        var (keyA, keyB) = GenerateKeyPair();
        var transport = new WireGuardTransport(keyA, keyB);
        var plaintext = new byte[10];
        var receiverIndex = 12345u;

        Assert.Equal(0ul, transport.GetCurrentSendCounter());

        transport.EncryptPacket(plaintext, receiverIndex);
        Assert.Equal(1ul, transport.GetCurrentSendCounter());

        transport.EncryptPacket(plaintext, receiverIndex);
        Assert.Equal(2ul, transport.GetCurrentSendCounter());
    }

    /// <summary>
    /// Verifies that constructing with a key that is not 32 bytes throws ArgumentException.
    /// </summary>
    [Fact]
    public void Constructor_InvalidKeySize_ShouldThrow()
    {
        Assert.Throws<ArgumentException>(() => new WireGuardTransport(new byte[16], new byte[32]));
        Assert.Throws<ArgumentException>(() => new WireGuardTransport(new byte[32], new byte[16]));
    }

    /// <summary>
    /// Verifies that a 1500-byte payload round trips correctly.
    /// </summary>
    [Fact]
    public void EncryptPacket_LargePayload_ShouldWork()
    {
        var (keyA, keyB) = GenerateKeyPair();
        var transportA = new WireGuardTransport(keyA, keyB);
        var transportB = new WireGuardTransport(keyB, keyA);
        var plaintext = new byte[1500];
        new Random(42).NextBytes(plaintext);
        var receiverIndex = 12345u;

        var encrypted = transportA.EncryptPacket(plaintext, receiverIndex);
        var decrypted = transportB.DecryptPacket(encrypted, out var recvIndex);

        Assert.Equal(plaintext, decrypted);
        Assert.Equal(receiverIndex, recvIndex);
    }

    /// <summary>
    /// Verifies that a forged packet with a huge counter fails authentication without advancing the replay window, so a valid packet still decrypts.
    /// </summary>
    [Fact]
    public void DecryptPacket_ForgedHugeCounter_ShouldNotPoisonReplayWindow()
    {
        // 对抗性回归：伪造大 counter 的包（AEAD 校验必然失败）不得提交重放窗口。
        // 修复前 ValidateCounter 先于解密执行，伪造 counter=2^40 会推高窗口，
        // 导致后续合法包（counter=0）被误判为重放而拒绝（远程 DoS）。
        var (keyA, keyB) = GenerateKeyPair();
        var transportA = new WireGuardTransport(keyA, keyB);
        var transportB = new WireGuardTransport(keyB, keyA);
        var plaintext = System.Text.Encoding.UTF8.GetBytes("legit");
        var receiverIndex = 12345u;

        var legitPacket = transportA.EncryptPacket(plaintext, receiverIndex);

        // 构造伪造包：合法包头 + 巨大 counter + 合法密文（tag 对不上 counter，解密必败）
        var forged = (byte[])legitPacket.Clone();
        BitConverter.GetBytes(1UL << 40).CopyTo(forged, 8);

        Assert.ThrowsAny<Exception>(() => transportB.DecryptPacket(forged, out _));

        // 合法包必须仍然被接受
        var decrypted = transportB.DecryptPacket(legitPacket, out _);
        Assert.Equal(plaintext, decrypted);
    }

    /// <summary>
    /// Verifies that a replayed packet that authenticates is still rejected by the replay window.
    /// </summary>
    [Fact]
    public void DecryptPacket_ReplayedValidPacket_ShouldBeRejectedAfterDecrypt()
    {
        // 重放的合法包（AEAD 可通过）仍必须被重放窗口拒绝
        var (keyA, keyB) = GenerateKeyPair();
        var transportA = new WireGuardTransport(keyA, keyB);
        var transportB = new WireGuardTransport(keyB, keyA);
        var plaintext = System.Text.Encoding.UTF8.GetBytes("hello");
        var receiverIndex = 12345u;

        var encrypted = transportA.EncryptPacket(plaintext, receiverIndex);

        var first = transportB.DecryptPacket(encrypted, out _);
        Assert.Equal(plaintext, first);

        Assert.Throws<InvalidOperationException>(() => transportB.DecryptPacket(encrypted, out _));
    }
}
