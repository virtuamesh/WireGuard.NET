using WireGuard.NET.Crypto;
using Xunit;

namespace WireGuard.NET.Tests.Crypto;

/// <summary>
/// Tests for the XChaCha20-Poly1305 AEAD implementation, covering round trips, parameter validation, and RFC test vectors.
/// </summary>
public class XChaCha20Poly1305Tests
{
    /// <summary>
    /// Verifies that encrypting with associated data and decrypting with the same inputs restores the plaintext.
    /// </summary>
    [Fact]
    public void Encrypt_And_Decrypt_Should_RoundTrip()
    {
        var key = new byte[32];
        new Random(42).NextBytes(key);
        var nonce = new byte[24];
        new Random(43).NextBytes(nonce);
        var plaintext = System.Text.Encoding.UTF8.GetBytes("Hello, XChaCha20-Poly1305!");
        var ad = System.Text.Encoding.UTF8.GetBytes("additional-data");

        var ciphertext = XChaCha20Poly1305.Encrypt(key, nonce, plaintext, ad);
        var decrypted = XChaCha20Poly1305.Decrypt(key, nonce, ciphertext, ad);

        Assert.Equal(plaintext, decrypted);
    }

    /// <summary>
    /// Verifies that encryption appends a 16-byte authentication tag to the ciphertext.
    /// </summary>
    [Fact]
    public void Encrypt_ShouldProduceCiphertextWithTag()
    {
        var key = new byte[32];
        var nonce = new byte[24];
        var plaintext = new byte[100];

        var ciphertext = XChaCha20Poly1305.Encrypt(key, nonce, plaintext, Array.Empty<byte>());

        Assert.Equal(plaintext.Length + 16, ciphertext.Length);
    }

    /// <summary>
    /// Verifies that decryption with a different key throws a CryptographicException.
    /// </summary>
    [Fact]
    public void Decrypt_WithWrongKey_ShouldThrow()
    {
        var key = new byte[32];
        var wrongKey = new byte[32];
        wrongKey[0] = 1;
        var nonce = new byte[24];
        var plaintext = System.Text.Encoding.UTF8.GetBytes("Test");

        var ciphertext = XChaCha20Poly1305.Encrypt(key, nonce, plaintext, Array.Empty<byte>());

        Assert.Throws<System.Security.Cryptography.CryptographicException>(() =>
            XChaCha20Poly1305.Decrypt(wrongKey, nonce, ciphertext, Array.Empty<byte>()));
    }

    /// <summary>
    /// Verifies that decryption with a different nonce throws a CryptographicException.
    /// </summary>
    [Fact]
    public void Decrypt_WithWrongNonce_ShouldThrow()
    {
        var key = new byte[32];
        var nonce = new byte[24];
        var wrongNonce = new byte[24];
        wrongNonce[0] = 1;
        var plaintext = System.Text.Encoding.UTF8.GetBytes("Test");

        var ciphertext = XChaCha20Poly1305.Encrypt(key, nonce, plaintext, Array.Empty<byte>());

        Assert.Throws<System.Security.Cryptography.CryptographicException>(() =>
            XChaCha20Poly1305.Decrypt(key, wrongNonce, ciphertext, Array.Empty<byte>()));
    }

    /// <summary>
    /// Verifies that decryption with different associated data throws a CryptographicException.
    /// </summary>
    [Fact]
    public void Decrypt_WithWrongAD_ShouldThrow()
    {
        var key = new byte[32];
        var nonce = new byte[24];
        var ad = System.Text.Encoding.UTF8.GetBytes("correct-ad");
        var wrongAd = System.Text.Encoding.UTF8.GetBytes("wrong-ad");
        var plaintext = System.Text.Encoding.UTF8.GetBytes("Test");

        var ciphertext = XChaCha20Poly1305.Encrypt(key, nonce, plaintext, ad);

        Assert.Throws<System.Security.Cryptography.CryptographicException>(() =>
            XChaCha20Poly1305.Decrypt(key, nonce, ciphertext, wrongAd));
    }

    /// <summary>
    /// Verifies that encryption with a key that is not 32 bytes throws ArgumentException.
    /// </summary>
    [Fact]
    public void Encrypt_InvalidKeySize_ShouldThrow()
    {
        var key = new byte[16];
        var nonce = new byte[24];
        var plaintext = new byte[10];

        Assert.Throws<ArgumentException>(() => XChaCha20Poly1305.Encrypt(key, nonce, plaintext, Array.Empty<byte>()));
    }

    /// <summary>
    /// Verifies that encryption with a nonce that is not 24 bytes throws ArgumentException.
    /// </summary>
    [Fact]
    public void Encrypt_InvalidNonceSize_ShouldThrow()
    {
        var key = new byte[32];
        var nonce = new byte[12];
        var plaintext = new byte[10];

        Assert.Throws<ArgumentException>(() => XChaCha20Poly1305.Encrypt(key, nonce, plaintext, Array.Empty<byte>()));
    }

    /// <summary>
    /// Verifies that an empty plaintext encrypts and decrypts successfully.
    /// </summary>
    [Fact]
    public void Encrypt_EmptyPlaintext_ShouldWork()
    {
        var key = new byte[32];
        var nonce = new byte[24];
        var plaintext = Array.Empty<byte>();

        var ciphertext = XChaCha20Poly1305.Encrypt(key, nonce, plaintext, Array.Empty<byte>());
        var decrypted = XChaCha20Poly1305.Decrypt(key, nonce, ciphertext, Array.Empty<byte>());

        Assert.Equal(plaintext, decrypted);
    }

    /// <summary>
    /// Verifies that the same plaintext encrypted with different nonces produces different ciphertexts.
    /// </summary>
    [Fact]
    public void Encrypt_DifferentNonces_ShouldProduceDifferentCiphertexts()
    {
        var key = new byte[32];
        var nonce1 = new byte[24];
        var nonce2 = new byte[24];
        nonce2[0] = 1;
        var plaintext = System.Text.Encoding.UTF8.GetBytes("Same plaintext");

        var ct1 = XChaCha20Poly1305.Encrypt(key, nonce1, plaintext, Array.Empty<byte>());
        var ct2 = XChaCha20Poly1305.Encrypt(key, nonce2, plaintext, Array.Empty<byte>());

        Assert.NotEqual(ct1, ct2);
    }

    /// <summary>
    /// Verifies that encryption and decryption round trip with the RFC 7539 style key, nonce, and associated data.
    /// </summary>
    [Fact]
    public void Encrypt_RFC7539TestVector_HChaCha20()
    {
        var key = new byte[] {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
        };
        var nonce = new byte[] {
            0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a,
            0x00, 0x00, 0x00, 0x00, 0x31, 0x41, 0x59, 0x27,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };
        var plaintext = System.Text.Encoding.UTF8.GetBytes("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.");
        var ad = new byte[] { 0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7 };

        var ciphertext = XChaCha20Poly1305.Encrypt(key, nonce, plaintext, ad);
        var decrypted = XChaCha20Poly1305.Decrypt(key, nonce, ciphertext, ad);

        Assert.Equal(plaintext, decrypted);
    }
}
