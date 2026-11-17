using WireGuard.NET.Crypto;
using Xunit;

namespace WireGuard.NET.Tests.Crypto;

/// <summary>
/// Tests for the ChaCha20-Poly1305 AEAD implementation.
/// </summary>
public class ChaCha20Poly1305Tests
{
    /// <summary>
    /// Verifies that encrypting with associated data and decrypting with the same inputs restores the plaintext.
    /// </summary>
    [Fact]
    public void Encrypt_And_Decrypt_Should_RoundTrip()
    {
        var key = new byte[32];
        var nonce = new byte[12];
        var plaintext = System.Text.Encoding.UTF8.GetBytes("Hello, WireGuard!");
        var associatedData = System.Text.Encoding.UTF8.GetBytes("AD");

        var ciphertextWithTag = ChaCha20Poly1305.Encrypt(key, nonce, plaintext, associatedData);
        var decrypted = ChaCha20Poly1305.Decrypt(key, nonce, ciphertextWithTag, associatedData);

        Assert.Equal(plaintext, decrypted);
    }

    /// <summary>
    /// Verifies that decryption with a different key throws a CryptographicException.
    /// </summary>
    [Fact]
    public void Decrypt_With_WrongKey_Should_Throw()
    {
        var key = new byte[32];
        var wrongKey = new byte[32];
        wrongKey[0] = 1;
        var nonce = new byte[12];
        var plaintext = System.Text.Encoding.UTF8.GetBytes("Test");

        var ciphertextWithTag = ChaCha20Poly1305.Encrypt(key, nonce, plaintext, Array.Empty<byte>());

        Assert.Throws<System.Security.Cryptography.CryptographicException>(() => 
            ChaCha20Poly1305.Decrypt(wrongKey, nonce, ciphertextWithTag, Array.Empty<byte>()));
    }
}
