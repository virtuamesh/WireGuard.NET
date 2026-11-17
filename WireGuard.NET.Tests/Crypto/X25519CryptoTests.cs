using WireGuard.NET.Crypto;
using Xunit;

namespace WireGuard.NET.Tests.Crypto;

/// <summary>
/// Tests for the X25519 key generation and Diffie-Hellman implementation.
/// </summary>
public class X25519CryptoTests
{
    /// <summary>
    /// Verifies that generated private keys are 32 bytes long.
    /// </summary>
    [Fact]
    public void GeneratePrivateKey_ShouldReturn32Bytes()
    {
        var privateKey = X25519Crypto.GeneratePrivateKey();
        
        Assert.NotNull(privateKey);
        Assert.Equal(32, privateKey.Length);
    }

    /// <summary>
    /// Verifies that a public key derived from a generated private key is 32 bytes long.
    /// </summary>
    [Fact]
    public void GeneratePublicKey_ShouldReturn32Bytes()
    {
        var privateKey = X25519Crypto.GeneratePrivateKey();
        var publicKey = X25519Crypto.GeneratePublicKey(privateKey);
        
        Assert.NotNull(publicKey);
        Assert.Equal(32, publicKey.Length);
    }

    /// <summary>
    /// Verifies that both parties compute the same shared secret from their private key and the other public key.
    /// </summary>
    [Fact]
    public void ScalarMult_ShouldComputeSameSharedSecret()
    {
        var alicePrivate = X25519Crypto.GeneratePrivateKey();
        var alicePublic = X25519Crypto.GeneratePublicKey(alicePrivate);
        
        var bobPrivate = X25519Crypto.GeneratePrivateKey();
        var bobPublic = X25519Crypto.GeneratePublicKey(bobPrivate);
        
        var aliceShared = X25519Crypto.ScalarMult(alicePrivate, bobPublic);
        var bobShared = X25519Crypto.ScalarMult(bobPrivate, alicePublic);
        
        Assert.Equal(aliceShared, bobShared);
    }
}
