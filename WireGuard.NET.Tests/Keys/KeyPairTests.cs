using WireGuard.NET.Keys;
using Xunit;

namespace WireGuard.NET.Tests.Keys;

/// <summary>
/// Tests for the WireGuard key pair type.
/// </summary>
public class KeyPairTests
{
    /// <summary>
    /// Verifies that a generated key pair contains non-null 32-byte private and public keys.
    /// </summary>
    [Fact]
    public void Generate_ShouldCreateValidKeyPair()
    {
        var keyPair = KeyPair.Generate();
        
        Assert.NotNull(keyPair);
        Assert.NotNull(keyPair.PrivateKey);
        Assert.NotNull(keyPair.PublicKey);
        Assert.Equal(32, keyPair.PrivateKey.Length);
        Assert.Equal(32, keyPair.PublicKey.Length);
    }

    /// <summary>
    /// Verifies that reconstructing a key pair from a private key derives the same public key.
    /// </summary>
    [Fact]
    public void Constructor_WithPrivateKey_ShouldGenerateCorrectPublicKey()
    {
        var original = KeyPair.Generate();
        var copy = new KeyPair(original.PrivateKey);
        
        Assert.Equal(original.PublicKey, copy.PublicKey);
    }

    /// <summary>
    /// Verifies that two peers compute the same shared secret from each other public keys.
    /// </summary>
    [Fact]
    public void ComputeSharedSecret_ShouldMatchBetweenPeers()
    {
        var alice = KeyPair.Generate();
        var bob = KeyPair.Generate();
        
        var aliceShared = alice.ComputeSharedSecret(bob.PublicKey);
        var bobShared = bob.ComputeSharedSecret(alice.PublicKey);
        
        Assert.Equal(aliceShared, bobShared);
    }
}
