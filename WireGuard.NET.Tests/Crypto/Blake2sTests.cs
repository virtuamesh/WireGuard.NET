using WireGuard.NET.Crypto;
using Xunit;

namespace WireGuard.NET.Tests.Crypto;

/// <summary>
/// Tests for the BLAKE2s hash implementation.
/// </summary>
public class Blake2sTests
{
    /// <summary>
    /// Verifies that hashing without a key produces a 32-byte digest.
    /// </summary>
    [Fact]
    public void Hash_ShouldReturn32Bytes()
    {
        var input = System.Text.Encoding.UTF8.GetBytes("Hello, WireGuard!");
        var hash = Blake2s.Hash(input);
        
        Assert.NotNull(hash);
        Assert.Equal(32, hash.Length);
    }

    /// <summary>
    /// Verifies that keyed hashing produces a 32-byte digest.
    /// </summary>
    [Fact]
    public void Hash_WithKey_ShouldReturn32Bytes()
    {
        var input = System.Text.Encoding.UTF8.GetBytes("Hello, WireGuard!");
        var key = new byte[32];
        var hash = Blake2s.Hash(input, key);
        
        Assert.NotNull(hash);
        Assert.Equal(32, hash.Length);
    }

    /// <summary>
    /// Verifies that the same input always produces the same digest.
    /// </summary>
    [Fact]
    public void Hash_SameInput_ShouldReturnSameHash()
    {
        var input = System.Text.Encoding.UTF8.GetBytes("Test");
        var hash1 = Blake2s.Hash(input);
        var hash2 = Blake2s.Hash(input);
        
        Assert.Equal(hash1, hash2);
    }

    /// <summary>
    /// Verifies that different inputs produce different digests.
    /// </summary>
    [Fact]
    public void Hash_DifferentInput_ShouldReturnDifferentHash()
    {
        var input1 = System.Text.Encoding.UTF8.GetBytes("Test1");
        var input2 = System.Text.Encoding.UTF8.GetBytes("Test2");
        var hash1 = Blake2s.Hash(input1);
        var hash2 = Blake2s.Hash(input2);
        
        Assert.NotEqual(hash1, hash2);
    }
}
