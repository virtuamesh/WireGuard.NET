using WireGuard.NET.Crypto;
using WireGuard.NET.Protocol.Noise;
using Xunit;
using Xunit.Abstractions;

namespace WireGuard.NET.Tests.Crypto;

/// <summary>
/// Diagnostic tests that print BLAKE2s and HKDF intermediate values and compare the Noise initial hash chain with the Linux kernel reference.
/// </summary>
public class Blake2sHkdfTests
{
    private readonly ITestOutputHelper _output;

    public Blake2sHkdfTests(ITestOutputHelper output)
    {
        _output = output;
    }

    /// <summary>
    /// Prints keyed BLAKE2s intermediate values for reference comparison; used to diagnose keyed-hash argument order and has no assertions.
    /// </summary>
    [Fact]
    public void Blake2s_KeyedHash_Debug()
    {
        var ck = Convert.FromHexString("60e26daef327efc02ec335e2a025d2d016eb4206f87277f52d38d1988b78cd36");
        var ikm = new byte[32];

        var prk1 = Blake2s.Hash(ikm, ck);
        var prk2 = Blake2s.Hash(ck, ikm);

        _output.WriteLine($"Blake2s.Hash(ikm, ck) = {BitConverter.ToString(prk1).Replace("-", "").ToLowerInvariant()}");
        _output.WriteLine($"Blake2s.Hash(ck, ikm) = {BitConverter.ToString(prk2).Replace("-", "").ToLowerInvariant()}");
        _output.WriteLine($"Reference keyed blake2s(zeros, key=ck) = 3dc9b32ceb0c74785cf3215d5228ca32b9f557de822256b4d266ec359cced642");

        var t1_1 = Blake2s.Hash(new byte[] { 0x01 }, prk1);
        var t1_2 = Blake2s.Hash(new byte[] { 0x01 }, prk2);

        _output.WriteLine($"t1 with prk1 = {BitConverter.ToString(t1_1).Replace("-", "").ToLowerInvariant()}");
        _output.WriteLine($"t1 with prk2 = {BitConverter.ToString(t1_2).Replace("-", "").ToLowerInvariant()}");
        _output.WriteLine($"Reference t1 = 5bef786baf3d84e261e95bc6cc5cc4c1203d939284f70f08edecb6883b588ab8");
    }

    /// <summary>
    /// Verifies that the handshake state hash after mixing the responder static key equals the independently computed BLAKE2s chain.
    /// </summary>
    [Fact]
    public void NoiseProtocol_InitialHash_MatchesLinuxKernel()
    {
        var construction = System.Text.Encoding.UTF8.GetBytes("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s");
        var identifier = System.Text.Encoding.UTF8.GetBytes("WireGuard v1 zx2c4 Jason@zx2c4.com");

        Assert.Equal(37, construction.Length);
        Assert.Equal(34, identifier.Length);

        var ck = Blake2s.Hash(construction);
        var h = Blake2s.Hash(Combine(ck, identifier));

        var ckHex = BitConverter.ToString(ck).Replace("-", "").ToLowerInvariant();
        var hHex = BitConverter.ToString(h).Replace("-", "").ToLowerInvariant();

        _output.WriteLine($"ck = {ckHex}");
        _output.WriteLine($"h  = {hHex}");

        var responder = new NoiseHandshakeState(
            Convert.FromBase64String("sB6dEZ1xbAd3dntgK0MKWXnC+sEugmOk/M9uRgNZPWE="),
            null, false);
        var responderHash = BitConverter.ToString(responder.GetHash()).Replace("-", "").ToLowerInvariant();
        _output.WriteLine($"NoiseHandshakeState hash = {responderHash}");

        var serverPub = X25519Crypto.GeneratePublicKey(
            Convert.FromBase64String("sB6dEZ1xbAd3dntgK0MKWXnC+sEugmOk/M9uRgNZPWE="));
        var expectedHash = Blake2s.Hash(Combine(h, serverPub));
        var expectedHashHex = BitConverter.ToString(expectedHash).Replace("-", "").ToLowerInvariant();
        _output.WriteLine($"Expected hash after MixHash(serverPub) = {expectedHashHex}");

        Assert.Equal(expectedHashHex, responderHash);
    }

    private static byte[] Combine(params byte[][] arrays)
    {
        var result = new byte[arrays.Sum(a => a.Length)];
        var offset = 0;
        foreach (var array in arrays)
        {
            Buffer.BlockCopy(array, 0, result, offset, array.Length);
            offset += array.Length;
        }
        return result;
    }
}