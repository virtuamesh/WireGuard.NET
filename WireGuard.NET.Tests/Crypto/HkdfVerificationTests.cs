using WireGuard.NET.Crypto;
using Xunit;
using Xunit.Abstractions;

namespace WireGuard.NET.Tests.Crypto;

/// <summary>
/// Diagnostic tests that print HKDF values and verify the Noise protocol initial hash chain against reference values.
/// </summary>
public class HkdfVerificationTests
{
    private readonly ITestOutputHelper _output;

    public HkdfVerificationTests(ITestOutputHelper output)
    {
        _output = output;
    }

    /// <summary>
    /// Prints HMAC-BLAKE2s values for the HKDF extract and expand steps for comparison with a Python reference; no assertions.
    /// </summary>
    [Fact]
    public void HMAC_Blake2s_Matches_Python()
    {
        var salt = Convert.FromHexString("60e26daef327efc02ec335e2a025d2d016eb4206f87277f52d38d1988b78cd36");
        var ikm = new byte[32];

        var prk = Blake2s.HMAC(salt, ikm);
        _output.WriteLine($"HMAC(salt=zeros_32, ikm=zeros_32): prk={BitConverter.ToString(prk).Replace("-", "").ToLowerInvariant()}");

        var t1 = Blake2s.HMAC(prk, new byte[] { 0x01 });
        _output.WriteLine($"HMAC(prk, 0x01): t1={BitConverter.ToString(t1).Replace("-", "").ToLowerInvariant()}");

        var t2Input = new byte[t1.Length + 1];
        Buffer.BlockCopy(t1, 0, t2Input, 0, t1.Length);
        t2Input[t1.Length] = 0x02;
        var t2 = Blake2s.HMAC(prk, t2Input);
        _output.WriteLine($"HMAC(prk, t1||0x02): t2={BitConverter.ToString(t2).Replace("-", "").ToLowerInvariant()}");
    }

    /// <summary>
    /// Verifies that the initial chaining key and the hash after mixing the protocol identifier match the reference values.
    /// </summary>
    [Fact]
    public void Full_Noise_Init_Matches_Python()
    {
        var construction = System.Text.Encoding.UTF8.GetBytes("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s");
        var identifier = System.Text.Encoding.UTF8.GetBytes("WireGuard v1 zx2c4 Jason@zx2c4.com");

        byte[] h;
        if (construction.Length <= 32)
        {
            h = new byte[32];
            Buffer.BlockCopy(construction, 0, h, 0, construction.Length);
        }
        else
        {
            h = Blake2s.Hash(construction);
        }
        var ck = (byte[])h.Clone();

        _output.WriteLine($"Initial h: {BitConverter.ToString(h).Replace("-", "").ToLowerInvariant()}");
        _output.WriteLine($"Expected:  60e26daef327efc02ec335e2a025d2d016eb4206f87277f52d38d1988b78cd36");

        h = Blake2s.Hash(Combine(h, identifier));
        _output.WriteLine($"After MixHash(identifier): {BitConverter.ToString(h).Replace("-", "").ToLowerInvariant()}");
        _output.WriteLine($"Expected:                  2211b361081ac566691243db458ad5322d9c6c662293e8b70ee19c65ba079ef3");

        Assert.Equal("60e26daef327efc02ec335e2a025d2d016eb4206f87277f52d38d1988b78cd36",
            BitConverter.ToString(ck).Replace("-", "").ToLowerInvariant());
        Assert.Equal("2211b361081ac566691243db458ad5322d9c6c662293e8b70ee19c65ba079ef3",
            BitConverter.ToString(h).Replace("-", "").ToLowerInvariant());
    }

    /// <summary>
    /// Prints HKDF outputs and the derived pseudorandom key for a known chaining key for comparison with a Python reference; no assertions.
    /// </summary>
    [Fact]
    public void HKDF_MixKey_Matches_Python()
    {
        var ck = Convert.FromHexString("60e26daef327efc02ec335e2a025d2d016eb4206f87277f52d38d1988b78cd36");
        var dhShared = new byte[32];

        var (t1, t2, _) = HKDF(ck, dhShared, 2);

        _output.WriteLine($"HKDF(ck, zeros): t1={BitConverter.ToString(t1).Replace("-", "").ToLowerInvariant()}");
        _output.WriteLine($"HKDF(ck, zeros): t2={BitConverter.ToString(t2).Replace("-", "").ToLowerInvariant()}");

        var prk = Blake2s.HMAC(ck, dhShared);
        _output.WriteLine($"PRK = HMAC(ck, ikm): {BitConverter.ToString(prk).Replace("-", "").ToLowerInvariant()}");
    }

    private static (byte[] output1, byte[] output2, byte[] output3) HKDF(byte[] salt, byte[] ikm, int numOutputs)
    {
        var prk = Blake2s.HMAC(salt, ikm);

        var t1Input = new byte[] { 0x01 };
        var t1 = Blake2s.HMAC(prk, t1Input);

        if (numOutputs == 1)
        {
            return (t1, Array.Empty<byte>(), Array.Empty<byte>());
        }

        var t2Input = new byte[t1.Length + 1];
        Buffer.BlockCopy(t1, 0, t2Input, 0, t1.Length);
        t2Input[t1.Length] = 0x02;
        var t2 = Blake2s.HMAC(prk, t2Input);

        if (numOutputs == 2)
        {
            return (t1, t2, Array.Empty<byte>());
        }

        var t3Input = new byte[t2.Length + 1];
        Buffer.BlockCopy(t2, 0, t3Input, 0, t2.Length);
        t3Input[t2.Length] = 0x03;
        var t3 = Blake2s.HMAC(prk, t3Input);

        return (t1, t2, t3);
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
