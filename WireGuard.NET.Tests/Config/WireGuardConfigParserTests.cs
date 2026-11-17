using Xunit;
using WireGuard.NET.Config;
using WGIPNetwork = WireGuard.NET.Protocol.IPNetwork;
using WGWireGuardConfig = WireGuard.NET.Protocol.WireGuardConfig;
using WGPeerConfig = WireGuard.NET.Protocol.PeerConfig;
using WireGuard.NET.Keys;
using System.Net;

namespace WireGuard.NET.Tests.Config;

/// <summary>
/// Tests for the WireGuard configuration text parser and generator.
/// </summary>
public class WireGuardConfigParserTests
{
    /// <summary>
    /// Verifies that parsing a complete configuration yields the expected listen port, interface address, and peer settings.
    /// </summary>
    [Fact]
    public void Parse_ValidConfig_ReturnsCorrectConfig()
    {
        var keyPair = KeyPair.Generate();
        var peerKeyPair = KeyPair.Generate();
        var privateKeyB64 = Convert.ToBase64String(keyPair.PrivateKey);
        var publicKeyB64 = Convert.ToBase64String(peerKeyPair.PublicKey);
        
        var configText = $@"
[Interface]
PrivateKey = {privateKeyB64}
ListenPort = 51820
Address = 10.0.0.1/24

[Peer]
PublicKey = {publicKeyB64}
AllowedIPs = 10.0.0.2/32, 192.168.1.0/24
Endpoint = 1.2.3.4:51820
PersistentKeepalive = 25
";

        var config = WireGuardConfigParser.Parse(configText);

        Assert.NotNull(config);
        Assert.Equal(51820, config.ListenPort);
        Assert.Equal(IPAddress.Parse("10.0.0.1"), config.Address);
        Assert.Single(config.Peers);
        
        var peer = config.Peers[0];
        Assert.NotNull(peer.PublicKey);
        Assert.Equal(2, peer.AllowedIPs.Count);
        Assert.NotNull(peer.Endpoint);
        Assert.Equal(25, peer.PersistentKeepalive);
    }

    /// <summary>
    /// Verifies that generating configuration text emits the expected interface and peer sections with their fields.
    /// </summary>
    [Fact]
    public void Generate_ValidConfig_ReturnsCorrectFormat()
    {
        var keyPair = KeyPair.Generate();
        var peerKeyPair = KeyPair.Generate();
        
        var config = new WGWireGuardConfig
        {
            PrivateKey = keyPair.PrivateKey,
            ListenPort = 51820,
            Address = IPAddress.Parse("10.0.0.1"),
            Peers = new List<WGPeerConfig>
            {
                new WGPeerConfig
                {
                    PublicKey = peerKeyPair.PublicKey,
                    AllowedIPs = new List<WGIPNetwork>
                    {
                        new WGIPNetwork { Address = IPAddress.Parse("10.0.0.2"), PrefixLength = 32 }
                    },
                    Endpoint = new IPEndPoint(IPAddress.Parse("1.2.3.4"), 51820),
                    PersistentKeepalive = 25
                }
            }
        };

        var generated = WireGuardConfigParser.Generate(config);

        Assert.Contains("[Interface]", generated);
        Assert.Contains("PrivateKey = ", generated);
        Assert.Contains("ListenPort = 51820", generated);
        Assert.Contains("[Peer]", generated);
        Assert.Contains("PublicKey = ", generated);
        Assert.Contains("AllowedIPs = 10.0.0.2/32", generated);
        Assert.Contains("Endpoint = 1.2.3.4:51820", generated);
        Assert.Contains("PersistentKeepalive = 25", generated);
    }

    /// <summary>
    /// Verifies that a configuration containing only an interface private key parses with no peers.
    /// </summary>
    [Fact]
    public void Parse_MinimalConfig_ReturnsConfig()
    {
        var keyPair = KeyPair.Generate();
        var privateKeyB64 = Convert.ToBase64String(keyPair.PrivateKey);
        
        var configText = $@"
[Interface]
PrivateKey = {privateKeyB64}
";

        var config = WireGuardConfigParser.Parse(configText);

        Assert.NotNull(config);
        Assert.NotNull(config.PrivateKey);
        Assert.Empty(config.Peers);
    }

    /// <summary>
    /// Verifies that comment lines do not affect the parsed values.
    /// </summary>
    [Fact]
    public void Parse_Comments_AreIgnored()
    {
        var keyPair = KeyPair.Generate();
        var privateKeyB64 = Convert.ToBase64String(keyPair.PrivateKey);
        
        var configText = $@"
# This is a comment
[Interface]
PrivateKey = {privateKeyB64}
# Another comment
ListenPort = 51820
";

        var config = WireGuardConfigParser.Parse(configText);

        Assert.NotNull(config);
        Assert.Equal(51820, config.ListenPort);
    }
}
