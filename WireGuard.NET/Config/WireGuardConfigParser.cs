using System.Net;
using System.Text.RegularExpressions;
using WGIPNetwork = WireGuard.NET.Protocol.IPNetwork;
using WGWireGuardConfig = WireGuard.NET.Protocol.WireGuardConfig;
using WGPeerConfig = WireGuard.NET.Protocol.PeerConfig;

namespace WireGuard.NET.Config;

/// <summary>
/// Parses and generates WireGuard configuration files in the standard wg-quick
/// ini-like format ([Interface] and [Peer] sections).
/// </summary>
public static class WireGuardConfigParser
{
    private static readonly Regex SectionRegex = new Regex(@"^\[(\w+)\]$", RegexOptions.Compiled);
    private static readonly Regex KeyValueRegex = new Regex(@"^(\w+)\s*=\s*(.+)$", RegexOptions.Compiled);

    /// <summary>
    /// Parses the text of a WireGuard configuration file into a
    /// <see cref="WGWireGuardConfig"/> instance.
    /// </summary>
    /// <param name="configText">The raw configuration file content, with lines separated by \n and/or \r.</param>
    /// <returns>
    /// The parsed configuration. Empty lines, comment lines (starting with '#') and
    /// unrecognized keys are silently skipped.
    /// </returns>
    /// <exception cref="FormatException">
    /// A Base64-encoded key is malformed, an IP address is invalid, or a numeric field
    /// cannot be parsed.
    /// </exception>
    public static WGWireGuardConfig Parse(string configText)
    {
        var config = new WGWireGuardConfig
        {
            Peers = new List<WGPeerConfig>()
        };

        var lines = configText.Split(new[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries);
        string? currentSection = null;
        WGPeerConfig? currentPeer = null;

        foreach (var line in lines)
        {
            var trimmedLine = line.Trim();
            
            if (string.IsNullOrEmpty(trimmedLine) || trimmedLine.StartsWith('#'))
                continue;

            var sectionMatch = SectionRegex.Match(trimmedLine);
            if (sectionMatch.Success)
            {
                var sectionName = sectionMatch.Groups[1].Value.ToLower();
                
                if (currentPeer != null && currentSection == "peer")
                {
                    config.Peers.Add(currentPeer);
                }
                
                currentSection = sectionName;
                
                if (sectionName == "peer")
                {
                    currentPeer = new WGPeerConfig
                    {
                        AllowedIPs = new List<WGIPNetwork>()
                    };
                }
                continue;
            }

            var keyValueMatch = KeyValueRegex.Match(trimmedLine);
            if (keyValueMatch.Success)
            {
                var key = keyValueMatch.Groups[1].Value.ToLower();
                var value = keyValueMatch.Groups[2].Value.Trim();

                if (currentSection == "interface")
                {
                    ParseInterfaceConfig(config, key, value);
                }
                else if (currentSection == "peer" && currentPeer != null)
                {
                    ParsePeerConfig(currentPeer, key, value);
                }
            }
        }

        if (currentPeer != null && currentSection == "peer")
        {
            config.Peers.Add(currentPeer);
        }

        return config;
    }

    /// <summary>
    /// Applies a single [Interface] key/value pair to the configuration.
    /// </summary>
    private static void ParseInterfaceConfig(WGWireGuardConfig config, string key, string value)
    {
        switch (key)
        {
            case "privatekey":
                config.PrivateKey = Convert.FromBase64String(value);
                break;
            case "listenport":
                config.ListenPort = int.Parse(value);
                break;
            case "address":
                ParseAddress(config, value);
                break;
            case "mtu":
                if (int.TryParse(value, out var mtu))
                    config.Mtu = mtu;
                break;
        }
    }

    /// <summary>
    /// Parses a comma-separated list of interface addresses (with or without a prefix
    /// length) and stores the first IPv4 and first IPv6 address on the configuration.
    /// </summary>
    private static void ParseAddress(WGWireGuardConfig config, string value)
    {
        var addresses = value.Split(',');
        foreach (var addr in addresses)
        {
            var trimmedAddr = addr.Trim();
            if (trimmedAddr.Contains('/'))
            {
                var lastSlash = trimmedAddr.LastIndexOf('/');
                var ip = IPAddress.Parse(trimmedAddr[..lastSlash]);
                var prefix = int.Parse(trimmedAddr[(lastSlash + 1)..]);

                // [VM-S6] Preserve the prefix length instead of discarding it. IPv4 and IPv6 are stored separately.
                if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
                {
                    config.AddressV6 ??= ip;
                    config.AddressV6PrefixLength = prefix;
                }
                else
                {
                    config.Address ??= ip;
                    config.AddressPrefixLength = prefix;
                }
            }
            else
            {
                var ip = IPAddress.Parse(trimmedAddr);
                if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
                {
                    config.AddressV6 ??= ip;
                }
                else
                {
                    config.Address ??= ip;
                }
            }
        }
    }

    /// <summary>
    /// Applies a single [Peer] key/value pair to the peer configuration.
    /// </summary>
    private static void ParsePeerConfig(WGPeerConfig peer, string key, string value)
    {
        switch (key)
        {
            case "publickey":
                peer.PublicKey = Convert.FromBase64String(value);
                break;
            case "presharedkey":
                peer.PresharedKey = Convert.FromBase64String(value);
                break;
            case "allowedips":
                ParseAllowedIPs(peer, value);
                break;
            case "endpoint":
                ParseEndpoint(peer, value);
                break;
            case "persistentkeepalive":
                peer.PersistentKeepalive = int.Parse(value);
                break;
        }
    }

    /// <summary>
    /// Parses a comma-separated AllowedIPs list and adds each entry (address plus prefix
    /// length) to the peer. Entries without a prefix length are skipped.
    /// </summary>
    private static void ParseAllowedIPs(WGPeerConfig peer, string value)
    {
        var ips = value.Split(',');
        foreach (var ip in ips)
        {
            var trimmedIp = ip.Trim();
            if (trimmedIp.Contains('/'))
            {
                var parts = trimmedIp.Split('/');
                var address = IPAddress.Parse(parts[0]);
                var prefixLength = int.Parse(parts[1]);
                peer.AllowedIPs.Add(new WGIPNetwork { Address = address, PrefixLength = prefixLength });
            }
        }
    }

    /// <summary>
    /// Parses an Endpoint value in either IPv6 bracket notation ([::1]:51820) or IPv4/hostname
    /// notation (host:port), resolving hostnames via DNS when necessary, and assigns it to
    /// the peer. Malformed endpoints are silently ignored.
    /// </summary>
    private static void ParseEndpoint(WGPeerConfig peer, string value)
    {
        var trimmed = value.Trim();

        // [VM-S5] Support the IPv6 endpoint format [::1]:51820 as well as the IPv4 host:port format
        int port;
        string host;

        if (trimmed.StartsWith('['))
        {
            // IPv6 format: [address]:port
            var closeBracket = trimmed.IndexOf(']');
            if (closeBracket < 0 || closeBracket + 1 >= trimmed.Length || trimmed[closeBracket + 1] != ':')
                return;

            host = trimmed[1..closeBracket];
            var portStr = trimmed[(closeBracket + 2)..];
            if (!int.TryParse(portStr, out port))
                return;
        }
        else
        {
            // IPv4 or hostname format: host:port
            var lastColon = trimmed.LastIndexOf(':');
            if (lastColon < 0)
                return;

            host = trimmed[..lastColon];
            if (!int.TryParse(trimmed[(lastColon + 1)..], out port))
                return;
        }

        try
        {
            // Try to parse the IP address directly to avoid a DNS lookup
            if (IPAddress.TryParse(host, out var directIp))
            {
                peer.Endpoint = new IPEndPoint(directIp, port);
            }
            else
            {
                var addresses = Dns.GetHostAddresses(host);
                if (addresses.Length > 0)
                {
                    peer.Endpoint = new IPEndPoint(addresses[0], port);
                }
            }
        }
        catch
        {
            // Ignore DNS resolution failures
        }
    }

    /// <summary>
    /// Generates a WireGuard configuration file text from the specified configuration.
    /// </summary>
    /// <param name="config">The configuration to serialize; <see cref="WGWireGuardConfig.Peers"/> may be empty.</param>
    /// <returns>The configuration file content in wg-quick format, terminated by a trailing empty line.</returns>
    /// <exception cref="ArgumentNullException">A required key (PrivateKey / PublicKey) is <c>null</c>.</exception>
    public static string Generate(WGWireGuardConfig config)
    {
        var sb = new System.Text.StringBuilder();
        
        sb.AppendLine("[Interface]");
        sb.AppendLine($"PrivateKey = {Convert.ToBase64String(config.PrivateKey)}");
        
        if (config.ListenPort > 0)
        {
            sb.AppendLine($"ListenPort = {config.ListenPort}");
        }

        if (config.Mtu > 0 && config.Mtu != 1420)
        {
            sb.AppendLine($"MTU = {config.Mtu}");
        }
        
        if (config.Address != null)
        {
            // [VM-S7] Use the actually configured prefix length instead of hard-coding /24
            sb.AppendLine($"Address = {config.Address}/{config.AddressPrefixLength}");
        }

        if (config.AddressV6 != null)
        {
            sb.AppendLine($"Address = {config.AddressV6}/{config.AddressV6PrefixLength}");
        }
        
        sb.AppendLine();
        
        foreach (var peer in config.Peers)
        {
            sb.AppendLine("[Peer]");
            sb.AppendLine($"PublicKey = {Convert.ToBase64String(peer.PublicKey)}");
            
            if (peer.PresharedKey != null && peer.PresharedKey.Length > 0)
            {
                sb.AppendLine($"PresharedKey = {Convert.ToBase64String(peer.PresharedKey)}");
            }
            
            if (peer.AllowedIPs != null && peer.AllowedIPs.Count > 0)
            {
                var allowedIps = string.Join(", ", peer.AllowedIPs.Select(ip => $"{ip.Address}/{ip.PrefixLength}"));
                sb.AppendLine($"AllowedIPs = {allowedIps}");
            }
            
            if (peer.Endpoint != null)
            {
                sb.AppendLine($"Endpoint = {peer.Endpoint}");
            }
            
            if (peer.PersistentKeepalive > 0)
            {
                sb.AppendLine($"PersistentKeepalive = {peer.PersistentKeepalive}");
            }
            
            sb.AppendLine();
        }
        
        return sb.ToString();
    }
}
