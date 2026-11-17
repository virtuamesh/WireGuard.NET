using System.CommandLine;
using System.CommandLine.Builder;
using System.CommandLine.Parsing;
using WireGuard.NET.Config;
using WireGuard.NET.Keys;
using WireGuard.NET.Protocol;
using WireGuard.NET.Tun;
using System.Net;

namespace WireGuard.NET.CLI;

/// <summary>
/// Command-line entry point for WireGuard.NET. Provides key management commands
/// (genkey, pubkey, genpsk), configuration commands (genconfig, showconfig,
/// verifyconfig, wg-quick up/down/save/strip), device status, and version information.
/// </summary>
class Program
{
    /// <summary>
    /// Builds the command hierarchy and dispatches the requested command.
    /// </summary>
    /// <param name="args">The command-line arguments passed to the process.</param>
    /// <returns>The process exit code returned to the operating system.</returns>
    static async Task<int> Main(string[] args)
    {
        var rootCommand = new RootCommand("WireGuard.NET - WireGuard 协议的 .NET 实现");

        var genkeyCommand = new Command("genkey", "生成私钥");
        genkeyCommand.SetHandler(() =>
        {
            var keyPair = KeyPair.Generate();
            Console.WriteLine(Convert.ToBase64String(keyPair.PrivateKey));
        });

        var pubkeyCommand = new Command("pubkey", "从私钥计算公钥");
        var privateKeyOption = new Option<string>("--private-key", "Base64 编码的私钥")
        {
            IsRequired = true
        };
        pubkeyCommand.Add(privateKeyOption);
        pubkeyCommand.SetHandler((privateKeyStr) =>
        {
            var privateKey = Convert.FromBase64String(privateKeyStr);
            var publicKey = KeyPair.DerivePublicKey(privateKey);
            Console.WriteLine(Convert.ToBase64String(publicKey));
        }, privateKeyOption);

        var genpskCommand = new Command("genpsk", "生成预共享密钥 (PSK)");
        genpskCommand.SetHandler(() =>
        {
            var psk = new byte[32];
            System.Security.Cryptography.RandomNumberGenerator.Fill(psk);
            Console.WriteLine(Convert.ToBase64String(psk));
        });

        var genconfigCommand = new Command("genconfig", "生成示例配置文件");
        var outputFileOption = new Option<string>("--output", () => "wg0.conf", "输出文件路径");
        var serverAddressOption = new Option<string>("--server-address", () => "10.0.0.1/24", "服务器地址");
        var clientAddressOption = new Option<string>("--client-address", () => "10.0.0.2/32", "客户端地址");
        var listenPortOption = new Option<int>("--listen-port", () => 51820, "监听端口");
        genconfigCommand.Add(outputFileOption);
        genconfigCommand.Add(serverAddressOption);
        genconfigCommand.Add(clientAddressOption);
        genconfigCommand.Add(listenPortOption);
        genconfigCommand.SetHandler((outputFile, serverAddress, clientAddress, listenPort) =>
        {
            var serverKeyPair = KeyPair.Generate();
            var clientKeyPair = KeyPair.Generate();
            var psk = new byte[32];
            System.Security.Cryptography.RandomNumberGenerator.Fill(psk);

            var serverConfig = $@"[Interface]
PrivateKey = {Convert.ToBase64String(serverKeyPair.PrivateKey)}
Address = {serverAddress}
ListenPort = {listenPort}

[Peer]
PublicKey = {Convert.ToBase64String(clientKeyPair.PublicKey)}
PresharedKey = {Convert.ToBase64String(psk)}
AllowedIPs = {clientAddress}
";

            var clientConfig = $@"[Interface]
PrivateKey = {Convert.ToBase64String(clientKeyPair.PrivateKey)}
Address = {clientAddress}

[Peer]
PublicKey = {Convert.ToBase64String(serverKeyPair.PublicKey)}
PresharedKey = {Convert.ToBase64String(psk)}
Endpoint = 127.0.0.1:{listenPort}
AllowedIPs = {serverAddress.Split('/')[0]}/24
PersistentKeepalive = 25
";

            File.WriteAllText(outputFile, serverConfig);
            File.WriteAllText(Path.ChangeExtension(outputFile, ".client.conf"), clientConfig);

            Console.WriteLine($"服务器配置已生成: {outputFile}");
            Console.WriteLine($"客户端配置已生成: {Path.ChangeExtension(outputFile, ".client.conf")}");
            Console.WriteLine();
            Console.WriteLine("服务器公钥: " + Convert.ToBase64String(serverKeyPair.PublicKey));
            Console.WriteLine("客户端公钥: " + Convert.ToBase64String(clientKeyPair.PublicKey));
        }, outputFileOption, serverAddressOption, clientAddressOption, listenPortOption);

        var showConfigCommand = new Command("showconfig", "显示配置");
        var configFileOption = new Option<string>("--config", "配置文件路径")
        {
            IsRequired = true
        };
        showConfigCommand.Add(configFileOption);
        showConfigCommand.SetHandler((configFile) =>
        {
            if (!File.Exists(configFile))
            {
                Console.Error.WriteLine($"错误: 文件不存在 - {configFile}");
                return;
            }

            var configContent = File.ReadAllText(configFile);
            var config = WireGuardConfigParser.Parse(configContent);

            Console.WriteLine("=== WireGuard 配置 ===");
            Console.WriteLine();
            Console.WriteLine("[Interface]");
            Console.WriteLine($"PrivateKey = (隐藏)");
            Console.WriteLine($"ListenPort = {config.ListenPort}");
            if (config.Address != null)
            {
                Console.WriteLine($"Address = {config.Address}");
            }
            Console.WriteLine();

            foreach (var peer in config.Peers)
            {
                Console.WriteLine("[Peer]");
                Console.WriteLine($"PublicKey = {Convert.ToBase64String(peer.PublicKey)}");
                if (peer.PresharedKey != null)
                {
                    Console.WriteLine($"PresharedKey = (隐藏)");
                }
                if (peer.AllowedIPs.Count > 0)
                {
                    var ips = string.Join(", ", peer.AllowedIPs.Select(ip => $"{ip.Address}/{ip.PrefixLength}"));
                    Console.WriteLine($"AllowedIPs = {ips}");
                }
                if (peer.Endpoint != null)
                {
                    Console.WriteLine($"Endpoint = {peer.Endpoint}");
                }
                if (peer.PersistentKeepalive > 0)
                {
                    Console.WriteLine($"PersistentKeepalive = {peer.PersistentKeepalive}");
                }
                Console.WriteLine();
            }
        }, configFileOption);

        var verifyconfigCommand = new Command("verifyconfig", "验证配置文件");
        verifyconfigCommand.Add(configFileOption);
        verifyconfigCommand.SetHandler((configFile) =>
        {
            if (!File.Exists(configFile))
            {
                Console.Error.WriteLine($"错误: 文件不存在 - {configFile}");
                return;
            }

            try
            {
                var configContent = File.ReadAllText(configFile);
                var config = WireGuardConfigParser.Parse(configContent);

                Console.WriteLine("✅ 配置文件验证成功！");
                Console.WriteLine();
                Console.WriteLine($"接口监听端口: {config.ListenPort}");
                Console.WriteLine($"接口地址: {config.Address}");
                Console.WriteLine($"对等节点数量: {config.Peers.Count}");

                if (config.PrivateKey.Length != 32)
                {
                    Console.WriteLine("⚠️ 警告: 私钥长度不正确");
                }

                foreach (var peer in config.Peers)
                {
                    if (peer.PublicKey.Length != 32)
                    {
                        Console.WriteLine($"⚠️ 警告: 对等节点公钥长度不正确 - {Convert.ToBase64String(peer.PublicKey)}");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"❌ 配置文件验证失败: {ex.Message}");
            }
        }, configFileOption);

        var showCommand = new Command("show", "显示设备状态");
        var deviceNameOption = new Option<string>("--device", () => "wg0", "设备名称");
        showCommand.Add(deviceNameOption);
        showCommand.SetHandler((deviceName) =>
        {
            Console.WriteLine($"=== {deviceName} 设备状态 ===");
            Console.WriteLine();
            Console.WriteLine("注意: CLI 无法附加到其他进程中运行的设备（无跨进程 IPC）");
            Console.WriteLine("如需查询运行中设备，请在应用内调用 WireGuardDevice.GetStatus()/GetPeer()/GetAllPeers()");
            Console.WriteLine("查看静态配置请使用 showconfig 命令");
        }, deviceNameOption);

        var versionCommand = new Command("version", "显示版本信息");
        versionCommand.SetHandler(() =>
        {
            var version = typeof(Program).Assembly.GetName().Version;
            Console.WriteLine("WireGuard.NET CLI");
            Console.WriteLine($"版本: {(version != null ? version.ToString(3) : "unknown")}");
            Console.WriteLine();
            Console.WriteLine("已实现功能:");
            Console.WriteLine("  ✅ 加密原语 (X25519, ChaCha20-Poly1305, BLAKE2s)");
            Console.WriteLine("  ✅ Noise_IKpsk2 协议框架");
            Console.WriteLine("  ✅ 重放保护");
            Console.WriteLine("  ✅ Cookie 回复机制");
            Console.WriteLine("  ✅ Keepalive 机制");
            Console.WriteLine("  ✅ AllowedIPs 过滤");
            Console.WriteLine("  ✅ 配置文件解析");
            Console.WriteLine("  ✅ TUN 设备抽象");
            Console.WriteLine("  ✅ 握手超时和重传");
            Console.WriteLine("  ✅ 连接超时检测");
            Console.WriteLine("  ✅ 会话密钥轮换");
            Console.WriteLine("  ✅ 真实 TUN 设备 (Wintun / tun / utun)");
            Console.WriteLine("  ✅ 运行时配置管理与状态查询");
            Console.WriteLine();
            Console.WriteLine("未实现功能:");
            Console.WriteLine("  ⏳ 内核模块集成");
            Console.WriteLine("  ⏳ 完整 wg-quick (DNS/防火墙)");
            Console.WriteLine("  ⏳ BSD / Android / iOS TUN 后端");
        });

        var wgQuickCommand = new Command("wg-quick", "WireGuard 快速设置工具");
        
        var upCommand = new Command("up", "启动 WireGuard 接口");
        var upConfigOption = new Option<string>("--config", "配置文件路径") { IsRequired = true };
        var upDeviceOption = new Option<string>("--device", () => "wg0", "设备名称");
        upCommand.Add(upConfigOption);
        upCommand.Add(upDeviceOption);
        upCommand.SetHandler(async (configFile, deviceName) =>
        {
            if (!File.Exists(configFile))
            {
                Console.Error.WriteLine($"❌ 错误: 文件不存在 - {configFile}");
                return;
            }

            try
            {
                Console.WriteLine($"🚀 启动 WireGuard 接口 {deviceName}...");
                var configContent = File.ReadAllText(configFile);
                var config = WireGuardConfigParser.Parse(configContent);
                
                Console.WriteLine("✅ 配置文件加载成功");
                Console.WriteLine($"   - 监听端口: {config.ListenPort}");
                Console.WriteLine($"   - 接口地址: {config.Address}");
                Console.WriteLine($"   - 对等节点数量: {config.Peers.Count}");
                
                var device = new WireGuardDevice(config);
                device.CreateTunDevice(deviceName);
                await device.StartAsync();
                
                Console.WriteLine($"✅ WireGuard 接口 {deviceName} 已启动！");
                Console.WriteLine();
                Console.WriteLine("按任意键停止...");
                Console.ReadKey();
                
                device.Stop();
                Console.WriteLine($"✅ WireGuard 接口 {deviceName} 已停止");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"❌ 启动失败: {ex.Message}");
            }
        }, upConfigOption, upDeviceOption);
        wgQuickCommand.Add(upCommand);
        
        var downCommand = new Command("down", "停止 WireGuard 接口");
        var downDeviceOption = new Option<string>("--device", () => "wg0", "设备名称");
        downCommand.Add(downDeviceOption);
        downCommand.SetHandler((deviceName) =>
        {
            Console.WriteLine($"⏹️  停止 WireGuard 接口 {deviceName}...");
            Console.WriteLine("⚠️ 注意: WireGuard.NET 当前不支持通过 wg-quick down 停止其他进程启动的接口");
            Console.WriteLine("请使用 Ctrl+C 停止运行中的 wg-quick up 进程");
        }, downDeviceOption);
        wgQuickCommand.Add(downCommand);
        
        var saveCommand = new Command("save", "保存配置");
        var saveConfigOption = new Option<string>("--config", "配置文件路径") { IsRequired = true };
        var saveOutputOption = new Option<string>("--output", "输出文件路径") { IsRequired = true };
        saveCommand.Add(saveConfigOption);
        saveCommand.Add(saveOutputOption);
        saveCommand.SetHandler((configFile, outputFile) =>
        {
            if (!File.Exists(configFile))
            {
                Console.Error.WriteLine($"❌ 错误: 文件不存在 - {configFile}");
                return;
            }

            try
            {
                var configContent = File.ReadAllText(configFile);
                File.WriteAllText(outputFile, configContent);
                Console.WriteLine($"✅ 配置已保存到: {outputFile}");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"❌ 保存失败: {ex.Message}");
            }
        }, saveConfigOption, saveOutputOption);
        wgQuickCommand.Add(saveCommand);
        
        var stripCommand = new Command("strip", "移除私钥和预共享密钥");
        var stripConfigOption = new Option<string>("--config", "配置文件路径") { IsRequired = true };
        var stripOutputOption = new Option<string>("--output", () => "wg0.strip.conf", "输出文件路径");
        stripCommand.Add(stripConfigOption);
        stripCommand.Add(stripOutputOption);
        stripCommand.SetHandler((configFile, outputFile) =>
        {
            if (!File.Exists(configFile))
            {
                Console.Error.WriteLine($"❌ 错误: 文件不存在 - {configFile}");
                return;
            }

            try
            {
                var lines = File.ReadAllLines(configFile);
                var strippedLines = new List<string>();
                foreach (var line in lines)
                {
                    if (line.Trim().StartsWith("PrivateKey") || line.Trim().StartsWith("PresharedKey"))
                    {
                        strippedLines.Add(line.Split('=')[0] + "= (隐藏)");
                    }
                    else
                    {
                        strippedLines.Add(line);
                    }
                }
                File.WriteAllLines(outputFile, strippedLines);
                Console.WriteLine($"✅ 配置已保存到: {outputFile}（已移除敏感信息）");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"❌ 处理失败: {ex.Message}");
            }
        }, stripConfigOption, stripOutputOption);
        wgQuickCommand.Add(stripCommand);

        rootCommand.Add(genkeyCommand);
        rootCommand.Add(pubkeyCommand);
        rootCommand.Add(genpskCommand);
        rootCommand.Add(genconfigCommand);
        rootCommand.Add(showConfigCommand);
        rootCommand.Add(verifyconfigCommand);
        rootCommand.Add(showCommand);
        rootCommand.Add(versionCommand);
        rootCommand.Add(wgQuickCommand);

        return await rootCommand.InvokeAsync(args);
    }
}
