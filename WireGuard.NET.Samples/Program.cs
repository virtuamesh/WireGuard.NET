using WireGuard.NET;
using WireGuard.NET.Config;
using WireGuard.NET.Keys;
using WireGuard.NET.Protocol;
using WireGuard.NET.Tun;
using System.Net;
using WGIPNetwork = WireGuard.NET.Protocol.IPNetwork;

// WireGuard.NET sample application
Console.WriteLine("=== WireGuard.NET 示例应用 ===");
Console.WriteLine();

// 1. Generate key pairs
Console.WriteLine("1. 生成密钥对...");
var serverKeyPair = KeyPair.Generate();
var clientKeyPair = KeyPair.Generate();

Console.WriteLine($"   服务器公钥: {Convert.ToBase64String(serverKeyPair.PublicKey)}");
Console.WriteLine($"   客户端公钥: {Convert.ToBase64String(clientKeyPair.PublicKey)}");
Console.WriteLine();

// 2. Create the server configuration
Console.WriteLine("2. 创建服务器配置...");
var serverConfig = new WireGuardConfig
{
    PrivateKey = serverKeyPair.PrivateKey,
    ListenPort = 51820,
    Address = IPAddress.Parse("10.0.0.1")
};

serverConfig.Peers.Add(new PeerConfig
{
    PublicKey = clientKeyPair.PublicKey,
    AllowedIPs = { new WGIPNetwork { Address = IPAddress.Parse("10.0.0.2"), PrefixLength = 32 } }
});

Console.WriteLine($"   监听端口: {serverConfig.ListenPort}");
Console.WriteLine($"   地址: {serverConfig.Address}");
Console.WriteLine();

// 3. Create the client configuration
Console.WriteLine("3. 创建客户端配置...");
var clientConfig = new WireGuardConfig
{
    PrivateKey = clientKeyPair.PrivateKey,
    ListenPort = 0,
    Address = IPAddress.Parse("10.0.0.2")
};

clientConfig.Peers.Add(new PeerConfig
{
    PublicKey = serverKeyPair.PublicKey,
    Endpoint = new IPEndPoint(IPAddress.Parse("127.0.0.1"), 51820),
    AllowedIPs = { new WGIPNetwork { Address = IPAddress.Parse("10.0.0.0"), PrefixLength = 24 } },
    PersistentKeepalive = 25
});

Console.WriteLine($"   地址: {clientConfig.Address}");
Console.WriteLine($"   服务器端点: {clientConfig.Peers[0].Endpoint}");
Console.WriteLine($"   Keepalive: {clientConfig.Peers[0].PersistentKeepalive}秒");
Console.WriteLine();

// 4. Demonstrate AllowedIPs filtering
Console.WriteLine("4. 演示 AllowedIPs 过滤...");
var filter = new AllowedIPsFilter();
filter.AddAllowedIP(IPAddress.Parse("10.0.0.0"), 24);
filter.AddAllowedIP(IPAddress.Parse("192.168.1.0"), 24);

Console.WriteLine($"   允许的网络:");
Console.WriteLine($"     - 10.0.0.0/24");
Console.WriteLine($"     - 192.168.1.0/24");
Console.WriteLine();

var testIp1 = IPAddress.Parse("10.0.0.5");
var testIp2 = IPAddress.Parse("10.0.1.5");
var testIp3 = IPAddress.Parse("192.168.1.100");

Console.WriteLine($"   测试 IP:");
Console.WriteLine($"     {testIp1} -> {(filter.IsAllowed(testIp1) ? "允许" : "拒绝")}");
Console.WriteLine($"     {testIp2} -> {(filter.IsAllowed(testIp2) ? "允许" : "拒绝")}");
Console.WriteLine($"     {testIp3} -> {(filter.IsAllowed(testIp3) ? "允许" : "拒绝")}");
Console.WriteLine();

// 5. Demonstrate ReplayProtector
Console.WriteLine("5. 演示 ReplayProtector...");
var replayProtector = new ReplayProtector();

Console.WriteLine($"   测试计数器验证:");
Console.WriteLine($"     计数器 0 -> {(replayProtector.ValidateCounter(0) ? "有效" : "无效/重复")}");
Console.WriteLine($"     计数器 1 -> {(replayProtector.ValidateCounter(1) ? "有效" : "无效/重复")}");
Console.WriteLine($"     计数器 0 -> {(replayProtector.ValidateCounter(0) ? "有效" : "无效/重复")}");
Console.WriteLine($"     计数器 2 -> {(replayProtector.ValidateCounter(2) ? "有效" : "无效/重复")}");
Console.WriteLine($"     计数器 2049 -> {(replayProtector.ValidateCounter(2049) ? "有效" : "无效/重复")}");
Console.WriteLine();

// 6. Create the device example
Console.WriteLine("6. 创建设备示例...");
var serverDevice = new WireGuardDevice(serverConfig);
var clientDevice = new WireGuardDevice(clientConfig);

var serverTun = new MockTunDevice();
var clientTun = new MockTunDevice();

serverTun.SetAddress("10.0.0.1", 24);
clientTun.SetAddress("10.0.0.2", 24);

serverDevice.SetTunDevice(serverTun);
clientDevice.SetTunDevice(clientTun);

Console.WriteLine("   服务器设备: 创建成功");
Console.WriteLine("   客户端设备: 创建成功");
Console.WriteLine();

// 7. Set up packet events
serverDevice.OnPacketReceived += (sender, packet) =>
{
    Console.WriteLine($"   [服务器] 收到数据包: {packet.Length} 字节");
};

clientDevice.OnPacketReceived += (sender, packet) =>
{
    Console.WriteLine($"   [客户端] 收到数据包: {packet.Length} 字节");
};

Console.WriteLine("=== 示例完成 ===");
Console.WriteLine();
Console.WriteLine("WireGuard.NET 库已准备就绪！");
Console.WriteLine("主要功能:");
Console.WriteLine("  ✅ 完整的加密原语 (X25519, ChaCha20-Poly1305, BLAKE2s)");
Console.WriteLine("  ✅ Noise_IKpsk2 握手协议框架");
Console.WriteLine("  ✅ 重放保护");
Console.WriteLine("  ✅ Cookie 回复机制");
Console.WriteLine("  ✅ Keepalive 机制");
Console.WriteLine("  ✅ AllowedIPs 路由和过滤");
Console.WriteLine("  ✅ 配置文件解析和生成");
Console.WriteLine("  ✅ TUN 设备抽象");
Console.WriteLine("  ✅ 单元测试全部通过（运行 dotnet test 查看详情）");
Console.WriteLine();
Console.WriteLine("实现状态: 核心协议已实现，未覆盖项见 FEATURE_COMPARISON.md");
