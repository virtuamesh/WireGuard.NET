# WireGuard.NET

一个完整的 .NET 10.0 WireGuard 协议实现库，使用成熟的加密库构建。

## 特性

### ✅ 已实现功能

- **完整的加密原语**
  - X25519 (Curve25519) 密钥交换
  - ChaCha20-Poly1305 AEAD 加密
  - BLAKE2s-256 哈希
  - HKDF 密钥派生

- **Noise 协议框架**
  - Noise_IKpsk2 握手模式
  - 预共享密钥 (PSK) 支持
  - 完整的 Noise 状态机

- **安全机制**
  - 重放保护（滑动窗口，8128 大小，完美匹配官方算法）
  - Cookie 回复机制（DDoS 防护）
  - 速率限制器（令牌桶算法，完美匹配官方算法）
  - 完整的传输加密

- **连接管理**
  - Keepalive 机制（NAT 穿透）
  - WireGuardPeer 会话管理
  - AllowedIPs 路由和过滤（IPv4/IPv6）
  - 握手超时和重传
  - 连接超时检测
  - 端点更新（动态 IP）
  - 会话密钥轮换
  - Rx/Tx 字节统计
  - 最后握手时间

- **配置管理**
  - 完整的 wg0.conf 格式解析
  - 配置文件生成
  - 支持所有标准配置选项
  - 运行时配置更新（AddPeer/RemovePeer/UpdatePeer）
  - 状态查询和监控（GetStatus/GetPeer/GetAllPeers）

- **TUN 设备抽象**
  - ITunDevice 接口
  - MockTunDevice（用于测试）
  - WindowsWintunDevice（Windows 真实 TUN 设备）
  - LinuxTunDevice（Linux 真实 TUN 设备）
  - MacOSUtunDevice（macOS 真实 utun 设备）
  - TunDeviceFactory（跨平台工厂）

- **CLI 工具**
  - wg 基础命令（genkey/pubkey/genpsk/genconfig/showconfig/verifyconfig/show/version）
  - wg-quick 命令（up/down/save/strip）

- **完整的测试覆盖**
  - `dotnet test` 全部通过（当前 221 个通过、1 个跳过）
  - 涵盖所有核心功能
  - 官方 WireGuard-Go 重放保护测试完整移植并通过
  - 官方 WireGuard-Go 速率限制器测试完整移植并通过
  - 官方 WireGuard-Go AllowedIPs 测试完整移植并通过

## 快速开始

### 基本用法

```csharp
using WireGuard.NET;
using WireGuard.NET.Config;
using WireGuard.NET.Keys;
using WireGuard.NET.Protocol;
using WireGuard.NET.Tun;

// 1. 创建或加载配置
var config = new WireGuardConfig
{
    PrivateKey = KeyPair.Generate().PrivateKey,
    ListenPort = 51820,
    Address = System.Net.IPAddress.Parse("10.0.0.1")
};

// 添加对等节点
config.Peers.Add(new PeerConfig
{
    PublicKey = peerPublicKey,
    Endpoint = new System.Net.IPEndPoint(System.Net.IPAddress.Parse("1.2.3.4"), 51820),
    AllowedIPs = { new IPNetwork { Address = System.Net.IPAddress.Parse("10.0.0.2"), PrefixLength = 32 } },
    PersistentKeepalive = 25
});

// 2. 创建设备
var device = new WireGuardDevice(config);

// 3. 设置 TUN 设备
var tunDevice = TunDeviceFactory.CreateTunDevice();
tunDevice.SetAddress("10.0.0.1", 24);
device.SetTunDevice(tunDevice);

// 4. 启动设备
await device.StartAsync();

// 5. 处理接收到的数据包
device.OnPacketReceived += (sender, packet) =>
{
    Console.WriteLine($"Received packet: {packet.Length} bytes");
};

// 查询设备状态
var status = device.GetStatus();
Console.WriteLine($"Device status: {status}");

// 停止设备
device.Stop();
```

### 配置文件解析

```csharp
using WireGuard.NET.Config;

// 从文件解析
var configText = await File.ReadAllTextAsync("wg0.conf");
var config = WireGuardConfigParser.Parse(configText);

// 生成配置文件
var generatedConfig = WireGuardConfigParser.Generate(config);
await File.WriteAllTextAsync("wg0.conf", generatedConfig);
```

## 项目结构

```
WireGuard.NET/
├── WireGuard.NET/              # 主项目
│   ├── Crypto/                 # 加密算法实现
│   ├── Keys/                   # 密钥管理
│   ├── Protocol/               # WireGuard 协议核心
│   │   ├── Noise/              # Noise 协议框架
│   │   ├── ReplayProtector.cs
│   │   ├── CookieProtector.cs
│   │   ├── KeepaliveManager.cs
│   │   ├── RateLimiter.cs
│   │   ├── AllowedIPsFilter.cs
│   │   ├── WireGuardPeer.cs
│   │   ├── HandshakeManager.cs
│   │   ├── ConnectionManager.cs
│   │   ├── KeyRotationManager.cs
│   │   └── ...
│   ├── Tun/                    # TUN 设备抽象
│   │   ├── ITunDevice.cs
│   │   ├── MockTunDevice.cs
│   │   ├── WindowsWintunDevice.cs
│   │   ├── LinuxTunDevice.cs
│   │   ├── MacOSUtunDevice.cs
│   │   └── TunDeviceFactory.cs
│   ├── Config/                 # 配置管理
│   │   └── WireGuardConfigParser.cs
│   ├── Compression/            # 可选的分组压缩
│   ├── StunEndpointDiscovery.cs # STUN 端点发现
│   └── WireGuardDevice.cs      # 主设备类
├── WireGuard.NET.CLI/          # CLI 工具
├── WireGuard.NET.Samples/      # 示例项目
└── WireGuard.NET.Tests/        # 测试项目
```

## 依赖项

- [BouncyCastle.Cryptography](https://www.nuget.org/packages/BouncyCastle.Cryptography/) - X25519、ChaCha20-Poly1305 / XChaCha20-Poly1305 与 BLAKE2s

## 测试

```bash
cd WireGuard.NET.Tests
dotnet test
```

## 与官方 WireGuard 的对比

详细的功能对比请参见 [FEATURE_COMPARISON.md](../FEATURE_COMPARISON.md)。

**当前实现进度：核心协议与网络管理功能已实现；内核模块集成、完整 wg-quick（DNS/防火墙）、
BSD/Android/iOS TUN 后端等未覆盖项见上方功能对比。**

### 已实现
- ✅ 所有核心加密算法
- ✅ Noise_IKpsk2 协议框架
- ✅ 重放保护（完美匹配官方算法）
- ✅ 速率限制器（完美匹配官方算法）
- ✅ Cookie 回复
- ✅ Keepalive 机制
- ✅ AllowedIPs 过滤
- ✅ 配置文件解析
- ✅ TUN 设备抽象
- ✅ 真实 TUN 设备实现（Windows Wintun、Linux tun、macOS utun）
- ✅ 完整的握手状态机
- ✅ CLI 工具
- ✅ wg-quick 命令
- ✅ 运行时配置更新
- ✅ 状态查询和监控

## 平台支持

- ✅ **Windows** - 使用 Wintun 驱动
- ✅ **Linux** - 使用 /dev/net/tun 接口
- ✅ **macOS** - 使用 utun 设备
- ⏳ **BSD** - 待实现
- ⏳ **Android** - 待实现
- ⏳ **iOS** - 待实现

## 许可协议

本项目采用 [GNU General Public License v3.0](../LICENSE)（GPL-3.0）授权：
允许个人与商业使用、修改和分发；衍生作品对外分发时须同样以 GPL-3.0 开源并提供源代码。
完整条款见仓库根目录的 [LICENSE](../LICENSE)。

## 参考资料

- [WireGuard 官方网站](https://www.wireguard.com/)
- [WireGuard 白皮书](https://www.wireguard.com/papers/wireguard.pdf)
- [Noise 协议规范](http://noiseprotocol.org/noise.html)
- [WireGuard-Go 源代码](https://github.com/WireGuard/wireguard-go)

## 反馈

- 官方网站：<https://www.virtuamesh.com/>
- 邮箱：support@virtuamesh.com

## 免责声明

这是一个完整的 WireGuard 协议实现。虽然我们尽最大努力确保安全性并已通过官方测试，但在生产环境中使用前请进行充分测试和安全审查。
