# WireGuard.NET

一个使用纯 .NET（net10.0）实现的 WireGuard 协议库，包含协议核心、跨平台 TUN 设备适配、
`wg` / `wg-quick` 风格的命令行工具、示例程序与测试套件。

WireGuard.NET 在用户态完成 Noise_IKpsk2 握手、传输加密、重放保护和 Cookie 抗 DoS 处理，
可直接以库的形式集成到桌面应用、服务端程序或自定义 VPN 客户端中。

官方网站：<https://www.virtuamesh.com/>

## 特性

### 协议与加密

- X25519 密钥交换、ChaCha20-Poly1305 AEAD、BLAKE2s-256、HKDF
- Noise_IKpsk2 握手（发起 / 响应、预共享密钥 PSK 支持）
- Cookie 回复（type 3）与 MAC1/MAC2 校验
- 传输数据包（type 4）加解密与密钥安装
- 重放保护（8128 包滑动窗口，与参考实现一致）
- 令牌桶速率限制（与参考实现默认值一致）

### 连接与路由

- 握手重试 / 超时、会话密钥轮换（rekey / reject 计时器）
- 持久化 Keepalive 与被动 Keepalive
- AllowedIPs 过滤（IPv4 / IPv6 前缀匹配）
- 运行时对等节点管理：`AddPeer` / `UpdatePeer` / `RemovePeer`
- 状态查询：`GetStatus`、`GetPeer`、`GetAllPeers`，以及 Rx/Tx 字节统计、最后握手时间
- 端点更新（对端 IP 变化）、UDP 死链路检测与直连探测
- 可选的分组压缩（`WireGuard.NET.Compression`，超过阈值的报文才压缩）
- STUN 端点发现（复用 WireGuard 自身的 UDP socket，便于 NAT 穿越）

### TUN 设备

| 平台 | 实现 |
| --- | --- |
| Windows | Wintun（`WindowsWintunDevice`） |
| Linux | `/dev/net/tun`（`LinuxTunDevice`） |
| macOS | `utun`（`MacOSUtunDevice`） |
| 测试 | `MockTunDevice` |

`TunDeviceFactory` 负责按当前平台选择实现，`MockTunDevice` 使测试无需管理员权限即可运行。

### 命令行工具

`WireGuard.NET.CLI` 提供：

- `genkey`、`pubkey`、`genpsk`、`genconfig`、`showconfig`、`verifyconfig`、`show`、`version`
- `wg-quick` 子集：`up`、`down`、`save`、`strip`

其中 `show` 为占位命令：CLI 无法跨进程查询运行中的设备，库内请使用 `GetStatus()` / `GetPeer()` / `GetAllPeers()`。

## 项目结构

```
WireGuard.NET/
├── WireGuard.NET/            # 主库：Crypto / Protocol / Tun / Config / Compression
├── WireGuard.NET.CLI/        # 命令行工具
├── WireGuard.NET.Samples/    # 示例程序
├── WireGuard.NET.Tests/      # 单元与集成测试
├── Directory.Build.props     # 仓库级共享属性（统一版本号）
├── FEATURE_COMPARISON.md     # 协议/工具实现状态说明
├── LICENSE                   # GNU General Public License v3.0
└── README.md
```

## 快速开始

### 环境要求

- .NET 10 SDK
- Windows：`wintun.dll` 需位于应用程序目录
- Linux：进程需要有 `/dev/net/tun` 的读写权限
- macOS：进程需要创建并配置 `utun` 接口的权限

### 构建

仓库未提供解决方案文件，直接构建需要的项目即可：

```powershell
dotnet build WireGuard.NET/WireGuard.NET.csproj
dotnet build WireGuard.NET.CLI/WireGuard.NET.CLI.csproj
```

### 作为库使用

```csharp
using System.Net;
using WireGuard.NET;
using WireGuard.NET.Keys;
using WireGuard.NET.Protocol;

var config = new WireGuardConfig
{
    PrivateKey = KeyPair.Generate().PrivateKey,
    ListenPort = 51820,
    Address = IPAddress.Parse("10.0.0.1")
};

config.Peers.Add(new PeerConfig
{
    PublicKey = peerPublicKey,
    Endpoint = new IPEndPoint(IPAddress.Parse("1.2.3.4"), 51820),
    AllowedIPs = { new IPNetwork { Address = IPAddress.Parse("10.0.0.0"), PrefixLength = 24 } },
    PersistentKeepalive = 25
});

using var device = new WireGuardDevice(config);
device.CreateTunDevice();          // 按当前平台创建 Wintun / tun / utun
await device.StartAsync();

device.OnPacketReceived += (_, packet) =>
    Console.WriteLine($"收到 {packet.Length} 字节");

var status = device.GetStatus();
Console.WriteLine(status);

device.Stop();
```

配置文件解析与生成：

```csharp
using WireGuard.NET.Config;

var config = WireGuardConfigParser.Parse(await File.ReadAllTextAsync("wg0.conf"));
await File.WriteAllTextAsync("wg0.conf", WireGuardConfigParser.Generate(config));
```

### 使用 CLI

```powershell
# 生成密钥
dotnet run --project WireGuard.NET.CLI -- genkey

# 由私钥推导公钥
dotnet run --project WireGuard.NET.CLI -- pubkey --private-key "<base64-private-key>"

# 生成一对示例配置（wg0.conf 与 wg0.client.conf）
dotnet run --project WireGuard.NET.CLI -- genconfig --output wg0.conf

# 校验 / 查看配置
dotnet run --project WireGuard.NET.CLI -- verifyconfig --config wg0.conf
dotnet run --project WireGuard.NET.CLI -- showconfig --config wg0.conf
```

### 运行测试

```powershell
dotnet test WireGuard.NET.Tests/WireGuard.NET.Tests.csproj
```

测试覆盖加密原语、握手状态机、重放保护、速率限制、AllowedIPs、配置解析、设备启停等；
其中重放保护、速率限制与 AllowedIPs 的用例移植自官方 WireGuard-Go。

## 平台支持

- 已完成：Windows、Linux、macOS
- 尚未实现：BSD、Android、iOS

更细粒度的实现状态与已知缺口见 [FEATURE_COMPARISON.md](FEATURE_COMPARISON.md)。

## 参与贡献

欢迎提交 Issue 与 Pull Request。提交前请确保：

1. `dotnet test` 全部通过；
2. 新增协议行为尽量附带测试；
3. 代码风格与现有实现保持一致。

## 许可协议

本项目采用 [GNU General Public License v3.0](LICENSE)（GPL-3.0）授权。

用通俗的语言概括（以 [LICENSE](LICENSE) 原文为准）：

- **个人使用与修改**：允许，无需取得额外授权。
- **商业使用**：允许，无需事先声明或向作者报备。
- **衍生作品必须开源**：如果你基于本项目修改、链接或以其他方式形成衍生作品并**对外分发**，
  则该作品整体必须以 GPL-3.0（或与之兼容的协议）开源，并提供完整的对应源代码。
- **保留声明**：分发时需保留版权声明与许可证文本，且不得对 GPL-3.0 附加额外限制。

说明：GPL-3.0 的源码开放义务由「分发」触发；仅在组织内部使用、不对外分发二进制或源码时，
不产生对外开源义务（这一点与 AGPL 不同）。

Copyright (C) 2026 VirtuaMesh

## 免责声明

本项目是 WireGuard 协议的独立实现，与 WireGuard 官方项目无隶属关系。
尽管已通过官方测试用例，生产环境使用前仍请进行充分测试与安全审查。
