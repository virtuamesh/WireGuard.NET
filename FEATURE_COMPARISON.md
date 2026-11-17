# WireGuard.NET — Implementation Status

This document tracks which parts of the WireGuard protocol and the surrounding tooling are
implemented by the library. It is descriptive, not a benchmark: it states what exists in the
source tree and which behaviours are covered by tests.

Last reviewed: 2026-11-17 (test suite: 221 passing, 1 skipped).

## Protocol and cryptography

| Area | Status | Notes |
| --- | --- | --- |
| X25519 key agreement | Implemented | Public/private key pairs, shared secret derivation |
| ChaCha20-Poly1305 AEAD | Implemented | RFC 8439 AEAD used by the transport layer |
| BLAKE2s-256 | Implemented | Hashing and keyed MAC primitives |
| HKDF | Implemented | Key derivation for handshake and transport keys |
| Noise_IKpsk2 handshake | Implemented | Initiation (type 1), response (type 2), PSK support |
| Cookie reply (type 3) | Implemented | MAC1/MAC2 validation and cookie generation |
| Transport data (type 4) | Implemented | Nonce handling and transport key installation |
| Replay protection | Implemented | Sliding window, 8128-packet window as in the protocol |
| Rate limiting | Implemented | Token bucket, matching the reference implementation's defaults |
| Keepalive | Implemented | Persistent keepalive and passive keepalive timers |
| Handshake retry/timeout | Implemented | `HandshakeManager` |
| Key rotation | Implemented | `KeyRotationManager` (rekey/reject timers and message counters) |
| AllowedIPs filtering | Implemented | IPv4 and IPv6 prefix matching |
| Configuration parsing | Implemented | `wg0.conf`-style `[Interface]` / `[Peer]` files |

## TUN devices

| Platform | Status | Notes |
| --- | --- | --- |
| Windows | Implemented | Wintun-based device, adapter/route/MTU configuration |
| Linux | Implemented | `/dev/net/tun` |
| macOS | Implemented | `utun` control socket |
| BSD / Android / iOS | Not implemented | Contributions welcome |

`TunDeviceFactory` selects the platform implementation, and `MockTunDevice` supports tests
without elevated privileges.

## Tooling and runtime management

| Area | Status | Notes |
| --- | --- | --- |
| CLI (`genkey`, `pubkey`, `genpsk`, `genconfig`, `showconfig`, `verifyconfig`, `show`, `version`) | Implemented | `WireGuard.NET.CLI`; `show` is a stub that prints guidance (no cross-process query) |
| `wg-quick` subset (`up`, `down`, `save`, `strip`) | Implemented | DNS and firewall integration are not covered |
| Runtime peer management (`AddPeer`, `RemovePeer`, `UpdatePeer`) | Implemented | No restart required |
| Status queries (`GetStatus`, `GetPeer`, `GetAllPeers`) | Implemented | `DeviceStatus` / `PeerStatus` models |
| Connection monitoring | Implemented | `ConnectionManager` (timeouts, endpoint updates) |

## Not implemented

- Kernel-module integration (the library drives a user-space TUN device instead).
- Full `wg-quick` feature parity (DNS, firewall rules, routing policy scripts).
- BSD, Android and iOS TUN back-ends.
- System-wide network stack integration.

## Platform prerequisites

- **Windows**: `wintun.dll` must be present in the application directory.
- **Linux**: the process needs read/write access to `/dev/net/tun`.
- **macOS**: the process needs access to create and configure `utun` interfaces.

## Reference material

- [WireGuard](https://www.wireguard.com/)
- [WireGuard whitepaper](https://www.wireguard.com/papers/wireguard.pdf)
- [WireGuard-Go](https://github.com/WireGuard/wireguard-go)
- [Noise Protocol Framework](http://noiseprotocol.org/noise.html)
