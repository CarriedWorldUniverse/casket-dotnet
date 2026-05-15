# Casket.Net

[![CI](https://github.com/CarriedWorldUniverse/casket-dotnet/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/CarriedWorldUniverse/casket-dotnet/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/CarriedWorldUniverse/casket-dotnet?include_prereleases&sort=semver&display_name=tag)](https://github.com/CarriedWorldUniverse/casket-dotnet/releases)
[![License](https://img.shields.io/github/license/CarriedWorldUniverse/casket-dotnet)](LICENSE)

Authenticated encryption and Ed25519 channel identity for .NET.

- **AES-256-GCM** and **ChaCha20-Poly1305** with Argon2id key derivation
- **Channel** module: Ed25519/P-256 identity + ECDH E2E encryption for frame-to-frame relay
- Cross-compatible wire format with [`@nexus-cw/casket`](https://github.com/nexus-cw/casket-ts) (Node.js / Cloudflare Workers) and [`casket-go`](https://github.com/nexus-cw/casket-go)
- Targets `netstandard2.1`, `net8.0`, `net9.0`, `net10.0`

## Install

```
dotnet add package Casket.Net
```

## License

MIT
