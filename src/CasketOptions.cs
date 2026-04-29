using System;

namespace Casket;

public enum CasketAlgorithm : byte
{
    Aes256Gcm        = 0x01,
    ChaCha20Poly1305 = 0x02,
}

public enum CasketKdf : byte
{
    None        = 0x00,
    Argon2id    = 0x01,
    Pbkdf2Sha256 = 0x02,
}

public sealed class CasketOptions
{
    public CasketAlgorithm Algorithm { get; init; } = CasketAlgorithm.Aes256Gcm;
    public CasketKdf Kdf { get; init; } = CasketKdf.Argon2id;
    public uint Argon2MemoryKiB { get; init; } = 65536;
    public uint Argon2Iterations { get; init; } = 3;
    public ushort Argon2Parallelism { get; init; } = 1;
    public uint Pbkdf2Iterations { get; init; } = 600_000;
    public int ChunkSize { get; init; } = 65536;
    public CasketKeyPolicy? KeyPolicy { get; init; } = null;
}
