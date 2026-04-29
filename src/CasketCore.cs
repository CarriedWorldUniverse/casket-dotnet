using System;
using Casket.Internals.Wire;

namespace Casket;

public static class CasketCore
{
    public static byte[] Seal(ReadOnlySpan<byte> plaintext, string password, CasketOptions? options = null)
    {
        var o = options ?? new CasketOptions();
        o.KeyPolicy?.RecordSeal();
        return BlobTokenLayout.SealPassword(plaintext, password, o.Algorithm, o.Kdf, o.Argon2MemoryKiB, o.Argon2Iterations, o.Argon2Parallelism);
    }

    public static byte[] Unseal(ReadOnlySpan<byte> token, string password)
        => BlobTokenLayout.UnsealPassword(token, password);

    public static byte[] Seal(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> key, ushort keyId = 0, CasketOptions? options = null)
    {
        var o = options ?? new CasketOptions();
        o.KeyPolicy?.RecordSeal();
        return BlobTokenLayout.SealRawKey(plaintext, key, o.Algorithm, keyId);
    }

    public static byte[] Unseal(ReadOnlySpan<byte> token, ReadOnlySpan<byte> key)
        => BlobTokenLayout.UnsealRawKey(token, key);
}
