using System;
using System.Diagnostics.CodeAnalysis;
#pragma warning disable CASKET001
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Casket.Internals.Wire;

namespace Casket;

[Experimental("CASKET001")]
public static class CasketStream
{
    public static Task SealAsync(
        Stream plaintext, Stream destination,
        ReadOnlySpan<byte> key,
        ushort keyId = 0,
        CasketOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        var o = options ?? new CasketOptions();
        o.KeyPolicy?.RecordSeal();
        return StreamTokenLayout.SealAsync(
            plaintext, destination, key.ToArray(),
            (byte)o.Algorithm, (byte)CasketKdf.None, keyId,
            0, 0, 0, o.ChunkSize, cancellationToken);
    }

    public static Task UnsealAsync(
        Stream source, Stream destination,
        ReadOnlySpan<byte> key,
        CasketOptions? options = null,
        CancellationToken cancellationToken = default)
        => StreamTokenLayout.UnsealAsync(source, destination, key.ToArray(), cancellationToken);

    public static async Task SealAsync(
        Stream plaintext, Stream destination,
        IAsyncCasketKeySource keySource,
        CasketOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        var o = options ?? new CasketOptions();
        o.KeyPolicy?.RecordSeal();
        ReadOnlyMemory<byte> key = await keySource.GetKeyAsync(cancellationToken).ConfigureAwait(false);
        await StreamTokenLayout.SealAsync(
            plaintext, destination, key.ToArray(),
            (byte)o.Algorithm, (byte)CasketKdf.None, keySource.KeyId,
            0, 0, 0, o.ChunkSize, cancellationToken).ConfigureAwait(false);
    }

    public static async Task UnsealAsync(
        Stream source, Stream destination,
        IAsyncCasketKeySource keySource,
        CasketOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        ReadOnlyMemory<byte> key = await keySource.GetKeyAsync(cancellationToken).ConfigureAwait(false);
        await StreamTokenLayout.UnsealAsync(source, destination, key.ToArray(), cancellationToken).ConfigureAwait(false);
    }

    public static Task SealAsync(
        Stream plaintext, Stream destination,
        string password,
        CasketOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        var o = options ?? new CasketOptions();
        o.KeyPolicy?.RecordSeal();
        // Pass password as UTF-8 bytes; StreamTokenLayout derives the actual key internally
        byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
        return StreamTokenLayout.SealAsync(
            plaintext, destination, passwordBytes,
            (byte)o.Algorithm, (byte)o.Kdf, 0,
            o.Argon2MemoryKiB, o.Argon2Iterations, o.Argon2Parallelism,
            o.ChunkSize, cancellationToken);
    }

    public static Task UnsealAsync(
        Stream source, Stream destination,
        string password,
        CasketOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
        return StreamTokenLayout.UnsealAsync(source, destination, passwordBytes, cancellationToken);
    }
}
