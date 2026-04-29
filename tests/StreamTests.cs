using System;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace Casket.Tests;

[Experimental("CASKET001")]
public class StreamTests
{
    [Fact]
    public async Task Stream_RoundTrip_SmallPayload()
    {
        byte[] key = new byte[32]; key[0] = 0x01;
        byte[] plaintext = Encoding.UTF8.GetBytes("Hello stream world!");

        using var input = new MemoryStream(plaintext);
        using var encrypted = new MemoryStream();
        await CasketStream.SealAsync(input, encrypted, key.AsSpan());

        encrypted.Position = 0;
        using var decrypted = new MemoryStream();
        await CasketStream.UnsealAsync(encrypted, decrypted, key.AsSpan());

        Assert.Equal(plaintext, decrypted.ToArray());
    }

    [Fact]
    public async Task Stream_RoundTrip_MultiChunk()
    {
        byte[] key = new byte[32]; key[0] = 0x02;
        byte[] plaintext = new byte[200_000];
        new Random(42).NextBytes(plaintext);

        var opts = new CasketOptions { ChunkSize = 65536 };
        using var input = new MemoryStream(plaintext);
        using var encrypted = new MemoryStream();
        await CasketStream.SealAsync(input, encrypted, key.AsSpan(), options: opts);

        encrypted.Position = 0;
        using var decrypted = new MemoryStream();
        await CasketStream.UnsealAsync(encrypted, decrypted, key.AsSpan());

        Assert.Equal(plaintext, decrypted.ToArray());
    }

    [Fact]
    public async Task Stream_TruncatedStream_Throws()
    {
        byte[] key = new byte[32]; key[0] = 0x03;
        byte[] plaintext = new byte[200_000];
        new Random(1).NextBytes(plaintext);

        var opts = new CasketOptions { ChunkSize = 65536 };
        using var input = new MemoryStream(plaintext);
        using var encrypted = new MemoryStream();
        await CasketStream.SealAsync(input, encrypted, key.AsSpan(), options: opts);

        // Truncate the stream — drop the last 100 bytes
        byte[] full = encrypted.ToArray();
        byte[] truncated = full[..^100];

        using var truncStream = new MemoryStream(truncated);
        using var output = new MemoryStream();

        await Assert.ThrowsAnyAsync<CasketException>(
            () => CasketStream.UnsealAsync(truncStream, output, key.AsSpan()));
    }

    [Fact]
    public async Task Stream_EmptyPayload_RoundTrip()
    {
        byte[] key = new byte[32]; key[0] = 0x04;
        using var input = new MemoryStream(Array.Empty<byte>());
        using var encrypted = new MemoryStream();
        await CasketStream.SealAsync(input, encrypted, key.AsSpan());

        encrypted.Position = 0;
        using var decrypted = new MemoryStream();
        await CasketStream.UnsealAsync(encrypted, decrypted, key.AsSpan());

        Assert.Empty(decrypted.ToArray());
    }

    [Fact]
    public async Task Stream_WrongKey_Throws()
    {
        byte[] key1 = new byte[32]; key1[0] = 0x01;
        byte[] key2 = new byte[32]; key2[0] = 0x02;
        byte[] plaintext = Encoding.UTF8.GetBytes("test data");

        using var input = new MemoryStream(plaintext);
        using var encrypted = new MemoryStream();
        await CasketStream.SealAsync(input, encrypted, key1.AsSpan());

        encrypted.Position = 0;
        using var output = new MemoryStream();
        await Assert.ThrowsAsync<CasketDecryptionException>(
            () => CasketStream.UnsealAsync(encrypted, output, key2.AsSpan()));
    }
}
