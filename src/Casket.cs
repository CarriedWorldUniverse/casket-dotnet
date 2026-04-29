using System;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Casket.Internals.Wire;

namespace Casket;

public static class Casket
{
    public static string Seal(string plaintext, string password, CasketOptions? options = null)
    {
        var o = options ?? new CasketOptions();
        o.KeyPolicy?.RecordSeal();
        byte[] token = BlobTokenLayout.SealPassword(
            Encoding.UTF8.GetBytes(plaintext), password,
            o.Algorithm, o.Kdf, o.Argon2MemoryKiB, o.Argon2Iterations, o.Argon2Parallelism);
        return Base64Url(token);
    }

    public static string Unseal(string token, string password)
    {
        byte[] tokenBytes = FromBase64Url(token);
        byte[] plaintext = BlobTokenLayout.UnsealPassword(tokenBytes, password);
        return Encoding.UTF8.GetString(plaintext);
    }

    public static string Seal(string plaintext, ICasketKeySource keySource, CasketOptions? options = null)
    {
        var o = options ?? new CasketOptions();
        o.KeyPolicy?.RecordSeal();
        ReadOnlyMemory<byte> key = keySource.GetKey();
        byte[] token = BlobTokenLayout.SealRawKey(
            Encoding.UTF8.GetBytes(plaintext), key.Span, o.Algorithm, keySource.KeyId);
        return Base64Url(token);
    }

    public static string Unseal(string token, ICasketKeySource keySource)
    {
        byte[] tokenBytes = FromBase64Url(token);
        ReadOnlyMemory<byte> key = keySource.GetKey();
        byte[] plaintext = BlobTokenLayout.UnsealRawKey(tokenBytes, key.Span);
        return Encoding.UTF8.GetString(plaintext);
    }

    public static async ValueTask<string> SealAsync(
        string plaintext,
        IAsyncCasketKeySource keySource,
        CasketOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        var o = options ?? new CasketOptions();
        o.KeyPolicy?.RecordSeal();
        ReadOnlyMemory<byte> key = await keySource.GetKeyAsync(cancellationToken).ConfigureAwait(false);
        byte[] token = BlobTokenLayout.SealRawKey(
            Encoding.UTF8.GetBytes(plaintext), key.Span, o.Algorithm, keySource.KeyId);
        return Base64Url(token);
    }

    public static async ValueTask<string> UnsealAsync(
        string token,
        IAsyncCasketKeySource keySource,
        CancellationToken cancellationToken = default)
    {
        byte[] tokenBytes = FromBase64Url(token);
        ReadOnlyMemory<byte> key = await keySource.GetKeyAsync(cancellationToken).ConfigureAwait(false);
        byte[] plaintext = BlobTokenLayout.UnsealRawKey(tokenBytes, key.Span);
        return Encoding.UTF8.GetString(plaintext);
    }

    public static string GenerateKey()
    {
        byte[] key = new byte[32];
        RandomNumberGenerator.Fill(key);
        return Base64Url(key);
    }

    internal static string Base64Url(byte[] bytes)
    {
        string b64 = Convert.ToBase64String(bytes);
        return b64.Replace('+', '-').Replace('/', '_').TrimEnd('=');
    }

    internal static byte[] FromBase64Url(string s)
    {
        string padded = s.Replace('-', '+').Replace('_', '/');
        int mod = padded.Length % 4;
        if (mod == 2) padded += "==";
        else if (mod == 3) padded += "=";
        try { return Convert.FromBase64String(padded); }
        catch (FormatException ex) { throw new CasketDecryptionException(ex); }
    }
}
