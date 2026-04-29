using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Casket;

public interface ICasketKeySource
{
    ReadOnlyMemory<byte> GetKey();
    ushort KeyId { get; }
}

public interface IAsyncCasketKeySource
{
    ValueTask<ReadOnlyMemory<byte>> GetKeyAsync(CancellationToken cancellationToken = default);
    ushort KeyId { get; }
}

public static class CasketKeySource
{
    public static ICasketKeySource FromEnvironmentVariable(string name = "CASKET_KEY", ushort keyId = 0)
    {
        string? value = Environment.GetEnvironmentVariable(name);
        if (value is null)
            throw new CasketConfigurationException($"Environment variable '{name}' is not set.");
        byte[] key = DecodeBase64Url(value, name);
        return new BytesKeySource(key, keyId);
    }

    public static ICasketKeySource FromFile(string path, ushort keyId = 0)
    {
        if (!File.Exists(path))
            throw new CasketConfigurationException($"Key file not found: {path}");
        string value = File.ReadAllText(path).Trim();
        byte[] key = DecodeBase64Url(value, path);
        return new BytesKeySource(key, keyId);
    }

    public static ICasketKeySource FromBytes(ReadOnlyMemory<byte> keyBytes, ushort keyId = 0)
    {
        if (keyBytes.Length != 32)
            throw new CasketConfigurationException($"Key must be exactly 32 bytes, got {keyBytes.Length}.");
        byte[] copy = keyBytes.ToArray();
        return new BytesKeySource(copy, keyId);
    }

    private static byte[] DecodeBase64Url(string value, string source)
    {
        string padded = value.Replace('-', '+').Replace('_', '/');
        int mod = padded.Length % 4;
        if (mod == 2) padded += "==";
        else if (mod == 3) padded += "=";
        byte[] key;
        try { key = Convert.FromBase64String(padded); }
        catch (Exception ex) { throw new CasketConfigurationException($"Key source '{source}' is not valid Base64Url.", ex); }
        if (key.Length != 32)
            throw new CasketConfigurationException($"Key source '{source}' decoded to {key.Length} bytes; expected 32.");
        return key;
    }

    private sealed class BytesKeySource : ICasketKeySource
    {
        private readonly byte[] _key;
        public ushort KeyId { get; }
        public BytesKeySource(byte[] key, ushort keyId) { _key = key; KeyId = keyId; }
        public ReadOnlyMemory<byte> GetKey() => _key;
    }
}
