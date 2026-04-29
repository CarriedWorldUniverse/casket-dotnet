using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Casket.Internals.Wire;

namespace Casket;

public sealed class CasketKeyRing
{
    private readonly List<ICasketKeySource> _syncSources = new();
    private readonly List<IAsyncCasketKeySource> _asyncSources = new();
    private readonly List<ushort> _keyIds = new();

    public CasketKeyRing Add(ICasketKeySource source)
    {
        if (source.KeyId == 0)
            throw new ArgumentException("KeyId must be non-zero when registering with a CasketKeyRing.", nameof(source));
        if (_keyIds.Contains(source.KeyId))
            throw new ArgumentException($"Key ID 0x{source.KeyId:X4} is already registered.", nameof(source));
        _syncSources.Add(source);
        _keyIds.Add(source.KeyId);
        return this;
    }

    public CasketKeyRing Add(IAsyncCasketKeySource source)
    {
        if (source.KeyId == 0)
            throw new ArgumentException("KeyId must be non-zero when registering with a CasketKeyRing.", nameof(source));
        if (_keyIds.Contains(source.KeyId))
            throw new ArgumentException($"Key ID 0x{source.KeyId:X4} is already registered.", nameof(source));
        _asyncSources.Add(source);
        _keyIds.Add(source.KeyId);
        return this;
    }

    public IReadOnlyList<ushort> RegisteredKeyIds => _keyIds;

    public string Unseal(string token)
    {
        byte[] tokenBytes = Casket.FromBase64Url(token);
        var (kdf, keyId) = BlobTokenLayout.PeekHeader(tokenBytes);
        if (kdf != CasketKdf.None) throw new CasketDecryptionException();

        if (keyId != 0)
        {
            ICasketKeySource? src = _syncSources.Find(s => s.KeyId == keyId);
            if (src is null) throw new CasketKeyNotFoundException(keyId);
            return TryUnsealSync(tokenBytes, src);
        }

        // Anonymous — try all sync sources
        foreach (var src in _syncSources)
        {
            try { return TryUnsealSync(tokenBytes, src); }
            catch (CasketDecryptionException) { }
        }
        throw new CasketKeyNotFoundException(0);
    }

    public async ValueTask<string> UnsealAsync(string token, CancellationToken cancellationToken = default)
    {
        byte[] tokenBytes = Casket.FromBase64Url(token);
        var (kdf, keyId) = BlobTokenLayout.PeekHeader(tokenBytes);
        if (kdf != CasketKdf.None) throw new CasketDecryptionException();

        if (keyId != 0)
        {
            IAsyncCasketKeySource? asyncSrc = _asyncSources.Find(s => s.KeyId == keyId);
            if (asyncSrc is not null)
            {
                ReadOnlyMemory<byte> k = await asyncSrc.GetKeyAsync(cancellationToken).ConfigureAwait(false);
                byte[] pt = BlobTokenLayout.UnsealRawKey(tokenBytes, k.Span);
                return Encoding.UTF8.GetString(pt);
            }
            ICasketKeySource? syncSrc = _syncSources.Find(s => s.KeyId == keyId);
            if (syncSrc is not null) return TryUnsealSync(tokenBytes, syncSrc);
            throw new CasketKeyNotFoundException(keyId);
        }

        foreach (var src in _syncSources)
        {
            try { return TryUnsealSync(tokenBytes, src); }
            catch (CasketDecryptionException) { }
        }
        foreach (var src in _asyncSources)
        {
            try
            {
                ReadOnlyMemory<byte> k = await src.GetKeyAsync(cancellationToken).ConfigureAwait(false);
                byte[] pt = BlobTokenLayout.UnsealRawKey(tokenBytes, k.Span);
                return Encoding.UTF8.GetString(pt);
            }
            catch (CasketDecryptionException) { }
        }
        throw new CasketKeyNotFoundException(0);
    }

    private static string TryUnsealSync(byte[] tokenBytes, ICasketKeySource src)
    {
        ReadOnlyMemory<byte> k = src.GetKey();
        byte[] pt = BlobTokenLayout.UnsealRawKey(tokenBytes, k.Span);
        return Encoding.UTF8.GetString(pt);
    }
}
