using System;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
#if NET6_0_OR_GREATER
using NSec.Cryptography;
#endif

namespace Casket;

/// <summary>
/// Wire-format token exchanged out-of-band between two Frame operators.
/// Serialize with <see cref="CasketChannel.SerializePairingToken"/> for paste/QR.
/// The human IS the trust channel — no signature on the token itself.
/// </summary>
public sealed class CasketPairingToken
{
    public int V { get; init; } = 1;
    public string NexusId { get; init; } = "";
    /// <summary>base64url public key: 32-byte Ed25519 raw key on .NET 6+, SPKI P-256 on netstandard2.1.</summary>
    public string Pubkey { get; init; } = "";
    /// <summary>Signing algorithm: "ed25519" on .NET 6+, "p256" on netstandard2.1.</summary>
    public string SigAlg { get; init; } = "";
    /// <summary>base64url uncompressed ECDH P-256 public key (65 bytes: 0x04 || X || Y).</summary>
    public string DhPubkey { get; init; } = "";
    public string Endpoint { get; init; } = "";
    public string Nonce { get; init; } = "";
    public long Ts { get; init; }
}

/// <summary>Stored record for a paired peer.</summary>
public sealed class CasketPeerRecord
{
    public string NexusId { get; init; } = "";
    public string Pubkey { get; init; } = "";
    public string SigAlg { get; init; } = "";
    public string DhPubkey { get; init; } = "";
    public string Endpoint { get; init; } = "";
    public string PathId { get; init; } = "";
    public long PairedAt { get; init; }
}

/// <summary>
/// A Frame's local identity. One per Nexus instance.
/// Call <see cref="LoadAsync"/> on every cold start.
/// </summary>
public sealed class CasketChannel : IDisposable
{
    private const string SigPrivKey = "casket:channel:sig_private_key";
    private const string SigPubKey  = "casket:channel:sig_public_key";
    private const string DhPrivKey  = "casket:channel:dh_private_key";
    private const string DhPubKey   = "casket:channel:dh_public_key";
    private const string PeerPrefix = "casket:peers:";

    private readonly string _nexusId;
    private readonly byte[] _sigPrivateKeyBytes;  // Ed25519 seed (32B) on .NET 6+, PKCS8 P-256 on netstandard2.1
    private readonly byte[] _sigPublicKeyBytes;   // Ed25519 raw pub (32B) on .NET 6+, SPKI P-256 on netstandard2.1
    private readonly byte[] _dhPrivateKeyBytes;   // PKCS8 P-256
    private readonly byte[] _dhPublicKeyBytes;    // raw 65-byte uncompressed P-256
    private readonly ICasketChannelStorage _storage;
    private bool _disposed;

    private CasketChannel(
        string nexusId,
        byte[] sigPriv, byte[] sigPub,
        byte[] dhPriv,  byte[] dhPub,
        ICasketChannelStorage storage)
    {
        _nexusId = nexusId;
        _sigPrivateKeyBytes = sigPriv;
        _sigPublicKeyBytes  = sigPub;
        _dhPrivateKeyBytes  = dhPriv;
        _dhPublicKeyBytes   = dhPub;
        _storage = storage;
    }

    public static async ValueTask<CasketChannel> LoadAsync(
        string nexusId,
        ICasketChannelStorage storage,
        CancellationToken cancellationToken = default)
    {
        string? storedSigPriv = await storage.GetAsync(SigPrivKey, cancellationToken).ConfigureAwait(false);
        string? storedSigPub  = await storage.GetAsync(SigPubKey,  cancellationToken).ConfigureAwait(false);
        string? storedDhPriv  = await storage.GetAsync(DhPrivKey,  cancellationToken).ConfigureAwait(false);
        string? storedDhPub   = await storage.GetAsync(DhPubKey,   cancellationToken).ConfigureAwait(false);

        if (storedSigPriv != null && storedSigPub != null && storedDhPriv != null && storedDhPub != null)
        {
            return new CasketChannel(nexusId,
                B64uDecode(storedSigPriv), B64uDecode(storedSigPub),
                B64uDecode(storedDhPriv),  B64uDecode(storedDhPub),
                storage);
        }

        // First run — generate both keypairs.
        byte[] sigPriv, sigPub;
#if NET6_0_OR_GREATER
        var ed25519 = SignatureAlgorithm.Ed25519;
        using (var sigKey = Key.Create(ed25519, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport }))
        {
            sigPriv = sigKey.Export(KeyBlobFormat.RawPrivateKey);
            sigPub  = sigKey.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        }
#else
        using (var ecdsa = CreateSigningKey())
        {
            sigPriv = ecdsa.ExportPkcs8PrivateKey();
            sigPub  = ecdsa.ExportSubjectPublicKeyInfo();
        }
#endif

        byte[] dhPriv, dhPubRaw;
        using (var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256))
        {
            dhPriv  = ecdh.ExportPkcs8PrivateKey();
            dhPubRaw = ExportEcdhPublicKeyRaw(ecdh);
        }

        await storage.PutAsync(SigPrivKey, B64uEncode(sigPriv),  cancellationToken).ConfigureAwait(false);
        await storage.PutAsync(SigPubKey,  B64uEncode(sigPub),   cancellationToken).ConfigureAwait(false);
        await storage.PutAsync(DhPrivKey,  B64uEncode(dhPriv),   cancellationToken).ConfigureAwait(false);
        await storage.PutAsync(DhPubKey,   B64uEncode(dhPubRaw), cancellationToken).ConfigureAwait(false);

        return new CasketChannel(nexusId, sigPriv, sigPub, dhPriv, dhPubRaw, storage);
    }

    public string NexusId        => _nexusId;
    public string PublicKeyB64u  => B64uEncode(_sigPublicKeyBytes);
    public string DhPublicKeyB64u => B64uEncode(_dhPublicKeyBytes);
#if NET6_0_OR_GREATER
    public const string SigAlgId = "ed25519";
#else
    public const string SigAlgId = "p256";
#endif

    public CasketPairingToken MakePairingToken(string endpoint)
    {
        byte[] nonce = new byte[16];
        RandomNumberGenerator.Fill(nonce);
        return new CasketPairingToken
        {
            V        = 1,
            NexusId  = _nexusId,
            Pubkey   = PublicKeyB64u,
            SigAlg   = SigAlgId,
            DhPubkey = DhPublicKeyB64u,
            Endpoint = endpoint,
            Nonce    = B64uEncode(nonce),
            Ts       = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
        };
    }

    public static string SerializePairingToken(CasketPairingToken token)
    {
        string json = JsonSerializer.Serialize(token, CasketChannelJsonContext.Default.CasketPairingToken);
        return B64uEncode(Encoding.UTF8.GetBytes(json));
    }

    public static CasketPairingToken DeserializePairingToken(string blob)
    {
        byte[] json = B64uDecode(blob);
        return JsonSerializer.Deserialize(json, CasketChannelJsonContext.Default.CasketPairingToken)
               ?? throw new CasketChannelPairException("Invalid pairing token blob.");
    }

    public async ValueTask<CasketPairedChannel> PairAsync(
        CasketPairingToken token,
        int maxAgeSeconds = 86400,
        CancellationToken cancellationToken = default)
    {
        long age = DateTimeOffset.UtcNow.ToUnixTimeSeconds() - token.Ts;
        if (age > maxAgeSeconds || age < -300)
            throw new CasketChannelPairException($"Pairing token is too old or from the future (age={age}s).");

        byte[] peerDhPubRaw = B64uDecode(token.DhPubkey);
        if (peerDhPubRaw.Length != 65)
            throw new CasketChannelPairException("Peer ECDH public key must be 65 bytes (uncompressed P-256).");

        byte[] peerSigPub = B64uDecode(token.Pubkey);
        string pathId   = ComputePathId(_sigPublicKeyBytes, peerSigPub);
        byte[] sharedKey = DeriveSharedKey(_dhPrivateKeyBytes, peerDhPubRaw);

        var record = new CasketPeerRecord
        {
            NexusId  = token.NexusId,
            Pubkey   = token.Pubkey,
            SigAlg   = token.SigAlg,
            DhPubkey = token.DhPubkey,
            Endpoint = token.Endpoint,
            PathId   = pathId,
            PairedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
        };
        string json = JsonSerializer.Serialize(record, CasketChannelJsonContext.Default.CasketPeerRecord);
        await _storage.PutAsync($"{PeerPrefix}{token.NexusId}", json, cancellationToken).ConfigureAwait(false);

        return new CasketPairedChannel(_sigPrivateKeyBytes, record, sharedKey);
    }

    public async ValueTask<CasketPairedChannel?> GetPairedAsync(
        string peerId,
        CancellationToken cancellationToken = default)
    {
        string? raw = await _storage.GetAsync($"{PeerPrefix}{peerId}", cancellationToken).ConfigureAwait(false);
        if (raw is null) return null;

        var record = JsonSerializer.Deserialize(raw, CasketChannelJsonContext.Default.CasketPeerRecord)
                     ?? throw new CasketConfigurationException("Corrupt peer record in storage.");
        byte[] sharedKey = DeriveSharedKey(_dhPrivateKeyBytes, B64uDecode(record.DhPubkey));
        return new CasketPairedChannel(_sigPrivateKeyBytes, record, sharedKey);
    }

    public ValueTask RevokeAsync(string peerId, CancellationToken cancellationToken = default)
        => _storage.DeleteAsync($"{PeerPrefix}{peerId}", cancellationToken);

    // ── Private helpers ──────────────────────────────────────────────────────

    // netstandard2.1 fallback only — Ed25519 CNG gap means P-256 is used there.
    // On .NET 6+ we use NSec.Cryptography (libsodium) for Ed25519.
#if !NET6_0_OR_GREATER
    private static ECDsa CreateSigningKey()
        => ECDsa.Create(ECCurve.NamedCurves.nistP256);
#endif

    private static byte[] DeriveSharedKey(byte[] dhPrivBytes, byte[] peerDhPubRaw)
    {
        using var local = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        local.ImportPkcs8PrivateKey(dhPrivBytes, out _);

        var ecParams = new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint { X = peerDhPubRaw[1..33], Y = peerDhPubRaw[33..65] }
        };
        using var peerEc = ECDiffieHellman.Create(ecParams);

#if NET5_0_OR_GREATER
        byte[] rawSecret = local.DeriveRawSecretAgreement(peerEc.PublicKey);
#else
        // netstandard2.1: use DeriveKeyMaterial with no KDF and extract via SHA-256
        byte[] rawSecret = local.DeriveKeyFromHash(peerEc.PublicKey, HashAlgorithmName.SHA256);
        // DeriveKeyFromHash already applies the hash, but we want the raw point X
        // so we fall back to a manual approach using DeriveKeyMaterial
        rawSecret = DeriveRawSecretNetStd(local, peerEc);
#endif

        return HkdfSha256(rawSecret, Encoding.UTF8.GetBytes("nexus-casket-channel-v1"));
    }

#if !NET5_0_OR_GREATER
    private static byte[] DeriveRawSecretNetStd(ECDiffieHellman local, ECDiffieHellman peer)
    {
        // On netstandard2.1 there's no DeriveRawSecretAgreement.
        // Use DeriveKeyFromHash with SHA256 over just the shared X coordinate.
        // This matches what HKDF-Extract does when using the shared secret as IKM.
        return local.DeriveKeyFromHash(peer.PublicKey, HashAlgorithmName.SHA256, null, null);
    }
#endif

    private static byte[] HkdfSha256(byte[] ikm, byte[] info, int outputLength = 32)
    {
        byte[] salt = new byte[32];
        using var hmacExtract = new HMACSHA256(salt);
        byte[] prk = hmacExtract.ComputeHash(ikm);
        byte[] block1Input = new byte[info.Length + 1];
        Buffer.BlockCopy(info, 0, block1Input, 0, info.Length);
        block1Input[info.Length] = 0x01;
        using var hmacExpand = new HMACSHA256(prk);
        byte[] okm = hmacExpand.ComputeHash(block1Input);
        if (outputLength == okm.Length) return okm;
        byte[] result = new byte[outputLength];
        Buffer.BlockCopy(okm, 0, result, 0, outputLength);
        return result;
    }

    private static string ComputePathId(byte[] pubA, byte[] pubB)
    {
        byte[] first, second;
        if (CompareBytes(pubA, pubB) <= 0) { first = pubA; second = pubB; }
        else                               { first = pubB;  second = pubA; }

        byte[] combined = new byte[first.Length + second.Length];
        Buffer.BlockCopy(first,  0, combined, 0,            first.Length);
        Buffer.BlockCopy(second, 0, combined, first.Length, second.Length);

#if NET5_0_OR_GREATER
        byte[] digest = SHA256.HashData(combined);
#else
        byte[] digest;
        using (var sha = SHA256.Create()) digest = sha.ComputeHash(combined);
#endif
        return $"nxc_{B64uEncode(digest)}";
    }

    private static int CompareBytes(byte[] a, byte[] b)
    {
        int len = Math.Min(a.Length, b.Length);
        for (int i = 0; i < len; i++)
            if (a[i] != b[i]) return a[i] - b[i];
        return a.Length - b.Length;
    }

    internal static byte[] ExportEcdhPublicKeyRaw(ECDiffieHellman ecdh)
    {
        ECParameters p = ecdh.ExportParameters(false);
        byte[] raw = new byte[65];
        raw[0] = 0x04;
        p.Q.X!.CopyTo(raw, 1);
        p.Q.Y!.CopyTo(raw, 33);
        return raw;
    }

    internal static string B64uEncode(byte[] data)
        => Convert.ToBase64String(data).Replace('+', '-').Replace('/', '_').TrimEnd('=');

    internal static byte[] B64uDecode(string s)
    {
        string p = s.Replace('-', '+').Replace('_', '/');
        int mod = p.Length % 4;
        if (mod == 2) p += "==";
        else if (mod == 3) p += "=";
        return Convert.FromBase64String(p);
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        CryptographicOperations.ZeroMemory(_sigPrivateKeyBytes);
        CryptographicOperations.ZeroMemory(_dhPrivateKeyBytes);
    }
}

/// <summary>
/// An active channel to a specific peer.
/// Obtained from <see cref="CasketChannel.PairAsync"/> or <see cref="CasketChannel.GetPairedAsync"/>.
/// </summary>
public sealed class CasketPairedChannel : IDisposable
{
    private const int NonceSize = 12;
    private const int TagSize   = 16;

    private readonly byte[] _sigPrivateKeyBytes;
    private readonly byte[] _sharedKey;
    private readonly CasketPeerRecord _peer;
    private bool _disposed;

    internal CasketPairedChannel(byte[] sigPriv, CasketPeerRecord peer, byte[] sharedKey)
    {
        _sigPrivateKeyBytes = sigPriv;
        _peer      = peer;
        _sharedKey = sharedKey;
    }

    public string PathId       => _peer.PathId;
    public string PeerId       => _peer.NexusId;
    public string PeerEndpoint => _peer.Endpoint;
    public CasketPeerRecord PeerRecord => _peer;

    /// <summary>
    /// Sign arbitrary bytes for the outer envelope.
    /// Pass UTF-8(JSON.Serialize(canonicalEnvelope, sortedKeys)).
    /// Returns base64url signature.
    /// </summary>
    public string Sign(ReadOnlySpan<byte> data)
    {
#if NET6_0_OR_GREATER
        var ed25519 = SignatureAlgorithm.Ed25519;
        using var sigKey = Key.Import(ed25519, _sigPrivateKeyBytes, KeyBlobFormat.RawPrivateKey);
        byte[] sig = ed25519.Sign(sigKey, data);
#else
        using var ecdsa = CreateAndImportSigning(_sigPrivateKeyBytes);
        byte[] sig = ecdsa.SignData(data.ToArray(), HashAlgorithmName.SHA256);
#endif
        return CasketChannel.B64uEncode(sig);
    }

    /// <summary>
    /// Verify a signature from the peer.
    /// Throws <see cref="CasketChannelVerifyException"/> on bad signature.
    /// </summary>
    public void Verify(string signatureB64u, ReadOnlySpan<byte> data)
    {
        byte[] sig     = CasketChannel.B64uDecode(signatureB64u);
        byte[] peerPub = CasketChannel.B64uDecode(_peer.Pubkey);
#if NET6_0_OR_GREATER
        var ed25519 = SignatureAlgorithm.Ed25519;
        var pubKey = PublicKey.Import(ed25519, peerPub, KeyBlobFormat.RawPublicKey);
        bool valid = ed25519.Verify(pubKey, data, sig);
#else
        using var ecdsa = ImportVerifyKey(peerPub);
        bool valid = ecdsa.VerifyData(data.ToArray(), sig, HashAlgorithmName.SHA256);
#endif
        if (!valid) throw new CasketChannelVerifyException();
    }

    /// <summary>
    /// Encrypt the message body (inner layer).
    /// Returns base64url: nonce (12) || tag (16) || ciphertext.
    /// </summary>
    public string EncryptBody(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> aad = default)
    {
        byte[] nonce = new byte[NonceSize];
        RandomNumberGenerator.Fill(nonce);
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag        = new byte[TagSize];

#if NET8_0_OR_GREATER
        using var aesGcm = new AesGcm(_sharedKey, TagSize);
#else
        using var aesGcm = new AesGcm(_sharedKey);
#endif
        aesGcm.Encrypt(nonce, plaintext, ciphertext, tag, aad.IsEmpty ? ReadOnlySpan<byte>.Empty : aad);

        byte[] result = new byte[NonceSize + TagSize + ciphertext.Length];
        Buffer.BlockCopy(nonce,      0, result, 0,                  NonceSize);
        Buffer.BlockCopy(tag,        0, result, NonceSize,           TagSize);
        Buffer.BlockCopy(ciphertext, 0, result, NonceSize + TagSize, ciphertext.Length);
        return CasketChannel.B64uEncode(result);
    }

    /// <summary>
    /// Decrypt a body produced by <see cref="EncryptBody"/>.
    /// Throws <see cref="CasketChannelDecryptException"/> if authentication fails.
    /// </summary>
    public byte[] DecryptBody(string ciphertextB64u, ReadOnlySpan<byte> aad = default)
    {
        byte[] blob = CasketChannel.B64uDecode(ciphertextB64u);
        if (blob.Length < NonceSize + TagSize)
            throw new CasketChannelDecryptException("Ciphertext too short.");

        ReadOnlySpan<byte> nonce      = blob.AsSpan(0, NonceSize);
        ReadOnlySpan<byte> tag        = blob.AsSpan(NonceSize, TagSize);
        ReadOnlySpan<byte> ciphertext = blob.AsSpan(NonceSize + TagSize);
        byte[] plaintext = new byte[ciphertext.Length];

        try
        {
#if NET8_0_OR_GREATER
            using var aesGcm = new AesGcm(_sharedKey, TagSize);
#else
            using var aesGcm = new AesGcm(_sharedKey);
#endif
            aesGcm.Decrypt(nonce, ciphertext, tag, plaintext, aad.IsEmpty ? ReadOnlySpan<byte>.Empty : aad);
            return plaintext;
        }
        catch (CryptographicException ex)
        {
            throw new CasketChannelDecryptException(ex.Message);
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        CryptographicOperations.ZeroMemory(_sharedKey);
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

#if !NET6_0_OR_GREATER
    private static ECDsa CreateAndImportSigning(byte[] pkcs8)
    {
        var key = ECDsa.Create(ECCurve.NamedCurves.nistP256)!;
        key.ImportPkcs8PrivateKey(pkcs8, out _);
        return key;
    }

    private static ECDsa ImportVerifyKey(byte[] spki)
    {
        var key = ECDsa.Create(ECCurve.NamedCurves.nistP256)!;
        key.ImportSubjectPublicKeyInfo(spki, out _);
        return key;
    }
#endif
}

[System.Text.Json.Serialization.JsonSerializable(typeof(CasketPairingToken))]
[System.Text.Json.Serialization.JsonSerializable(typeof(CasketPeerRecord))]
[System.Text.Json.Serialization.JsonSourceGenerationOptions(
    PropertyNamingPolicy = System.Text.Json.Serialization.JsonKnownNamingPolicy.SnakeCaseLower)]
internal partial class CasketChannelJsonContext : System.Text.Json.Serialization.JsonSerializerContext { }
