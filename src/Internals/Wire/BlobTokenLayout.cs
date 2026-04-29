using System;
using System.Buffers.Binary;
using System.Security.Cryptography;
using Casket.Internals.Kdf;

namespace Casket.Internals.Wire;

/// <summary>
/// Wire format for blob tokens (version 0x01).
///
/// Password-mode layout (58 bytes header):
///   [0]      version        = 0x01
///   [1]      algorithm      0x01=AES-256-GCM, 0x02=ChaCha20-Poly1305
///   [2]      kdf            0x01=Argon2id, 0x02=PBKDF2-SHA256
///   [3..6]   argon2_mem_kb  uint32 LE
///   [7..10]  argon2_iter    uint32 LE
///   [11..12] argon2_par     uint16 LE
///   [13]     argon2_outlen  uint8 = 32
///   [14..29] salt           16 bytes
///   [30..41] nonce          12 bytes
///   [42..57] tag            16 bytes
///   [58..]   ciphertext
///   AAD = bytes [0..41]
///
/// Raw-key-mode layout (33 bytes header):
///   [0]      version        = 0x01
///   [1]      algorithm
///   [2]      kdf            = 0x00
///   [3..4]   key_id         uint16 LE
///   [5..16]  nonce          12 bytes
///   [17..32] tag            16 bytes
///   [33..]   ciphertext
///   AAD = bytes [0..16]
/// </summary>
internal static class BlobTokenLayout
{
    private const byte Version = 0x01;
    private const int TagSize = 16;
    private const int NonceSize = 12;
    private const int SaltSize = 16;

    // Password-mode offsets
    private const int PwdAlgorithmOffset = 1;
    private const int PwdKdfOffset = 2;
    private const int PwdMemKbOffset = 3;
    private const int PwdIterOffset = 7;
    private const int PwdParOffset = 11;
    private const int PwdOutlenOffset = 13;
    private const int PwdSaltOffset = 14;
    private const int PwdNonceOffset = 30;
    private const int PwdTagOffset = 42;
    private const int PwdCiphertextOffset = 58;
    private const int PwdAadLength = 42;

    // Raw-key-mode offsets
    private const int RawAlgorithmOffset = 1;
    private const int RawKeyIdOffset = 3;
    private const int RawNonceOffset = 5;
    private const int RawTagOffset = 17;
    private const int RawCiphertextOffset = 33;
    private const int RawAadLength = 17;

    internal static byte[] SealPassword(
        ReadOnlySpan<byte> plaintext,
        string password,
        CasketAlgorithm algorithm,
        CasketKdf kdf,
        uint memKiB,
        uint iterations,
        ushort parallelism,
        byte[]? saltOverride = null,
        byte[]? nonceOverride = null)
    {
        byte[] salt = saltOverride ?? NonceGenerator.GenerateSalt();
        byte[] nonce = nonceOverride ?? NonceGenerator.Generate();

        byte[] key = kdf == CasketKdf.Argon2id
            ? Argon2idKdf.DeriveKey(password, salt, memKiB, iterations, parallelism)
            : Pbkdf2Kdf.DeriveKey(password, salt, kdf == CasketKdf.Pbkdf2Sha256 ? iterations : 600_000);

        int tokenLength = PwdCiphertextOffset + plaintext.Length;
        byte[] token = new byte[tokenLength];
        Span<byte> t = token;

        t[0] = Version;
        t[PwdAlgorithmOffset] = (byte)algorithm;
        t[PwdKdfOffset] = (byte)kdf;

        if (kdf == CasketKdf.Argon2id)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(t.Slice(PwdMemKbOffset, 4), memKiB);
            BinaryPrimitives.WriteUInt32LittleEndian(t.Slice(PwdIterOffset, 4), iterations);
            BinaryPrimitives.WriteUInt16LittleEndian(t.Slice(PwdParOffset, 2), parallelism);
            t[PwdOutlenOffset] = 32;
        }
        else // PBKDF2 — pbkdf2_iter at same offset as argon2_mem_kb, rest zeros, outlen=32
        {
            BinaryPrimitives.WriteUInt32LittleEndian(t.Slice(PwdMemKbOffset, 4), iterations);
            t.Slice(PwdIterOffset, 6).Clear();
            t[PwdOutlenOffset] = 32;
        }

        salt.CopyTo(t.Slice(PwdSaltOffset, SaltSize));
        nonce.CopyTo(t.Slice(PwdNonceOffset, NonceSize));

        Span<byte> aad = t.Slice(0, PwdAadLength);
        Span<byte> tag = t.Slice(PwdTagOffset, TagSize);
        Span<byte> ciphertext = t.Slice(PwdCiphertextOffset);

        Encrypt(algorithm, key, nonce, plaintext, aad, ciphertext, tag);
        return token;
    }

    internal static byte[] UnsealPassword(ReadOnlySpan<byte> token, string password)
    {
        if (token.Length < PwdCiphertextOffset)
            throw new CasketDecryptionException();
        if (token[0] != Version)
            throw new CasketUnsupportedVersionException(token[0]);

        var algorithm = (CasketAlgorithm)token[PwdAlgorithmOffset];
        var kdf = (CasketKdf)token[PwdKdfOffset];

        if (token[PwdOutlenOffset] != 32)
            throw new CasketConfigurationException("Token has invalid key output length.");

        byte[] salt = token.Slice(PwdSaltOffset, SaltSize).ToArray();
        byte[] nonce = token.Slice(PwdNonceOffset, NonceSize).ToArray();
        ReadOnlySpan<byte> tag = token.Slice(PwdTagOffset, TagSize);
        ReadOnlySpan<byte> ciphertext = token.Slice(PwdCiphertextOffset);
        ReadOnlySpan<byte> aad = token.Slice(0, PwdAadLength);

        byte[] key;
        if (kdf == CasketKdf.Argon2id)
        {
            uint memKiB = BinaryPrimitives.ReadUInt32LittleEndian(token.Slice(PwdMemKbOffset, 4));
            uint iter   = BinaryPrimitives.ReadUInt32LittleEndian(token.Slice(PwdIterOffset, 4));
            ushort par  = BinaryPrimitives.ReadUInt16LittleEndian(token.Slice(PwdParOffset, 2));
            key = Argon2idKdf.DeriveKey(password, salt, memKiB, iter, par);
        }
        else if (kdf == CasketKdf.Pbkdf2Sha256)
        {
            uint iter = BinaryPrimitives.ReadUInt32LittleEndian(token.Slice(PwdMemKbOffset, 4));
            key = Pbkdf2Kdf.DeriveKey(password, salt, iter);
        }
        else
        {
            throw new CasketDecryptionException();
        }

        return Decrypt(algorithm, key, nonce, ciphertext, aad, tag);
    }

    internal static byte[] SealRawKey(
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> key,
        CasketAlgorithm algorithm,
        ushort keyId,
        byte[]? nonceOverride = null)
    {
        byte[] nonce = nonceOverride ?? NonceGenerator.Generate();
        int tokenLength = RawCiphertextOffset + plaintext.Length;
        byte[] token = new byte[tokenLength];
        Span<byte> t = token;

        t[0] = Version;
        t[RawAlgorithmOffset] = (byte)algorithm;
        t[2] = (byte)CasketKdf.None;
        BinaryPrimitives.WriteUInt16LittleEndian(t.Slice(RawKeyIdOffset, 2), keyId);
        nonce.CopyTo(t.Slice(RawNonceOffset, NonceSize));

        Span<byte> aad = t.Slice(0, RawAadLength);
        Span<byte> tag = t.Slice(RawTagOffset, TagSize);
        Span<byte> ciphertext = t.Slice(RawCiphertextOffset);

        Encrypt(algorithm, key.ToArray(), nonce, plaintext, aad, ciphertext, tag);
        return token;
    }

    internal static byte[] UnsealRawKey(ReadOnlySpan<byte> token, ReadOnlySpan<byte> key)
    {
        if (token.Length < RawCiphertextOffset)
            throw new CasketDecryptionException();
        if (token[0] != Version)
            throw new CasketUnsupportedVersionException(token[0]);

        var algorithm = (CasketAlgorithm)token[RawAlgorithmOffset];
        byte[] nonce = token.Slice(RawNonceOffset, NonceSize).ToArray();
        ReadOnlySpan<byte> tag = token.Slice(RawTagOffset, TagSize);
        ReadOnlySpan<byte> ciphertext = token.Slice(RawCiphertextOffset);
        ReadOnlySpan<byte> aad = token.Slice(0, RawAadLength);

        return Decrypt(algorithm, key.ToArray(), nonce, ciphertext, aad, tag);
    }

    internal static (CasketKdf kdf, ushort keyId) PeekHeader(ReadOnlySpan<byte> token)
    {
        if (token.Length < 5) throw new CasketDecryptionException();
        var kdf = (CasketKdf)token[2];
        ushort keyId = kdf == CasketKdf.None
            ? BinaryPrimitives.ReadUInt16LittleEndian(token.Slice(RawKeyIdOffset, 2))
            : (ushort)0;
        return (kdf, keyId);
    }

    private static void Encrypt(
        CasketAlgorithm algorithm,
        byte[] key,
        byte[] nonce,
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> aad,
        Span<byte> ciphertext,
        Span<byte> tag)
        => AeadHelpers.Encrypt((byte)algorithm, key, nonce, plaintext, aad, ciphertext, tag);

    private static byte[] Decrypt(
        CasketAlgorithm algorithm,
        byte[] key,
        byte[] nonce,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> aad,
        ReadOnlySpan<byte> tag)
    {
        byte[] plaintext = new byte[ciphertext.Length];
        try { AeadHelpers.Decrypt((byte)algorithm, key, nonce, ciphertext, aad, tag, plaintext); }
        catch (CryptographicException ex) { throw new CasketDecryptionException(ex); }
        return plaintext;
    }
}
