using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Casket.Internals.Kdf;

namespace Casket.Internals.Wire;

/// <summary>
/// Stream wire format (version 0x81). See spec for full layout.
/// </summary>
internal static class StreamTokenLayout
{
    private const byte StreamVersion = 0x81;
    private const int TagSize = 16;
    private const int NonceSize = 12;
    private const int SaltSize = 16;
    private const int SessionIdSize = 16;
    private const int PwdHeaderSize = 58;
    private const int RawHeaderSize = 33;
    private const int ChunkFrameHeaderSize = 41;
    private const int TotalChunksOffset = 23;

    internal static async Task SealAsync(
        Stream source,
        Stream destination,
        byte[] key,
        byte algorithmByte,
        byte kdfByte,
        ushort keyId,
        uint memKiB,
        uint iterations,
        ushort parallelism,
        int chunkSize,
        CancellationToken ct)
    {
        byte[] sessionId = NonceGenerator.GenerateSalt(SessionIdSize);
        bool isPwd = kdfByte != (byte)CasketKdf.None;
        byte[] salt = isPwd ? NonceGenerator.GenerateSalt(SaltSize) : Array.Empty<byte>();

        // Derive key for password mode
        if (isPwd)
        {
            if (kdfByte == (byte)CasketKdf.Argon2id)
                key = Argon2idKdf.DeriveKey(Encoding.UTF8.GetString(key), salt, memKiB, iterations, parallelism);
            else
                key = Pbkdf2Kdf.DeriveKey(Encoding.UTF8.GetString(key), salt, memKiB);
        }

        byte[] header = BuildHeader(algorithmByte, kdfByte, keyId, sessionId, (uint)chunkSize, memKiB, iterations, parallelism, salt);

        // Collect all chunk frames so we know total_chunks before writing header
        // (works for both seekable and non-seekable destinations)
        var frames = new List<byte[]>();
        ulong chunkIndex = 0;

        byte[] buf = new byte[chunkSize];
        int buffered = 0;

        while (true)
        {
            int read = await ReadFullAsync(source, buf, buffered, chunkSize - buffered, ct).ConfigureAwait(false);
            buffered += read;

            if (buffered == 0)
            {
                // Empty source — write a single empty final chunk
                frames.Add(EncryptChunk(buf.AsSpan(0, 0), key, algorithmByte, sessionId, chunkIndex, true, (uint)chunkSize));
                chunkIndex++;
                break;
            }

            if (read == 0)
            {
                // EOF — flush whatever is buffered as the final chunk
                frames.Add(EncryptChunk(buf.AsSpan(0, buffered), key, algorithmByte, sessionId, chunkIndex, true, (uint)chunkSize));
                chunkIndex++;
                break;
            }

            if (buffered == chunkSize)
            {
                // Full chunk — peek to see if there's more data
                int peek = source.ReadByte();
                if (peek == -1)
                {
                    // This was the last chunk
                    frames.Add(EncryptChunk(buf.AsSpan(0, chunkSize), key, algorithmByte, sessionId, chunkIndex, true, (uint)chunkSize));
                    chunkIndex++;
                    break;
                }
                else
                {
                    // Non-final chunk
                    frames.Add(EncryptChunk(buf.AsSpan(0, chunkSize), key, algorithmByte, sessionId, chunkIndex, false, (uint)chunkSize));
                    chunkIndex++;
                    // Start next buffer with the peeked byte
                    buf[0] = (byte)peek;
                    buffered = 1;
                }
            }
        }

        ulong totalChunks = chunkIndex;
        BinaryPrimitives.WriteUInt64LittleEndian(header.AsSpan(TotalChunksOffset, 8), totalChunks);

        await destination.WriteAsync(header, 0, header.Length, ct).ConfigureAwait(false);
        foreach (byte[] frame in frames)
            await destination.WriteAsync(frame, 0, frame.Length, ct).ConfigureAwait(false);
    }

    internal static async Task UnsealAsync(
        Stream source,
        Stream destination,
        byte[] key,
        CancellationToken ct)
    {
        // Read the 3-byte prefix to determine header size
        byte[] prefix = new byte[3];
        if (await ReadExactAsync(source, prefix, 3, ct).ConfigureAwait(false) != 3)
            throw new CasketDecryptionException();

        if (prefix[0] != StreamVersion)
            throw new CasketUnsupportedVersionException(prefix[0]);

        byte algorithmByte = prefix[1];
        byte kdfByte = prefix[2];
        bool isPwd = kdfByte != (byte)CasketKdf.None;

        int remainingHeaderSize = (isPwd ? PwdHeaderSize : RawHeaderSize) - 3;
        byte[] headerRest = new byte[remainingHeaderSize];
        if (await ReadExactAsync(source, headerRest, remainingHeaderSize, ct).ConfigureAwait(false) != remainingHeaderSize)
            throw new CasketDecryptionException();

        // session_id at absolute [3..18] => headerRest[0..15]
        byte[] sessionId = new byte[SessionIdSize];
        Array.Copy(headerRest, 0, sessionId, 0, SessionIdSize);

        // chunk_size at absolute [19..22] => headerRest[16..19]
        uint chunkSize = BinaryPrimitives.ReadUInt32LittleEndian(headerRest.AsSpan(16, 4));

        // total_chunks at absolute [23..30] => headerRest[20..27]
        ulong totalChunks = BinaryPrimitives.ReadUInt64LittleEndian(headerRest.AsSpan(20, 8));

        if (totalChunks == 0)
            throw new CasketStreamCorruptedException("total_chunks is zero.");

        ValidateChunkSize(chunkSize);

        // Derive key for password mode
        // headerRest for pwd: [28..31]=argon2_mem_kb, [32..35]=argon2_iter, [36..37]=argon2_par, [38]=outlen, [39..54]=salt
        if (isPwd)
        {
            uint memKiB = BinaryPrimitives.ReadUInt32LittleEndian(headerRest.AsSpan(28, 4));
            uint iter   = BinaryPrimitives.ReadUInt32LittleEndian(headerRest.AsSpan(32, 4));
            ushort par  = BinaryPrimitives.ReadUInt16LittleEndian(headerRest.AsSpan(36, 2));
            byte[] salt = new byte[SaltSize];
            Array.Copy(headerRest, 39, salt, 0, SaltSize);
            string passwordStr = Encoding.UTF8.GetString(key);

            if (kdfByte == (byte)CasketKdf.Argon2id)
                key = Argon2idKdf.DeriveKey(passwordStr, salt, memKiB, iter, par);
            else
                key = Pbkdf2Kdf.DeriveKey(passwordStr, salt, memKiB);
        }

        ulong expectedIndex = 0;
        bool sawFinal = false;

        while (expectedIndex < totalChunks)
        {
            byte[] chunkHeader = new byte[ChunkFrameHeaderSize];
            if (await ReadExactAsync(source, chunkHeader, ChunkFrameHeaderSize, ct).ConfigureAwait(false) != ChunkFrameHeaderSize)
                throw new CasketStreamTruncatedException();

            ulong chunkIndex = BinaryPrimitives.ReadUInt64LittleEndian(chunkHeader.AsSpan(0, 8));
            byte flags = chunkHeader[8];
            uint plaintextLen = BinaryPrimitives.ReadUInt32LittleEndian(chunkHeader.AsSpan(9, 4));
            byte[] nonce = new byte[NonceSize];
            Array.Copy(chunkHeader, 13, nonce, 0, NonceSize);
            byte[] tag = new byte[TagSize];
            Array.Copy(chunkHeader, 25, tag, 0, TagSize);

            bool isFinal = (flags & 0x01) != 0;

            if (chunkIndex != expectedIndex)
                throw new CasketStreamCorruptedException($"Chunk index out of sequence: expected {expectedIndex}, got {chunkIndex}.");
            if (isFinal && expectedIndex != totalChunks - 1)
                throw new CasketStreamCorruptedException("is_final flag set on non-last chunk.");
            if (!isFinal && expectedIndex == totalChunks - 1)
                throw new CasketStreamTruncatedException();

            byte[] ciphertext = new byte[plaintextLen];
            if (await ReadExactAsync(source, ciphertext, (int)plaintextLen, ct).ConfigureAwait(false) != (int)plaintextLen)
                throw new CasketStreamTruncatedException();

            byte[] aad = BuildChunkAad(sessionId, chunkIndex, flags, plaintextLen, chunkSize);
            byte[] plaintext = DecryptChunk(ciphertext, key, algorithmByte, nonce, tag, aad);
            await destination.WriteAsync(plaintext, 0, plaintext.Length, ct).ConfigureAwait(false);

            if (isFinal) sawFinal = true;
            expectedIndex++;
        }

        if (!sawFinal)
            throw new CasketStreamTruncatedException();
    }

    private static byte[] BuildHeader(
        byte algorithm, byte kdf, ushort keyId,
        byte[] sessionId, uint chunkSize,
        uint memKiB, uint iterations, ushort parallelism,
        byte[] salt)
    {
        bool isPwd = kdf != (byte)CasketKdf.None;
        byte[] h = new byte[isPwd ? PwdHeaderSize : RawHeaderSize];
        h[0] = StreamVersion;
        h[1] = algorithm;
        h[2] = kdf;
        sessionId.CopyTo(h, 3);
        BinaryPrimitives.WriteUInt32LittleEndian(h.AsSpan(19, 4), chunkSize);
        // total_chunks placeholder — overwritten before writing
        BinaryPrimitives.WriteUInt64LittleEndian(h.AsSpan(TotalChunksOffset, 8), 0xFFFFFFFFFFFFFFFFUL);

        if (isPwd)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(h.AsSpan(31, 4), memKiB);
            BinaryPrimitives.WriteUInt32LittleEndian(h.AsSpan(35, 4), iterations);
            BinaryPrimitives.WriteUInt16LittleEndian(h.AsSpan(39, 2), parallelism);
            h[41] = 32;
            salt.CopyTo(h, 42);
        }
        else
        {
            BinaryPrimitives.WriteUInt16LittleEndian(h.AsSpan(31, 2), keyId);
        }
        return h;
    }

    private static byte[] EncryptChunk(
        ReadOnlySpan<byte> plaintext,
        byte[] key,
        byte algorithmByte,
        byte[] sessionId,
        ulong chunkIndex,
        bool isFinal,
        uint chunkSize)
    {
        byte[] nonce = NonceGenerator.Generate();
        byte flags = isFinal ? (byte)0x01 : (byte)0x00;
        uint plaintextLen = (uint)plaintext.Length;
        byte[] aad = BuildChunkAad(sessionId, chunkIndex, flags, plaintextLen, chunkSize);

        byte[] ciphertext = new byte[plaintextLen];
        byte[] tag = new byte[TagSize];
        EncryptBytes(algorithmByte, key, nonce, plaintext, aad, ciphertext, tag);

        byte[] frame = new byte[ChunkFrameHeaderSize + plaintextLen];
        Span<byte> f = frame;
        BinaryPrimitives.WriteUInt64LittleEndian(f.Slice(0, 8), chunkIndex);
        f[8] = flags;
        BinaryPrimitives.WriteUInt32LittleEndian(f.Slice(9, 4), plaintextLen);
        nonce.CopyTo(f.Slice(13, NonceSize));
        tag.CopyTo(f.Slice(25, TagSize));
        ciphertext.CopyTo(f.Slice(ChunkFrameHeaderSize));
        return frame;
    }

    private static byte[] DecryptChunk(byte[] ciphertext, byte[] key, byte algorithmByte, byte[] nonce, byte[] tag, byte[] aad)
    {
        byte[] plaintext = new byte[ciphertext.Length];
        try { DecryptBytes(algorithmByte, key, nonce, ciphertext, aad, tag, plaintext); }
        catch (CryptographicException ex) { throw new CasketDecryptionException(ex); }
        return plaintext;
    }

    private static byte[] BuildChunkAad(byte[] sessionId, ulong chunkIndex, byte flags, uint plaintextLen, uint chunkSize)
    {
        byte[] aad = new byte[33];
        sessionId.CopyTo(aad, 0);
        BinaryPrimitives.WriteUInt64LittleEndian(aad.AsSpan(16, 8), chunkIndex);
        aad[24] = flags;
        BinaryPrimitives.WriteUInt32LittleEndian(aad.AsSpan(25, 4), plaintextLen);
        BinaryPrimitives.WriteUInt32LittleEndian(aad.AsSpan(29, 4), chunkSize);
        return aad;
    }

    private static void EncryptBytes(byte alg, byte[] key, byte[] nonce, ReadOnlySpan<byte> pt, byte[] aad, byte[] ct, byte[] tag)
        => AeadHelpers.Encrypt(alg, key, nonce, pt, aad, ct, tag);

    private static void DecryptBytes(byte alg, byte[] key, byte[] nonce, byte[] ct, byte[] aad, byte[] tag, byte[] pt)
        => AeadHelpers.Decrypt(alg, key, nonce, ct, aad, tag, pt);

    private static void ValidateChunkSize(uint chunkSize)
    {
        if (chunkSize < 4096 || chunkSize > 16777216 || (chunkSize & (chunkSize - 1)) != 0)
            throw new CasketStreamCorruptedException($"Invalid chunk_size: {chunkSize}.");
    }

    private static async Task<int> ReadExactAsync(Stream stream, byte[] buffer, int count, CancellationToken ct)
    {
        int total = 0;
        while (total < count)
        {
            int read = await stream.ReadAsync(buffer, total, count - total, ct).ConfigureAwait(false);
            if (read == 0) break;
            total += read;
        }
        return total;
    }

    private static async Task<int> ReadFullAsync(Stream stream, byte[] buffer, int offset, int count, CancellationToken ct)
    {
        int total = 0;
        while (total < count)
        {
            int read = await stream.ReadAsync(buffer, offset + total, count - total, ct).ConfigureAwait(false);
            if (read == 0) break;
            total += read;
        }
        return total;
    }
}
