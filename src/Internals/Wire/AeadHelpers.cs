using System;
using System.Security.Cryptography;

namespace Casket.Internals.Wire;

internal static class AeadHelpers
{
    private const int TagSize = 16;

    internal static void Encrypt(
        byte algorithmByte,
        byte[] key,
        byte[] nonce,
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> aad,
        Span<byte> ciphertext,
        Span<byte> tag)
    {
        if (algorithmByte == (byte)CasketAlgorithm.Aes256Gcm)
        {
#if NET8_0_OR_GREATER
            using var aes = new AesGcm(key, TagSize);
#else
            using var aes = new AesGcm(key);
#endif
            aes.Encrypt(nonce, plaintext, ciphertext, tag, aad);
        }
        else if (algorithmByte == (byte)CasketAlgorithm.ChaCha20Poly1305)
        {
#if NETSTANDARD2_1
            throw new CasketConfigurationException("ChaCha20-Poly1305 is not supported on netstandard2.1.");
#else
            using var chacha = new ChaCha20Poly1305(key);
            chacha.Encrypt(nonce, plaintext, ciphertext, tag, aad);
#endif
        }
        else
        {
            throw new CasketConfigurationException($"Unknown algorithm byte: 0x{algorithmByte:X2}");
        }
    }

    internal static void Decrypt(
        byte algorithmByte,
        byte[] key,
        byte[] nonce,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> aad,
        ReadOnlySpan<byte> tag,
        Span<byte> plaintext)
    {
        if (algorithmByte == (byte)CasketAlgorithm.Aes256Gcm)
        {
#if NET8_0_OR_GREATER
            using var aes = new AesGcm(key, TagSize);
#else
            using var aes = new AesGcm(key);
#endif
            aes.Decrypt(nonce, ciphertext, tag, plaintext, aad);
        }
        else if (algorithmByte == (byte)CasketAlgorithm.ChaCha20Poly1305)
        {
#if NETSTANDARD2_1
            throw new CasketConfigurationException("ChaCha20-Poly1305 is not supported on netstandard2.1.");
#else
            using var chacha = new ChaCha20Poly1305(key);
            chacha.Decrypt(nonce, ciphertext, tag, plaintext, aad);
#endif
        }
        else
        {
            throw new CasketConfigurationException($"Unknown algorithm byte: 0x{algorithmByte:X2}");
        }
    }
}
