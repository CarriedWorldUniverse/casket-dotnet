using System;
using System.Security.Cryptography;

namespace Casket.Internals;

internal static class NonceGenerator
{
    internal static byte[] Generate(int length = 12)
    {
        byte[] nonce = new byte[length];
        RandomNumberGenerator.Fill(nonce);
        return nonce;
    }

    internal static byte[] GenerateSalt(int length = 16)
    {
        byte[] salt = new byte[length];
        RandomNumberGenerator.Fill(salt);
        return salt;
    }
}
