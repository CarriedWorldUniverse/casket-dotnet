using System;
using System.Security.Cryptography;
using System.Text;

namespace Casket.Internals.Kdf;

internal static class Pbkdf2Kdf
{
    internal static byte[] DeriveKey(string password, byte[] salt, uint iterations, int outputLength = 32)
    {
        byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
#if NET6_0_OR_GREATER
        return Rfc2898DeriveBytes.Pbkdf2(passwordBytes, salt, (int)iterations, HashAlgorithmName.SHA256, outputLength);
#else
        using var kdf = new Rfc2898DeriveBytes(password, salt, (int)iterations, HashAlgorithmName.SHA256);
        return kdf.GetBytes(outputLength);
#endif
    }
}
