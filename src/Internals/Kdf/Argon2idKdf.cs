using System;
using System.Text;
using Konscious.Security.Cryptography;

namespace Casket.Internals.Kdf;

internal static class Argon2idKdf
{
    internal static byte[] DeriveKey(
        string password,
        byte[] salt,
        uint memorySizeKiB,
        uint iterations,
        ushort parallelism,
        int outputLength = 32)
    {
        byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
        using var argon2 = new Argon2id(passwordBytes);
        argon2.Salt = salt;
        argon2.MemorySize = (int)memorySizeKiB;
        argon2.Iterations = (int)iterations;
        argon2.DegreeOfParallelism = parallelism;
        return argon2.GetBytes(outputLength);
    }
}
