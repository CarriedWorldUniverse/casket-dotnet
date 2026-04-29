using System;
using System.Text;
using Xunit;
using Casket.Internals.Wire;

namespace Casket.Tests;

/// <summary>
/// Fixed-input test vectors shared with the TypeScript package.
/// Both implementations must produce identical Base64Url tokens for the same inputs.
/// </summary>
public class CrossCompatTests
{
    // Vector 1: password-mode blob with Argon2id + AES-256-GCM
    private const string V1Pass = "correct horse battery staple";
    private const string V1Plain = "Hello, Casket!";
    private static readonly byte[] V1Salt = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    ];
    private static readonly byte[] V1Nonce = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b
    ];

    // Vector 2: raw-key-mode blob with AES-256-GCM
    private static readonly byte[] V2Key = new byte[32]; // all 0x42
    private const ushort V2KeyId = 0x0001;
    private const string V2Plain = "raw key test";
    private static readonly byte[] V2Nonce = [
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b
    ];

    static CrossCompatTests() { Array.Fill(V2Key, (byte)0x42); }

    private static string ToBase64Url(byte[] bytes)
    {
        string b64 = Convert.ToBase64String(bytes);
        return b64.Replace('+', '-').Replace('/', '_').TrimEnd('=');
    }

    [Fact]
    public void Vector1_PasswordBlob_Deterministic()
    {
        byte[] token = BlobTokenLayout.SealPassword(
            Encoding.UTF8.GetBytes(V1Plain), V1Pass,
            CasketAlgorithm.Aes256Gcm, CasketKdf.Argon2id,
            65536, 3, 1,
            saltOverride: V1Salt, nonceOverride: V1Nonce);

        string tokenStr = ToBase64Url(token);

        // Verify round-trip via the public API
        string decrypted = Casket.Unseal(tokenStr, V1Pass);
        Assert.Equal(V1Plain, decrypted);

        // Header structure assertions
        Assert.Equal(0x01, token[0]);  // version
        Assert.Equal(0x01, token[1]);  // AES-256-GCM
        Assert.Equal(0x01, token[2]);  // Argon2id
        Assert.Equal(V1Salt, token[14..30]);
        Assert.Equal(V1Nonce, token[30..42]);

        // Print token for cross-language comparison
        Console.WriteLine($"[CrossCompat] Vector1 token: {tokenStr}");
    }

    [Fact]
    public void Vector2_RawKeyBlob_Deterministic()
    {
        byte[] token = BlobTokenLayout.SealRawKey(
            Encoding.UTF8.GetBytes(V2Plain), V2Key,
            CasketAlgorithm.Aes256Gcm, V2KeyId,
            nonceOverride: V2Nonce);

        string tokenStr = ToBase64Url(token);

        string decrypted = Casket.Unseal(tokenStr, CasketKeySource.FromBytes(V2Key, keyId: V2KeyId));
        Assert.Equal(V2Plain, decrypted);

        Assert.Equal(0x01, token[0]);  // version
        Assert.Equal(0x01, token[1]);  // AES-256-GCM
        Assert.Equal(0x00, token[2]);  // raw key (kdf=None)
        Assert.Equal(0x01, token[3]);  // key_id low byte = 1
        Assert.Equal(0x00, token[4]);  // key_id high byte = 0
        Assert.Equal(V2Nonce, token[5..17]);

        Console.WriteLine($"[CrossCompat] Vector2 token: {tokenStr}");
    }
}
