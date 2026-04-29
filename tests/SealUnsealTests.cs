using System;
using System.Text;
using Xunit;

namespace Casket.Tests;

public class SealUnsealTests
{
    [Fact]
    public void PasswordRoundTrip_Aes256Gcm_Argon2id()
    {
        string token = Casket.Seal("Hello, World!", "secret");
        string result = Casket.Unseal(token, "secret");
        Assert.Equal("Hello, World!", result);
    }

    [Fact]
    public void PasswordRoundTrip_ChaCha20Poly1305()
    {
        var opts = new CasketOptions { Algorithm = CasketAlgorithm.ChaCha20Poly1305 };
        string token = Casket.Seal("test message", "password", opts);
        string result = Casket.Unseal(token, "password");
        Assert.Equal("test message", result);
    }

    [Fact]
    public void PasswordRoundTrip_Pbkdf2()
    {
        var opts = new CasketOptions { Kdf = CasketKdf.Pbkdf2Sha256, Pbkdf2Iterations = 10000 };
        string token = Casket.Seal("pbkdf2 test", "password", opts);
        string result = Casket.Unseal(token, "password");
        Assert.Equal("pbkdf2 test", result);
    }

    [Fact]
    public void RawKeyRoundTrip()
    {
        byte[] key = new byte[32];
        new Random(42).NextBytes(key);
        var src = CasketKeySource.FromBytes(key, keyId: 1);
        string token = Casket.Seal("raw key test", src);
        string result = Casket.Unseal(token, src);
        Assert.Equal("raw key test", result);
    }

    [Fact]
    public void WrongPassword_Throws()
    {
        string token = Casket.Seal("secret data", "correct");
        Assert.Throws<CasketDecryptionException>(() => Casket.Unseal(token, "wrong"));
    }

    [Fact]
    public void WrongKey_Throws()
    {
        byte[] key1 = new byte[32]; key1[0] = 1;
        byte[] key2 = new byte[32]; key2[0] = 2;
        var src1 = CasketKeySource.FromBytes(key1, keyId: 1);
        var src2 = CasketKeySource.FromBytes(key2, keyId: 2);
        string token = Casket.Seal("data", src1);
        Assert.Throws<CasketDecryptionException>(() => Casket.Unseal(token, src2));
    }

    [Fact]
    public void GenerateKey_Returns44CharBase64Url()
    {
        string key = Casket.GenerateKey();
        Assert.Equal(43, key.Length); // 32 bytes -> 43 chars base64url no padding
        Assert.DoesNotContain("=", key);
        Assert.DoesNotContain("+", key);
        Assert.DoesNotContain("/", key);
    }

    [Fact]
    public void EmptyPlaintext_RoundTrip()
    {
        string token = Casket.Seal("", "password");
        string result = Casket.Unseal(token, "password");
        Assert.Equal("", result);
    }

    [Fact]
    public void UnicodePlaintext_RoundTrip()
    {
        string plaintext = "こんにちは世界 🔐";
        string token = Casket.Seal(plaintext, "password");
        string result = Casket.Unseal(token, "password");
        Assert.Equal(plaintext, result);
    }

    [Fact]
    public void TokenIsDifferentEachCall()
    {
        string t1 = Casket.Seal("same", "same");
        string t2 = Casket.Seal("same", "same");
        Assert.NotEqual(t1, t2); // different random nonce/salt each time
    }

    [Fact]
    public void CoreApi_RoundTrip()
    {
        byte[] key = new byte[32]; key[0] = 0xAB;
        byte[] plaintext = Encoding.UTF8.GetBytes("core api test");
        byte[] token = CasketCore.Seal(plaintext, key, keyId: 0);
        byte[] result = CasketCore.Unseal(token, key);
        Assert.Equal(plaintext, result);
    }
}
