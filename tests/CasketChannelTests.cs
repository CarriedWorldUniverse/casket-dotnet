using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace Casket.Tests;

public class CasketChannelTests
{
    // ── Storage helpers ──────────────────────────────────────────────────────

    private sealed class MemoryStorage : ICasketChannelStorage
    {
        private readonly Dictionary<string, string> _store = new();

        public ValueTask<string?> GetAsync(string key, System.Threading.CancellationToken _ = default)
            => ValueTask.FromResult(_store.TryGetValue(key, out var v) ? v : null);

        public ValueTask PutAsync(string key, string value, System.Threading.CancellationToken _ = default)
        {
            _store[key] = value;
            return ValueTask.CompletedTask;
        }

        public ValueTask DeleteAsync(string key, System.Threading.CancellationToken _ = default)
        {
            _store.Remove(key);
            return ValueTask.CompletedTask;
        }
    }

    private static Task<(CasketChannel a, CasketChannel b)> MakePairAsync()
        => Task.WhenAll(
               CasketChannel.LoadAsync("nexus-a", new MemoryStorage()).AsTask(),
               CasketChannel.LoadAsync("nexus-b", new MemoryStorage()).AsTask()
           ).ContinueWith(t => (t.Result[0], t.Result[1]));

    // ── Identity ─────────────────────────────────────────────────────────────

    [Fact]
    public async Task LoadAsync_GeneratesKeypairs()
    {
        using var ch = await CasketChannel.LoadAsync("test-nexus", new MemoryStorage());
        Assert.NotEmpty(ch.PublicKeyB64u);
        Assert.NotEmpty(ch.DhPublicKeyB64u);
        Assert.Equal("test-nexus", ch.NexusId);
    }

    [Fact]
    public async Task LoadAsync_ReloadsFromStorage()
    {
        var storage = new MemoryStorage();
        using var ch1 = await CasketChannel.LoadAsync("nexus-x", storage);
        string pub1 = ch1.PublicKeyB64u;
        ch1.Dispose();

        using var ch2 = await CasketChannel.LoadAsync("nexus-x", storage);
        Assert.Equal(pub1, ch2.PublicKeyB64u);
    }

    [Fact]
    public async Task TwoInstances_HaveDifferentKeys()
    {
        using var a = await CasketChannel.LoadAsync("a", new MemoryStorage());
        using var b = await CasketChannel.LoadAsync("b", new MemoryStorage());
        Assert.NotEqual(a.PublicKeyB64u, b.PublicKeyB64u);
        Assert.NotEqual(a.DhPublicKeyB64u, b.DhPublicKeyB64u);
    }

    // ── Pairing token ────────────────────────────────────────────────────────

    [Fact]
    public async Task MakePairingToken_ContainsExpectedFields()
    {
        using var ch = await CasketChannel.LoadAsync("nexus-z", new MemoryStorage());
        var token = ch.MakePairingToken("https://example.com");
        Assert.Equal(1, token.V);
        Assert.Equal("nexus-z", token.NexusId);
        Assert.Equal("https://example.com", token.Endpoint);
        Assert.NotEmpty(token.Pubkey);
        Assert.NotEmpty(token.DhPubkey);
        Assert.NotEmpty(token.Nonce);
        Assert.True(token.Ts > 0);
    }

    [Fact]
    public async Task SerializeDeserializePairingToken_RoundTrips()
    {
        using var ch = await CasketChannel.LoadAsync("nexus-z", new MemoryStorage());
        var token = ch.MakePairingToken("https://example.com");
        string blob = CasketChannel.SerializePairingToken(token);
        var token2 = CasketChannel.DeserializePairingToken(blob);
        Assert.Equal(token.NexusId, token2.NexusId);
        Assert.Equal(token.Pubkey, token2.Pubkey);
        Assert.Equal(token.DhPubkey, token2.DhPubkey);
        Assert.Equal(token.Endpoint, token2.Endpoint);
        Assert.Equal(token.Nonce, token2.Nonce);
        Assert.Equal(token.Ts, token2.Ts);
    }

    [Fact]
    public async Task MakePairingToken_NonceIsUniquePerCall()
    {
        using var ch = await CasketChannel.LoadAsync("nexus-n", new MemoryStorage());
        var t1 = ch.MakePairingToken("https://x.com");
        var t2 = ch.MakePairingToken("https://x.com");
        Assert.NotEqual(t1.Nonce, t2.Nonce);
    }

    // ── Path ID ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task PathId_IsSymmetric()
    {
        var (a, b) = await MakePairAsync();
        using (a) using (b)
        {
            var tokenA = a.MakePairingToken("https://a.com");
            var tokenB = b.MakePairingToken("https://b.com");

            using var pairedB = await a.PairAsync(tokenB);
            using var pairedA = await b.PairAsync(tokenA);

            Assert.Equal(pairedB.PathId, pairedA.PathId);
            Assert.StartsWith("nxc_", pairedB.PathId);
        }
    }

    // ── Pair + GetPaired ─────────────────────────────────────────────────────

    [Fact]
    public async Task PairAsync_SetsPeerMetadata()
    {
        var (a, b) = await MakePairAsync();
        using (a) using (b)
        {
            var tokenB = b.MakePairingToken("https://b.endpoint");
            using var paired = await a.PairAsync(tokenB);
            Assert.Equal("nexus-b", paired.PeerId);
            Assert.Equal("https://b.endpoint", paired.PeerEndpoint);
        }
    }

    [Fact]
    public async Task GetPairedAsync_ReturnsSamePathId()
    {
        var (a, b) = await MakePairAsync();
        using (a) using (b)
        {
            var tokenB = b.MakePairingToken("https://b.endpoint");
            using var paired1 = await a.PairAsync(tokenB);
            using var paired2 = (await a.GetPairedAsync("nexus-b"))!;
            Assert.NotNull(paired2);
            Assert.Equal(paired1.PathId, paired2.PathId);
        }
    }

    [Fact]
    public async Task GetPairedAsync_ReturnsNullForUnknownPeer()
    {
        using var ch = await CasketChannel.LoadAsync("lone", new MemoryStorage());
        var result = await ch.GetPairedAsync("nobody");
        Assert.Null(result);
    }

    [Fact]
    public async Task RevokeAsync_RemovesPeer()
    {
        var (a, b) = await MakePairAsync();
        using (a) using (b)
        {
            var tokenB = b.MakePairingToken("https://b.endpoint");
            using var _ = await a.PairAsync(tokenB);
            await a.RevokeAsync("nexus-b");
            var after = await a.GetPairedAsync("nexus-b");
            Assert.Null(after);
        }
    }

    // ── Stale / invalid tokens ───────────────────────────────────────────────

    [Fact]
    public async Task PairAsync_RejectsStaleToken()
    {
        var (a, b) = await MakePairAsync();
        using (a) using (b)
        {
            var token = b.MakePairingToken("https://b.com");
            var stale = new CasketPairingToken
            {
                V        = token.V,
                NexusId  = token.NexusId,
                Pubkey   = token.Pubkey,
                DhPubkey = token.DhPubkey,
                Endpoint = token.Endpoint,
                Nonce    = token.Nonce,
                Ts       = DateTimeOffset.UtcNow.ToUnixTimeSeconds() - 90001,
            };
            await Assert.ThrowsAsync<CasketChannelPairException>(() => a.PairAsync(stale).AsTask());
        }
    }

    [Fact]
    public async Task PairAsync_RejectsFutureToken()
    {
        var (a, b) = await MakePairAsync();
        using (a) using (b)
        {
            var token = b.MakePairingToken("https://b.com");
            var future = new CasketPairingToken
            {
                V        = token.V,
                NexusId  = token.NexusId,
                Pubkey   = token.Pubkey,
                DhPubkey = token.DhPubkey,
                Endpoint = token.Endpoint,
                Nonce    = token.Nonce,
                Ts       = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 400,
            };
            await Assert.ThrowsAsync<CasketChannelPairException>(() => a.PairAsync(future).AsTask());
        }
    }

    [Fact]
    public async Task PairAsync_RejectsBadDhPubkey()
    {
        var (a, b) = await MakePairAsync();
        using (a) using (b)
        {
            var token = new CasketPairingToken
            {
                V        = 1,
                NexusId  = "nexus-b",
                Pubkey   = b.PublicKeyB64u,
                DhPubkey = CasketChannel.B64uEncode(new byte[32]),   // wrong length
                Endpoint = "https://b.com",
                Nonce    = CasketChannel.B64uEncode(new byte[16]),
                Ts       = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            };
            await Assert.ThrowsAsync<CasketChannelPairException>(() => a.PairAsync(token).AsTask());
        }
    }

    // ── Sign / Verify ────────────────────────────────────────────────────────

    [Fact]
    public async Task SignAndVerify_RoundTrip()
    {
        var (a, b) = await MakePairAsync();
        using (a) using (b)
        {
            var tokenB = b.MakePairingToken("https://b.com");
            var tokenA = a.MakePairingToken("https://a.com");
            using var pairedFromA = await a.PairAsync(tokenB);
            using var pairedFromB = await b.PairAsync(tokenA);

            byte[] data = Encoding.UTF8.GetBytes("hello world");
            string sig = pairedFromA.Sign(data);
            pairedFromB.Verify(sig, data);   // throws on failure
        }
    }

    [Fact]
    public async Task Verify_ThrowsOnTamperedData()
    {
        var (a, b) = await MakePairAsync();
        using (a) using (b)
        {
            var tokenB = b.MakePairingToken("https://b.com");
            var tokenA = a.MakePairingToken("https://a.com");
            using var pairedFromA = await a.PairAsync(tokenB);
            using var pairedFromB = await b.PairAsync(tokenA);

            byte[] data = Encoding.UTF8.GetBytes("hello world");
            string sig = pairedFromA.Sign(data);
            byte[] tampered = Encoding.UTF8.GetBytes("hello world!");
            Assert.Throws<CasketChannelVerifyException>(() => pairedFromB.Verify(sig, tampered));
        }
    }

    [Fact]
    public async Task Verify_ThrowsOnTamperedSignature()
    {
        var (a, b) = await MakePairAsync();
        using (a) using (b)
        {
            var tokenB = b.MakePairingToken("https://b.com");
            var tokenA = a.MakePairingToken("https://a.com");
            using var pairedFromA = await a.PairAsync(tokenB);
            using var pairedFromB = await b.PairAsync(tokenA);

            byte[] data = Encoding.UTF8.GetBytes("hello");
            string sig = pairedFromA.Sign(data);
            byte[] sigBytes = CasketChannel.B64uDecode(sig);
            sigBytes[0] ^= 0xFF;
            string bad = CasketChannel.B64uEncode(sigBytes);
            Assert.Throws<CasketChannelVerifyException>(() => pairedFromB.Verify(bad, data));
        }
    }

    // ── EncryptBody / DecryptBody ────────────────────────────────────────────

    [Fact]
    public async Task EncryptDecrypt_RoundTrip()
    {
        var (a, b) = await MakePairAsync();
        using (a) using (b)
        {
            var tokenB = b.MakePairingToken("https://b.com");
            var tokenA = a.MakePairingToken("https://a.com");
            using var pairedFromA = await a.PairAsync(tokenB);
            using var pairedFromB = await b.PairAsync(tokenA);

            byte[] plaintext = Encoding.UTF8.GetBytes("secret message");
            string ciphertext = pairedFromA.EncryptBody(plaintext);
            byte[] decrypted = pairedFromB.DecryptBody(ciphertext);
            Assert.Equal(plaintext, decrypted);
        }
    }

    [Fact]
    public async Task EncryptDecrypt_BothDirections()
    {
        var (a, b) = await MakePairAsync();
        using (a) using (b)
        {
            var tokenB = b.MakePairingToken("https://b.com");
            var tokenA = a.MakePairingToken("https://a.com");
            using var pairedFromA = await a.PairAsync(tokenB);
            using var pairedFromB = await b.PairAsync(tokenA);

            byte[] msg1 = Encoding.UTF8.GetBytes("a->b");
            byte[] msg2 = Encoding.UTF8.GetBytes("b->a");

            Assert.Equal(msg1, pairedFromB.DecryptBody(pairedFromA.EncryptBody(msg1)));
            Assert.Equal(msg2, pairedFromA.DecryptBody(pairedFromB.EncryptBody(msg2)));
        }
    }

    [Fact]
    public async Task EncryptDecrypt_WithAad()
    {
        var (a, b) = await MakePairAsync();
        using (a) using (b)
        {
            var tokenB = b.MakePairingToken("https://b.com");
            var tokenA = a.MakePairingToken("https://a.com");
            using var pairedFromA = await a.PairAsync(tokenB);
            using var pairedFromB = await b.PairAsync(tokenA);

            byte[] plaintext = Encoding.UTF8.GetBytes("with aad");
            byte[] aad = Encoding.UTF8.GetBytes("path-id-aad");
            string ct = pairedFromA.EncryptBody(plaintext, aad);
            byte[] decrypted = pairedFromB.DecryptBody(ct, aad);
            Assert.Equal(plaintext, decrypted);
        }
    }

    [Fact]
    public async Task DecryptBody_ThrowsOnTamperedCiphertext()
    {
        var (a, b) = await MakePairAsync();
        using (a) using (b)
        {
            var tokenB = b.MakePairingToken("https://b.com");
            var tokenA = a.MakePairingToken("https://a.com");
            using var pairedFromA = await a.PairAsync(tokenB);
            using var pairedFromB = await b.PairAsync(tokenA);

            byte[] plaintext = Encoding.UTF8.GetBytes("tamper test");
            string ct = pairedFromA.EncryptBody(plaintext);
            byte[] blob = CasketChannel.B64uDecode(ct);
            blob[blob.Length - 1] ^= 0xFF;
            string bad = CasketChannel.B64uEncode(blob);
            Assert.Throws<CasketChannelDecryptException>(() => pairedFromB.DecryptBody(bad));
        }
    }

    [Fact]
    public async Task DecryptBody_ThrowsOnWrongKey()
    {
        var (a, b) = await MakePairAsync();
        using var c = await CasketChannel.LoadAsync("nexus-c", new MemoryStorage());
        using (a) using (b) using (c)
        {
            var tokenB = b.MakePairingToken("https://b.com");
            var tokenA = a.MakePairingToken("https://a.com");
            var tokenC = c.MakePairingToken("https://c.com");

            using var pairedFromA = await a.PairAsync(tokenB);
            using var pairedFromC = await c.PairAsync(tokenA);  // c paired with a, not b

            byte[] plaintext = Encoding.UTF8.GetBytes("wrong key test");
            string ct = pairedFromA.EncryptBody(plaintext);
            Assert.Throws<CasketChannelDecryptException>(() => pairedFromC.DecryptBody(ct));
        }
    }

    [Fact]
    public async Task DecryptBody_ThrowsOnAadMismatch()
    {
        var (a, b) = await MakePairAsync();
        using (a) using (b)
        {
            var tokenB = b.MakePairingToken("https://b.com");
            var tokenA = a.MakePairingToken("https://a.com");
            using var pairedFromA = await a.PairAsync(tokenB);
            using var pairedFromB = await b.PairAsync(tokenA);

            byte[] plaintext = Encoding.UTF8.GetBytes("aad mismatch test");
            byte[] aadEnc = Encoding.UTF8.GetBytes("correct-aad");
            byte[] aadDec = Encoding.UTF8.GetBytes("wrong-aad");
            string ct = pairedFromA.EncryptBody(plaintext, aadEnc);
            Assert.Throws<CasketChannelDecryptException>(() => pairedFromB.DecryptBody(ct, aadDec));
        }
    }

    [Fact]
    public async Task EncryptBody_ProducesUniqueNonces()
    {
        var (a, b) = await MakePairAsync();
        using (a) using (b)
        {
            var tokenB = b.MakePairingToken("https://b.com");
            using var pairedFromA = await a.PairAsync(tokenB);

            byte[] plaintext = Encoding.UTF8.GetBytes("same plaintext");
            string ct1 = pairedFromA.EncryptBody(plaintext);
            string ct2 = pairedFromA.EncryptBody(plaintext);
            Assert.NotEqual(ct1, ct2);
        }
    }

    [Fact]
    public async Task DecryptBody_ThrowsOnTooShortInput()
    {
        var (a, b) = await MakePairAsync();
        using (a) using (b)
        {
            var tokenB = b.MakePairingToken("https://b.com");
            using var pairedFromA = await a.PairAsync(tokenB);

            string tooShort = CasketChannel.B64uEncode(new byte[5]);
            Assert.Throws<CasketChannelDecryptException>(() => pairedFromA.DecryptBody(tooShort));
        }
    }

    // ── ECDH public key raw export ────────────────────────────────────────────

    [Fact]
    public void ExportEcdhPublicKeyRaw_Is65Bytes()
    {
        using var ecdh = System.Security.Cryptography.ECDiffieHellman.Create(
            System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
        byte[] raw = CasketChannel.ExportEcdhPublicKeyRaw(ecdh);
        Assert.Equal(65, raw.Length);
        Assert.Equal(0x04, raw[0]);
    }

    // ── B64u helpers ──────────────────────────────────────────────────────────

    [Theory]
    [InlineData(new byte[] { 0, 1, 2, 3 })]
    [InlineData(new byte[] { 0xFF, 0xFE, 0x00 })]
    [InlineData(new byte[] { })]
    public void B64uRoundTrip(byte[] data)
    {
        string enc = CasketChannel.B64uEncode(data);
        Assert.DoesNotContain("+", enc);
        Assert.DoesNotContain("/", enc);
        Assert.DoesNotContain("=", enc);
        Assert.Equal(data, CasketChannel.B64uDecode(enc));
    }
}
