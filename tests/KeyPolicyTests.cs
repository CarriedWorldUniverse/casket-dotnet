using System;
using Xunit;

namespace Casket.Tests;

public class KeyPolicyTests
{
    [Fact]
    public void Policy_TracksCount()
    {
        var policy = new CasketKeyPolicy { HardLimit = 10 };
        var opts = new CasketOptions { Kdf = CasketKdf.Pbkdf2Sha256, Pbkdf2Iterations = 1000, KeyPolicy = policy };
        byte[] key = new byte[32];
        var src = CasketKeySource.FromBytes(key, keyId: 1);

        Casket.Seal("a", src, opts);
        Casket.Seal("b", src, opts);
        Assert.Equal(2UL, policy.SealCount);
    }

    [Fact]
    public void Policy_ThrowsAtHardLimit()
    {
        var policy = new CasketKeyPolicy { HardLimit = 2 };
        var opts = new CasketOptions { Kdf = CasketKdf.Pbkdf2Sha256, Pbkdf2Iterations = 1000, KeyPolicy = policy };
        byte[] key = new byte[32];
        var src = CasketKeySource.FromBytes(key, keyId: 1);

        Casket.Seal("a", src, opts);
        Casket.Seal("b", src, opts);
        Assert.Throws<CasketKeyLimitExceededException>(() => Casket.Seal("c", src, opts));
    }

    [Fact]
    public void Policy_InvokesWarnCallback()
    {
        bool warned = false;
        var policy = new CasketKeyPolicy
        {
            HardLimit = 5,
            WarnThreshold = 2,
            OnApproachingLimit = _ => warned = true,
        };
        var opts = new CasketOptions { Kdf = CasketKdf.Pbkdf2Sha256, Pbkdf2Iterations = 1000, KeyPolicy = policy };
        byte[] key = new byte[32];
        var src = CasketKeySource.FromBytes(key, keyId: 1);

        Casket.Seal("a", src, opts);
        Assert.False(warned);
        Casket.Seal("b", src, opts);
        Assert.True(warned);
    }

    [Fact]
    public void Policy_Reset_ClearsCount()
    {
        var policy = new CasketKeyPolicy { HardLimit = 2 };
        var opts = new CasketOptions { Kdf = CasketKdf.Pbkdf2Sha256, Pbkdf2Iterations = 1000, KeyPolicy = policy };
        byte[] key = new byte[32];
        var src = CasketKeySource.FromBytes(key, keyId: 1);

        Casket.Seal("a", src, opts);
        Casket.Seal("b", src, opts);
        policy.Reset();
        Assert.Equal(0UL, policy.SealCount);
        Casket.Seal("c", src, opts); // should not throw after reset
    }
}
