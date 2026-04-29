using System;
using Xunit;

namespace Casket.Tests;

public class KeyRingTests
{
    [Fact]
    public void KeyRing_DispatchesByKeyId()
    {
        byte[] key1 = new byte[32]; key1[0] = 1;
        byte[] key2 = new byte[32]; key2[0] = 2;
        var src1 = CasketKeySource.FromBytes(key1, keyId: 1);
        var src2 = CasketKeySource.FromBytes(key2, keyId: 2);

        string token = Casket.Seal("sealed with key1", src1);

        var ring = new CasketKeyRing().Add(src1).Add(src2);
        string result = ring.Unseal(token);
        Assert.Equal("sealed with key1", result);
    }

    [Fact]
    public void KeyRing_FallsBackOnAnonymousKey()
    {
        byte[] key = new byte[32]; key[0] = 0xAA;
        var src = CasketKeySource.FromBytes(key, keyId: 0); // anonymous
        string token = Casket.Seal("anon", src);

        // Ring has key with keyId=1 pointing to same bytes
        var ringSrc = CasketKeySource.FromBytes(key, keyId: 1);
        var ring = new CasketKeyRing().Add(ringSrc);
        string result = ring.Unseal(token);
        Assert.Equal("anon", result);
    }

    [Fact]
    public void KeyRing_ThrowsIfKeyNotRegistered()
    {
        byte[] key = new byte[32]; key[0] = 1;
        var src = CasketKeySource.FromBytes(key, keyId: 1);
        string token = Casket.Seal("data", src);

        byte[] otherKey = new byte[32]; otherKey[0] = 2;
        var ring = new CasketKeyRing().Add(CasketKeySource.FromBytes(otherKey, keyId: 2));
        Assert.Throws<CasketKeyNotFoundException>(() => ring.Unseal(token));
    }

    [Fact]
    public void KeyRing_RejectsDuplicateKeyId()
    {
        byte[] key = new byte[32];
        var src1 = CasketKeySource.FromBytes(key, keyId: 1);
        var src2 = CasketKeySource.FromBytes(key, keyId: 1);
        var ring = new CasketKeyRing().Add(src1);
        Assert.Throws<ArgumentException>(() => ring.Add(src2));
    }
}
