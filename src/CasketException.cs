using System;

namespace Casket;

public abstract class CasketException : Exception
{
    protected CasketException(string message) : base(message) { }
    protected CasketException(string message, Exception inner) : base(message, inner) { }
}

/// <summary>Authentication or decryption failed. Message is intentionally generic to prevent oracle attacks.</summary>
public sealed class CasketDecryptionException : CasketException
{
    public CasketDecryptionException() : base("Decryption failed.") { }
    public CasketDecryptionException(Exception inner) : base("Decryption failed.", inner) { }
}

public sealed class CasketStreamTruncatedException : CasketException
{
    public CasketStreamTruncatedException() : base("Stream was truncated before the final chunk was reached.") { }
}

public sealed class CasketStreamCorruptedException : CasketException
{
    public CasketStreamCorruptedException(string detail) : base($"Stream is structurally invalid: {detail}") { }
}

public sealed class CasketKeyLimitExceededException : CasketException
{
    public ulong SealCount { get; }
    public ulong HardLimit { get; }

    public CasketKeyLimitExceededException(ulong sealCount, ulong hardLimit)
        : base($"Key seal limit exceeded ({sealCount}/{hardLimit}). Rotate the key.")
    {
        SealCount = sealCount;
        HardLimit = hardLimit;
    }
}

public sealed class CasketConfigurationException : CasketException
{
    public CasketConfigurationException(string detail) : base(detail) { }
    public CasketConfigurationException(string detail, Exception inner) : base(detail, inner) { }
}

public sealed class CasketKeyNotFoundException : CasketException
{
    public ushort KeyId { get; }

    public CasketKeyNotFoundException(ushort keyId)
        : base($"No key registered for key ID 0x{keyId:X4}.")
    {
        KeyId = keyId;
    }
}

public sealed class CasketUnsupportedVersionException : CasketException
{
    public byte Version { get; }

    public CasketUnsupportedVersionException(byte version)
        : base($"Unsupported token version: 0x{version:X2}.")
    {
        Version = version;
    }
}

public sealed class CasketChannelPairException : CasketException
{
    public CasketChannelPairException(string detail) : base(detail) { }
}

public sealed class CasketChannelVerifyException : CasketException
{
    public CasketChannelVerifyException() : base("Signature verification failed.") { }
}

public sealed class CasketChannelDecryptException : CasketException
{
    public CasketChannelDecryptException() : base("Body decryption failed — wrong key or tampered ciphertext.") { }
    public CasketChannelDecryptException(string detail) : base(detail) { }
}
