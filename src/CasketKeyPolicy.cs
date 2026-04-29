using System;
using System.Threading;

namespace Casket;

public sealed class CasketKeyLimitWarningEventArgs : EventArgs
{
    public ulong SealCount { get; init; }
    public ulong HardLimit { get; init; }
    public ulong? WarnThreshold { get; init; }
}

public sealed class CasketKeyPolicy
{
    // Stored as long internally — Interlocked supports long on all TFMs
    private long _sealCount;

    /// <summary>Maximum seal operations before an exception is thrown. Default: 2^32-1 per NIST SP 800-38D.</summary>
    public ulong HardLimit { get; init; } = 4_294_967_295UL;

    public ulong? WarnThreshold { get; init; } = null;

    public Action<CasketKeyLimitWarningEventArgs>? OnApproachingLimit { get; init; } = null;

    public ulong SealCount => (ulong)Interlocked.Read(ref _sealCount);

    public void Reset() => Interlocked.Exchange(ref _sealCount, 0L);

    internal void RecordSeal()
    {
        ulong next = (ulong)Interlocked.Increment(ref _sealCount);
        if (next > HardLimit)
            throw new CasketKeyLimitExceededException(next, HardLimit);

        if (WarnThreshold.HasValue && next == WarnThreshold.Value)
            OnApproachingLimit?.Invoke(new CasketKeyLimitWarningEventArgs
            {
                SealCount = next,
                HardLimit = HardLimit,
                WarnThreshold = WarnThreshold,
            });
    }
}
