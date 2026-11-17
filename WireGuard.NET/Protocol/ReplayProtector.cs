using System.Threading;

namespace WireGuard.NET.Protocol;

/// <summary>
/// Anti-replay protection for WireGuard data-packet counters, implemented as an RFC 6479-style
/// sliding-window bitmap.
/// </summary>
/// <remarks>
/// The ring holds 128 blocks of 64 bits (8,192 counters); the effective window spans 8,128
/// counters ((128 - 1) blocks) behind the highest accepted counter. A counter is accepted only if
/// it is below the configured limit, within the window, and not previously seen. Per RFC 6479,
/// blocks that fall out of the window as it advances are cleared wholesale rather than bit by bit.
/// All operations take a lock, so an instance may be shared across threads.
/// </remarks>
public class ReplayProtector
{
    /// <summary>log2 of the number of bits per ring block (64 bits per block).</summary>
    private const int BlockBitLog = 6;
    /// <summary>Bits per ring block (64).</summary>
    private const int BlockBits = 1 << BlockBitLog;
    /// <summary>Number of blocks in the ring (128, a power of two).</summary>
    private const int RingBlocks = 1 << 7;
    /// <summary>Sliding window size in counters: (RingBlocks - 1) * BlockBits = 8,128.</summary>
    private const int WindowSize = (RingBlocks - 1) * BlockBits;
    /// <summary>Bit mask selecting a block index within the ring (RingBlocks - 1).</summary>
    private const int BlockMask = RingBlocks - 1;
    /// <summary>Bit mask selecting a bit index within a block (BlockBits - 1).</summary>
    private const int BitMask = BlockBits - 1;

    /// <summary>Highest accepted counter so far; read atomically by <see cref="LastCounter"/>.</summary>
    private ulong _last;
    /// <summary>
    /// Ring of received-counter bitmaps; block i covers counters [i*64, i*64+63] modulo the ring.
    /// </summary>
    private readonly long[] _ring;

    /// <summary>
    /// [VM-DIAG 2026-10-21] The replay window's current advancement position (diagnostics only):
    /// replay-rejection logs carry this value to distinguish "same packet delivered twice"
    /// (the counter is already behind _last) from "window state anomaly".
    /// </summary>
    public ulong LastCounter => Volatile.Read(ref _last);

    // [VM-S4] The whole ValidateCounter operation is protected by a lock, fixing a race condition
    // under multi-threaded access. In the previous implementation the _last update and the _ring
    // clearing were not atomic, and the CAS retry logic had a bug: after the second CAS failed it
    // fell through to a decision based on stale state, which could cause replayed packets to be
    // accepted.
    private readonly object _lock = new();

    /// <summary>Creates a protector with an empty window (no counters accepted yet).</summary>
    public ReplayProtector()
    {
        _last = 0;
        _ring = new long[RingBlocks];
    }

    /// <summary>
    /// Validates a packet counter with the default limit of 2^64 - 2^13 - 1
    /// (mirroring the WireGuard reject-after-messages ceiling).
    /// </summary>
    /// <param name="counter">The 64-bit counter from the data-packet header.</param>
    /// <returns>
    /// <c>true</c> if the counter is fresh and accepted; <c>false</c> if replayed, out of window,
    /// or at/beyond the limit.
    /// </returns>
    public bool ValidateCounter(ulong counter)
    {
        return ValidateCounter(counter, unchecked((1UL << 64) - (1UL << 13) - 1));
    }

    /// <summary>
    /// Validates a packet counter against the sliding window.
    /// </summary>
    /// <param name="counter">The 64-bit counter from the data-packet header.</param>
    /// <param name="limit">Exclusive upper bound for accepted counters.</param>
    /// <returns>
    /// <c>true</c> if the counter is new and within the window; <c>false</c> if the counter is at
    /// or beyond <paramref name="limit"/>, older than the window, or a duplicate of an
    /// already-accepted counter.
    /// </returns>
    /// <remarks>
    /// Thread-safe: the bitmap check-and-set and the window advance run under a lock. When the
    /// window moves forward, whole blocks that leave the window are cleared at once (RFC 6479).
    /// </remarks>
    public bool ValidateCounter(ulong counter, ulong limit)
    {
        if (counter >= limit)
        {
            return false;
        }

        lock (_lock)
        {
            ulong last = _last;
            ulong indexBlock = counter >> BlockBitLog;

            if (counter > last)
            {
                ulong current = last >> BlockBitLog;
                ulong diff = indexBlock - current;
                if (diff > RingBlocks)
                {
                    diff = RingBlocks;
                }
                for (ulong i = current + 1; i <= current + diff; i++)
                {
                    _ring[i & BlockMask] = 0;
                }
                _last = counter;
            }
            else if (last - counter > WindowSize)
            {
                return false;
            }

            int blockIdx = (int)(indexBlock & BlockMask);
            int indexBit = (int)(counter & BitMask);
            long bit = 1L << indexBit;
            long old = _ring[blockIdx];

            // If this bit is already set, the packet is a replay.
            if ((old & bit) != 0)
            {
                return false;
            }

            _ring[blockIdx] = old | bit;
            return true;
        }
    }

    /// <summary>
    /// Clears all window state, as if no counters had been accepted. Thread-safe.
    /// </summary>
    public void Reset()
    {
        lock (_lock)
        {
            _last = 0;
            Array.Clear(_ring, 0, _ring.Length);
        }
    }
}
