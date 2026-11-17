namespace WireGuard.NET.Protocol;

public partial class KeyRotationManager
{
    /// <summary>
    /// Mutable per-peer transport-key rotation state tracked by
    /// <see cref="KeyRotationManager"/>: the current send/receive keys, session start
    /// time, activity timestamps, traffic counters and rekey bookkeeping for one peer.
    /// Instances live inside the manager's concurrent dictionary; the counter fields
    /// are mutated with <c>Interlocked</c>, while other members are written without
    /// additional synchronization, so readers may observe slightly stale values.
    /// </summary>
    public class KeyRotationState
    {
        /// <summary>
        /// The current 32-byte transport send key used to encrypt outbound packets
        /// to the peer.
        /// </summary>
        public byte[] SendKey { get; set; } = Array.Empty<byte>();

        /// <summary>
        /// The current 32-byte transport receive key used to decrypt inbound packets
        /// from the peer.
        /// </summary>
        public byte[] RecvKey { get; set; } = Array.Empty<byte>();

        /// <summary>
        /// The UTC time the current key generation was established; each rotation
        /// resets it, restarting the REKEY_AFTER_TIME / REJECT_AFTER_TIME windows.
        /// </summary>
        public DateTime SessionStartTime { get; set; }

        /// <summary>
        /// The UTC time of the last outbound packet recorded via
        /// <see cref="KeyRotationManager.RecordSend"/>.
        /// </summary>
        public DateTime LastSendTime { get; set; }

        /// <summary>
        /// The UTC time of the last inbound packet recorded via
        /// <see cref="KeyRotationManager.RecordRecv"/>.
        /// </summary>
        public DateTime LastRecvTime { get; set; }

        /// <summary>
        /// Number of packets sent under the current key generation. Public field
        /// incremented with <c>Interlocked</c>; read it through
        /// <see cref="SendCountUlong"/> for a coherent value.
        /// </summary>
        public long SendCount;

        /// <summary>
        /// Number of packets received under the current key generation. Public field
        /// incremented with <c>Interlocked</c>; read it through
        /// <see cref="RecvCountUlong"/> for a coherent value.
        /// </summary>
        public long RecvCount;

        /// <summary>
        /// Set when the peer has been explicitly flagged for key rotation (e.g. via
        /// <see cref="KeyRotationManager.MarkForRotation"/>), forcing an immediate
        /// rekey regardless of the time/counter thresholds.
        /// </summary>
        public bool NeedsRotation { get; set; }

        /// <summary>
        /// Per-peer jitter added to <c>REKEY_AFTER_TIME</c> so peers do not rekey in
        /// lockstep; randomly chosen in the range −15..+15 seconds when the peer is
        /// initialized.
        /// </summary>
        public TimeSpan RekeyJitter { get; set; } = TimeSpan.Zero;

        /// <summary>
        /// Atomic, torn-read-safe view of <see cref="SendCount"/> as <c>ulong</c>,
        /// used for the REKEY_AFTER_MESSAGES / REJECT_AFTER_MESSAGES thresholds.
        /// </summary>
        public ulong SendCountUlong => (ulong)Interlocked.Read(ref SendCount);

        /// <summary>
        /// Atomic, torn-read-safe view of <see cref="RecvCount"/> as <c>ulong</c>,
        /// used for the REKEY_AFTER_MESSAGES / REJECT_AFTER_MESSAGES thresholds.
        /// </summary>
        public ulong RecvCountUlong => (ulong)Interlocked.Read(ref RecvCount);
    }
}
