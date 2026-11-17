namespace WireGuard.NET.Protocol;

// Partial class file for AllowedIPsFilter: contains the PacketMatchResult packet-match result type.
// Immutable value object: NoMatch / DefaultRoute static instances + prefix length specified at construction.
public partial class AllowedIPsFilter
{
    /// <summary>
    /// The result of matching a raw IP packet against the AllowedIPs set.
    /// Immutable value object: <see cref="NoMatch"/> and <see cref="DefaultRoute"/> are shared
    /// static instances; other outcomes are constructed with an explicit prefix length.
    /// </summary>
    public readonly struct PacketMatchResult
    {
        /// <summary>Whether the packet matched any AllowedIPs rule.</summary>
        public bool IsMatch { get; }

        /// <summary>The matched longest prefix length in bits; <c>-1</c> when no rule matched.</summary>
        public int PrefixLength { get; }

        /// <summary>Whether the match is a default route (prefix length 0, i.e. 0.0.0.0/0 or ::/0).</summary>
        public bool IsDefaultRoute { get; }

        /// <summary>Sentinel result for "no rule matched" (IsMatch=false, PrefixLength=-1).</summary>
        public static readonly PacketMatchResult NoMatch = new(false, -1, false);

        /// <summary>Sentinel result for a default-route match (IsMatch=true, PrefixLength=0).</summary>
        public static readonly PacketMatchResult DefaultRoute = new(true, 0, true);

        private PacketMatchResult(bool isMatch, int prefixLength, bool isDefaultRoute)
        {
            IsMatch = isMatch;
            PrefixLength = prefixLength;
            IsDefaultRoute = isDefaultRoute;
        }

        /// <summary>
        /// Creates a match result; <see cref="IsDefaultRoute"/> is derived from the prefix length.
        /// </summary>
        /// <param name="isMatch">Whether a rule matched.</param>
        /// <param name="prefixLength">The matched prefix length in bits (<c>-1</c> indicates no match).</param>
        public PacketMatchResult(bool isMatch, int prefixLength)
        {
            IsMatch = isMatch;
            PrefixLength = prefixLength;
            IsDefaultRoute = prefixLength == 0;
        }
    }
}
