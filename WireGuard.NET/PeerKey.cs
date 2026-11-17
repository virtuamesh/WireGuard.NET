using System.Runtime.CompilerServices;

namespace WireGuard.NET;

/// <summary>
/// A lightweight wrapper for a peer public key that provides value-based equality
/// and a precomputed hash code, suitable for use as dictionary keys.
/// </summary>
/// <remarks>
/// The hash code is computed once in the constructor. The wrapped array is stored by
/// reference (not copied), so callers must not mutate it after wrapping.
/// </remarks>
public readonly struct PeerKey : IEquatable<PeerKey>
{
    /// <summary>Gets the raw key bytes.</summary>
    public byte[] Bytes { get; }

    private readonly int _hashCode;

    /// <summary>
    /// Initializes a new instance of the <see cref="PeerKey"/> struct and precomputes
    /// its hash code.
    /// </summary>
    /// <param name="bytes">The raw key bytes. The array is stored by reference and must not be mutated afterwards.</param>
    /// <exception cref="ArgumentNullException"><paramref name="bytes"/> is <c>null</c>.</exception>
    public PeerKey(byte[] bytes)
    {
        Bytes = bytes ?? throw new ArgumentNullException(nameof(bytes));
        unchecked
        {
            int hash = 17;
            for (int i = 0; i < bytes.Length; i++)
            {
                hash = hash * 31 + bytes[i];
            }
            _hashCode = hash;
        }
    }

    /// <summary>
    /// Implicitly converts a raw byte array into a <see cref="PeerKey"/>.
    /// </summary>
    /// <param name="bytes">The raw key bytes.</param>
    public static implicit operator PeerKey(byte[] bytes) => new(bytes);

    /// <summary>
    /// Determines whether this key and the specified key contain identical bytes.
    /// </summary>
    /// <param name="other">The key to compare with this instance.</param>
    /// <returns><c>true</c> if both keys wrap arrays of the same length with equal content; otherwise, <c>false</c>.</returns>
    /// <remarks>A precomputed hash-code mismatch short-circuits the byte-by-byte comparison.</remarks>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool Equals(PeerKey other)
    {
        if (_hashCode != other._hashCode) return false;
        var a = Bytes;
        var b = other.Bytes;
        if (a.Length != b.Length) return false;
        for (int i = 0; i < a.Length; i++)
        {
            if (a[i] != b[i]) return false;
        }
        return true;
    }

    /// <summary>
    /// Determines whether the specified object is a <see cref="PeerKey"/> equal to this instance.
    /// </summary>
    /// <param name="obj">The object to compare with this instance.</param>
    /// <returns><c>true</c> if <paramref name="obj"/> is a <see cref="PeerKey"/> with identical bytes; otherwise, <c>false</c>.</returns>
    public override bool Equals(object? obj) => obj is PeerKey other && Equals(other);

    /// <summary>
    /// Returns the hash code precomputed at construction time.
    /// </summary>
    /// <returns>A content-based hash code of the wrapped key bytes.</returns>
    public override int GetHashCode() => _hashCode;

    /// <summary>
    /// Determines whether two peer keys are equal.
    /// </summary>
    /// <param name="left">The first key.</param>
    /// <param name="right">The second key.</param>
    /// <returns><c>true</c> if both keys are equal; otherwise, <c>false</c>.</returns>
    public static bool operator ==(PeerKey left, PeerKey right) => left.Equals(right);

    /// <summary>
    /// Determines whether two peer keys are not equal.
    /// </summary>
    /// <param name="left">The first key.</param>
    /// <param name="right">The second key.</param>
    /// <returns><c>true</c> if the keys are not equal; otherwise, <c>false</c>.</returns>
    public static bool operator !=(PeerKey left, PeerKey right) => !left.Equals(right);
}
