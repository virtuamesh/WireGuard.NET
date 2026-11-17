namespace WireGuard.NET;

/// <summary>
/// Provides content-based equality comparison and hashing for byte arrays, allowing
/// them to be used as keys in dictionaries and hash sets (the default comparison for
/// arrays is by reference, which is not suitable for keying on key material).
/// </summary>
public class ByteArrayComparer : IEqualityComparer<byte[]>
{
    /// <summary>
    /// Determines whether two byte arrays contain identical content.
    /// </summary>
    /// <param name="x">The first array, or <c>null</c>.</param>
    /// <param name="y">The second array, or <c>null</c>.</param>
    /// <returns>
    /// <c>true</c> if both arrays are <c>null</c>, or if both are non-null and contain
    /// the same bytes in the same order; otherwise, <c>false</c>.
    /// </returns>
    public bool Equals(byte[]? x, byte[]? y)
    {
        if (x == null && y == null) return true;
        if (x == null || y == null) return false;
        if (x.Length != y.Length) return false;

        for (int i = 0; i < x.Length; i++)
        {
            if (x[i] != y[i]) return false;
        }
        return true;
    }

    /// <summary>
    /// Computes a content-based hash code for the specified byte array.
    /// </summary>
    /// <param name="obj">The array to hash.</param>
    /// <returns>A hash code computed from every byte in the array.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="obj"/> is <c>null</c>.</exception>
    public int GetHashCode(byte[] obj)
    {
        if (obj == null) throw new ArgumentNullException(nameof(obj));

        unchecked
        {
            int hash = 17;
            foreach (byte b in obj)
            {
                hash = hash * 31 + b;
            }
            return hash;
        }
    }
}
