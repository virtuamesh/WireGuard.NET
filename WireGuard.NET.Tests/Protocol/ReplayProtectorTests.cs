using Xunit;
using WireGuard.NET.Protocol;

namespace WireGuard.NET.Tests.Protocol;

/// <summary>
/// Tests for the sliding-window replay protector, including the official WireGuard counter test sequence.
/// </summary>
public class ReplayProtectorTests
{
    private const ulong RejectAfterMessages = unchecked((1UL << 64) - (1UL << 13) - 1);

    /// <summary>
    /// Verifies that a fresh counter is accepted.
    /// </summary>
    [Fact]
    public void ValidateCounter_NewCounter_ReturnsTrue()
    {
        var protector = new ReplayProtector();
        
        var result = protector.ValidateCounter(0);
        
        Assert.True(result);
    }

    /// <summary>
    /// Verifies that increasing counters are accepted in order.
    /// </summary>
    [Fact]
    public void ValidateCounter_SequentialCounters_ReturnsTrue()
    {
        var protector = new ReplayProtector();
        
        Assert.True(protector.ValidateCounter(0));
        Assert.True(protector.ValidateCounter(1));
        Assert.True(protector.ValidateCounter(2));
        Assert.True(protector.ValidateCounter(3));
    }

    /// <summary>
    /// Verifies that repeating an already accepted counter is rejected.
    /// </summary>
    [Fact]
    public void ValidateCounter_DuplicateCounter_ReturnsFalse()
    {
        var protector = new ReplayProtector();
        
        Assert.True(protector.ValidateCounter(0));
        Assert.False(protector.ValidateCounter(0));
    }

    /// <summary>
    /// Verifies that a counter more than the window size behind is rejected after the window advances.
    /// </summary>
    [Fact]
    public void ValidateCounter_OutOfWindow_ReturnsFalse()
    {
        var protector = new ReplayProtector();
        
        Assert.True(protector.ValidateCounter(0));
        Assert.True(protector.ValidateCounter(8128));
        Assert.False(protector.ValidateCounter(0));
    }

    /// <summary>
    /// Verifies that a slightly older unseen counter inside the window is accepted.
    /// </summary>
    [Fact]
    public void ValidateCounter_SlightlyOldCounter_ReturnsTrue()
    {
        var protector = new ReplayProtector();
        
        Assert.True(protector.ValidateCounter(100));
        Assert.True(protector.ValidateCounter(50));
    }

    /// <summary>
    /// Verifies that an older counter that was already accepted is rejected.
    /// </summary>
    [Fact]
    public void ValidateCounter_OldAndUsedCounter_ReturnsFalse()
    {
        var protector = new ReplayProtector();
        
        Assert.True(protector.ValidateCounter(0));
        Assert.True(protector.ValidateCounter(100));
        Assert.False(protector.ValidateCounter(0));
    }

    /// <summary>
    /// Verifies that Reset allows the same counter to be accepted again.
    /// </summary>
    [Fact]
    public void Reset_ClearsState()
    {
        var protector = new ReplayProtector();
        
        Assert.True(protector.ValidateCounter(0));
        Assert.False(protector.ValidateCounter(0));
        
        protector.Reset();
        
        Assert.True(protector.ValidateCounter(0));
    }

    /// <summary>
    /// Verifies the official WireGuard replay window test sequence, including wrap-around scenarios and the reject-after limit.
    /// </summary>
    [Fact]
    public void ValidateCounter_OfficialWireGuardTests_AllPass()
    {
        var protector = new ReplayProtector();
        const int windowSize = 8128;
        const ulong T_LIM = windowSize + 1;
        int testNumber = 0;

        void T(ulong n, bool expected)
        {
            testNumber++;
            var actual = protector.ValidateCounter(n);
            Assert.Equal(expected, actual);
        }

        protector.Reset();

        T(0, true);
        T(1, true);
        T(1, false);
        T(9, true);
        T(8, true);
        T(7, true);
        T(7, false);
        T(T_LIM, true);
        T(T_LIM - 1, true);
        T(T_LIM - 1, false);
        T(T_LIM - 2, true);
        T(2, true);
        T(2, false);
        T(T_LIM + 16, true);
        T(3, false);
        T(T_LIM + 16, false);
        T(T_LIM * 4, true);
        T(T_LIM * 4 - (T_LIM - 1), true);
        T(10, false);
        T(T_LIM * 4 - T_LIM, false);
        T(T_LIM * 4 - (T_LIM + 1), false);
        T(T_LIM * 4 - (T_LIM - 2), true);
        T(T_LIM * 4 + 1 - T_LIM, false);
        T(0, false);
        T(RejectAfterMessages, false);
        T(RejectAfterMessages - 1, true);
        T(RejectAfterMessages, false);
        T(RejectAfterMessages - 1, false);
        T(RejectAfterMessages - 2, true);
        T(RejectAfterMessages + 1, false);
        T(RejectAfterMessages + 2, false);
        T(RejectAfterMessages - 2, false);
        T(RejectAfterMessages - 3, true);
        T(0, false);

        protector.Reset();
        testNumber = 0;
        for (ulong i = 1; i <= windowSize; i++)
        {
            T(i, true);
        }
        T(0, true);
        T(0, false);

        protector.Reset();
        testNumber = 0;
        for (ulong i = 2; i <= windowSize + 1; i++)
        {
            T(i, true);
        }
        T(1, true);
        T(0, false);

        protector.Reset();
        testNumber = 0;
        for (ulong i = windowSize + 1; i > 0; i--)
        {
            T(i, true);
        }

        protector.Reset();
        testNumber = 0;
        for (ulong i = windowSize + 2; i > 1; i--)
        {
            T(i, true);
        }
        T(0, false);

        protector.Reset();
        testNumber = 0;
        for (ulong i = windowSize; i > 0; i--)
        {
            T(i, true);
        }
        T(windowSize + 1, true);
        T(0, false);

        protector.Reset();
        testNumber = 0;
        for (ulong i = windowSize; i > 0; i--)
        {
            T(i, true);
        }
        T(0, true);
        T(windowSize + 1, true);
    }
}
