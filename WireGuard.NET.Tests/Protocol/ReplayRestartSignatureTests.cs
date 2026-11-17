using WireGuard.NET;
using Xunit;

namespace WireGuard.NET.Tests.Protocol;

/// <summary>
/// Regression tests for the replay window reset gate (VM-REPLAY-RECOVER-GATE): the window may only be reset when a peer rebuilt its session with counters restarting near zero, while replayed packets and stale historical packets must still be rejected.
/// </summary>
public class ReplayRestartSignatureTests
{
    /// <summary>
    /// Verifies that counters near zero relative to the current window are recognized as a session restart and allow a window reset.
    /// </summary>
    [Theory]
    [InlineData(0UL, 9UL)]    // iOS 重握手 counter=0 撞 windowLast=9：原始恢复场景
    [InlineData(0UL, 11UL)]
    [InlineData(3UL, 40UL)]   // 重建后已有几包丢失/被拒
    [InlineData(32UL, 33UL)]  // 起点区间上界
    public void RestartSignature_AllowsWindowReset(ulong counter, ulong windowLast)
    {
        Assert.True(WireGuardDevice.IsReplayRestartSignature(counter, windowLast));
    }

    /// <summary>
    /// Verifies that duplicate, non-advancing, or historical counters are not treated as a session restart.
    /// </summary>
    [Theory]
    [InlineData(5UL, 5UL)]      // 同一条最新包的重投（DERP+直连双投/对端重传）
    [InlineData(0UL, 0UL)]      // 窗口未推进，不构成重建
    [InlineData(33UL, 40UL)]    // 已越过起点区间，属于历史包
    [InlineData(100UL, 5000UL)] // 旧会话包，重置等于回滚防重放状态
    [InlineData(5000UL, 5000UL)]
    public void NonRestartSignature_KeepsWindow(ulong counter, ulong windowLast)
    {
        Assert.False(WireGuardDevice.IsReplayRestartSignature(counter, windowLast));
    }
}
