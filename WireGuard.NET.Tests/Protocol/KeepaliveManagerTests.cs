using Xunit;
using WireGuard.NET.Protocol;
using System.Net;

namespace WireGuard.NET.Tests.Protocol;

/// <summary>
/// Tests for the keepalive manager peer registration, packet bookkeeping, and lifecycle operations.
/// </summary>
public class KeepaliveManagerTests
{
    /// <summary>
    /// Verifies that adding a peer is accepted and the manager can then be started and stopped without error.
    /// </summary>
    [Fact]
    public void AddPeer_ShouldStorePeer()
    {
        var manager = new KeepaliveManager();
        var publicKey = new byte[32];
        
        manager.AddPeer(publicKey, 25);
        
        manager.Start();
        manager.Stop();
    }

    /// <summary>
    /// Verifies that removing a peer is accepted and the manager can then be started and stopped without error.
    /// </summary>
    [Fact]
    public void RemovePeer_ShouldRemovePeer()
    {
        var manager = new KeepaliveManager();
        var publicKey = new byte[32];
        
        manager.AddPeer(publicKey, 25);
        manager.RemovePeer(publicKey);
        
        manager.Start();
        manager.Stop();
    }

    /// <summary>
    /// Verifies that recording a received packet for a peer is accepted and the manager can still start and stop.
    /// </summary>
    [Fact]
    public void PacketReceived_ShouldUpdateTimestamp()
    {
        var manager = new KeepaliveManager();
        var publicKey = new byte[32];
        
        manager.AddPeer(publicKey, 25);
        manager.PacketReceived(publicKey);
        
        manager.Start();
        manager.Stop();
    }

    /// <summary>
    /// Verifies that recording a sent packet for a peer is accepted and the manager can still start and stop.
    /// </summary>
    [Fact]
    public void PacketSent_ShouldUpdateTimestamp()
    {
        var manager = new KeepaliveManager();
        var publicKey = new byte[32];
        
        manager.AddPeer(publicKey, 25);
        manager.PacketSent(publicKey);
        
        manager.Start();
        manager.Stop();
    }

    /// <summary>
    /// Verifies that starting the manager does not throw.
    /// </summary>
    [Fact]
    public void Start_ShouldNotThrow()
    {
        var manager = new KeepaliveManager();
        
        var exception = Record.Exception(() => manager.Start());
        
        Assert.Null(exception);
        manager.Stop();
    }

    /// <summary>
    /// Verifies that stopping a started manager does not throw.
    /// </summary>
    [Fact]
    public void Stop_ShouldNotThrow()
    {
        var manager = new KeepaliveManager();
        manager.Start();
        
        var exception = Record.Exception(() => manager.Stop());
        
        Assert.Null(exception);
    }
}
