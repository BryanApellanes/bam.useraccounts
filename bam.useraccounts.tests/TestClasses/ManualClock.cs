namespace Bam.UserAccounts.Tests.TestClasses;

/// <summary>A clock that starts at the real time and moves only when a test advances it.</summary>
public sealed class ManualClock : TimeProvider
{
    private DateTimeOffset _now = DateTimeOffset.UtcNow;

    /// <inheritdoc />
    public override DateTimeOffset GetUtcNow()
    {
        return _now;
    }

    /// <summary>Moves the clock forward.</summary>
    /// <param name="by">How far.</param>
    public void Advance(TimeSpan by)
    {
        _now = _now.Add(by);
    }
}
