namespace SharpClaw.Contracts.Kernel;

/// <summary>
/// Snapshot of execution metrics for a single registration tool.
/// Computed on demand from the atomic counters in <c>PackageMetricsCollector</c>.
/// </summary>
public sealed record ToolMetrics(
    /// <summary>Prefixed tool name (e.g. "cu_enumerate_windows").</summary>
    string PrefixedToolName,

    /// <summary>Total invocations (completed + failed + timed out).</summary>
    long TotalCalls,

    /// <summary>Invocations that completed successfully.</summary>
    long SuccessCount,

    /// <summary>Invocations that threw an exception.</summary>
    long FailureCount,

    /// <summary>Invocations that exceeded the execution timeout.</summary>
    long TimeoutCount,

    /// <summary>
    /// Cumulative execution time across all completed calls.
    /// Divide by <see cref="SuccessCount"/> for average duration.
    /// </summary>
    TimeSpan TotalDuration,

    /// <summary>
    /// Average execution duration for successful calls.
    /// <see cref="TimeSpan.Zero"/> if no successful calls have been recorded.
    /// </summary>
    TimeSpan AverageDuration,

    /// <summary>Timestamp of the last successful call (UTC).</summary>
    DateTimeOffset? LastCallAt,

    /// <summary>Timestamp of the last failure (UTC).</summary>
    DateTimeOffset? LastFailureAt
);

/// <summary>
/// Aggregated metrics for an entire registration — sum of all its tools.
/// </summary>
public sealed record PackageMetricsSnapshot(
    string SourceId,
    string DisplayName,
    long TotalCalls,
    long SuccessCount,
    long FailureCount,
    long TimeoutCount,
    TimeSpan TotalDuration,
    TimeSpan AverageDuration,
    DateTimeOffset? LastCallAt,
    DateTimeOffset? LastFailureAt,
    IReadOnlyList<ToolMetrics> Tools
);
