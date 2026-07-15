namespace SharpClaw.Contracts.Enums;

/// <summary>
/// Describes whether the durable diagnostic stream for an execution owner is complete.
/// </summary>
public enum DiagnosticCompleteness
{
    /// <summary>No diagnostic append has failed.</summary>
    Complete = 0,

    /// <summary>At least one diagnostic append failed or was rejected.</summary>
    Incomplete = 1,

    /// <summary>The durable diagnostic store could not be initialized or recovered.</summary>
    Failed = 2,

    /// <summary>Retention intentionally removed at least one historical record.</summary>
    Expired = 3,
}
