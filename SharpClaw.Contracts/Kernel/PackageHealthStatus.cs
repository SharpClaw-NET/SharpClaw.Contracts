namespace SharpClaw.Contracts.Kernel;

/// <summary>
/// Result of a registration health check.
/// </summary>
public sealed record PackageHealthStatus(
    /// <summary>Whether the registration considers itself healthy.</summary>
    bool IsHealthy,

    /// <summary>
    /// Optional diagnostic message. Always logged; shown in admin UI
    /// and CLI. Should not contain secrets or PII.
    /// </summary>
    string? Message = null,

    /// <summary>
    /// Optional structured diagnostics (e.g. connection pool size,
    /// queue depth, cache hit rate). Serialized to JSON for the
    /// <c>/packages/{id}/health</c> endpoint.
    /// </summary>
    IReadOnlyDictionary<string, object>? Details = null
);
