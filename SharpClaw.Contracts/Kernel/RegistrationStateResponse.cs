namespace SharpClaw.Contracts.Kernel;

/// <summary>
/// Lightweight registration state descriptor returned by lifecycle operations.
/// </summary>
public sealed record RegistrationStateResponse(
    string SourceId,
    string DisplayName,
    string ToolPrefix,
    bool Enabled,
    string? Version,
    bool Registered,
    bool IsExternal,
    DateTimeOffset? CreatedAt,
    DateTimeOffset? UpdatedAt,
    string? ContractHash = null);
