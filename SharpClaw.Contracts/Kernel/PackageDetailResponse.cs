namespace SharpClaw.Contracts.Kernel;

/// <summary>
/// Extended registration detail descriptor returned by registration lifecycle APIs.
/// </summary>
public sealed record PackageDetailResponse(
    string SourceId,
    string DisplayName,
    string ToolPrefix,
    bool Enabled,
    string? Version,
    bool Registered,
    bool IsExternal,
    DateTimeOffset? CreatedAt,
    DateTimeOffset? UpdatedAt,
    string? Author,
    string? Description,
    string? License,
    string[]? Platforms,
    int ExecutionTimeoutSeconds,
    int ActionCount,
    int EventCount,
    int FeatureCount,
    string[] ExportedContracts,
    string[] RequiredContracts,
    bool AllRequirementsSatisfied);
