namespace SharpClaw.Contracts.Modules;

/// <summary>
/// Extended module detail descriptor returned by module lifecycle APIs.
/// </summary>
public sealed record ModuleDetailResponse(
    string ModuleId,
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
