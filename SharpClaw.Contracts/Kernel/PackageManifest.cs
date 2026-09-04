using System.Text.Json.Serialization;

namespace SharpClaw.Contracts.Kernel;

/// <summary>
/// JSON-compatible reference to a contract in a <c>package.json</c> manifest.
/// Maps to the <c>exports</c>/<c>requires</c> array entries.
/// </summary>
public sealed record PackageContractReference(
    [property: JsonPropertyName("contractName")] string ContractName,
    [property: JsonPropertyName("serviceType")] string? ServiceType = null,
    [property: JsonPropertyName("optional")] bool Optional = false
);

public sealed record PackageFeatureReference(
    string ContractName,
    int SchemaVersion,
    int MaxBytes,
    bool Required = false);

public sealed record PackageHookRequest(
    string Target,
    IReadOnlyList<string> Effects,
    bool Sensitive = false,
    ContractVersionRange? VersionRange = null);

public sealed record PackageEventRequest(
    string Target,
    string Delivery,
    IReadOnlyList<string> Effects,
    bool Sensitive = false,
    ContractVersionRange? VersionRange = null);

/// <summary>
/// Strongly typed representation of a package manifest.
/// Deserialized with hardened <c>JsonSerializerOptions</c> (MaxDepth=8).
/// </summary>
public sealed record PackageManifest(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("displayName")] string DisplayName,
    [property: JsonPropertyName("version")] string Version,
    [property: JsonPropertyName("toolPrefix")] string ToolPrefix,
    [property: JsonPropertyName("entryAssembly")] string EntryAssembly,
    [property: JsonPropertyName("minHostVersion")] string MinHostVersion,
    [property: JsonPropertyName("author")] string? Author = null,
    [property: JsonPropertyName("description")] string? Description = null,
    [property: JsonPropertyName("license")] string? License = null,
    [property: JsonPropertyName("platforms")] string[]? Platforms = null,
    [property: JsonPropertyName("enabled")] bool Enabled = true,
    [property: JsonPropertyName("defaultEnabled")] bool DefaultEnabled = true,
    [property: JsonPropertyName("executionTimeoutSeconds")] int ExecutionTimeoutSeconds = 60,
    [property: JsonPropertyName("exports")] PackageContractReference[]? Exports = null,
    [property: JsonPropertyName("requires")] PackageContractReference[]? Requires = null,
    [property: JsonPropertyName("runtime")] string? Runtime = null,
    [property: JsonPropertyName("entryType")] string? EntryType = null,
    [property: JsonPropertyName("hostMode")] string? HostMode = null,
    [property: JsonPropertyName("features")] PackageFeatureReference[]? Features = null,
    [property: JsonPropertyName("requestedHooks")] PackageHookRequest[]? RequestedHooks = null,
    [property: JsonPropertyName("requestedEvents")] PackageEventRequest[]? RequestedEvents = null
);
