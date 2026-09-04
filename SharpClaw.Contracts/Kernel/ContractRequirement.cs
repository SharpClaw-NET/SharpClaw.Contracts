namespace SharpClaw.Contracts.Kernel;

/// <summary>
/// Declares a contract that a registration depends on. The dependency is satisfied
/// by any loaded registration that exports a <see cref="ContractExport"/>
/// with the same <see cref="ContractName"/> and a compatible
/// <see cref="ServiceType"/>. This is contract-bound: the consuming registration
/// does not name a specific provider registration — any registration that fits the
/// contract satisfies the dependency.
/// </summary>
public sealed record ContractRequirement(
    /// <summary>
    /// Contract identifier that must be exported by some loaded registration.
    /// Matched against <see cref="ContractExport.ContractName"/>.
    /// </summary>
    string ContractName,

    /// <summary>
    /// The service interface type this registration expects to resolve from DI.
    /// When non-null, validated for type compatibility against the provider's
    /// <see cref="ContractExport.ServiceType"/> using
    /// <see cref="Type.IsAssignableFrom"/>. When <c>null</c>, the dependency
    /// is purely logical — the provider registration must be loaded, but no
    /// specific DI service resolution is required.
    /// </summary>
    Type? ServiceType = null,

    /// <summary>
    /// If <c>true</c>, the registration loads even when no provider exists.
    /// The registration is expected to degrade gracefully when the contract is
    /// absent (e.g. skip optional features, return reduced results).
    /// </summary>
    bool Optional = false,

    /// <summary>Optional description for diagnostics and discoverability.</summary>
    string? Description = null
);
