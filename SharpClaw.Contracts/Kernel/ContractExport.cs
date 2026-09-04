namespace SharpClaw.Contracts.Kernel;

/// <summary>
/// Describes a service contract that a registration provides to other registrations.
/// The providing registration must register an implementation of <see cref="ServiceType"/>
/// in DI by the providing registration.
/// Any registration that declares a <see cref="ContractRequirement"/> with
/// the same <see cref="ContractName"/> is considered a dependent and will be
/// initialized after this registration.
/// </summary>
/// <remarks>
/// Contract interfaces should live in shared assemblies (e.g.
/// <c>SharpClaw.Contracts</c>) so that provider and consumer registrations
/// reference the same CLR type. Assemblies loaded from the default
/// <see cref="System.Runtime.Loader.AssemblyLoadContext"/> are shared across
/// all registration load contexts, ensuring type identity.
/// </remarks>
public sealed record ContractExport(
    /// <summary>
    /// Unique contract identifier (e.g. <c>"desktop_capture"</c>).
    /// Format: <c>^[a-z][a-z0-9_]{0,59}$</c> — lowercase alphanumeric
    /// plus underscores, starting with a letter, max 60 characters.
    /// Only one registration may export a given contract name at a time.
    /// </summary>
    string ContractName,

    /// <summary>
    /// The service interface type registered in DI by the providing registration
    /// (e.g. <c>typeof(IDesktopCapture)</c>). Consuming registrations resolve
    /// this type from their scoped <see cref="IServiceProvider"/>.
    /// </summary>
    Type ServiceType,

    /// <summary>Optional human-readable description for discoverability.</summary>
    string? Description = null
);
