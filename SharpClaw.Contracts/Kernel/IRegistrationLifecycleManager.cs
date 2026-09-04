namespace SharpClaw.Contracts.Kernel;

/// <summary>
/// Host-side interface for registration lifecycle operations.
/// </summary>
public interface IRegistrationLifecycleManager
{
    /// <summary>
    /// Absolute path to the external-registrations root directory.
    /// Registrations use this as the sandbox boundary for path validation.
    /// </summary>
    string ExternalPackagesDirectory { get; }

    /// <summary>Returns <c>true</c> if a registration with the given ID is registered.</summary>
    bool IsRegistrationPresent(string SourceId);

    /// <summary>Loads an external registration from the given directory.</summary>
    Task<RegistrationStateResponse> LoadExternalAsync(
        string registrationDir, IServiceProvider hostServices, CancellationToken ct = default);

    /// <summary>Unloads the external registration with the given ID.</summary>
    Task UnloadExternalAsync(string SourceId, CancellationToken ct = default);

    /// <summary>Unloads then reloads the external registration with the given ID.</summary>
    Task<RegistrationStateResponse> ReloadExternalAsync(
        string SourceId, IServiceProvider hostServices, CancellationToken ct = default);
}
