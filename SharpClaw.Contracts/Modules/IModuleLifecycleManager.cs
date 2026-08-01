namespace SharpClaw.Contracts.Modules;

/// <summary>
/// Host-side interface for module lifecycle operations.
/// </summary>
public interface IModuleLifecycleManager
{
    /// <summary>
    /// Absolute path to the external-modules root directory.
    /// Modules use this as the sandbox boundary for path validation.
    /// </summary>
    string ExternalModulesDir { get; }

    /// <summary>Returns <c>true</c> if a module with the given ID is registered.</summary>
    bool IsModuleRegistered(string moduleId);

    /// <summary>Loads an external module from the given directory.</summary>
    Task<ModuleStateResponse> LoadExternalAsync(
        string moduleDir, IServiceProvider hostServices, CancellationToken ct = default);

    /// <summary>Unloads the external module with the given ID.</summary>
    Task UnloadExternalAsync(string moduleId, CancellationToken ct = default);

    /// <summary>Unloads then reloads the external module with the given ID.</summary>
    Task<ModuleStateResponse> ReloadExternalAsync(
        string moduleId, IServiceProvider hostServices, CancellationToken ct = default);
}
