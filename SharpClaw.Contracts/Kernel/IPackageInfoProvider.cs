namespace SharpClaw.Contracts.Kernel;

/// <summary>
/// Provides read-only information about loaded registrations.
/// Implemented host-side by <c>RegistrationCatalog</c>; injected into registrations
/// that need to introspect the registration roster without referencing Core.
/// </summary>
public interface IPackageInfoProvider
{
    /// <summary>Returns lightweight descriptors for every currently registered registration.</summary>
    IReadOnlyList<PackageInfo> GetAllPackages();
}

/// <summary>
/// Lightweight descriptor of a registered registration, safe to cross the
/// registration boundary without exposing host implementation details.
/// </summary>
/// <param name="Id">Registration identifier (e.g. <c>"sharpclaw_dangerous_shell"</c>).</param>
/// <param name="ToolPrefix">Short prefix used in tool and CLI names.</param>
/// <param name="ExportedContractNames">Names of contracts this registration exports.</param>
public sealed record PackageInfo(
    string Id,
    string ToolPrefix,
    IReadOnlyList<string> ExportedContractNames);
