using System.Text.Json;

namespace SharpClaw.Contracts.Modules;

/// <summary>
/// Parsed runtime metadata from a module manifest. This is the canonical
/// runtime/host-mode interpretation used by SharpClaw hosts.
/// </summary>
public sealed record ModuleManifestRuntimeInfo(
    string Runtime,
    string? ModuleType = null,
    string? HostMode = null)
{
    public const string DotNet = "dotnet";
    public const string HostModeInProcess = "in-process";
    public const string HostModeSidecar = "sidecar";
    public static ModuleManifestRuntimeInfo DotNetDefault { get; } = new(DotNet, null);

    private static readonly JsonDocumentOptions DocumentOptions = new()
    {
        MaxDepth = 8,
        AllowTrailingCommas = false,
        CommentHandling = JsonCommentHandling.Skip,
    };

    public bool IsDotNet => string.Equals(Runtime, DotNet, StringComparison.Ordinal);
    public bool IsSidecarHostMode => string.Equals(HostMode, HostModeSidecar, StringComparison.Ordinal);
    public bool IsInProcessHostMode => string.Equals(HostMode, HostModeInProcess, StringComparison.Ordinal);

    public static ModuleManifestRuntimeInfo FromJson(string json)
    {
        using var doc = JsonDocument.Parse(json, DocumentOptions);
        var root = doc.RootElement;
        var runtime = TryGetString(root, "runtime");
        var moduleType = TryGetString(root, "moduleType")
            ?? TryGetString(root, "type");
        var hostMode = NormalizeHostMode(TryGetString(root, "hostMode"));

        return new ModuleManifestRuntimeInfo(
            Normalize(runtime),
            moduleType,
            hostMode);
    }

    public static string Normalize(string? runtime) =>
        string.IsNullOrWhiteSpace(runtime)
            ? DotNet
            : runtime.Trim().ToLowerInvariant();

    public static string? NormalizeHostMode(string? hostMode)
    {
        if (string.IsNullOrWhiteSpace(hostMode))
            return null;

        var normalized = hostMode.Trim().ToLowerInvariant();
        return normalized is "inprocess" or "in-process"
            ? HostModeInProcess
            : normalized;
    }

    public void EnsureDotNetEntryAssembly(ModuleManifest manifest)
    {
        ArgumentNullException.ThrowIfNull(manifest);

        if (!IsDotNet)
        {
            throw new NotSupportedException(
                $"Module '{manifest.Id}' declares runtime '{Runtime}', but this SharpClaw build only supports " +
                $"'{DotNet}' modules.");
        }

        if (string.IsNullOrWhiteSpace(manifest.EntryAssembly))
        {
            throw new InvalidOperationException(
                $"Module '{manifest.Id}' declares runtime '{DotNet}' but has no entryAssembly.");
        }

        EnsureFileName(manifest.EntryAssembly, nameof(manifest.EntryAssembly));
        EnsureExtension(manifest.EntryAssembly, ".dll");

        if (!string.IsNullOrWhiteSpace(ModuleType)
            && ModuleType.Any(char.IsControl))
        {
            throw new InvalidOperationException(
                $"Module '{manifest.Id}' declares an invalid moduleType.");
        }
    }

    private static string? TryGetString(JsonElement root, string propertyName)
    {
        if (root.ValueKind != JsonValueKind.Object
            || !root.TryGetProperty(propertyName, out var property)
            || property.ValueKind != JsonValueKind.String)
        {
            return null;
        }

        return property.GetString();
    }

    private static void EnsureFileName(string value, string parameterName)
    {
        if (value.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0
            || value.Contains(Path.DirectorySeparatorChar)
            || value.Contains(Path.AltDirectorySeparatorChar)
            || Path.IsPathRooted(value))
        {
            throw new ArgumentException(
                $"'{parameterName}' must be a file name, not a path.",
                parameterName);
        }
    }

    private static void EnsureExtension(string value, string extension)
    {
        if (!string.Equals(
            Path.GetExtension(value),
            extension,
            StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException(
                $"File name '{value}' must have extension '{extension}'.");
        }
    }
}
