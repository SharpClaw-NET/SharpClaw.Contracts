using System.Text.Json;
using SharpClaw.Contracts.Kernel;

namespace SharpClaw.Contracts.Tests;

public sealed class PackageManifestRuntimeInfoTests
{
    [Fact]
    public void FromJsonNormalizesRuntimeTypeAliasAndHostMode()
    {
        const string json = """
            {
              "runtime": " DOTNET ",
              "type": "runtime",
              "hostMode": "inprocess"
            }
            """;

        var runtime = PackageRuntimeInfo.FromJson(json);

        Assert.Equal(PackageRuntimeInfo.DotNet, runtime.Runtime);
        Assert.Equal("runtime", runtime.EntryType);
        Assert.Equal(PackageRuntimeInfo.HostModeInProcess, runtime.HostMode);
        Assert.True(runtime.IsInProcessHostMode);
    }

    [Fact]
    public void PublicRuntimeContractExposesOnlyDotNetAndHostModeMetadata()
    {
        var publicProperties = typeof(PackageRuntimeInfo)
            .GetProperties()
            .Select(property => property.Name)
            .OrderBy(name => name)
            .ToArray();

        Assert.Equal(
            ["DotNetDefault", "EntryType", "HostMode", "IsDotNet", "IsInProcessHostMode", "IsSidecarHostMode", "Runtime"],
            publicProperties);
    }

    [Fact]
    public void EnsureDotNetEntryAssemblyAllowsDllFileName()
    {
        var manifest = CreateManifest(entryAssembly: "Demo.Entry.dll");
        var runtime = new PackageRuntimeInfo(PackageRuntimeInfo.DotNet, null);

        runtime.EnsureDotNetEntryAssembly(manifest);
    }

    [Fact]
    public void EnsureDotNetEntryAssemblyRejectsMissingEntryAssembly()
    {
        var manifest = CreateManifest(entryAssembly: "");
        var runtime = new PackageRuntimeInfo(PackageRuntimeInfo.DotNet, null);

        var ex = Assert.Throws<InvalidOperationException>(() =>
            runtime.EnsureDotNetEntryAssembly(manifest));

        Assert.Contains("entryAssembly", ex.Message);
    }

    [Fact]
    public void EnsureDotNetEntryAssemblyRejectsPathInsteadOfFileName()
    {
        var manifest = CreateManifest(entryAssembly: "bin/Demo.Entry.dll");
        var runtime = new PackageRuntimeInfo(PackageRuntimeInfo.DotNet, null);

        var ex = Assert.Throws<ArgumentException>(() =>
            runtime.EnsureDotNetEntryAssembly(manifest));

        Assert.Contains("file name", ex.Message);
    }

    [Fact]
    public void EnsureDotNetEntryAssemblyRejectsNonDllExtension()
    {
        var manifest = CreateManifest(entryAssembly: "Demo.Entry.exe");
        var runtime = new PackageRuntimeInfo(PackageRuntimeInfo.DotNet, null);

        var ex = Assert.Throws<ArgumentException>(() =>
            runtime.EnsureDotNetEntryAssembly(manifest));

        Assert.Contains(".dll", ex.Message);
    }

    [Fact]
    public void EnsureDotNetEntryAssemblyRejectsUnsupportedRuntime()
    {
        var manifest = CreateManifest(entryAssembly: "Demo.Entry.dll");
        var runtime = new PackageRuntimeInfo("unsupported-runtime");

        var ex = Assert.Throws<NotSupportedException>(() =>
            runtime.EnsureDotNetEntryAssembly(manifest));

        Assert.Contains("dotnet", ex.Message);
    }

    [Fact]
    public void ExpectedCodeFlowDeserializesManifestAndValidatesRuntime()
    {
        const string json = """
            {
              "id": "demo.package",
              "displayName": "Demo Package",
              "version": "1.0.0",
              "toolPrefix": "demo",
              "entryAssembly": "Demo.Entry.dll",
              "minHostVersion": "0.1.0",
              "runtime": "dotnet"
            }
            """;

        var manifest = JsonSerializer.Deserialize<PackageManifest>(json)!;
        var runtime = PackageRuntimeInfo.FromJson(json);

        runtime.EnsureDotNetEntryAssembly(manifest);

        Assert.Equal("demo.package", manifest.Id);
        Assert.True(runtime.IsDotNet);
    }

    private static PackageManifest CreateManifest(string entryAssembly) =>
        new(
            "demo.package",
            "Demo Package",
            "1.0.0",
            "demo",
            entryAssembly,
            "0.1.0");
}
