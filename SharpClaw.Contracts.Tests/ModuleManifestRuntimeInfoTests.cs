using System.Text.Json;
using SharpClaw.Contracts.Modules;

namespace SharpClaw.Contracts.Tests;

public sealed class ModuleManifestRuntimeInfoTests
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

        var runtime = ModuleManifestRuntimeInfo.FromJson(json);

        Assert.Equal(ModuleManifestRuntimeInfo.DotNet, runtime.Runtime);
        Assert.Equal("runtime", runtime.ModuleType);
        Assert.Equal(ModuleManifestRuntimeInfo.HostModeInProcess, runtime.HostMode);
        Assert.True(runtime.IsInProcessHostMode);
    }

    [Fact]
    public void PublicRuntimeContractExposesOnlyDotNetAndHostModeMetadata()
    {
        var publicProperties = typeof(ModuleManifestRuntimeInfo)
            .GetProperties()
            .Select(property => property.Name)
            .OrderBy(name => name)
            .ToArray();

        Assert.Equal(
            ["DotNetDefault", "HostMode", "IsDotNet", "IsInProcessHostMode", "IsSidecarHostMode", "ModuleType", "Runtime"],
            publicProperties);
    }

    [Fact]
    public void EnsureDotNetEntryAssemblyAllowsDllFileName()
    {
        var manifest = CreateManifest(entryAssembly: "Demo.Module.dll");
        var runtime = new ModuleManifestRuntimeInfo(ModuleManifestRuntimeInfo.DotNet, null);

        runtime.EnsureDotNetEntryAssembly(manifest);
    }

    [Fact]
    public void EnsureDotNetEntryAssemblyRejectsMissingEntryAssembly()
    {
        var manifest = CreateManifest(entryAssembly: "");
        var runtime = new ModuleManifestRuntimeInfo(ModuleManifestRuntimeInfo.DotNet, null);

        var ex = Assert.Throws<InvalidOperationException>(() =>
            runtime.EnsureDotNetEntryAssembly(manifest));

        Assert.Contains("entryAssembly", ex.Message);
    }

    [Fact]
    public void EnsureDotNetEntryAssemblyRejectsPathInsteadOfFileName()
    {
        var manifest = CreateManifest(entryAssembly: "bin/Demo.Module.dll");
        var runtime = new ModuleManifestRuntimeInfo(ModuleManifestRuntimeInfo.DotNet, null);

        var ex = Assert.Throws<ArgumentException>(() =>
            runtime.EnsureDotNetEntryAssembly(manifest));

        Assert.Contains("file name", ex.Message);
    }

    [Fact]
    public void EnsureDotNetEntryAssemblyRejectsNonDllExtension()
    {
        var manifest = CreateManifest(entryAssembly: "Demo.Module.exe");
        var runtime = new ModuleManifestRuntimeInfo(ModuleManifestRuntimeInfo.DotNet, null);

        var ex = Assert.Throws<ArgumentException>(() =>
            runtime.EnsureDotNetEntryAssembly(manifest));

        Assert.Contains(".dll", ex.Message);
    }

    [Fact]
    public void EnsureDotNetEntryAssemblyRejectsUnsupportedRuntime()
    {
        var manifest = CreateManifest(entryAssembly: "Demo.Module.dll");
        var runtime = new ModuleManifestRuntimeInfo("unsupported-runtime");

        var ex = Assert.Throws<NotSupportedException>(() =>
            runtime.EnsureDotNetEntryAssembly(manifest));

        Assert.Contains("dotnet", ex.Message);
    }

    [Fact]
    public void ExpectedCodeFlowDeserializesManifestAndValidatesRuntime()
    {
        const string json = """
            {
              "id": "demo.module",
              "displayName": "Demo Module",
              "version": "1.0.0",
              "toolPrefix": "demo",
              "entryAssembly": "Demo.Module.dll",
              "minHostVersion": "0.1.0",
              "runtime": "dotnet"
            }
            """;

        var manifest = JsonSerializer.Deserialize<ModuleManifest>(json)!;
        var runtime = ModuleManifestRuntimeInfo.FromJson(json);

        runtime.EnsureDotNetEntryAssembly(manifest);

        Assert.Equal("demo.module", manifest.Id);
        Assert.True(runtime.IsDotNet);
    }

    private static ModuleManifest CreateManifest(string entryAssembly) =>
        new(
            "demo.module",
            "Demo Module",
            "1.0.0",
            "demo",
            entryAssembly,
            "0.1.0");
}
