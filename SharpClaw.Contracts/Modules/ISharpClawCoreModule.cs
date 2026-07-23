using System.Text.Json;

using Microsoft.Extensions.DependencyInjection;

namespace SharpClaw.Contracts.Modules;

/// <summary>
/// Contract for a SharpClaw Core module. Core modules extend the pure
/// SharpClaw pipeline: providers, tools, resource and
/// permission descriptors, module storage, contracts, health, and lifecycle.
/// They cannot publish application runtime surfaces such as CLI commands,
/// API endpoints, gateway routes, or frontend contributions.
/// </summary>
public interface ISharpClawCoreModule
{
    /// <summary>Unique module identifier (e.g. "computer_use").</summary>
    string Id { get; }

    /// <summary>Human-readable name (e.g. "Computer Use").</summary>
    string DisplayName { get; }

    /// <summary>Tool name prefix. Must be unique across all loaded modules.</summary>
    string ToolPrefix { get; }

    /// <summary>
    /// Register services into the DI container.
    /// Called once at startup before any tool execution.
    /// </summary>
    void ConfigureServices(IServiceCollection services);

    /// <summary>
    /// Return all job-pipeline tool definitions this module exposes.
    /// Each definition includes the schema sent to the LLM.
    /// These tools flow through the full AgentJobService lifecycle.
    /// </summary>
    IReadOnlyList<ModuleToolDefinition> GetToolDefinitions();

    /// <summary>
    /// Return inline tool definitions. Inline tools execute directly within
    /// the chat streaming loop without creating a job record.
    /// </summary>
    IReadOnlyList<ModuleInlineToolDefinition> GetInlineToolDefinitions() => [];

    /// <summary>
    /// Contracts this module provides to other modules.
    /// </summary>
    IReadOnlyList<ModuleContractExport> ExportedContracts => [];

    /// <summary>
    /// Contracts this module depends on.
    /// </summary>
    IReadOnlyList<ModuleContractRequirement> RequiredContracts => [];

    /// <summary>
    /// Called once after the DI container is built but before the first HTTP
    /// request is served.
    /// </summary>
    Task InitializeAsync(IServiceProvider services, CancellationToken ct) =>
        Task.CompletedTask;

    /// <summary>
    /// Called once during graceful application shutdown.
    /// </summary>
    Task ShutdownAsync() => Task.CompletedTask;

    /// <summary>
    /// Called once after a module is freshly installed and loaded for the
    /// first time.
    /// </summary>
    Task SeedDataAsync(IServiceProvider services, CancellationToken ct) =>
        Task.CompletedTask;

    /// <summary>
    /// Execute a job-pipeline tool by name.
    /// </summary>
    Task<string> ExecuteToolAsync(
        string toolName,
        JsonElement parameters,
        AgentJobContext job,
        IServiceProvider scopedServices,
        CancellationToken ct);

    /// <summary>
    /// Return lifecycle behavior for a job-pipeline tool.
    /// </summary>
    ModuleJobCompletionBehavior GetJobCompletionBehavior(
        string toolName,
        JsonElement parameters,
        AgentJobContext job) =>
        ModuleJobCompletionBehavior.CompleteWhenExecutionReturns;

    /// <summary>
    /// Execute an inline tool by name.
    /// </summary>
    Task<string> ExecuteInlineToolAsync(
        string toolName,
        JsonElement parameters,
        InlineToolContext context,
        IServiceProvider scopedServices,
        CancellationToken ct) =>
        throw new NotImplementedException(
            $"Module '{Id}' does not implement ExecuteInlineToolAsync for tool '{toolName}'.");

    /// <summary>
    /// Optional. Return header tag definitions this module provides.
    /// </summary>
    IReadOnlyList<ModuleHeaderTag>? GetHeaderTags() => null;

    /// <summary>
    /// Optional. Return resource type descriptors this module owns.
    /// </summary>
    IReadOnlyList<ModuleResourceTypeDescriptor> GetResourceTypeDescriptors() => [];

    /// <summary>
    /// Optional. Return global flag descriptors this module owns.
    /// </summary>
    IReadOnlyList<ModuleGlobalFlagDescriptor> GetGlobalFlagDescriptors() => [];

    /// <summary>
    /// Optional. Return host-owned storage contracts this module uses.
    /// </summary>
    IReadOnlyList<ModuleStorageContractDescriptor> GetStorageContracts() => [];

    /// <summary>
    /// Optional periodic health check.
    /// </summary>
    Task<ModuleHealthStatus> HealthCheckAsync(CancellationToken ct) =>
        Task.FromResult(new ModuleHealthStatus(IsHealthy: true));

    /// <summary>
    /// Optional streaming variant of <see cref="ExecuteToolAsync"/>.
    /// </summary>
    IAsyncEnumerable<string>? ExecuteToolStreamingAsync(
        string toolName,
        JsonElement parameters,
        AgentJobContext job,
        IServiceProvider scopedServices,
        CancellationToken ct) => null;
}
