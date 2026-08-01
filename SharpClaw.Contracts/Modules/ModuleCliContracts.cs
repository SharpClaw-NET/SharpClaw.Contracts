using System.Text.Json;

namespace SharpClaw.Contracts.Modules;

public sealed record ModuleCliCommandDescriptor(
    string Name,
    IReadOnlyList<string> Aliases,
    string Description,
    JsonSchemaReference ArgumentsSchema,
    JsonSchemaReference ResultSchema,
    bool RequiresAdministrator = false);

public sealed record ModuleCliInvocation(
    Guid InvocationId,
    string Command,
    IReadOnlyList<string> Arguments,
    RequestPrincipal Caller,
    DateTimeOffset Deadline);

public sealed record ModuleCliOutput(
    string Stream,
    string Text,
    bool IsSensitive = false);

public sealed record ModuleCliResult(
    bool Succeeded,
    IReadOnlyList<ModuleCliOutput> Output,
    ExecutionError? Error = null);

public interface IModuleCliHandler
{
    ValueTask<ModuleCliResult> ExecuteAsync(
        ModuleCliInvocation invocation,
        CancellationToken ct);
}
