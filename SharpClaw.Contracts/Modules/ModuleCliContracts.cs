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
    HostActionEntryRequestContext HostActionContext)
{
    public bool IsWellFormed(DateTimeOffset now) =>
        InvocationId != Guid.Empty &&
        !string.IsNullOrWhiteSpace(Command) &&
        Arguments is not null &&
        HostActionContext is not null &&
        HostActionContext.Ingress == HostActionEntryIngress.Cli &&
        HostActionContext.InvocationId == InvocationId &&
        HostActionContext.Contribution?.IngressBinding.Ingress == HostActionEntryIngress.Cli &&
        string.Equals(HostActionContext.Contribution.IngressBinding.PrimaryIdentity, Command, StringComparison.Ordinal) &&
        HostActionContext.IsWellFormed(now);
}

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
