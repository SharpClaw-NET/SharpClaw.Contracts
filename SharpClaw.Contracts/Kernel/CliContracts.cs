using System.Text.Json;

namespace SharpClaw.Contracts.Kernel;

public sealed record CliCommandDescriptor(
    string Name,
    IReadOnlyList<string> Aliases,
    string Description,
    JsonSchemaReference ArgumentsSchema,
    JsonSchemaReference ResultSchema,
    bool RequiresAdministrator = false);

public sealed record CliInvocation(
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

public sealed record CliOutput(
    string Stream,
    string Text,
    bool IsSensitive = false);

public sealed record CliResult(
    bool Succeeded,
    IReadOnlyList<CliOutput> Output,
    ExecutionError? Error = null);

public interface ICliHandler
{
    ValueTask<CliResult> ExecuteAsync(
        CliInvocation invocation,
        CancellationToken ct);
}
