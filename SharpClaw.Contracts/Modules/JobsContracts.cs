using System.Text.Json;

namespace SharpClaw.Contracts.Modules;

/// <summary>Safety class for one Jobs handler.</summary>
public enum JobExecutionSafety
{
    Pure,
    Idempotent,
    Receipted,
    NonIdempotent
}

/// <summary>Bounded serialized input or output owned by one Jobs contract.</summary>
public sealed record JobPayloadEnvelope(
    string ContractName,
    int SchemaVersion,
    string Value);

/// <summary>References a stored Jobs result without embedding a large payload.</summary>
public sealed record JobResultReference(
    string ContractName,
    int SchemaVersion,
    string? ArtifactKey = null,
    string? MediaType = null,
    long? Length = null,
    string? Sha256 = null);

/// <summary>One canonical Jobs record owned by the kernel.</summary>
public sealed record JobDocument(
    Guid Id,
    Guid InvocationId,
    Guid IdempotencyKey,
    Guid? ConversationId,
    SharpClawActionKey ActionKey,
    RequestPrincipal Caller,
    ExtensionFeatureSet Features,
    JobStatus Status,
    IReadOnlyList<ToolHoldRequirement> Holds,
    DateTimeOffset CreatedAt,
    DateTimeOffset? StartedAt,
    DateTimeOffset? CompletedAt,
    Guid? ActiveAttemptId,
    ActionOutcomeCertainty OutcomeCertainty,
    JobPayloadEnvelope Input,
    JobResultReference? Result = null,
    ExecutionError? Error = null);

/// <summary>One durable attempt for a canonical Jobs record.</summary>
public sealed record JobAttemptDocument(
    Guid AttemptId,
    Guid JobId,
    Guid InvocationId,
    Guid IdempotencyKey,
    int AttemptNumber,
    JobExecutionSafety Safety,
    string? ReceiptId,
    DateTimeOffset StartedAt,
    DateTimeOffset? LeaseExpiresAt,
    DateTimeOffset? FinishedAt);

/// <summary>Typed request for one canonical Jobs submission.</summary>
public sealed record JobSubmission<TInput>(
    SharpClawActionKey ActionKey,
    TInput Input,
    RequestPrincipal Caller,
    ExtensionFeatureSet Features,
    Guid? ConversationId = null,
    IReadOnlyList<ToolHoldRequirement>? Holds = null,
    Guid? IdempotencyKey = null);

/// <summary>Execution data supplied to a typed Jobs handler.</summary>
public sealed record JobExecutionContext(
    JobDocument Job,
    JobAttemptDocument Attempt,
    RequestPrincipal Caller,
    ExtensionFeatureSet Features);

/// <summary>Typed result returned by the canonical Jobs coordinator.</summary>
public sealed record JobExecutionResult<TResult>(
    JobDocument Job,
    TResult? Result,
    ActionOutcomeKind Outcome,
    ExecutionError? Error = null,
    ActionUncertainty? Uncertainty = null);

/// <summary>Typed progress value owned by the Jobs lifecycle.</summary>
public sealed record JobProgress(
    Guid JobId,
    Guid? AttemptId,
    string Code,
    string Message,
    double? Percent = null,
    DateTimeOffset? OccurredAt = null);

/// <summary>Typed JSON codec for a Jobs payload contract.</summary>
public interface IJobPayloadCodec<T>
{
    string ContractName { get; }

    int SchemaVersion { get; }

    JobPayloadEnvelope Encode(T value);

    T Decode(JobPayloadEnvelope payload);
}

/// <summary>Non-generic view of one typed Jobs handler.</summary>
public interface IJobHandler
{
    SharpClawActionKey ActionKey { get; }

    JobExecutionSafety Safety { get; }

    Type InputType { get; }

    Type ResultType { get; }

    string InputContractName { get; }

    int InputSchemaVersion { get; }

    string ResultContractName { get; }

    int ResultSchemaVersion { get; }

    ValueTask<JobPayloadEnvelope> ExecuteAsync(
        JobExecutionContext context,
        JobPayloadEnvelope input,
        CancellationToken cancellationToken);

    JobPayloadEnvelope EncodeResult(object result);

    object DecodeResult(JobPayloadEnvelope result);
}

/// <summary>Typed handler contract used by the Core Jobs coordinator.</summary>
public interface IJobHandler<TInput, TResult> : IJobHandler
{
    IJobPayloadCodec<TInput> InputCodec { get; }

    IJobPayloadCodec<TResult> ResultCodec { get; }

    ValueTask<TResult> ExecuteAsync(
        JobExecutionContext context,
        TInput input,
        CancellationToken cancellationToken);

    Type IJobHandler.InputType => typeof(TInput);

    Type IJobHandler.ResultType => typeof(TResult);

    string IJobHandler.InputContractName => InputCodec.ContractName;

    int IJobHandler.InputSchemaVersion => InputCodec.SchemaVersion;

    string IJobHandler.ResultContractName => ResultCodec.ContractName;

    int IJobHandler.ResultSchemaVersion => ResultCodec.SchemaVersion;

    async ValueTask<JobPayloadEnvelope> IJobHandler.ExecuteAsync(
        JobExecutionContext context,
        JobPayloadEnvelope input,
        CancellationToken cancellationToken) =>
        ResultCodec.Encode(
            await ExecuteAsync(
                context,
                InputCodec.Decode(input),
                cancellationToken));

    JobPayloadEnvelope IJobHandler.EncodeResult(object result) =>
        result is TResult typed
            ? ResultCodec.Encode(typed)
            : throw new ArgumentException(
                $"The Jobs result must be '{typeof(TResult).FullName}'.",
                nameof(result));

    object IJobHandler.DecodeResult(JobPayloadEnvelope result) =>
        ResultCodec.Decode(result)!;
}

/// <summary>Default bounded JSON codec for a Jobs payload contract.</summary>
public sealed class JsonJobPayloadCodec<T> : IJobPayloadCodec<T>
{
    private readonly JsonSerializerOptions _options;

    public JsonJobPayloadCodec(
        string contractName,
        int schemaVersion = 1,
        JsonSerializerOptions? options = null)
    {
        if (string.IsNullOrWhiteSpace(contractName))
            throw new ArgumentException("A Jobs payload requires a contract name.", nameof(contractName));
        if (schemaVersion < 1)
            throw new ArgumentOutOfRangeException(nameof(schemaVersion));

        ContractName = contractName;
        SchemaVersion = schemaVersion;
        _options = options ?? new JsonSerializerOptions(JsonSerializerDefaults.Web);
    }

    public string ContractName { get; }

    public int SchemaVersion { get; }

    public JobPayloadEnvelope Encode(T value) =>
        new(
            ContractName,
            SchemaVersion,
            JsonSerializer.Serialize(value, _options));

    public T Decode(JobPayloadEnvelope payload)
    {
        ArgumentNullException.ThrowIfNull(payload);
        if (!string.Equals(payload.ContractName, ContractName, StringComparison.Ordinal) ||
            payload.SchemaVersion != SchemaVersion)
        {
            throw new InvalidOperationException(
                $"Jobs payload '{payload.ContractName}' version {payload.SchemaVersion} " +
                $"does not match '{ContractName}' version {SchemaVersion}.");
        }

        return JsonSerializer.Deserialize<T>(payload.Value, _options)
            ?? throw new InvalidOperationException(
                $"Jobs payload '{ContractName}' did not deserialize to '{typeof(T).FullName}'.");
    }
}
