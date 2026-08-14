using System.Security.Cryptography;
using System.Text.Json;

namespace SharpClaw.Contracts.Modules;

[Flags]
public enum ActionInterceptionCapabilities
{
    Inspect = 1 << 0,
    ReplaceInput = 1 << 1,
    Cancel = 1 << 2,
    ReplaceResult = 1 << 3,
    Defer = 1 << 4,
    Repeat = 1 << 5,
    Wrap = 1 << 6,
    Observe = 1 << 7,
    PublishEvents = 1 << 8,
}

public enum ActionRepeatKind
{
    None,
    ConflictOnly,
    Idempotent,
    Receipted,
}

public sealed record ActionRepeatPolicy(
    ActionRepeatKind Kind,
    int MaximumAttempts,
    TimeSpan MinimumBackoff,
    string IdempotencyScope);

public sealed record ActionContinuationPolicy(
    TimeSpan MaximumLifetime,
    bool Durable,
    bool SingleClaim);

public sealed record ActionDescriptor<TAction, TResult>(
    SharpClawActionKey Key,
    int Version,
    string Category,
    ActionInterceptionCapabilities Capabilities,
    bool ContainsSensitiveData,
    bool HasIrreversibleEffects,
    ActionRepeatPolicy RepeatPolicy,
    ActionContinuationPolicy? ContinuationPolicy,
    TimeSpan DefaultTimeout)
{
    public ContractVersionRange ProtocolVersionRange { get; init; } =
        ContractVersionRange.Exact(1);

    public IReadOnlyList<ActionSafePoint> SafePoints { get; init; } = [];

    public JsonSchemaReference? InputSchema { get; init; }

    public JsonSchemaReference? ResultSchema { get; init; }
}

public enum ActionOutcomeKind
{
    Completed,
    Cancelled,
    Deferred,
    Failed,
    Uncertain,
}

public enum ActionExecutionStage
{
    BeforeContinuation,
    ContinuationRunning,
    TerminalReturned,
    Committed,
    AfterContinuation,
}

public sealed record ActionRecoveryReference(
    Guid RecoveryId,
    SharpClawActionKey ActionKey,
    int ActionVersion,
    Guid IdempotencyKey);

public sealed record ActionUncertainty(
    string Code,
    string Message,
    ActionExecutionStage Stage,
    string? ReceiptReference,
    ActionRecoveryReference Recovery,
    DateTimeOffset RecordedAt)
{
    public bool AutomaticRepeatAllowed => false;
}

public interface IActionOutcome<out TResult>
{
    ActionOutcomeKind Kind { get; }
    TResult? Result { get; }
    ContinuationToken? Continuation { get; }
    ExecutionError? Error { get; }
    ActionUncertainty? Uncertainty { get; }
}

public sealed record ActionReplacement<TAction>(TAction Value, string Reason);

public sealed record ActionRepeatRequest<TAction>(
    TAction Value,
    string Reason,
    TimeSpan? Backoff = null);

public sealed record ActionDeferRequest(
    DateTimeOffset ExpiresAt,
    string Reason);

public interface IActionControl<TAction, TResult>
{
    ValueTask<IActionOutcome<TResult>> ProceedAsync(CancellationToken ct);

    ValueTask<IActionOutcome<TResult>> ProceedWithInputAsync(
        ActionReplacement<TAction> replacement,
        CancellationToken ct);

    IActionOutcome<TResult> ReplaceResult(TResult result, string reason);
    IActionOutcome<TResult> Cancel(string code, string message);
    IActionOutcome<TResult> Fail(ExecutionError error);

    ValueTask<IActionOutcome<TResult>> DeferAsync(
        ActionDeferRequest request,
        CancellationToken ct);

    ValueTask<IActionOutcome<TResult>> RepeatAsync(
        ActionRepeatRequest<TAction> request,
        CancellationToken ct);
}

public interface IActionInterceptor<TAction, TResult>
{
    ValueTask<IActionOutcome<TResult>> InvokeAsync(
        ActionContext<TAction> context,
        IActionControl<TAction, TResult> control,
        CancellationToken ct);
}

public abstract record BeforeActionDecision<TAction>
{
    public sealed record Continue : BeforeActionDecision<TAction>;
    public sealed record Replace(ActionReplacement<TAction> Replacement) : BeforeActionDecision<TAction>;
    public sealed record Cancel(string Code, string Message) : BeforeActionDecision<TAction>;
}

public interface IBeforeAction<TAction>
{
    ValueTask<BeforeActionDecision<TAction>> BeforeAsync(
        ActionContext<TAction> context,
        CancellationToken ct);
}

public interface IAfterAction<TAction, TResult>
{
    ValueTask<IActionOutcome<TResult>> AfterAsync(
        ActionContext<TAction> context,
        IActionOutcome<TResult> outcome,
        IActionControl<TAction, TResult> control,
        CancellationToken ct);
}

public interface IActionFaultHandler<TAction, TResult>
{
    ValueTask<IActionOutcome<TResult>> OnFaultAsync(
        ActionContext<TAction> context,
        Exception exception,
        IActionControl<TAction, TResult> control,
        CancellationToken ct);
}

public interface IActionCancellationListener<TAction>
{
    ValueTask OnCancelledAsync(
        ActionContext<TAction> context,
        CancellationToken ct);
}

public sealed record ActionContext<TAction>(
    Guid InvocationId,
    Guid? ParentInvocationId,
    Guid TraceId,
    Guid IdempotencyKey,
    int Depth,
    int Attempt,
    DateTimeOffset Deadline,
    SharpClawActionKey ActionKey,
    string OwnerModuleId,
    RequestPrincipal Caller,
    TAction Action,
    ExtensionFeatureSet Features,
    ActionPipelineSnapshot Snapshot);

public sealed record HostActionEntryValidationResult(
    bool Accepted,
    string Code,
    string Message)
{
    public static HostActionEntryValidationResult Accept() =>
        new(true, "accepted", "Accepted.");

    public static HostActionEntryValidationResult Reject(string code, string message) =>
        new(false, code, message);
}

/// <summary>Host-issued authority for one typed module action entry.</summary>
public sealed record HostActionEntryAuthority(
    string ModuleId,
    string GraphId,
    Guid SessionId,
    Guid RequestId,
    Guid CancellationId,
    Guid CallId,
    string ReplayNonce,
    long Sequence,
    RequestPrincipal Caller,
    ExtensionFeatureSet Features,
    Guid TraceId,
    Guid IdempotencyKey,
    SharpClawActionKey ActionKey,
    int ActionVersion,
    string Category,
    string InputTypeIdentity,
    string ResultTypeIdentity,
    string DescriptorHash,
    string InputSchemaHash,
    int InputSchemaVersion,
    string ResultSchemaHash,
    int ResultSchemaVersion,
    string ActionContentHash,
    int ActionByteLength,
    DateTimeOffset Deadline,
    DateTimeOffset IssuedAt,
    DateTimeOffset ExpiresAt,
    string Proof)
{
    public bool IsValid =>
        !string.IsNullOrWhiteSpace(ModuleId) &&
        !string.IsNullOrWhiteSpace(GraphId) &&
        SessionId != Guid.Empty &&
        RequestId != Guid.Empty &&
        CancellationId != Guid.Empty &&
        CallId != Guid.Empty &&
        !string.IsNullOrWhiteSpace(ReplayNonce) &&
        Sequence > 0 &&
        Caller is not null &&
        !string.IsNullOrWhiteSpace(Caller.SubjectId) &&
        Features is not null &&
        Features.Items is not null &&
        TraceId != Guid.Empty &&
        IdempotencyKey != Guid.Empty &&
        !string.IsNullOrWhiteSpace(ActionKey.Value) &&
        ActionVersion >= 1 &&
        !string.IsNullOrWhiteSpace(Category) &&
        !string.IsNullOrWhiteSpace(InputTypeIdentity) &&
        !string.IsNullOrWhiteSpace(ResultTypeIdentity) &&
        !string.IsNullOrWhiteSpace(DescriptorHash) &&
        !string.IsNullOrWhiteSpace(InputSchemaHash) &&
        InputSchemaVersion >= 1 &&
        !string.IsNullOrWhiteSpace(ResultSchemaHash) &&
        ResultSchemaVersion >= 1 &&
        !string.IsNullOrWhiteSpace(ActionContentHash) &&
        ActionByteLength > 0 &&
        !string.IsNullOrWhiteSpace(Proof);
}

/// <summary>Typed input supplied to the host action entry.</summary>
public sealed record HostActionEntryRequestContext(
    Guid RequestId,
    RequestPrincipal Caller,
    ExtensionFeatureSet Features,
    Guid TraceId,
    Guid IdempotencyKey,
    DateTimeOffset ExpiresAt)
{
    public bool IsWellFormed(DateTimeOffset now) =>
        RequestId != Guid.Empty &&
        Caller is not null &&
        !string.IsNullOrWhiteSpace(Caller.SubjectId) &&
        Features is not null &&
        Features.Items is not null &&
        TraceId != Guid.Empty &&
        IdempotencyKey != Guid.Empty &&
        ExpiresAt > now;
}

public sealed record HostActionEntryRequest<TAction, TResult>(
    ActionDescriptor<TAction, TResult> Descriptor,
    TAction Action,
    RequestPrincipal Caller,
    ExtensionFeatureSet Features,
    Guid TraceId,
    Guid IdempotencyKey,
    DateTimeOffset Deadline)
{
    public bool IsWellFormed(DateTimeOffset now) =>
        Descriptor is not null &&
        Descriptor.Version >= 1 &&
        !string.IsNullOrWhiteSpace(Descriptor.Key.Value) &&
        Caller is not null &&
        !string.IsNullOrWhiteSpace(Caller.SubjectId) &&
        Features is not null &&
        Features.Items is not null &&
        TraceId != Guid.Empty &&
        IdempotencyKey != Guid.Empty &&
        Deadline > now;
}

/// <summary>Host-only transport envelope after authority issuance.</summary>
public sealed record HostActionEntryTransportRequest<TAction, TResult>(
    HostActionEntryRequest<TAction, TResult> Request,
    HostActionEntryAuthority Authority)
{
    public HostActionEntryValidationResult Validate(
        DateTimeOffset now,
        Func<HostActionEntryAuthority, bool> authenticateAuthority) =>
        HostActionEntryAuthorityValidator.Validate(Request, Authority, now, authenticateAuthority);
}

public static class HostActionEntryAuthorityValidator
{
    public static HostActionEntryValidationResult Validate<TAction, TResult>(
        HostActionEntryRequest<TAction, TResult> request,
        HostActionEntryAuthority authority,
        DateTimeOffset now,
        Func<HostActionEntryAuthority, bool> authenticateAuthority)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(authenticateAuthority);

        if (authority is null || !authority.IsValid)
            return HostActionEntryValidationResult.Reject(
                "host_action_invalid_authority",
                "The host action entry authority is incomplete.");

        if (authority.IssuedAt > now || authority.ExpiresAt <= now ||
            authority.Deadline <= now || authority.Deadline > authority.ExpiresAt)
        {
            return HostActionEntryValidationResult.Reject(
                "host_action_expired",
                "The host action entry authority is expired or outside its deadline.");
        }

        if (!authenticateAuthority(authority))
            return HostActionEntryValidationResult.Reject(
                "host_action_unauthenticated",
                "The host action entry authority proof was not accepted.");

        if (request.Descriptor is null || request.Descriptor.Version < 1 ||
            string.IsNullOrWhiteSpace(request.Descriptor.Key.Value) ||
            request.Caller is null || string.IsNullOrWhiteSpace(request.Caller.SubjectId) ||
            request.Features is null || request.Features.Items is null || request.TraceId == Guid.Empty ||
            request.IdempotencyKey == Guid.Empty || request.Deadline <= now)
        {
            return HostActionEntryValidationResult.Reject(
                "host_action_invalid_request",
                "The host action entry request is incomplete.");
        }

        var inputTypeIdentity = TypeIdentity<TAction>();
        var resultTypeIdentity = TypeIdentity<TResult>();
        var descriptorHash = ComputeDescriptorHash(request.Descriptor);
        if (request.Descriptor.InputSchema is null || request.Descriptor.ResultSchema is null ||
            string.IsNullOrWhiteSpace(request.Descriptor.InputSchema.ContentHash) ||
            string.IsNullOrWhiteSpace(request.Descriptor.ResultSchema.ContentHash) ||
            request.Descriptor.InputSchema.Version < 1 ||
            request.Descriptor.ResultSchema.Version < 1)
        {
            return HostActionEntryValidationResult.Reject(
                "host_action_missing_schema",
                "The host action descriptor does not contain complete schema authority.");
        }

        var actionBytes = SidecarCapabilityTransportCodec.Serialize(request.Action);
        var actionContentHash = Convert.ToHexString(SHA256.HashData(actionBytes));
        if (!string.Equals(authority.ActionKey.Value, request.Descriptor.Key.Value, StringComparison.Ordinal) ||
            authority.ActionVersion != request.Descriptor.Version ||
            !string.Equals(authority.Category, request.Descriptor.Category, StringComparison.Ordinal) ||
            !string.Equals(authority.InputTypeIdentity, inputTypeIdentity, StringComparison.Ordinal) ||
            !string.Equals(authority.ResultTypeIdentity, resultTypeIdentity, StringComparison.Ordinal) ||
            !string.Equals(authority.DescriptorHash, descriptorHash, StringComparison.Ordinal) ||
            !string.Equals(authority.InputSchemaHash, request.Descriptor.InputSchema.ContentHash, StringComparison.Ordinal) ||
            authority.InputSchemaVersion != request.Descriptor.InputSchema.Version ||
            !string.Equals(authority.ResultSchemaHash, request.Descriptor.ResultSchema.ContentHash, StringComparison.Ordinal) ||
            authority.ResultSchemaVersion != request.Descriptor.ResultSchema.Version ||
            !string.Equals(authority.ActionContentHash, actionContentHash, StringComparison.Ordinal) ||
            authority.ActionByteLength != actionBytes.Length ||
            !SamePrincipal(authority.Caller, request.Caller) ||
            !SameFeatures(authority.Features, request.Features) ||
            authority.TraceId != request.TraceId ||
            authority.IdempotencyKey != request.IdempotencyKey ||
            authority.Deadline != request.Deadline)
        {
            return HostActionEntryValidationResult.Reject(
                "host_action_spoofed_authority",
                "The host action entry request does not match its host-issued authority.");
        }

        return HostActionEntryValidationResult.Accept();
    }

    public static bool MatchesRequestContext<TAction, TResult>(
        HostActionEntryRequest<TAction, TResult> request,
        HostActionEntryRequestContext context) =>
        request is not null &&
        context is not null &&
        request.Deadline <= context.ExpiresAt &&
        SamePrincipal(request.Caller, context.Caller) &&
        SameFeatures(request.Features, context.Features) &&
        request.TraceId == context.TraceId &&
        request.IdempotencyKey == context.IdempotencyKey;

    public static bool MatchesAuthorityContext(
        HostActionEntryAuthority authority,
        HostActionEntryRequestContext context) =>
        authority is not null &&
        context is not null &&
        authority.RequestId == context.RequestId &&
        authority.Deadline <= context.ExpiresAt &&
        SamePrincipal(authority.Caller, context.Caller) &&
        SameFeatures(authority.Features, context.Features) &&
        authority.TraceId == context.TraceId &&
        authority.IdempotencyKey == context.IdempotencyKey;

    public static string ComputeDescriptorHash<TAction, TResult>(
        ActionDescriptor<TAction, TResult> descriptor)
    {
        ArgumentNullException.ThrowIfNull(descriptor);
        var canonical = new
        {
            Key = descriptor.Key.Value,
            descriptor.Version,
            descriptor.Category,
            Capabilities = (int)descriptor.Capabilities,
            descriptor.ContainsSensitiveData,
            descriptor.HasIrreversibleEffects,
            Repeat = new
            {
                Kind = descriptor.RepeatPolicy.Kind.ToString(),
                descriptor.RepeatPolicy.MaximumAttempts,
                MinimumBackoffTicks = descriptor.RepeatPolicy.MinimumBackoff.Ticks,
                descriptor.RepeatPolicy.IdempotencyScope,
            },
            Continuation = descriptor.ContinuationPolicy is null
                ? null
                : new
                {
                    MaximumLifetimeTicks = descriptor.ContinuationPolicy.MaximumLifetime.Ticks,
                    descriptor.ContinuationPolicy.Durable,
                    descriptor.ContinuationPolicy.SingleClaim,
                },
            DefaultTimeoutTicks = descriptor.DefaultTimeout.Ticks,
            ProtocolMinimum = descriptor.ProtocolVersionRange.Minimum,
            ProtocolMaximum = descriptor.ProtocolVersionRange.Maximum,
            SafePoints = descriptor.SafePoints.Select(point => point.ToString()).ToArray(),
            InputSchema = descriptor.InputSchema is null
                ? null
                : new
                {
                    descriptor.InputSchema.ContractName,
                    descriptor.InputSchema.Version,
                    descriptor.InputSchema.ContentHash,
                },
            ResultSchema = descriptor.ResultSchema is null
                ? null
                : new
                {
                    descriptor.ResultSchema.ContractName,
                    descriptor.ResultSchema.Version,
                    descriptor.ResultSchema.ContentHash,
                },
            InputTypeIdentity = TypeIdentity<TAction>(),
            ResultTypeIdentity = TypeIdentity<TResult>(),
        };
        return Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(canonical)));
    }

    public static string ComputeAuthorityHash(HostActionEntryAuthority authority)
    {
        ArgumentNullException.ThrowIfNull(authority);
        var canonical = new
        {
            authority.ModuleId,
            authority.GraphId,
            authority.SessionId,
            authority.RequestId,
            authority.CancellationId,
            authority.CallId,
            authority.ReplayNonce,
            authority.Sequence,
            Caller = new
            {
                authority.Caller.SubjectId,
                authority.Caller.DisplayName,
                Roles = authority.Caller.Roles?.Order(StringComparer.Ordinal).ToArray(),
                authority.Caller.IsAuthenticated,
            },
            Features = authority.Features.Items.Select(feature => new
            {
                feature.ContractName,
                feature.SchemaVersion,
                feature.OwnerModuleId,
                feature.MaxBytes,
                Value = feature.Value.GetRawText(),
            }).ToArray(),
            authority.TraceId,
            authority.IdempotencyKey,
            ActionKey = authority.ActionKey.Value,
            authority.ActionVersion,
            authority.Category,
            authority.InputTypeIdentity,
            authority.ResultTypeIdentity,
            authority.DescriptorHash,
            authority.InputSchemaHash,
            authority.InputSchemaVersion,
            authority.ResultSchemaHash,
            authority.ResultSchemaVersion,
            authority.ActionContentHash,
            authority.ActionByteLength,
            authority.Deadline,
            authority.IssuedAt,
            authority.ExpiresAt,
        };
        return Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(canonical)));
    }

    private static string TypeIdentity<T>() =>
        typeof(T).AssemblyQualifiedName ?? typeof(T).FullName ?? typeof(T).Name;

    private static bool SamePrincipal(RequestPrincipal left, RequestPrincipal right) =>
        string.Equals(left.SubjectId, right.SubjectId, StringComparison.Ordinal) &&
        string.Equals(left.DisplayName, right.DisplayName, StringComparison.Ordinal) &&
        left.IsAuthenticated == right.IsAuthenticated &&
        SameSets(left.Roles, right.Roles);

    private static bool SameSets(IReadOnlySet<string>? left, IReadOnlySet<string>? right) =>
        left is null && right is null ||
        left is not null && right is not null && left.SetEquals(right);

    private static bool SameFeatures(ExtensionFeatureSet left, ExtensionFeatureSet right) =>
        left.Items.Count == right.Items.Count &&
        left.Items.Zip(right.Items).All(pair =>
            string.Equals(pair.First.ContractName, pair.Second.ContractName, StringComparison.Ordinal) &&
            pair.First.SchemaVersion == pair.Second.SchemaVersion &&
            string.Equals(pair.First.OwnerModuleId, pair.Second.OwnerModuleId, StringComparison.Ordinal) &&
            pair.First.MaxBytes == pair.Second.MaxBytes &&
            string.Equals(pair.First.Value.GetRawText(), pair.Second.Value.GetRawText(), StringComparison.Ordinal));
}

/// <summary>Host-owned entry for typed module action calls.</summary>
/// <remarks>
/// Implementations resolve the authorized descriptor and pipeline snapshot from host state.
/// They must not use caller-supplied descriptor capabilities as authorization.
/// They must validate the request authority before resolving the descriptor or snapshot.
/// </remarks>
public interface IHostActionEntry
{
    ValueTask<IActionOutcome<TResult>> InvokeAsync<TAction, TResult>(
        HostActionEntryRequest<TAction, TResult> request,
        CancellationToken cancellationToken = default);
}

public interface IActionDispatcher
{
    ValueTask<IActionOutcome<TResult>> RunAsync<TAction, TResult>(
        ActionDescriptor<TAction, TResult> descriptor,
        TAction action,
        Func<TAction, CancellationToken, ValueTask<TResult>> terminal,
        ActionPipelineSnapshot snapshot,
        CancellationToken ct);

    ValueTask<TResult> RunRequiredAsync<TAction, TResult>(
        ActionDescriptor<TAction, TResult> descriptor,
        TAction action,
        Func<TAction, CancellationToken, ValueTask<TResult>> terminal,
        ActionPipelineSnapshot snapshot,
        CancellationToken ct);
}

public sealed class ActionOutcomeUncertainException : Exception
{
    public ActionOutcomeUncertainException(ActionUncertainty uncertainty)
        : base(uncertainty.Message)
    {
        Uncertainty = uncertainty;
    }

    public ActionUncertainty Uncertainty { get; }

    public bool IsRetryable => false;
}
