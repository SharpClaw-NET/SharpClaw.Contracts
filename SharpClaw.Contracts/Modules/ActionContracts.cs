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

/// <summary>Typed input supplied to the host action entry.</summary>
public sealed record HostActionEntryRequest<TAction, TResult>(
    ActionDescriptor<TAction, TResult> Descriptor,
    TAction Action,
    RequestPrincipal Caller,
    Guid TraceId,
    Guid IdempotencyKey,
    DateTimeOffset Deadline)
{
    public bool IsValid(DateTimeOffset now) =>
        Descriptor is not null &&
        Descriptor.Version >= 1 &&
        Caller is not null &&
        !string.IsNullOrWhiteSpace(Caller.SubjectId) &&
        TraceId != Guid.Empty &&
        IdempotencyKey != Guid.Empty &&
        Deadline > now;
}

/// <summary>Host-owned entry for typed module action calls.</summary>
/// <remarks>
/// Implementations resolve the authorized descriptor and pipeline snapshot from host state.
/// They must not use caller-supplied descriptor capabilities as authorization.
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
