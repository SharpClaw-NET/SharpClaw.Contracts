using System.Text.Json;

namespace SharpClaw.Contracts.Modules;

public sealed record EventDescriptor<TEvent>(
    SharpClawEventKey Key,
    int Version,
    string Category,
    EventInterceptionCapabilities Capabilities,
    bool DurableByDefault,
    bool ContainsSensitiveData)
{
    public ContractVersionRange ProtocolVersionRange { get; init; } =
        ContractVersionRange.Exact(1);

    public IReadOnlyList<EventDelivery> DeliveryClasses { get; init; } =
        [EventDelivery.Inline];
}

[Flags]
public enum EventInterceptionCapabilities
{
    Inspect = 1 << 0,
    Replace = 1 << 1,
    Cancel = 1 << 2,
    StopPropagation = 1 << 3,
    Observe = 1 << 4,
}

public enum EventInterceptionKind
{
    Continued,
    Replaced,
    Cancelled,
    PropagationStopped,
    Failed,
}

public sealed record EventEnvelope<TEvent>(
    Guid EventId,
    Guid? ActionInvocationId,
    Guid TraceId,
    DateTimeOffset Timestamp,
    string OwnerModuleId,
    TEvent Payload);

public sealed record EventContext<TEvent>(
    EventDescriptor<TEvent> Descriptor,
    EventEnvelope<TEvent> Envelope,
    RequestPrincipal Caller,
    ExtensionFeatureSet Features,
    string SnapshotContractHash);

public interface IEventInterception<out TEvent>
{
    EventInterceptionKind Kind { get; }
    TEvent? Payload { get; }
    ExecutionError? Error { get; }
}

public interface IEventControl<TEvent>
{
    IEventInterception<TEvent> Continue();
    IEventInterception<TEvent> Replace(TEvent payload, string reason);
    IEventInterception<TEvent> Cancel(string code, string message);
    IEventInterception<TEvent> StopPropagation();
}

public interface IEventInterceptor<TEvent>
{
    ValueTask<IEventInterception<TEvent>> InterceptAsync(
        EventContext<TEvent> context,
        IEventControl<TEvent> control,
        CancellationToken ct);
}

public interface IEventListener<TEvent>
{
    ValueTask OnEventAsync(
        EventEnvelope<TEvent> evt,
        CancellationToken ct);
}

public interface IAnyEventListener
{
    ValueTask OnEventAsync(
        UntypedEventEnvelope evt,
        CancellationToken ct);
}

public sealed record UntypedEventDescriptor(
    SharpClawEventKey Key,
    int Version,
    string Category,
    EventInterceptionCapabilities Capabilities,
    JsonSchemaReference PayloadSchema,
    bool ContainsSensitiveData)
{
    public ContractVersionRange ProtocolVersionRange { get; init; } =
        ContractVersionRange.Exact(1);
}

public sealed record UntypedEventEnvelope(
    UntypedEventDescriptor Descriptor,
    Guid EventId,
    Guid? ActionInvocationId,
    Guid TraceId,
    DateTimeOffset Timestamp,
    string OwnerModuleId,
    JsonElement Payload);

public sealed record UntypedEventContext(UntypedEventEnvelope Envelope)
{
    public UntypedEventDescriptor Descriptor => Envelope.Descriptor;
}

public interface IUntypedEventInterception
{
    EventInterceptionKind Kind { get; }
    JsonElement? Payload { get; }
    ExecutionError? Error { get; }
}

public interface IUntypedEventControl
{
    IUntypedEventInterception Continue();
    IUntypedEventInterception Replace(JsonElement payload, string reason);
    IUntypedEventInterception Cancel(string code, string message);
    IUntypedEventInterception StopPropagation();
}

public interface IAnyEventInterceptor
{
    ValueTask<IUntypedEventInterception> InterceptAsync(
        UntypedEventContext context,
        IUntypedEventControl control,
        CancellationToken ct);
}

public sealed record UntypedActionDescriptor(
    SharpClawActionKey Key,
    int Version,
    string Category,
    ActionInterceptionCapabilities Capabilities,
    JsonSchemaReference InputSchema,
    JsonSchemaReference ResultSchema,
    bool ContainsSensitiveData)
{
    public ContractVersionRange ProtocolVersionRange { get; init; } =
        ContractVersionRange.Exact(1);

    public bool AcceptsUnknownNonSensitiveSchemas { get; init; }
}

public sealed record UntypedActionContext(
    Guid InvocationId,
    Guid? ParentInvocationId,
    Guid TraceId,
    Guid IdempotencyKey,
    int Depth,
    int Attempt,
    DateTimeOffset Deadline,
    string OwnerModuleId,
    RequestPrincipal Caller,
    ExtensionFeatureSet Features,
    string SnapshotContractHash,
    UntypedActionDescriptor Descriptor,
    JsonElement Input);

public interface IUntypedActionOutcome
{
    ActionOutcomeKind Kind { get; }
    JsonElement? Result { get; }
    ContinuationToken? Continuation { get; }
    ExecutionError? Error { get; }
    ActionUncertainty? Uncertainty { get; }
}

public interface IUntypedActionControl
{
    ValueTask<IUntypedActionOutcome> ProceedAsync(CancellationToken ct);

    ValueTask<IUntypedActionOutcome> ProceedWithInputAsync(
        JsonElement replacement,
        string reason,
        CancellationToken ct);

    IUntypedActionOutcome ReplaceResult(JsonElement result, string reason);
    IUntypedActionOutcome Cancel(string code, string message);
    IUntypedActionOutcome Fail(ExecutionError error);

    ValueTask<IUntypedActionOutcome> DeferAsync(
        ActionDeferRequest request,
        CancellationToken ct);

    ValueTask<IUntypedActionOutcome> RepeatAsync(
        JsonElement replacement,
        string reason,
        TimeSpan? backoff,
        CancellationToken ct);
}

public interface IAnyActionInterceptor
{
    ValueTask<IUntypedActionOutcome> InvokeAsync(
        UntypedActionContext context,
        IUntypedActionControl control,
        CancellationToken ct);
}
