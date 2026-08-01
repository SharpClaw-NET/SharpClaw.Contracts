using System.Text.Json;

namespace SharpClaw.Contracts.Modules;

public enum SidecarPayloadMode
{
    Typed,
    Untyped,
}

public enum SidecarHookTargetKind
{
    Exact,
    Category,
    Wildcard,
}

public enum SidecarContinuationCommand
{
    ContinueOriginal,
    ContinueReplacement,
    ReplaceResult,
    Cancel,
    Defer,
    Repeat,
}

public enum SidecarProtocolMessageKind
{
    Discovery,
    DiscoveryDecision,
    NegotiationRequest,
    NegotiationResponse,
    HookInvokeStart,
    EffectRequest,
    EffectAccepted,
    ContinuationOutcome,
    HookOutcome,
    HookCompleted,
    EventInterceptStart,
    EventInterceptOutcome,
    StreamChunk,
    StreamControl,
    StreamAcknowledgement,
    Error,
}

public enum SidecarProtocolPhase
{
    Discovered,
    Negotiated,
    Invoking,
    EffectRequested,
    EffectAccepted,
    OutcomeSent,
    Completed,
    Cancelled,
    Disconnected,
    Rejected,
}

public sealed record SidecarPayloadLimits(
    int ActionInputBytes = 1_048_576,
    int ActionResultBytes = 1_048_576,
    int EventPayloadBytes = 1_048_576,
    int ProtocolMessageBytes = 4_194_304,
    int StreamChunkBytes = 262_144);

public sealed record SidecarMessageSizeAuthority(
    int PayloadBytes,
    int MaximumPayloadBytes)
{
    public bool IsWithinLimit =>
        PayloadBytes >= 0 && MaximumPayloadBytes >= 0 && PayloadBytes <= MaximumPayloadBytes;
}

public sealed record SidecarMessageHeader(
    int ProtocolVersion,
    long Sequence,
    DateTimeOffset Deadline,
    SidecarMessageSizeAuthority Size);

public interface ISidecarProtocolMessage
{
    SidecarMessageHeader Header { get; }
    SidecarProtocolMessageKind MessageKind { get; }
}

public sealed record SidecarProtocolOffer(
    int MinimumVersion,
    int MaximumVersion,
    IReadOnlyList<SidecarPayloadMode> PayloadModes,
    SidecarPayloadLimits Limits)
{
    public ProtocolVersionNegotiation Versions =>
        new(MinimumVersion, MaximumVersion);
}

public sealed record SidecarProtocolNegotiationRequest(
    SidecarMessageHeader Header,
    string ModuleId,
    int MinimumVersion,
    int MaximumVersion,
    IReadOnlyList<SidecarPayloadMode> PayloadModes,
    SidecarPayloadLimits Limits) : ISidecarProtocolMessage
{
    public SidecarProtocolMessageKind MessageKind => SidecarProtocolMessageKind.NegotiationRequest;
}

public sealed record SidecarProtocolNegotiationResponse(
    SidecarMessageHeader Header,
    bool Accepted,
    int? SelectedVersion,
    SidecarPayloadMode? SelectedPayloadMode = null,
    string? ErrorCode = null,
    string? ErrorMessage = null,
    SidecarPayloadLimits? Limits = null) : ISidecarProtocolMessage
{
    public SidecarProtocolMessageKind MessageKind => SidecarProtocolMessageKind.NegotiationResponse;
}

public sealed record SidecarActionDefinition(
    SharpClawActionKey ActionKey,
    int Version,
    string Category,
    JsonSchemaReference InputSchema,
    JsonSchemaReference ResultSchema,
    ActionInterceptionCapabilities Capabilities,
    bool ContainsSensitiveData,
    bool HasIrreversibleEffects,
    ActionRepeatPolicy RepeatPolicy,
    ActionContinuationPolicy? ContinuationPolicy,
    IReadOnlyList<ActionSafePoint> SafePoints,
    ContractVersionRange ProtocolVersionRange);

public sealed record SidecarEventDefinition(
    SharpClawEventKey EventKey,
    int Version,
    string Category,
    JsonSchemaReference PayloadSchema,
    EventInterceptionCapabilities Capabilities,
    bool ContainsSensitiveData,
    bool DurableByDefault,
    IReadOnlyList<EventDelivery> DeliveryClasses,
    ContractVersionRange ProtocolVersionRange);

public sealed record SidecarToolHandlerDefinition(
    string ToolName,
    string HandlerId,
    string Description,
    JsonSchemaReference InputSchema,
    JsonSchemaReference ResultSchema,
    bool SupportsStreaming,
    bool Durable,
    bool RequiresApproval);

public enum SidecarLifecycleCallKind
{
    Start,
    Stop,
    Enable,
    Disable,
    HealthCheck,
    Drain,
}

public sealed record SidecarLifecycleHandlerDefinition(
    SidecarLifecycleCallKind Call,
    string HandlerId,
    JsonSchemaReference? InputSchema,
    JsonSchemaReference? ResultSchema,
    ContractVersionRange ProtocolVersionRange,
    TimeSpan Deadline);

public sealed record SidecarActionSubscription(
    SidecarHookTargetKind TargetKind,
    SharpClawActionKey? ActionKey,
    string? Category,
    ContractVersionRange VersionRange,
    JsonSchemaReference InputSchema,
    JsonSchemaReference ResultSchema,
    ActionInterceptionCapabilities Capabilities,
    SidecarPayloadMode PayloadMode,
    HookOrdering Ordering,
    bool SensitiveWildcardApprovalRequired = false,
    bool AcceptUnknownNonSensitiveSchemas = false);

public sealed record SidecarEventSubscription(
    SidecarHookTargetKind TargetKind,
    SharpClawEventKey? EventKey,
    string? Category,
    ContractVersionRange VersionRange,
    JsonSchemaReference PayloadSchema,
    EventInterceptionCapabilities Capabilities,
    EventDelivery Delivery,
    SidecarPayloadMode PayloadMode,
    HookOrdering Ordering,
    bool SensitiveWildcardApprovalRequired = false,
    bool AcceptUnknownNonSensitiveSchemas = false);

public sealed record SidecarDiscoveryEnvelope(
    SidecarMessageHeader Header,
    string ModuleId,
    string ContractHash,
    SidecarProtocolOffer Protocol,
    IReadOnlyList<SidecarActionSubscription> Actions,
    IReadOnlyList<SidecarEventSubscription> Events,
    IReadOnlyList<SidecarActionDefinition> ActionDefinitions,
    IReadOnlyList<SidecarEventDefinition> EventDefinitions,
    IReadOnlyList<SidecarToolHandlerDefinition> ToolHandlers,
    IReadOnlyList<SidecarLifecycleHandlerDefinition> LifecycleHandlers,
    IReadOnlyList<ModuleFeatureDescriptor> Features) : ISidecarProtocolMessage
{
    public SidecarProtocolMessageKind MessageKind => SidecarProtocolMessageKind.Discovery;
}

/// <summary>Authorization issued by the host after discovery validation.</summary>
public sealed record SidecarHostAuthorization(
    string ModuleId,
    IReadOnlyList<ActionCapabilityGrant> ActionGrants,
    IReadOnlyList<EventCapabilityGrant> EventGrants,
    SensitiveWildcardApproval? SensitiveWildcardApproval = null);

public sealed record SidecarDiscoveryDecision(
    SidecarMessageHeader Header,
    string ModuleId,
    bool Accepted,
    SidecarHostAuthorization? Authorization = null,
    string? ErrorCode = null,
    string? ErrorMessage = null) : ISidecarProtocolMessage
{
    public SidecarProtocolMessageKind MessageKind => SidecarProtocolMessageKind.DiscoveryDecision;
}

public sealed record SidecarDiscoveryValidationResult(
    bool Accepted,
    string? ErrorCode = null,
    string? ErrorMessage = null);

public static class SidecarDiscoveryValidator
{
    public static SidecarDiscoveryValidationResult Validate(SidecarDiscoveryEnvelope discovery)
    {
        ArgumentNullException.ThrowIfNull(discovery);

        if (!discovery.Header.Size.IsWithinLimit)
            return new(false, SidecarProtocolErrors.ModulePayloadTooLarge, "Discovery exceeds its host size authority.");

        foreach (var subscription in discovery.Actions.Where(subscription =>
                     subscription.TargetKind == SidecarHookTargetKind.Exact))
        {
            var definition = discovery.ActionDefinitions.FirstOrDefault(item =>
                item.ActionKey == subscription.ActionKey &&
                item.Version == subscription.VersionRange.Minimum);

            if (definition is null ||
                !SameSchema(definition.InputSchema, subscription.InputSchema) ||
                !SameSchema(definition.ResultSchema, subscription.ResultSchema))
            {
                return new(false, SidecarProtocolErrors.SchemaMismatch, "The action subscription schema does not match its definition.");
            }
        }

        foreach (var subscription in discovery.Events.Where(subscription =>
                     subscription.TargetKind == SidecarHookTargetKind.Exact))
        {
            var definition = discovery.EventDefinitions.FirstOrDefault(item =>
                item.EventKey == subscription.EventKey &&
                item.Version == subscription.VersionRange.Minimum);

            if (definition is null || !SameSchema(definition.PayloadSchema, subscription.PayloadSchema))
            {
                return new(false, SidecarProtocolErrors.SchemaMismatch, "The event subscription schema does not match its definition.");
            }
        }

        return new(true);
    }

    private static bool SameSchema(JsonSchemaReference left, JsonSchemaReference right) =>
        string.Equals(left.ContractName, right.ContractName, StringComparison.Ordinal) &&
        left.Version == right.Version &&
        string.Equals(left.ContentHash, right.ContentHash, StringComparison.Ordinal);
}

/// <summary>Single-use host handle for a duplex sidecar continuation.</summary>
public sealed record ContinuationHandle(
    Guid HandleId,
    Guid InvocationId,
    string HookId,
    DateTimeOffset ExpiresAt,
    long Sequence,
    bool IsSingleUse = true);

public sealed record HookInvokeStart(
    SidecarMessageHeader Header,
    Guid InvocationId,
    Guid? ParentInvocationId,
    Guid TraceId,
    string HookId,
    SharpClawActionKey ActionKey,
    int ActionVersion,
    SidecarPayloadMode PayloadMode,
    JsonElement Input,
    UntypedActionDescriptor? UntypedDescriptor,
    ActionCapabilityGrant Grant,
    RequestPrincipal Caller,
    ExtensionFeatureSet Features,
    ContinuationHandle Continuation) : ISidecarProtocolMessage
{
    public SidecarProtocolMessageKind MessageKind => SidecarProtocolMessageKind.HookInvokeStart;
}

/// <summary>
/// A sidecar can request every supported effect before the terminal outcome.
/// The host validates the handle, sequence, deadline, capability, and schema.
/// </summary>
public sealed record SidecarEffectRequest(
    SidecarMessageHeader Header,
    Guid ContinuationHandleId,
    SidecarContinuationCommand Command,
    JsonElement? Value = null,
    string? Reason = null,
    string? Code = null,
    string? Message = null,
    ActionDeferRequest? Defer = null,
    TimeSpan? Backoff = null) : ISidecarProtocolMessage
{
    public SidecarProtocolMessageKind MessageKind => SidecarProtocolMessageKind.EffectRequest;
}

public sealed record ContinuationAccepted(
    SidecarMessageHeader Header,
    Guid ContinuationHandleId,
    SidecarContinuationCommand Command,
    ActionSafePoint SafePoint,
    ContinuationState State,
    ContinuationClaim? Claim = null) : ISidecarProtocolMessage
{
    public SidecarProtocolMessageKind MessageKind => SidecarProtocolMessageKind.EffectAccepted;
}

public sealed record ContinuationOutcome(
    SidecarMessageHeader Header,
    Guid ContinuationHandleId,
    ActionOutcomeKind Kind,
    ActionOutcomeCertainty Certainty,
    ActionSafePoint SafePoint,
    JsonElement? Result = null,
    ExecutionError? Error = null,
    ActionUncertainty? Uncertainty = null,
    ContinuationToken? Continuation = null) : ISidecarProtocolMessage
{
    public SidecarProtocolMessageKind MessageKind => SidecarProtocolMessageKind.ContinuationOutcome;
}

public sealed record HookOutcome(
    SidecarMessageHeader Header,
    Guid ContinuationHandleId,
    ActionOutcomeKind Kind,
    ActionOutcomeCertainty Certainty,
    JsonElement? Result = null,
    ExecutionError? Error = null,
    ActionUncertainty? Uncertainty = null,
    SidecarEffectRequest? RequestedEffect = null) : ISidecarProtocolMessage
{
    public SidecarProtocolMessageKind MessageKind => SidecarProtocolMessageKind.HookOutcome;
}

public sealed record HookCompleted(
    SidecarMessageHeader Header,
    Guid ContinuationHandleId,
    ActionOutcomeKind Kind,
    ActionOutcomeCertainty Certainty,
    JsonElement? Result = null,
    ExecutionError? Error = null,
    ActionUncertainty? Uncertainty = null) : ISidecarProtocolMessage
{
    public SidecarProtocolMessageKind MessageKind => SidecarProtocolMessageKind.HookCompleted;
}

public sealed record EventInterceptStart(
    SidecarMessageHeader Header,
    string HookId,
    UntypedEventEnvelope Envelope,
    EventCapabilityGrant Grant,
    ContinuationHandle Continuation) : ISidecarProtocolMessage
{
    public SidecarProtocolMessageKind MessageKind => SidecarProtocolMessageKind.EventInterceptStart;
}

public sealed record EventInterceptOutcome(
    SidecarMessageHeader Header,
    Guid ContinuationHandleId,
    EventInterceptionKind Kind,
    JsonElement? Payload = null,
    ExecutionError? Error = null,
    string? Reason = null) : ISidecarProtocolMessage
{
    public SidecarProtocolMessageKind MessageKind => SidecarProtocolMessageKind.EventInterceptOutcome;
}

public enum SidecarStreamMutationKind
{
    Pass,
    Transform,
    Suppress,
    Add,
}

public sealed record SidecarStreamMutation(
    SidecarStreamMutationKind Kind,
    JsonElement? Payload = null,
    string? Reason = null);

public enum SidecarStreamControlKind
{
    Cancel,
    Acknowledge,
    GrantCredit,
    Close,
}

public sealed record SidecarStreamChunk(
    SidecarMessageHeader Header,
    Guid StreamId,
    long ChunkSequence,
    JsonElement Payload,
    bool IsFinal,
    SidecarStreamMutation? Mutation = null) : ISidecarProtocolMessage
{
    public SidecarProtocolMessageKind MessageKind => SidecarProtocolMessageKind.StreamChunk;
}

public sealed record SidecarStreamControl(
    SidecarMessageHeader Header,
    Guid StreamId,
    SidecarStreamControlKind Control,
    long AcknowledgeSequence,
    int CreditBytes,
    int CreditChunks,
    string? Reason = null) : ISidecarProtocolMessage
{
    public SidecarProtocolMessageKind MessageKind => SidecarProtocolMessageKind.StreamControl;
}

public sealed record SidecarStreamAcknowledgement(
    SidecarMessageHeader Header,
    Guid StreamId,
    long AcknowledgeSequence,
    int GrantedBytes,
    int GrantedChunks) : ISidecarProtocolMessage
{
    public SidecarProtocolMessageKind MessageKind => SidecarProtocolMessageKind.StreamAcknowledgement;
}

public sealed record SidecarProtocolError(
    SidecarMessageHeader Header,
    string Code,
    string Message,
    SidecarProtocolMessageKind? RelatedMessageKind = null,
    Guid? ContinuationHandleId = null) : ISidecarProtocolMessage
{
    public SidecarProtocolMessageKind MessageKind => SidecarProtocolMessageKind.Error;
}

public sealed record SidecarProtocolState(
    Guid InvocationId,
    Guid ContinuationHandleId,
    SidecarProtocolPhase Phase,
    long LastSequence,
    DateTimeOffset Deadline);

public static class SidecarProtocolStateMachine
{
    public static bool CanApply(
        SidecarProtocolPhase phase,
        SidecarProtocolMessageKind message,
        SidecarContinuationCommand? command = null) =>
        (phase, message, command) switch
        {
            (SidecarProtocolPhase.Discovered, SidecarProtocolMessageKind.DiscoveryDecision, _) => true,
            (SidecarProtocolPhase.Discovered, SidecarProtocolMessageKind.NegotiationRequest, _) => true,
            (SidecarProtocolPhase.Discovered, SidecarProtocolMessageKind.NegotiationResponse, _) => true,
            (SidecarProtocolPhase.Negotiated, SidecarProtocolMessageKind.NegotiationResponse, _) => true,
            (SidecarProtocolPhase.Negotiated, SidecarProtocolMessageKind.HookInvokeStart, _) => true,
            (SidecarProtocolPhase.Negotiated, SidecarProtocolMessageKind.EventInterceptStart, _) => true,
            (SidecarProtocolPhase.Invoking, SidecarProtocolMessageKind.EffectRequest, not null) => true,
            (SidecarProtocolPhase.EffectRequested, SidecarProtocolMessageKind.EffectAccepted, _) => true,
            (SidecarProtocolPhase.EffectAccepted, SidecarProtocolMessageKind.EffectRequest, not null) => true,
            (SidecarProtocolPhase.EffectAccepted, SidecarProtocolMessageKind.ContinuationOutcome, _) => true,
            (SidecarProtocolPhase.OutcomeSent, SidecarProtocolMessageKind.HookOutcome, _) => true,
            (SidecarProtocolPhase.OutcomeSent, SidecarProtocolMessageKind.HookCompleted, _) => true,
            (SidecarProtocolPhase.Invoking, SidecarProtocolMessageKind.EventInterceptOutcome, _) => true,
            (SidecarProtocolPhase.Invoking, SidecarProtocolMessageKind.StreamChunk, _) => true,
            (SidecarProtocolPhase.EffectAccepted, SidecarProtocolMessageKind.StreamChunk, _) => true,
            (SidecarProtocolPhase.Invoking, SidecarProtocolMessageKind.StreamControl, _) => true,
            (SidecarProtocolPhase.EffectAccepted, SidecarProtocolMessageKind.StreamControl, _) => true,
            (_, SidecarProtocolMessageKind.StreamAcknowledgement, _) => true,
            (_, SidecarProtocolMessageKind.Error, _) => true,
            (_, _, _) => false,
        };
}

public sealed record GraphCompilationError(
    string Code,
    string ModuleId,
    string Target,
    string RequestedEffect,
    string Message);

public static class SidecarProtocolErrors
{
    public const string ContinuationAlreadyUsed = "continuation_already_used";
    public const string ContinuationExpired = "continuation_expired";
    public const string ModulePayloadTooLarge = "module_payload_too_large";
    public const string ModuleBusy = "module_busy";
    public const string UnsupportedEffect = "unsupported_effect";
    public const string UnsupportedSchema = "unsupported_schema";
    public const string SchemaMismatch = "schema_mismatch";
    public const string ForgedApproval = "forged_approval";
    public const string InvalidSequence = "invalid_sequence";
    public const string DeadlineExceeded = "deadline_exceeded";
    public const string BackpressureViolation = "backpressure_violation";
    public const string InvalidLifecyclePhase = "invalid_lifecycle_phase";
    public const string Disconnected = "sidecar_disconnected";
}
