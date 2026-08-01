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
    HookInvokeStart,
    ContinueOriginal,
    ContinueReplacement,
    ContinuationAccepted,
    ContinuationOutcome,
    HookOutcome,
    HookCompleted,
    EventInterceptStart,
    EventInterceptOutcome,
    Error,
}

public sealed record SidecarPayloadLimits(
    int ActionInputBytes = 1_048_576,
    int ActionResultBytes = 1_048_576,
    int EventPayloadBytes = 1_048_576,
    int ProtocolMessageBytes = 4_194_304,
    int StreamChunkBytes = 262_144);

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
    string ModuleId,
    int MinimumVersion,
    int MaximumVersion,
    IReadOnlyList<SidecarPayloadMode> PayloadModes,
    SidecarPayloadLimits Limits);

public sealed record SidecarProtocolNegotiationResponse(
    bool Accepted,
    int? SelectedVersion,
    SidecarPayloadMode? SelectedPayloadMode = null,
    string? ErrorCode = null,
    string? ErrorMessage = null,
    SidecarPayloadLimits? Limits = null);

public sealed record SidecarActionSubscription(
    SidecarHookTargetKind TargetKind,
    SharpClawActionKey? ActionKey,
    string? Category,
    ContractVersionRange VersionRange,
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
    EventInterceptionCapabilities Capabilities,
    EventDelivery Delivery,
    SidecarPayloadMode PayloadMode,
    HookOrdering Ordering,
    bool SensitiveWildcardApprovalRequired = false,
    bool AcceptUnknownNonSensitiveSchemas = false);

public sealed record SidecarDiscoveryEnvelope(
    string ModuleId,
    string ContractHash,
    SidecarProtocolOffer Protocol,
    IReadOnlyList<SidecarActionSubscription> Actions,
    IReadOnlyList<SidecarEventSubscription> Events,
    IReadOnlyList<ModuleFeatureDescriptor> Features,
    SensitiveWildcardApproval? SensitiveApproval = null);

/// <summary>Single-use host handle for a duplex sidecar continuation.</summary>
public sealed record ContinuationHandle(
    Guid HandleId,
    Guid InvocationId,
    string HookId,
    DateTimeOffset ExpiresAt,
    long Sequence,
    bool IsSingleUse = true);

public sealed record HookInvokeStart(
    int ProtocolVersion,
    long Sequence,
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
    DateTimeOffset Deadline,
    ContinuationHandle Continuation);

public sealed record ContinueOriginal(
    Guid ContinuationHandleId,
    long Sequence);

public sealed record ContinueReplacement(
    Guid ContinuationHandleId,
    long Sequence,
    JsonElement Replacement,
    string Reason);

public sealed record ContinuationAccepted(
    Guid ContinuationHandleId,
    long Sequence,
    ActionSafePoint SafePoint);

public sealed record ContinuationOutcome(
    Guid ContinuationHandleId,
    long Sequence,
    ActionOutcomeKind Kind,
    ActionSafePoint SafePoint,
    JsonElement? Result = null,
    ExecutionError? Error = null,
    ActionUncertainty? Uncertainty = null,
    ContinuationToken? Continuation = null);

public sealed record SidecarEffectRequest(
    SidecarContinuationCommand Command,
    JsonElement? Value = null,
    string? Reason = null,
    string? Code = null,
    string? Message = null,
    ActionDeferRequest? Defer = null,
    TimeSpan? Backoff = null);

public sealed record HookOutcome(
    Guid ContinuationHandleId,
    long Sequence,
    ActionOutcomeKind Kind,
    JsonElement? Result = null,
    ExecutionError? Error = null,
    ActionUncertainty? Uncertainty = null,
    SidecarEffectRequest? RequestedEffect = null);

public sealed record HookCompleted(
    Guid ContinuationHandleId,
    long Sequence,
    ActionOutcomeKind Kind,
    JsonElement? Result = null,
    ExecutionError? Error = null,
    ActionUncertainty? Uncertainty = null);

public sealed record EventInterceptStart(
    int ProtocolVersion,
    long Sequence,
    string HookId,
    UntypedEventEnvelope Envelope,
    EventCapabilityGrant Grant,
    DateTimeOffset Deadline,
    ContinuationHandle Continuation);

public sealed record EventInterceptOutcome(
    Guid ContinuationHandleId,
    long Sequence,
    EventInterceptionKind Kind,
    JsonElement? Payload = null,
    ExecutionError? Error = null,
    string? Reason = null);

public sealed record SidecarProtocolError(
    string Code,
    string Message,
    SidecarProtocolMessageKind? MessageKind = null,
    Guid? ContinuationHandleId = null,
    long? Sequence = null);

public sealed record SidecarStreamChunk(
    Guid StreamId,
    long Sequence,
    JsonElement Payload,
    bool IsFinal,
    DateTimeOffset Deadline);

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
    public const string Disconnected = "sidecar_disconnected";
}
