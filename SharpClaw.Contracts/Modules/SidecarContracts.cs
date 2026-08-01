using System.Collections.ObjectModel;
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
    Cancel,
    Defer,
    Repeat,
}

public enum SidecarHookOutcomeKind
{
    Completed,
    Failed,
    Cancelled,
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
    ToolHandlerInvokeStart,
    ToolHandlerResult,
    ToolHandlerCancelled,
    ToolHandlerFailed,
    LifecycleHandlerInvokeStart,
    LifecycleHandlerResult,
    LifecycleHandlerCancelled,
    LifecycleHandlerFailed,
    EventListenerDelivery,
    EventListenerAcknowledgement,
    HostTerminalCancellation,
    ResultReplacement,
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

public sealed record SidecarToolHandlerInvokeStart(
    SidecarMessageHeader Header,
    Guid InvocationId,
    string ToolName,
    string HandlerId,
    JsonElement Input,
    JsonSchemaReference InputSchema,
    RequestPrincipal Caller) : ISidecarProtocolMessage
{
    public SidecarProtocolMessageKind MessageKind => SidecarProtocolMessageKind.ToolHandlerInvokeStart;
}

public sealed record SidecarToolHandlerResult(
    SidecarMessageHeader Header,
    Guid InvocationId,
    JsonElement Result,
    JsonSchemaReference ResultSchema) : ISidecarProtocolMessage
{
    public SidecarProtocolMessageKind MessageKind => SidecarProtocolMessageKind.ToolHandlerResult;
}

public sealed record SidecarToolHandlerCancelled(
    SidecarMessageHeader Header,
    Guid InvocationId,
    string Code,
    string Message) : ISidecarProtocolMessage
{
    public SidecarProtocolMessageKind MessageKind => SidecarProtocolMessageKind.ToolHandlerCancelled;
}

public sealed record SidecarToolHandlerFailed(
    SidecarMessageHeader Header,
    Guid InvocationId,
    ExecutionError Error) : ISidecarProtocolMessage
{
    public SidecarProtocolMessageKind MessageKind => SidecarProtocolMessageKind.ToolHandlerFailed;
}

public sealed record SidecarLifecycleHandlerInvokeStart(
    SidecarMessageHeader Header,
    Guid InvocationId,
    SidecarLifecycleCallKind Call,
    string HandlerId,
    JsonElement? Input) : ISidecarProtocolMessage
{
    public SidecarProtocolMessageKind MessageKind => SidecarProtocolMessageKind.LifecycleHandlerInvokeStart;
}

public sealed record SidecarLifecycleHandlerResult(
    SidecarMessageHeader Header,
    Guid InvocationId,
    SidecarLifecycleCallKind Call,
    JsonElement? Result) : ISidecarProtocolMessage
{
    public SidecarProtocolMessageKind MessageKind => SidecarProtocolMessageKind.LifecycleHandlerResult;
}

public sealed record SidecarLifecycleHandlerCancelled(
    SidecarMessageHeader Header,
    Guid InvocationId,
    SidecarLifecycleCallKind Call,
    string Code,
    string Message) : ISidecarProtocolMessage
{
    public SidecarProtocolMessageKind MessageKind => SidecarProtocolMessageKind.LifecycleHandlerCancelled;
}

public sealed record SidecarLifecycleHandlerFailed(
    SidecarMessageHeader Header,
    Guid InvocationId,
    SidecarLifecycleCallKind Call,
    ExecutionError Error) : ISidecarProtocolMessage
{
    public SidecarProtocolMessageKind MessageKind => SidecarProtocolMessageKind.LifecycleHandlerFailed;
}

public sealed record SidecarEventListenerDelivery(
    SidecarMessageHeader Header,
    Guid DeliveryId,
    string ListenerId,
    UntypedEventEnvelope Envelope,
    EventDelivery Delivery,
    bool RequiresAcknowledgement) : ISidecarProtocolMessage
{
    public SidecarProtocolMessageKind MessageKind => SidecarProtocolMessageKind.EventListenerDelivery;
}

public sealed record SidecarEventListenerAcknowledgement(
    SidecarMessageHeader Header,
    Guid DeliveryId,
    EventDelivery Delivery,
    bool Accepted,
    ExecutionError? Error = null) : ISidecarProtocolMessage
{
    public SidecarProtocolMessageKind MessageKind => SidecarProtocolMessageKind.EventListenerAcknowledgement;
}

/// <summary>Host-owned action metadata used to validate sidecar subscriptions.</summary>
public sealed record SidecarHostActionDescriptor(
    SharpClawActionKey ActionKey,
    int Version,
    string Category,
    JsonSchemaReference InputSchema,
    JsonSchemaReference ResultSchema,
    ActionInterceptionCapabilities Capabilities,
    bool ContainsSensitiveData,
    ContractVersionRange ProtocolVersionRange);

/// <summary>Host-owned event metadata used to validate sidecar subscriptions.</summary>
public sealed record SidecarHostEventDescriptor(
    SharpClawEventKey EventKey,
    int Version,
    string Category,
    JsonSchemaReference PayloadSchema,
    EventInterceptionCapabilities Capabilities,
    bool ContainsSensitiveData,
    ContractVersionRange ProtocolVersionRange);

/// <summary>
/// Immutable host metadata. A sidecar discovery message cannot add or replace entries.
/// </summary>
public sealed class SidecarHostDescriptorCatalog
{
    public SidecarHostDescriptorCatalog(
        IReadOnlyList<SidecarHostActionDescriptor> actions,
        IReadOnlyList<SidecarHostEventDescriptor> events)
    {
        ArgumentNullException.ThrowIfNull(actions);
        ArgumentNullException.ThrowIfNull(events);

        if (actions.GroupBy(item => item.ActionKey).Any(group => group.Count() > 1))
            throw new ArgumentException("Host action descriptors must have unique keys.", nameof(actions));

        if (events.GroupBy(item => item.EventKey).Any(group => group.Count() > 1))
            throw new ArgumentException("Host event descriptors must have unique keys.", nameof(events));

        Actions = new ReadOnlyCollection<SidecarHostActionDescriptor>(actions.ToArray());
        Events = new ReadOnlyCollection<SidecarHostEventDescriptor>(events.ToArray());
    }

    public IReadOnlyList<SidecarHostActionDescriptor> Actions { get; }
    public IReadOnlyList<SidecarHostEventDescriptor> Events { get; }

    public bool TryGetAction(
        SharpClawActionKey key,
        int version,
        out SidecarHostActionDescriptor? descriptor)
    {
        descriptor = Actions.FirstOrDefault(item => item.ActionKey == key && item.Version == version);
        return descriptor is not null;
    }

    public bool TryGetEvent(
        SharpClawEventKey key,
        int version,
        out SidecarHostEventDescriptor? descriptor)
    {
        descriptor = Events.FirstOrDefault(item => item.EventKey == key && item.Version == version);
        return descriptor is not null;
    }

    public bool ContainsActionKey(SharpClawActionKey key) =>
        Actions.Any(item => item.ActionKey == key);

    public bool ContainsEventKey(SharpClawEventKey key) =>
        Events.Any(item => item.EventKey == key);
}

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
    public static SidecarDiscoveryValidationResult Validate(
        SidecarDiscoveryEnvelope discovery,
        SidecarHostDescriptorCatalog hostCatalog)
    {
        ArgumentNullException.ThrowIfNull(discovery);
        ArgumentNullException.ThrowIfNull(hostCatalog);

        if (!discovery.Header.Size.IsWithinLimit)
            return Reject(SidecarProtocolErrors.ModulePayloadTooLarge, "Discovery exceeds its host size authority.");

        if (discovery.Header.ProtocolVersion < discovery.Protocol.MinimumVersion ||
            discovery.Header.ProtocolVersion > discovery.Protocol.MaximumVersion)
        {
            return Reject(SidecarProtocolErrors.UnsupportedVersion, "The discovery header uses an unsupported protocol version.");
        }

        var duplicateAction = discovery.ActionDefinitions
            .GroupBy(item => item.ActionKey)
            .FirstOrDefault(group => group.Count() > 1);
        if (duplicateAction is not null)
            return Reject(SidecarProtocolErrors.DuplicateDescriptor, "The discovery contains duplicate module action definitions.");

        var duplicateEvent = discovery.EventDefinitions
            .GroupBy(item => item.EventKey)
            .FirstOrDefault(group => group.Count() > 1);
        if (duplicateEvent is not null)
            return Reject(SidecarProtocolErrors.DuplicateDescriptor, "The discovery contains duplicate module event definitions.");

        if (discovery.ToolHandlers.GroupBy(item => (item.ToolName, item.HandlerId)).Any(group => group.Count() > 1) ||
            discovery.LifecycleHandlers.GroupBy(item => (item.Call, item.HandlerId)).Any(group => group.Count() > 1))
        {
            return Reject(SidecarProtocolErrors.DuplicateDescriptor, "The discovery contains duplicate handler definitions.");
        }

        if (discovery.ActionDefinitions.Any(item => hostCatalog.ContainsActionKey(item.ActionKey)))
            return Reject(SidecarProtocolErrors.ShadowedHostKey, "A module action definition shadows a host action key.");

        if (discovery.EventDefinitions.Any(item => hostCatalog.ContainsEventKey(item.EventKey)))
            return Reject(SidecarProtocolErrors.ShadowedHostKey, "A module event definition shadows a host event key.");

        var actionSubscriptionKeys = new HashSet<string>(StringComparer.Ordinal);
        foreach (var subscription in discovery.Actions)
        {
            var subscriptionIdentity = subscription.TargetKind == SidecarHookTargetKind.Exact
                ? $"exact:{subscription.ActionKey?.Value}"
                : $"{subscription.TargetKind}:{subscription.Category}";
            if (!actionSubscriptionKeys.Add(subscriptionIdentity))
                return Reject(SidecarProtocolErrors.DuplicateDescriptor, "The discovery contains duplicate action subscriptions.");

            if (subscription.TargetKind == SidecarHookTargetKind.Exact)
            {
                if (subscription.ActionKey is not { } actionKey)
                {
                    return Reject(SidecarProtocolErrors.UnknownHostDescriptor, "The action subscription does not identify a host action descriptor.");
                }

                if (!hostCatalog.Actions.Any(item => item.ActionKey == actionKey))
                    return Reject(SidecarProtocolErrors.UnknownHostDescriptor, "The action subscription does not identify a host action descriptor.");

                if (!hostCatalog.Actions.Any(item => item.ActionKey == actionKey &&
                                                     subscription.VersionRange.Contains(item.Version)))
                {
                    return Reject(SidecarProtocolErrors.UnsupportedVersion, "The action subscription requests an unsupported version.");
                }

                var descriptor = hostCatalog.Actions
                    .Where(item => item.ActionKey == actionKey && subscription.VersionRange.Contains(item.Version))
                    .OrderByDescending(item => item.Version)
                    .First();
                if (!descriptor.ProtocolVersionRange.Contains(discovery.Header.ProtocolVersion))
                {
                    return Reject(SidecarProtocolErrors.UnsupportedVersion, "The action subscription uses an unsupported protocol version.");
                }

                if (!string.Equals(subscription.Category, descriptor.Category, StringComparison.Ordinal))
                    return Reject(SidecarProtocolErrors.CategoryMismatch, "The action subscription category does not match the host descriptor.");

                if (!SameSchema(descriptor.InputSchema, subscription.InputSchema) ||
                    !SameSchema(descriptor.ResultSchema, subscription.ResultSchema))
                {
                    return Reject(SidecarProtocolErrors.SchemaMismatch, "The action subscription schema does not match the host descriptor.");
                }

                if ((subscription.Capabilities & ~descriptor.Capabilities) != 0)
                    return Reject(SidecarProtocolErrors.UnsupportedCapability, "The action subscription requests an ungranted host capability.");
            }
            else if (string.IsNullOrWhiteSpace(subscription.Category) &&
                     subscription.TargetKind == SidecarHookTargetKind.Category)
            {
                return Reject(SidecarProtocolErrors.CategoryMismatch, "A category subscription requires a category.");
            }
            else if (!hostCatalog.Actions.Any(item =>
                         (subscription.TargetKind == SidecarHookTargetKind.Wildcard ||
                          string.Equals(item.Category, subscription.Category, StringComparison.Ordinal)) &&
                         subscription.VersionRange.Contains(item.Version) &&
                         item.ProtocolVersionRange.Contains(discovery.Header.ProtocolVersion)))
            {
                return Reject(SidecarProtocolErrors.UnknownHostDescriptor, "The action subscription matches no immutable host descriptor.");
            }
        }

        var eventSubscriptionKeys = new HashSet<string>(StringComparer.Ordinal);
        foreach (var subscription in discovery.Events)
        {
            var subscriptionIdentity = subscription.TargetKind == SidecarHookTargetKind.Exact
                ? $"exact:{subscription.EventKey?.Value}"
                : $"{subscription.TargetKind}:{subscription.Category}";
            if (!eventSubscriptionKeys.Add(subscriptionIdentity))
                return Reject(SidecarProtocolErrors.DuplicateDescriptor, "The discovery contains duplicate event subscriptions.");

            if (subscription.TargetKind == SidecarHookTargetKind.Exact)
            {
                if (subscription.EventKey is not { } eventKey)
                {
                    return Reject(SidecarProtocolErrors.UnknownHostDescriptor, "The event subscription does not identify a host event descriptor.");
                }

                if (!hostCatalog.Events.Any(item => item.EventKey == eventKey))
                    return Reject(SidecarProtocolErrors.UnknownHostDescriptor, "The event subscription does not identify a host event descriptor.");

                if (!hostCatalog.Events.Any(item => item.EventKey == eventKey &&
                                                    subscription.VersionRange.Contains(item.Version)))
                {
                    return Reject(SidecarProtocolErrors.UnsupportedVersion, "The event subscription requests an unsupported version.");
                }

                var descriptor = hostCatalog.Events
                    .Where(item => item.EventKey == eventKey && subscription.VersionRange.Contains(item.Version))
                    .OrderByDescending(item => item.Version)
                    .First();
                if (!descriptor.ProtocolVersionRange.Contains(discovery.Header.ProtocolVersion))
                {
                    return Reject(SidecarProtocolErrors.UnsupportedVersion, "The event subscription uses an unsupported protocol version.");
                }

                if (!string.Equals(subscription.Category, descriptor.Category, StringComparison.Ordinal))
                    return Reject(SidecarProtocolErrors.CategoryMismatch, "The event subscription category does not match the host descriptor.");

                if (!SameSchema(descriptor.PayloadSchema, subscription.PayloadSchema))
                    return Reject(SidecarProtocolErrors.SchemaMismatch, "The event subscription schema does not match the host descriptor.");

                if ((subscription.Capabilities & ~descriptor.Capabilities) != 0)
                    return Reject(SidecarProtocolErrors.UnsupportedCapability, "The event subscription requests an ungranted host capability.");
            }
            else if (string.IsNullOrWhiteSpace(subscription.Category) &&
                     subscription.TargetKind == SidecarHookTargetKind.Category)
            {
                return Reject(SidecarProtocolErrors.CategoryMismatch, "A category subscription requires a category.");
            }
            else if (!hostCatalog.Events.Any(item =>
                         (subscription.TargetKind == SidecarHookTargetKind.Wildcard ||
                          string.Equals(item.Category, subscription.Category, StringComparison.Ordinal)) &&
                         subscription.VersionRange.Contains(item.Version) &&
                         item.ProtocolVersionRange.Contains(discovery.Header.ProtocolVersion)))
            {
                return Reject(SidecarProtocolErrors.UnknownHostDescriptor, "The event subscription matches no immutable host descriptor.");
            }
        }

        return new(true);
    }

    private static SidecarDiscoveryValidationResult Reject(string code, string message) =>
        new(false, code, message);

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

/// <summary>Sidecar terminal results cannot assert host-only uncertainty.</summary>
public sealed record HookOutcome(
    SidecarMessageHeader Header,
    Guid ContinuationHandleId,
    SidecarHookOutcomeKind Kind,
    JsonElement? Result = null,
    ExecutionError? Error = null) : ISidecarProtocolMessage
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

public sealed record SidecarHostTerminalCancellation(
    SidecarMessageHeader Header,
    Guid ContinuationHandleId,
    ActionSafePoint SafePoint,
    string Code,
    string Message) : ISidecarProtocolMessage
{
    public SidecarProtocolMessageKind MessageKind => SidecarProtocolMessageKind.HostTerminalCancellation;
}

/// <summary>
/// A sidecar can replace a result only after the host has accepted a continuation outcome.
/// </summary>
public sealed record SidecarResultReplacement(
    SidecarMessageHeader Header,
    Guid ContinuationHandleId,
    JsonElement Result,
    string Reason) : ISidecarProtocolMessage
{
    public SidecarProtocolMessageKind MessageKind => SidecarProtocolMessageKind.ResultReplacement;
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

public sealed record SidecarProtocolTransitionResult(
    bool Accepted,
    SidecarProtocolState? State = null,
    string? ErrorCode = null,
    string? ErrorMessage = null);

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
            (SidecarProtocolPhase.Negotiated, SidecarProtocolMessageKind.ToolHandlerInvokeStart, _) => true,
            (SidecarProtocolPhase.Negotiated, SidecarProtocolMessageKind.LifecycleHandlerInvokeStart, _) => true,
            (SidecarProtocolPhase.Negotiated, SidecarProtocolMessageKind.EventListenerDelivery, _) => true,
            (SidecarProtocolPhase.Negotiated, SidecarProtocolMessageKind.EventListenerAcknowledgement, _) => true,
            (SidecarProtocolPhase.Invoking, SidecarProtocolMessageKind.EffectRequest, not null) => true,
            (SidecarProtocolPhase.EffectRequested, SidecarProtocolMessageKind.EffectAccepted, _) => true,
            (SidecarProtocolPhase.EffectAccepted, SidecarProtocolMessageKind.ContinuationOutcome, _) => true,
            (SidecarProtocolPhase.OutcomeSent, SidecarProtocolMessageKind.ResultReplacement, _) => true,
            (SidecarProtocolPhase.OutcomeSent, SidecarProtocolMessageKind.HookOutcome, _) => true,
            (SidecarProtocolPhase.OutcomeSent, SidecarProtocolMessageKind.HookCompleted, _) => true,
            (SidecarProtocolPhase.Invoking, SidecarProtocolMessageKind.EventInterceptOutcome, _) => true,
            (SidecarProtocolPhase.Invoking, SidecarProtocolMessageKind.ToolHandlerResult, _) => true,
            (SidecarProtocolPhase.Invoking, SidecarProtocolMessageKind.ToolHandlerCancelled, _) => true,
            (SidecarProtocolPhase.Invoking, SidecarProtocolMessageKind.ToolHandlerFailed, _) => true,
            (SidecarProtocolPhase.Invoking, SidecarProtocolMessageKind.LifecycleHandlerResult, _) => true,
            (SidecarProtocolPhase.Invoking, SidecarProtocolMessageKind.LifecycleHandlerCancelled, _) => true,
            (SidecarProtocolPhase.Invoking, SidecarProtocolMessageKind.LifecycleHandlerFailed, _) => true,
            (SidecarProtocolPhase.Invoking, SidecarProtocolMessageKind.EventListenerDelivery, _) => true,
            (SidecarProtocolPhase.Invoking, SidecarProtocolMessageKind.EventListenerAcknowledgement, _) => true,
            (SidecarProtocolPhase.Invoking, SidecarProtocolMessageKind.StreamChunk, _) => true,
            (SidecarProtocolPhase.EffectAccepted, SidecarProtocolMessageKind.StreamChunk, _) => true,
            (SidecarProtocolPhase.Invoking, SidecarProtocolMessageKind.StreamControl, _) => true,
            (SidecarProtocolPhase.EffectAccepted, SidecarProtocolMessageKind.StreamControl, _) => true,
            (SidecarProtocolPhase.Invoking, SidecarProtocolMessageKind.StreamAcknowledgement, _) => true,
            (SidecarProtocolPhase.EffectAccepted, SidecarProtocolMessageKind.StreamAcknowledgement, _) => true,
            (SidecarProtocolPhase.Invoking, SidecarProtocolMessageKind.HostTerminalCancellation, _) => true,
            (SidecarProtocolPhase.EffectRequested, SidecarProtocolMessageKind.HostTerminalCancellation, _) => true,
            (SidecarProtocolPhase.EffectAccepted, SidecarProtocolMessageKind.HostTerminalCancellation, _) => true,
            (SidecarProtocolPhase.Invoking, SidecarProtocolMessageKind.Error, _) => true,
            (SidecarProtocolPhase.EffectRequested, SidecarProtocolMessageKind.Error, _) => true,
            (SidecarProtocolPhase.EffectAccepted, SidecarProtocolMessageKind.Error, _) => true,
            (_, _, _) => false,
        };

    public static SidecarProtocolTransitionResult Validate(
        SidecarProtocolState state,
        ISidecarProtocolMessage message,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(message);

        if (state.Phase is SidecarProtocolPhase.Completed or
            SidecarProtocolPhase.Cancelled or
            SidecarProtocolPhase.Disconnected or
            SidecarProtocolPhase.Rejected)
        {
            return Reject(SidecarProtocolErrors.LateMessage, "The message arrived after the sidecar exchange ended.");
        }

        if (!message.Header.Size.IsWithinLimit)
            return Reject(SidecarProtocolErrors.ModulePayloadTooLarge, "The message exceeds its size authority.");

        if (message.Header.ProtocolVersion < 1 ||
            message.Header.Sequence <= state.LastSequence)
        {
            return Reject(
                message is SidecarEffectRequest or ContinuationOutcome or SidecarResultReplacement
                    ? SidecarProtocolErrors.ContinuationAlreadyUsed
                    : SidecarProtocolErrors.InvalidSequence,
                "The message sequence is not greater than the last accepted sequence.");
        }

        if (state.Phase == SidecarProtocolPhase.OutcomeSent &&
            message is SidecarEffectRequest or ContinuationOutcome)
        {
            return Reject(SidecarProtocolErrors.ContinuationAlreadyUsed, "The continuation already has a terminal outcome.");
        }

        if (now > state.Deadline || now > message.Header.Deadline)
            return Reject(SidecarProtocolErrors.DeadlineExceeded, "The message deadline has expired.");

        if (!CanApply(
                state.Phase,
                message.MessageKind,
                message is SidecarEffectRequest effect ? effect.Command : null))
        {
            return Reject(SidecarProtocolErrors.InvalidLifecyclePhase, "The message is not valid in the current protocol phase.");
        }

        var handleId = GetContinuationHandleId(message);
        if (handleId is not null &&
            state.ContinuationHandleId != Guid.Empty &&
            handleId != state.ContinuationHandleId)
        {
            return Reject(SidecarProtocolErrors.InvalidContinuationHandle, "The message references a different continuation handle.");
        }

        var nextPhase = message.MessageKind switch
        {
            SidecarProtocolMessageKind.HookInvokeStart or
            SidecarProtocolMessageKind.EventInterceptStart or
            SidecarProtocolMessageKind.ToolHandlerInvokeStart or
            SidecarProtocolMessageKind.LifecycleHandlerInvokeStart => SidecarProtocolPhase.Invoking,
            SidecarProtocolMessageKind.EffectRequest => SidecarProtocolPhase.EffectRequested,
            SidecarProtocolMessageKind.EffectAccepted => SidecarProtocolPhase.EffectAccepted,
            SidecarProtocolMessageKind.ContinuationOutcome => SidecarProtocolPhase.OutcomeSent,
            SidecarProtocolMessageKind.ResultReplacement or
            SidecarProtocolMessageKind.HookOutcome or
            SidecarProtocolMessageKind.HookCompleted or
            SidecarProtocolMessageKind.ToolHandlerResult or
            SidecarProtocolMessageKind.ToolHandlerCancelled or
            SidecarProtocolMessageKind.ToolHandlerFailed or
            SidecarProtocolMessageKind.LifecycleHandlerResult or
            SidecarProtocolMessageKind.LifecycleHandlerCancelled or
            SidecarProtocolMessageKind.LifecycleHandlerFailed or
            SidecarProtocolMessageKind.EventInterceptOutcome => SidecarProtocolPhase.Completed,
            SidecarProtocolMessageKind.HostTerminalCancellation => SidecarProtocolPhase.Cancelled,
            SidecarProtocolMessageKind.Error => SidecarProtocolPhase.Rejected,
            _ => state.Phase,
        };

        return new(true, state with
        {
            Phase = nextPhase,
            LastSequence = message.Header.Sequence,
        });
    }

    private static Guid? GetContinuationHandleId(ISidecarProtocolMessage message) =>
        message switch
        {
            SidecarEffectRequest item => item.ContinuationHandleId,
            ContinuationAccepted item => item.ContinuationHandleId,
            ContinuationOutcome item => item.ContinuationHandleId,
            HookOutcome item => item.ContinuationHandleId,
            HookCompleted item => item.ContinuationHandleId,
            SidecarHostTerminalCancellation item => item.ContinuationHandleId,
            SidecarResultReplacement item => item.ContinuationHandleId,
            _ => null,
        };

    private static SidecarProtocolTransitionResult Reject(string code, string message) =>
        new(false, ErrorCode: code, ErrorMessage: message);
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
    public const string InvalidContinuationHandle = "invalid_continuation_handle";
    public const string LateMessage = "late_message";
    public const string ModulePayloadTooLarge = "module_payload_too_large";
    public const string ModuleBusy = "module_busy";
    public const string UnsupportedEffect = "unsupported_effect";
    public const string UnsupportedSchema = "unsupported_schema";
    public const string UnsupportedCapability = "unsupported_capability";
    public const string UnsupportedVersion = "unsupported_version";
    public const string UnknownHostDescriptor = "unknown_host_descriptor";
    public const string DuplicateDescriptor = "duplicate_descriptor";
    public const string ShadowedHostKey = "shadowed_host_key";
    public const string CategoryMismatch = "category_mismatch";
    public const string SchemaMismatch = "schema_mismatch";
    public const string ForgedApproval = "forged_approval";
    public const string InvalidSequence = "invalid_sequence";
    public const string DeadlineExceeded = "deadline_exceeded";
    public const string BackpressureViolation = "backpressure_violation";
    public const string InvalidLifecyclePhase = "invalid_lifecycle_phase";
    public const string Disconnected = "sidecar_disconnected";
}
