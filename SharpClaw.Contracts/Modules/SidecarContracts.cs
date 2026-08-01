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
    SidecarOutcomeSent,
    Completed,
    Cancelled,
    Disconnected,
    Rejected,
}

public enum SidecarExchangeKind
{
    ActionHook,
    ToolHandler,
    LifecycleHandler,
    EventIntercept,
    EventListener,
    Stream,
}

public sealed record SidecarPayloadLimits(
    int ActionInputBytes = 1_048_576,
    int ActionResultBytes = 1_048_576,
    int EventPayloadBytes = 1_048_576,
    int ProtocolMessageBytes = 4_194_304,
    int StreamChunkBytes = 262_144)
{
    public bool IsValid =>
        ActionInputBytes >= 0 &&
        ActionResultBytes >= 0 &&
        EventPayloadBytes >= 0 &&
        ProtocolMessageBytes >= 0 &&
        StreamChunkBytes >= 0;

    public int MaximumFor(SidecarProtocolMessageKind messageKind) =>
        messageKind switch
        {
            SidecarProtocolMessageKind.HookInvokeStart or
            SidecarProtocolMessageKind.EventInterceptStart or
            SidecarProtocolMessageKind.ToolHandlerInvokeStart or
            SidecarProtocolMessageKind.LifecycleHandlerInvokeStart => ActionInputBytes,
            SidecarProtocolMessageKind.HookOutcome or
            SidecarProtocolMessageKind.HookCompleted or
            SidecarProtocolMessageKind.ResultReplacement or
            SidecarProtocolMessageKind.ContinuationOutcome or
            SidecarProtocolMessageKind.ToolHandlerResult or
            SidecarProtocolMessageKind.LifecycleHandlerResult => ActionResultBytes,
            SidecarProtocolMessageKind.EventListenerDelivery or
            SidecarProtocolMessageKind.EventInterceptOutcome => EventPayloadBytes,
            SidecarProtocolMessageKind.StreamChunk or
            SidecarProtocolMessageKind.StreamControl or
            SidecarProtocolMessageKind.StreamAcknowledgement => StreamChunkBytes,
            _ => ProtocolMessageBytes,
        };
}

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
    string HandlerId,
    JsonElement Result,
    JsonSchemaReference ResultSchema) : ISidecarProtocolMessage
{
    public SidecarProtocolMessageKind MessageKind => SidecarProtocolMessageKind.ToolHandlerResult;
}

public sealed record SidecarToolHandlerCancelled(
    SidecarMessageHeader Header,
    Guid InvocationId,
    string HandlerId,
    string Code,
    string Message) : ISidecarProtocolMessage
{
    public SidecarProtocolMessageKind MessageKind => SidecarProtocolMessageKind.ToolHandlerCancelled;
}

public sealed record SidecarToolHandlerFailed(
    SidecarMessageHeader Header,
    Guid InvocationId,
    string HandlerId,
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
    string HandlerId,
    JsonElement? Result) : ISidecarProtocolMessage
{
    public SidecarProtocolMessageKind MessageKind => SidecarProtocolMessageKind.LifecycleHandlerResult;
}

public sealed record SidecarLifecycleHandlerCancelled(
    SidecarMessageHeader Header,
    Guid InvocationId,
    SidecarLifecycleCallKind Call,
    string HandlerId,
    string Code,
    string Message) : ISidecarProtocolMessage
{
    public SidecarProtocolMessageKind MessageKind => SidecarProtocolMessageKind.LifecycleHandlerCancelled;
}

public sealed record SidecarLifecycleHandlerFailed(
    SidecarMessageHeader Header,
    Guid InvocationId,
    SidecarLifecycleCallKind Call,
    string HandlerId,
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
    string ListenerId,
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
        IReadOnlyList<SidecarHostEventDescriptor> events,
        int negotiatedProtocolVersion = 1,
        SidecarPayloadLimits? payloadLimits = null,
        SensitiveWildcardApproval? sensitiveWildcardApproval = null)
    {
        ArgumentNullException.ThrowIfNull(actions);
        ArgumentNullException.ThrowIfNull(events);

        if (negotiatedProtocolVersion < 1)
            throw new ArgumentOutOfRangeException(nameof(negotiatedProtocolVersion));

        if (actions.GroupBy(item => item.ActionKey).Any(group => group.Count() > 1))
            throw new ArgumentException("Host action descriptors must have unique keys.", nameof(actions));

        if (events.GroupBy(item => item.EventKey).Any(group => group.Count() > 1))
            throw new ArgumentException("Host event descriptors must have unique keys.", nameof(events));

        Actions = new ReadOnlyCollection<SidecarHostActionDescriptor>(actions.ToArray());
        Events = new ReadOnlyCollection<SidecarHostEventDescriptor>(events.ToArray());
        NegotiatedProtocolVersion = negotiatedProtocolVersion;
        PayloadLimits = payloadLimits ?? new SidecarPayloadLimits();
        if (!PayloadLimits.IsValid)
            throw new ArgumentException("Host payload limits must be non-negative.", nameof(payloadLimits));
        SensitiveWildcardApproval = sensitiveWildcardApproval;
    }

    public IReadOnlyList<SidecarHostActionDescriptor> Actions { get; }
    public IReadOnlyList<SidecarHostEventDescriptor> Events { get; }
    public int NegotiatedProtocolVersion { get; }
    public SidecarPayloadLimits PayloadLimits { get; }
    public SensitiveWildcardApproval? SensitiveWildcardApproval { get; }

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

        if (!discovery.Header.Size.IsWithinLimit ||
            discovery.Header.Size.MaximumPayloadBytes > hostCatalog.PayloadLimits.ProtocolMessageBytes ||
            discovery.Header.Size.PayloadBytes > hostCatalog.PayloadLimits.ProtocolMessageBytes)
            return Reject(SidecarProtocolErrors.ModulePayloadTooLarge, "Discovery exceeds its host size authority.");

        try
        {
            if (JsonSerializer.SerializeToUtf8Bytes(discovery, discovery.GetType()).Length >
                hostCatalog.PayloadLimits.ProtocolMessageBytes)
                return Reject(SidecarProtocolErrors.ModulePayloadTooLarge, "The measured discovery exceeds the host limit.");
        }
        catch (JsonException)
        {
            return Reject(SidecarProtocolErrors.MalformedMessage, "The discovery cannot be measured.");
        }

        if (discovery.Header.ProtocolVersion != hostCatalog.NegotiatedProtocolVersion ||
            discovery.Header.ProtocolVersion < discovery.Protocol.MinimumVersion ||
            discovery.Header.ProtocolVersion > discovery.Protocol.MaximumVersion)
        {
            return Reject(SidecarProtocolErrors.UnsupportedVersion, "The discovery header does not use the host negotiated protocol version.");
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

            if (subscription.TargetKind == SidecarHookTargetKind.Exact && subscription.ActionKey is not { } actionKey)
                return Reject(SidecarProtocolErrors.UnknownHostDescriptor, "The action subscription does not identify a host action descriptor.");

            if (string.IsNullOrWhiteSpace(subscription.Category) &&
                     subscription.TargetKind == SidecarHookTargetKind.Category)
            {
                return Reject(SidecarProtocolErrors.CategoryMismatch, "A category subscription requires a category.");
            }

            var actionMatches = hostCatalog.Actions
                .Where(item =>
                    (subscription.TargetKind == SidecarHookTargetKind.Exact
                        ? item.ActionKey == subscription.ActionKey
                        : subscription.TargetKind == SidecarHookTargetKind.Wildcard ||
                          string.Equals(item.Category, subscription.Category, StringComparison.Ordinal)) &&
                    subscription.VersionRange.Contains(item.Version))
                .ToArray();
            if (actionMatches.Length == 0)
            {
                return Reject(SidecarProtocolErrors.UnknownHostDescriptor, "The action subscription matches no immutable host descriptor.");
            }

            foreach (var descriptor in actionMatches)
            {
                if (!descriptor.ProtocolVersionRange.Contains(hostCatalog.NegotiatedProtocolVersion))
                    return Reject(SidecarProtocolErrors.UnsupportedVersion, "The action subscription uses an unsupported protocol version.");

                if (subscription.TargetKind == SidecarHookTargetKind.Exact &&
                    !string.Equals(subscription.Category, descriptor.Category, StringComparison.Ordinal))
                    return Reject(SidecarProtocolErrors.CategoryMismatch, "The action subscription category does not match the host descriptor.");

                if (!SameSchema(descriptor.InputSchema, subscription.InputSchema) ||
                    !SameSchema(descriptor.ResultSchema, subscription.ResultSchema))
                    return Reject(SidecarProtocolErrors.SchemaMismatch, "The action subscription schema does not match every host descriptor.");

                if ((subscription.Capabilities & ~descriptor.Capabilities) != 0)
                    return Reject(SidecarProtocolErrors.UnsupportedCapability, "The action subscription requests an ungranted host capability.");

                if (subscription.TargetKind == SidecarHookTargetKind.Wildcard &&
                    descriptor.ContainsSensitiveData &&
                    (hostCatalog.SensitiveWildcardApproval is null ||
                     !string.Equals(hostCatalog.SensitiveWildcardApproval.ModuleId, discovery.ModuleId, StringComparison.Ordinal) ||
                     !hostCatalog.SensitiveWildcardApproval.CoversAction(descriptor.ActionKey, descriptor.Version)))
                    return Reject(SidecarProtocolErrors.ForgedApproval, "The sensitive wildcard action lacks host approval.");
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

            if (subscription.TargetKind == SidecarHookTargetKind.Exact && subscription.EventKey is not { } eventKey)
                return Reject(SidecarProtocolErrors.UnknownHostDescriptor, "The event subscription does not identify a host event descriptor.");

            if (string.IsNullOrWhiteSpace(subscription.Category) &&
                     subscription.TargetKind == SidecarHookTargetKind.Category)
            {
                return Reject(SidecarProtocolErrors.CategoryMismatch, "A category subscription requires a category.");
            }

            var eventMatches = hostCatalog.Events
                .Where(item =>
                    (subscription.TargetKind == SidecarHookTargetKind.Exact
                        ? item.EventKey == subscription.EventKey
                        : subscription.TargetKind == SidecarHookTargetKind.Wildcard ||
                          string.Equals(item.Category, subscription.Category, StringComparison.Ordinal)) &&
                    subscription.VersionRange.Contains(item.Version))
                .ToArray();
            if (eventMatches.Length == 0)
            {
                return Reject(SidecarProtocolErrors.UnknownHostDescriptor, "The event subscription matches no immutable host descriptor.");
            }

            foreach (var descriptor in eventMatches)
            {
                if (!descriptor.ProtocolVersionRange.Contains(hostCatalog.NegotiatedProtocolVersion))
                    return Reject(SidecarProtocolErrors.UnsupportedVersion, "The event subscription uses an unsupported protocol version.");

                if (subscription.TargetKind == SidecarHookTargetKind.Exact &&
                    !string.Equals(subscription.Category, descriptor.Category, StringComparison.Ordinal))
                    return Reject(SidecarProtocolErrors.CategoryMismatch, "The event subscription category does not match the host descriptor.");

                if (!SameSchema(descriptor.PayloadSchema, subscription.PayloadSchema))
                    return Reject(SidecarProtocolErrors.SchemaMismatch, "The event subscription schema does not match every host descriptor.");

                if ((subscription.Capabilities & ~descriptor.Capabilities) != 0)
                    return Reject(SidecarProtocolErrors.UnsupportedCapability, "The event subscription requests an ungranted host capability.");

                if (subscription.TargetKind == SidecarHookTargetKind.Wildcard &&
                    descriptor.ContainsSensitiveData &&
                    (hostCatalog.SensitiveWildcardApproval is null ||
                     !string.Equals(hostCatalog.SensitiveWildcardApproval.ModuleId, discovery.ModuleId, StringComparison.Ordinal) ||
                     !hostCatalog.SensitiveWildcardApproval.CoversEvent(descriptor.EventKey, descriptor.Version)))
                    return Reject(SidecarProtocolErrors.ForgedApproval, "The sensitive wildcard event lacks host approval.");
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
    SharpClawEventKey EventKey,
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
    SidecarExchangeKind ExchangeKind,
    Guid InvocationId,
    Guid ContinuationHandleId,
    SidecarProtocolPhase Phase,
    long LastSequence,
    DateTimeOffset Deadline,
    int NegotiatedProtocolVersion,
    SidecarPayloadLimits HostLimits,
    string? HandlerId = null,
    SidecarLifecycleCallKind? LifecycleCall = null,
    Guid? DeliveryId = null,
    string? ListenerId = null,
    EventDelivery? Delivery = null,
    Guid? StreamId = null,
    SharpClawEventKey? EventKey = null,
    SharpClawActionKey? ActionKey = null,
    string? ToolName = null,
    string? HookId = null,
    Guid? TraceId = null,
    bool DeliveryAcknowledgementPending = false,
    bool ResultReplacementAccepted = false);

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
            (SidecarProtocolPhase.OutcomeSent, SidecarProtocolMessageKind.HookOutcome, _) => true,
            (SidecarProtocolPhase.SidecarOutcomeSent, SidecarProtocolMessageKind.ResultReplacement, _) => true,
            (SidecarProtocolPhase.SidecarOutcomeSent, SidecarProtocolMessageKind.HookCompleted, _) => true,
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
            (SidecarProtocolPhase.SidecarOutcomeSent, SidecarProtocolMessageKind.HostTerminalCancellation, _) => true,
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

        var hostPayloadLimit = state.HostLimits.MaximumFor(message.MessageKind);
        if (!message.Header.Size.IsWithinLimit ||
            message.Header.Size.MaximumPayloadBytes > hostPayloadLimit ||
            message.Header.Size.PayloadBytes > hostPayloadLimit)
            return Reject(SidecarProtocolErrors.ModulePayloadTooLarge, "The message exceeds its size authority.");

        if (message.Header.ProtocolVersion != state.NegotiatedProtocolVersion ||
            message.Header.ProtocolVersion < 1)
        {
            return Reject(SidecarProtocolErrors.UnsupportedVersion, "The message does not use the negotiated protocol version.");
        }

        if (message.Header.Sequence <= state.LastSequence)
        {
            return Reject(
                message is SidecarEffectRequest or ContinuationOutcome or SidecarResultReplacement
                    ? SidecarProtocolErrors.ContinuationAlreadyUsed
                    : SidecarProtocolErrors.InvalidSequence,
                "The message sequence is not greater than the last accepted sequence.");
        }

        try
        {
            if (JsonSerializer.SerializeToUtf8Bytes(message, message.GetType()).Length > state.HostLimits.ProtocolMessageBytes)
                return Reject(SidecarProtocolErrors.ModulePayloadTooLarge, "The measured protocol message exceeds the host limit.");
        }
        catch (JsonException)
        {
            return Reject(SidecarProtocolErrors.MalformedMessage, "The protocol message cannot be measured.");
        }

        if ((state.Phase == SidecarProtocolPhase.OutcomeSent ||
             state.Phase == SidecarProtocolPhase.SidecarOutcomeSent) &&
            message is SidecarEffectRequest or ContinuationAccepted or ContinuationOutcome)
        {
            return Reject(SidecarProtocolErrors.ContinuationAlreadyUsed, "The continuation already has a terminal outcome.");
        }

        if (state.Phase == SidecarProtocolPhase.SidecarOutcomeSent &&
            message is SidecarResultReplacement &&
            state.ResultReplacementAccepted)
        {
            return Reject(SidecarProtocolErrors.ContinuationAlreadyUsed, "The sidecar result replacement was already accepted.");
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

        var identityFailure = ValidateIdentity(state, message);
        if (identityFailure is not null)
            return identityFailure;

        var handleId = GetContinuationHandleId(message);
        if (handleId is not null &&
            message is not HookInvokeStart and not EventInterceptStart &&
            state.ContinuationHandleId == Guid.Empty)
        {
            return Reject(SidecarProtocolErrors.InvalidContinuationHandle, "The exchange has no established continuation handle.");
        }

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
            SidecarProtocolMessageKind.HookOutcome or
            SidecarProtocolMessageKind.ResultReplacement => SidecarProtocolPhase.SidecarOutcomeSent,
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

        var nextState = state with
        {
            Phase = nextPhase,
            LastSequence = message.Header.Sequence,
        };

        nextState = message switch
        {
            HookInvokeStart item => nextState with
            {
                InvocationId = item.InvocationId,
                ContinuationHandleId = item.Continuation.HandleId,
                HookId = item.HookId,
                ActionKey = item.ActionKey,
                TraceId = item.TraceId,
            },
            EventInterceptStart item => nextState with
            {
                InvocationId = item.Continuation.InvocationId,
                ContinuationHandleId = item.Continuation.HandleId,
                HookId = item.HookId,
                EventKey = item.Envelope.Descriptor.Key,
                TraceId = item.Envelope.TraceId,
            },
            SidecarToolHandlerInvokeStart item => nextState with
            {
                InvocationId = item.InvocationId,
                HandlerId = item.HandlerId,
                ToolName = item.ToolName,
            },
            SidecarLifecycleHandlerInvokeStart item => nextState with
            {
                InvocationId = item.InvocationId,
                HandlerId = item.HandlerId,
                LifecycleCall = item.Call,
            },
            SidecarEventListenerDelivery item => nextState with
            {
                DeliveryId = item.DeliveryId,
                ListenerId = item.ListenerId,
                Delivery = item.Delivery,
                DeliveryAcknowledgementPending = item.RequiresAcknowledgement,
            },
            SidecarEventListenerAcknowledgement => nextState with
            {
                DeliveryAcknowledgementPending = false,
            },
            SidecarResultReplacement => nextState with
            {
                ResultReplacementAccepted = true,
            },
            _ => nextState,
        };

        return new(true, nextState);
    }

    private static SidecarProtocolTransitionResult? ValidateIdentity(
        SidecarProtocolState state,
        ISidecarProtocolMessage message)
    {
        switch (message)
        {
            case HookInvokeStart item when state.ExchangeKind != SidecarExchangeKind.ActionHook:
                return Reject(SidecarProtocolErrors.ExchangeIdentityMismatch, "The message is not valid for this exchange kind.");
            case HookInvokeStart item:
                if (state.InvocationId != Guid.Empty && state.InvocationId != item.InvocationId ||
                    state.ContinuationHandleId != Guid.Empty && state.ContinuationHandleId != item.Continuation.HandleId ||
                    state.ActionKey is not null && state.ActionKey != item.ActionKey ||
                    state.HookId is not null && !string.Equals(state.HookId, item.HookId, StringComparison.Ordinal) ||
                    item.Continuation.InvocationId != item.InvocationId)
                    return Reject(SidecarProtocolErrors.ExchangeIdentityMismatch, "The action hook identity does not match the exchange.");
                break;
            case EventInterceptStart item when state.ExchangeKind != SidecarExchangeKind.EventIntercept:
                return Reject(SidecarProtocolErrors.ExchangeIdentityMismatch, "The message is not valid for this exchange kind.");
            case EventInterceptStart item:
                if (state.InvocationId != Guid.Empty && state.InvocationId != item.Continuation.InvocationId ||
                    state.ContinuationHandleId != Guid.Empty && state.ContinuationHandleId != item.Continuation.HandleId ||
                    state.EventKey is not null && state.EventKey != item.Envelope.Descriptor.Key ||
                    state.HookId is not null && !string.Equals(state.HookId, item.HookId, StringComparison.Ordinal))
                    return Reject(SidecarProtocolErrors.ExchangeIdentityMismatch, "The event interception identity does not match the exchange.");
                break;
            case SidecarToolHandlerInvokeStart item when state.ExchangeKind != SidecarExchangeKind.ToolHandler:
                return Reject(SidecarProtocolErrors.ExchangeIdentityMismatch, "The message is not valid for this exchange kind.");
            case SidecarToolHandlerInvokeStart item:
                if (!Matches(state.InvocationId, item.InvocationId) ||
                    !Matches(state.HandlerId, item.HandlerId) ||
                    !Matches(state.ToolName, item.ToolName))
                    return Reject(SidecarProtocolErrors.ExchangeIdentityMismatch, "The tool handler identity does not match the exchange.");
                break;
            case SidecarToolHandlerResult item:
                if (state.ExchangeKind != SidecarExchangeKind.ToolHandler ||
                    !Matches(state.InvocationId, item.InvocationId) ||
                    !Matches(state.HandlerId, item.HandlerId))
                    return Reject(SidecarProtocolErrors.ExchangeIdentityMismatch, "The tool result identity does not match the exchange.");
                break;
            case SidecarToolHandlerCancelled item:
                if (state.ExchangeKind != SidecarExchangeKind.ToolHandler ||
                    !Matches(state.InvocationId, item.InvocationId) ||
                    !Matches(state.HandlerId, item.HandlerId))
                    return Reject(SidecarProtocolErrors.ExchangeIdentityMismatch, "The tool cancellation identity does not match the exchange.");
                break;
            case SidecarToolHandlerFailed item:
                if (state.ExchangeKind != SidecarExchangeKind.ToolHandler ||
                    !Matches(state.InvocationId, item.InvocationId) ||
                    !Matches(state.HandlerId, item.HandlerId))
                    return Reject(SidecarProtocolErrors.ExchangeIdentityMismatch, "The tool failure identity does not match the exchange.");
                break;
            case SidecarLifecycleHandlerInvokeStart item when state.ExchangeKind != SidecarExchangeKind.LifecycleHandler:
                return Reject(SidecarProtocolErrors.ExchangeIdentityMismatch, "The message is not valid for this exchange kind.");
            case SidecarLifecycleHandlerInvokeStart item:
                if (!Matches(state.InvocationId, item.InvocationId) ||
                    !Matches(state.HandlerId, item.HandlerId) ||
                    state.LifecycleCall is not null && state.LifecycleCall != item.Call)
                    return Reject(SidecarProtocolErrors.ExchangeIdentityMismatch, "The lifecycle handler identity does not match the exchange.");
                break;
            case SidecarLifecycleHandlerResult item:
                if (state.ExchangeKind != SidecarExchangeKind.LifecycleHandler ||
                    !Matches(state.InvocationId, item.InvocationId) ||
                    !Matches(state.HandlerId, item.HandlerId) ||
                    state.LifecycleCall != item.Call)
                    return Reject(SidecarProtocolErrors.ExchangeIdentityMismatch, "The lifecycle result identity does not match the exchange.");
                break;
            case SidecarLifecycleHandlerCancelled item:
                if (state.ExchangeKind != SidecarExchangeKind.LifecycleHandler ||
                    !Matches(state.InvocationId, item.InvocationId) ||
                    !Matches(state.HandlerId, item.HandlerId) ||
                    state.LifecycleCall != item.Call)
                    return Reject(SidecarProtocolErrors.ExchangeIdentityMismatch, "The lifecycle cancellation identity does not match the exchange.");
                break;
            case SidecarLifecycleHandlerFailed item:
                if (state.ExchangeKind != SidecarExchangeKind.LifecycleHandler ||
                    !Matches(state.InvocationId, item.InvocationId) ||
                    !Matches(state.HandlerId, item.HandlerId) ||
                    state.LifecycleCall != item.Call)
                    return Reject(SidecarProtocolErrors.ExchangeIdentityMismatch, "The lifecycle failure identity does not match the exchange.");
                break;
            case EventInterceptOutcome item:
                if (state.ExchangeKind != SidecarExchangeKind.EventIntercept ||
                    !Matches(state.ContinuationHandleId, item.ContinuationHandleId) ||
                    state.EventKey != item.EventKey)
                    return Reject(SidecarProtocolErrors.ExchangeIdentityMismatch, "The event interception outcome identity does not match the exchange.");
                break;
            case SidecarEventListenerDelivery item:
                if (state.ExchangeKind != SidecarExchangeKind.EventListener ||
                    state.DeliveryAcknowledgementPending ||
                    state.DeliveryId is not null && state.DeliveryId != item.DeliveryId ||
                    state.ListenerId is not null && !string.Equals(state.ListenerId, item.ListenerId, StringComparison.Ordinal))
                    return Reject(SidecarProtocolErrors.ExchangeIdentityMismatch, "The event delivery identity does not match the exchange.");
                break;
            case SidecarEventListenerAcknowledgement item:
                if (state.ExchangeKind != SidecarExchangeKind.EventListener ||
                    !state.DeliveryAcknowledgementPending ||
                    state.DeliveryId != item.DeliveryId ||
                    !string.Equals(state.ListenerId, item.ListenerId, StringComparison.Ordinal) ||
                    state.Delivery != item.Delivery)
                    return Reject(SidecarProtocolErrors.DeliveryNotPending, "The event acknowledgement has no matching pending delivery.");
                break;
            case SidecarStreamChunk:
            case SidecarStreamControl:
            case SidecarStreamAcknowledgement:
                var streamId = message switch
                {
                    SidecarStreamChunk chunk => chunk.StreamId,
                    SidecarStreamControl control => control.StreamId,
                    SidecarStreamAcknowledgement acknowledgement => acknowledgement.StreamId,
                    _ => Guid.Empty,
                };
                if (state.ExchangeKind != SidecarExchangeKind.Stream ||
                    state.StreamId != streamId)
                    return Reject(SidecarProtocolErrors.ExchangeIdentityMismatch, "The stream identity does not match the exchange.");
                break;
            case HookOutcome or SidecarResultReplacement or HookCompleted or SidecarHostTerminalCancellation:
            case SidecarEffectRequest or ContinuationAccepted or ContinuationOutcome:
                if (state.ExchangeKind != SidecarExchangeKind.ActionHook)
                    return Reject(SidecarProtocolErrors.ExchangeIdentityMismatch, "The continuation message is not valid for this exchange kind.");
                break;
        }

        return null;
    }

    private static bool Matches(Guid expected, Guid actual) =>
        expected == Guid.Empty || expected == actual;

    private static bool Matches(string? expected, string actual) =>
        expected is null || string.Equals(expected, actual, StringComparison.Ordinal);

    private static Guid? GetContinuationHandleId(ISidecarProtocolMessage message) =>
        message switch
        {
            SidecarEffectRequest item => item.ContinuationHandleId,
            ContinuationAccepted item => item.ContinuationHandleId,
            ContinuationOutcome item => item.ContinuationHandleId,
            HookInvokeStart item => item.Continuation.HandleId,
            EventInterceptStart item => item.Continuation.HandleId,
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
    public const string ExchangeIdentityMismatch = "exchange_identity_mismatch";
    public const string DeliveryNotPending = "delivery_not_pending";
    public const string MalformedMessage = "malformed_message";
    public const string Disconnected = "sidecar_disconnected";
}
