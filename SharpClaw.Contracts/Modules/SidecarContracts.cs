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
            SidecarProtocolMessageKind.ToolHandlerInvokeStart or
            SidecarProtocolMessageKind.LifecycleHandlerInvokeStart or
            SidecarProtocolMessageKind.EffectRequest => ActionInputBytes,
            SidecarProtocolMessageKind.EventInterceptStart => EventPayloadBytes,
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
    RequestPrincipal Caller,
    HostActionEntryRequestContext HostActionContext) : ISidecarProtocolMessage
{
    public SidecarProtocolMessageKind MessageKind => SidecarProtocolMessageKind.ToolHandlerInvokeStart;

    public bool IsWellFormed(DateTimeOffset now) =>
        Header is not null &&
        InvocationId != Guid.Empty &&
        !string.IsNullOrWhiteSpace(ToolName) &&
        !string.IsNullOrWhiteSpace(HandlerId) &&
        Input.ValueKind != JsonValueKind.Undefined &&
        InputSchema is not null &&
        !string.IsNullOrWhiteSpace(InputSchema.ContractName) &&
        InputSchema.Version >= 1 &&
        !string.IsNullOrWhiteSpace(InputSchema.ContentHash) &&
        Caller is not null &&
        !string.IsNullOrWhiteSpace(Caller.SubjectId) &&
        HostActionContext is not null &&
        HostActionContext.IsWellFormed(now) &&
        HostActionContext.Ingress == HostActionEntryIngress.Tool &&
        HostActionContext.InvocationId == InvocationId &&
        HostActionContext.Contribution?.IngressBinding.Ingress == HostActionEntryIngress.Tool &&
        string.Equals(
            HostActionContext.Contribution.IngressBinding.PrimaryIdentity,
            ToolName,
            StringComparison.Ordinal) &&
        !HostActionContext.Contribution.Lineage.IsPayloadBound &&
        HostActionContext.Contribution.Lineage.InputSchemaVersion == InputSchema.Version &&
        string.Equals(
            HostActionContext.Contribution.Lineage.InputSchemaHash,
            InputSchema.ContentHash,
            StringComparison.Ordinal) &&
        Header.Deadline == HostActionContext.Deadline &&
        SamePrincipal(Caller, HostActionContext.Caller);

    private static bool SamePrincipal(RequestPrincipal left, RequestPrincipal right) =>
        string.Equals(left.SubjectId, right.SubjectId, StringComparison.Ordinal) &&
        string.Equals(left.DisplayName, right.DisplayName, StringComparison.Ordinal) &&
        left.IsAuthenticated == right.IsAuthenticated &&
        SameRoles(left.Roles, right.Roles);

    private static bool SameRoles(IReadOnlySet<string>? left, IReadOnlySet<string>? right)
    {
        if (left is null || right is null)
            return left is null && right is null;

        return left.Count == right.Count &&
            left.All(leftRole =>
                leftRole is not null &&
                right.Any(rightRole =>
                    rightRole is not null &&
                    string.Equals(leftRole, rightRole, StringComparison.Ordinal)));
    }
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
    UntypedEventDescriptor Descriptor,
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

                var acceptsUnknownNonSensitiveSchema =
                    (subscription.TargetKind is SidecarHookTargetKind.Category or SidecarHookTargetKind.Wildcard) &&
                    subscription.PayloadMode == SidecarPayloadMode.Untyped &&
                    subscription.AcceptUnknownNonSensitiveSchemas;
                if ((!acceptsUnknownNonSensitiveSchema || descriptor.ContainsSensitiveData) &&
                    (!SameSchema(descriptor.InputSchema, subscription.InputSchema) ||
                     !SameSchema(descriptor.ResultSchema, subscription.ResultSchema)))
                    return Reject(SidecarProtocolErrors.SchemaMismatch, "The action subscription schema does not match every host descriptor.");

                if ((subscription.Capabilities & ~descriptor.Capabilities) != 0)
                    return Reject(SidecarProtocolErrors.UnsupportedCapability, "The action subscription requests an ungranted host capability.");

                if ((subscription.TargetKind is SidecarHookTargetKind.Category or SidecarHookTargetKind.Wildcard) &&
                    (descriptor.ContainsSensitiveData || subscription.SensitiveWildcardApprovalRequired) &&
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

                var acceptsUnknownNonSensitiveSchema =
                    (subscription.TargetKind is SidecarHookTargetKind.Category or SidecarHookTargetKind.Wildcard) &&
                    subscription.PayloadMode == SidecarPayloadMode.Untyped &&
                    subscription.AcceptUnknownNonSensitiveSchemas;
                if ((!acceptsUnknownNonSensitiveSchema || descriptor.ContainsSensitiveData) &&
                    !SameSchema(descriptor.PayloadSchema, subscription.PayloadSchema))
                    return Reject(SidecarProtocolErrors.SchemaMismatch, "The event subscription schema does not match every host descriptor.");

                if ((subscription.Capabilities & ~descriptor.Capabilities) != 0)
                    return Reject(SidecarProtocolErrors.UnsupportedCapability, "The event subscription requests an ungranted host capability.");

                if ((subscription.TargetKind is SidecarHookTargetKind.Category or SidecarHookTargetKind.Wildcard) &&
                    (descriptor.ContainsSensitiveData || subscription.SensitiveWildcardApprovalRequired) &&
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
    int EventVersion,
    JsonSchemaReference EventSchema,
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
/// A sidecar can replace a result before continuation when the compiled host grant allows it.
/// The existing post-continuation replacement path remains available.
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
    bool ResultReplacementAccepted = false,
    UntypedActionDescriptor? ActionDescriptor = null,
    ActionCapabilityGrant? ActionGrant = null,
    int? ActionVersion = null,
    UntypedEventDescriptor? EventDescriptor = null,
    EventCapabilityGrant? EventGrant = null,
    int? EventVersion = null,
    SidecarContinuationCommand? RequestedCommand = null,
    SidecarHostAuthorization? HostAuthorization = null,
    HostActionEntryRequestContext? HostActionContext = null)
{
    /// <summary>Gets whether the sidecar supplied a terminal outcome before continuation.</summary>
    public bool DirectTerminalOutcomeAccepted { get; init; }
}

public sealed record SidecarProtocolTransitionResult(
    bool Accepted,
    SidecarProtocolState? State = null,
    string? ErrorCode = null,
    string? ErrorMessage = null);

public static class SidecarProtocolStateMachine
{
    /// <summary>Checks the phase and the host grant for one protocol message.</summary>
    public static bool CanApply(
        SidecarProtocolState state,
        ISidecarProtocolMessage message)
    {
        ArgumentNullException.ThrowIfNull(message);

        return CanApply(
                   state.Phase,
                   message.MessageKind,
                   message is SidecarEffectRequest effect ? effect.Command : null,
                   message is HookOutcome outcome ? outcome.Kind : null) &&
               ValidateCapabilities(state, message) is null &&
               ValidateMessageShape(state, message) is null;
    }

    /// <summary>Checks only the phase transition shape.</summary>
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
            (SidecarProtocolPhase.Invoking, SidecarProtocolMessageKind.ResultReplacement, _) => true,
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

    /// <summary>Checks a phase transition that includes a direct hook outcome kind.</summary>
    public static bool CanApply(
        SidecarProtocolPhase phase,
        SidecarProtocolMessageKind message,
        SidecarContinuationCommand? command,
        SidecarHookOutcomeKind? hookOutcomeKind) =>
        (phase == SidecarProtocolPhase.Invoking &&
         message == SidecarProtocolMessageKind.HookOutcome &&
         hookOutcomeKind == SidecarHookOutcomeKind.Failed) ||
        CanApply(phase, message, command);

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
            var measuredBytes = JsonSerializer.SerializeToUtf8Bytes(message, message.GetType()).Length;
            if (measuredBytes > hostPayloadLimit ||
                measuredBytes > state.HostLimits.ProtocolMessageBytes)
                return Reject(SidecarProtocolErrors.ModulePayloadTooLarge, "The measured protocol message exceeds the host limit.");
        }
        catch (Exception exception) when (exception is JsonException or InvalidOperationException or NotSupportedException)
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
            (message is HookOutcome ||
             message is SidecarResultReplacement &&
             (state.ResultReplacementAccepted || state.DirectTerminalOutcomeAccepted)))
        {
            return Reject(SidecarProtocolErrors.ContinuationAlreadyUsed, "The sidecar terminal outcome was already accepted.");
        }

        if (now > state.Deadline || now > message.Header.Deadline)
            return Reject(SidecarProtocolErrors.DeadlineExceeded, "The message deadline has expired.");

        if (message is SidecarToolHandlerInvokeStart toolStart)
        {
            var toolContextFailure = ValidateToolEntry(state, toolStart, now);
            if (toolContextFailure is not null)
                return toolContextFailure;
        }

        if (!CanApply(
                state.Phase,
                message.MessageKind,
                message is SidecarEffectRequest effect ? effect.Command : null,
                message is HookOutcome outcome ? outcome.Kind : null))
        {
            return Reject(SidecarProtocolErrors.InvalidLifecyclePhase, "The message is not valid in the current protocol phase.");
        }

        var identityFailure = ValidateIdentity(state, message);
        if (identityFailure is not null)
            return identityFailure;

        var capabilityFailure = ValidateCapabilities(state, message);
        if (capabilityFailure is not null)
            return capabilityFailure;

        var shapeFailure = ValidateMessageShape(state, message);
        if (shapeFailure is not null)
            return shapeFailure;

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

        var isDirectTerminalOutcome =
            state.Phase == SidecarProtocolPhase.Invoking &&
            message is HookOutcome or SidecarResultReplacement;
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
                ActionVersion = item.ActionVersion,
                ActionDescriptor = item.UntypedDescriptor,
                ActionGrant = item.Grant,
            },
            EventInterceptStart item => nextState with
            {
                InvocationId = item.Continuation.InvocationId,
                ContinuationHandleId = item.Continuation.HandleId,
                HookId = item.HookId,
                EventKey = item.Envelope.Descriptor.Key,
                TraceId = item.Envelope.TraceId,
                EventVersion = item.Envelope.Descriptor.Version,
                EventDescriptor = item.Envelope.Descriptor,
                EventGrant = item.Grant,
            },
            SidecarToolHandlerInvokeStart item => nextState with
            {
                InvocationId = item.InvocationId,
                HandlerId = item.HandlerId,
                ToolName = item.ToolName,
                HostActionContext = item.HostActionContext,
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
                EventKey = item.Envelope.Descriptor.Key,
                EventVersion = item.Envelope.Descriptor.Version,
                DeliveryAcknowledgementPending = item.RequiresAcknowledgement,
            },
            SidecarEventListenerAcknowledgement => nextState with
            {
                DeliveryAcknowledgementPending = false,
            },
            SidecarResultReplacement => nextState with
            {
                ResultReplacementAccepted = true,
                DirectTerminalOutcomeAccepted = isDirectTerminalOutcome,
            },
            HookOutcome when isDirectTerminalOutcome => nextState with
            {
                DirectTerminalOutcomeAccepted = true,
            },
            SidecarEffectRequest item => nextState with
            {
                RequestedCommand = item.Command,
            },
            _ => nextState,
        };

        return new(true, nextState);
    }

    private static SidecarProtocolTransitionResult? ValidateCapabilities(
        SidecarProtocolState state,
        ISidecarProtocolMessage message)
    {
        switch (message)
        {
            case HookInvokeStart item:
                if (item.Grant.ActionKey != item.ActionKey || item.Grant.ActionVersion != item.ActionVersion)
                    return Reject(SidecarProtocolErrors.UnsupportedCapability, "The action grant does not match the invoked descriptor.");
                if (!IsCompiledActionGrant(state, item.Grant))
                    return Reject(SidecarProtocolErrors.UnsupportedCapability, "The action grant was not issued by the compiled host authorization.");
                if (item.UntypedDescriptor is not null &&
                    (item.UntypedDescriptor.Key != item.ActionKey || item.UntypedDescriptor.Version != item.ActionVersion))
                    return Reject(SidecarProtocolErrors.ExchangeIdentityMismatch, "The action descriptor does not match the invocation.");
                if (item.UntypedDescriptor is not null &&
                    (item.Grant.Capabilities & ~item.UntypedDescriptor.Capabilities) != 0)
                    return Reject(SidecarProtocolErrors.UnsupportedCapability, "The action grant exceeds the descriptor capability set.");
                if (item.UntypedDescriptor is not null &&
                    !item.UntypedDescriptor.ProtocolVersionRange.Contains(state.NegotiatedProtocolVersion))
                    return Reject(SidecarProtocolErrors.UnsupportedVersion, "The action descriptor does not support the negotiated protocol version.");
                var actionAuthorizationFailure = ValidateActionAuthorization(item.Grant, item.UntypedDescriptor);
                if (actionAuthorizationFailure is not null)
                    return actionAuthorizationFailure;
                break;
            case EventInterceptStart item:
                if (item.Grant.EventKey != item.Envelope.Descriptor.Key ||
                    item.Grant.EventVersion != item.Envelope.Descriptor.Version)
                    return Reject(SidecarProtocolErrors.UnsupportedCapability, "The event grant does not match the intercepted descriptor.");
                if ((item.Grant.Capabilities & ~item.Envelope.Descriptor.Capabilities) != 0)
                    return Reject(SidecarProtocolErrors.UnsupportedCapability, "The event grant exceeds the descriptor capability set.");
                if (!IsCompiledEventGrant(state, item.Grant))
                    return Reject(SidecarProtocolErrors.UnsupportedCapability, "The event grant was not issued by the compiled host authorization.");
                var eventAuthorizationFailure = ValidateEventAuthorization(item.Grant, item.Envelope.Descriptor);
                if (eventAuthorizationFailure is not null)
                    return eventAuthorizationFailure;
                break;
            case SidecarEffectRequest item:
                if (state.ActionGrant is null || state.ActionKey is not { } actionKey)
                    return Reject(SidecarProtocolErrors.UnsupportedCapability, "The action exchange has no host capability grant.");

                var actionVersion = state.ActionVersion ?? state.ActionGrant.ActionVersion;
                if (state.ActionGrant.ActionKey != actionKey || state.ActionGrant.ActionVersion != actionVersion)
                    return Reject(SidecarProtocolErrors.ExchangeIdentityMismatch, "The action grant does not match the exchange descriptor.");
                if (!IsCompiledActionGrant(state, state.ActionGrant))
                    return Reject(SidecarProtocolErrors.UnsupportedCapability, "The action grant was not issued by the compiled host authorization.");
                var actionStateAuthorizationFailure = ValidateActionAuthorization(state.ActionGrant, state.ActionDescriptor);
                if (actionStateAuthorizationFailure is not null)
                    return actionStateAuthorizationFailure;
                if (state.RequestedCommand is not null)
                    return Reject(SidecarProtocolErrors.ContinuationAlreadyUsed, "The action exchange already has a requested continuation command.");
                if (!AllowsActionCommand(state.ActionGrant.Capabilities, item.Command))
                    return Reject(SidecarProtocolErrors.UnsupportedCapability, "The action grant does not allow the requested continuation command.");
                break;
            case ContinuationAccepted item:
                if (state.RequestedCommand is null || state.RequestedCommand != item.Command)
                    return Reject(SidecarProtocolErrors.ContinuationCommandMismatch, "The accepted command does not match the requested command.");
                break;
            case SidecarResultReplacement:
                return ValidateCurrentActionAuthority(
                    state,
                    ActionInterceptionCapabilities.ReplaceResult,
                    "The action grant does not allow result replacement.");
            case HookOutcome when state.Phase == SidecarProtocolPhase.Invoking:
                return ValidateCurrentActionAuthority(
                    state,
                    ActionInterceptionCapabilities.Inspect,
                    "The action grant does not allow direct failure.");
            case EventInterceptOutcome item:
                if (state.EventGrant is null || state.EventDescriptor is null)
                    return Reject(SidecarProtocolErrors.UnsupportedCapability, "The event exchange has no host capability grant.");
                if (state.EventGrant.EventKey != state.EventDescriptor.Key ||
                    state.EventGrant.EventVersion != state.EventDescriptor.Version)
                    return Reject(SidecarProtocolErrors.ExchangeIdentityMismatch, "The event grant does not match the exchange descriptor.");
                if (!IsCompiledEventGrant(state, state.EventGrant))
                    return Reject(SidecarProtocolErrors.UnsupportedCapability, "The event grant was not issued by the compiled host authorization.");
                var eventStateAuthorizationFailure = ValidateEventAuthorization(state.EventGrant, state.EventDescriptor);
                if (eventStateAuthorizationFailure is not null)
                    return eventStateAuthorizationFailure;
                if (!AllowsEventOutcome(state.EventGrant.Capabilities, item.Kind))
                    return Reject(SidecarProtocolErrors.UnsupportedCapability, "The event grant does not allow the requested event outcome.");
                break;
        }

        return null;
    }

    private static SidecarProtocolTransitionResult? ValidateCurrentActionAuthority(
        SidecarProtocolState state,
        ActionInterceptionCapabilities requiredCapability,
        string capabilityMessage)
    {
        if (state.ActionGrant is not { } grant ||
            state.ActionKey is not { } actionKey ||
            state.ActionVersion is not { } actionVersion)
        {
            return Reject(SidecarProtocolErrors.UnsupportedCapability, "The action exchange has no host capability grant.");
        }

        if (grant.ActionKey != actionKey || grant.ActionVersion != actionVersion)
            return Reject(SidecarProtocolErrors.ExchangeIdentityMismatch, "The action grant does not match the exchange descriptor.");

        if (state.ActionDescriptor is { } descriptor)
        {
            if (descriptor.Key != actionKey || descriptor.Version != actionVersion)
                return Reject(SidecarProtocolErrors.ExchangeIdentityMismatch, "The action descriptor does not match the exchange identity.");
            if ((grant.Capabilities & ~descriptor.Capabilities) != 0)
                return Reject(SidecarProtocolErrors.UnsupportedCapability, "The action grant exceeds the descriptor capability set.");
            if (!descriptor.ProtocolVersionRange.Contains(state.NegotiatedProtocolVersion))
                return Reject(SidecarProtocolErrors.UnsupportedVersion, "The action descriptor does not support the negotiated protocol version.");
        }

        if (!IsCompiledActionGrant(state, grant))
            return Reject(SidecarProtocolErrors.UnsupportedCapability, "The action grant was not issued by the compiled host authorization.");

        var authorizationFailure = ValidateActionAuthorization(grant, state.ActionDescriptor);
        if (authorizationFailure is not null)
            return authorizationFailure;

        return grant.Capabilities.HasFlag(requiredCapability)
            ? null
            : Reject(SidecarProtocolErrors.UnsupportedCapability, capabilityMessage);
    }

    private static bool AllowsActionCommand(
        ActionInterceptionCapabilities capabilities,
        SidecarContinuationCommand command) =>
        command switch
        {
            SidecarContinuationCommand.ContinueOriginal =>
                capabilities.HasFlag(ActionInterceptionCapabilities.Inspect) &&
                capabilities.HasFlag(ActionInterceptionCapabilities.Wrap),
            SidecarContinuationCommand.ContinueReplacement =>
                capabilities.HasFlag(ActionInterceptionCapabilities.ReplaceInput) &&
                capabilities.HasFlag(ActionInterceptionCapabilities.Wrap),
            SidecarContinuationCommand.Cancel => capabilities.HasFlag(ActionInterceptionCapabilities.Cancel),
            SidecarContinuationCommand.Defer => capabilities.HasFlag(ActionInterceptionCapabilities.Defer),
            SidecarContinuationCommand.Repeat => capabilities.HasFlag(ActionInterceptionCapabilities.Repeat),
            _ => false,
        };

    private static SidecarProtocolTransitionResult? ValidateActionAuthorization(
        ActionCapabilityGrant grant,
        UntypedActionDescriptor? descriptor)
    {
        if (descriptor is null)
        {
            return grant.AcceptUnknownSchemas
                ? Reject(SidecarProtocolErrors.ForgedApproval, "Unknown schema approval requires an untyped descriptor.")
                : null;
        }

        if (grant.SensitiveApproved != descriptor.ContainsSensitiveData ||
            grant.AcceptUnknownSchemas != descriptor.AcceptsUnknownNonSensitiveSchemas ||
            descriptor.ContainsSensitiveData && grant.AcceptUnknownSchemas)
        {
            return Reject(SidecarProtocolErrors.ForgedApproval, "The action runtime grant is inconsistent with its descriptor sensitivity and schema authority.");
        }

        return null;
    }

    private static SidecarProtocolTransitionResult? ValidateEventAuthorization(
        EventCapabilityGrant grant,
        UntypedEventDescriptor descriptor)
    {
        if (grant.SensitiveApproved != descriptor.ContainsSensitiveData ||
            grant.AcceptUnknownSchemas != descriptor.AcceptsUnknownNonSensitiveSchemas ||
            descriptor.ContainsSensitiveData && grant.AcceptUnknownSchemas)
        {
            return Reject(SidecarProtocolErrors.ForgedApproval, "The event runtime grant is inconsistent with its descriptor sensitivity and schema authority.");
        }

        return null;
    }

    private static bool IsCompiledActionGrant(
        SidecarProtocolState state,
        ActionCapabilityGrant grant) =>
        state.HostAuthorization?.ActionGrants?.Any(item => Equals(item, grant)) == true;

    private static bool IsCompiledEventGrant(
        SidecarProtocolState state,
        EventCapabilityGrant grant) =>
        state.HostAuthorization?.EventGrants?.Any(item => Equals(item, grant)) == true;

    private static SidecarProtocolTransitionResult? ValidateMessageShape(
        SidecarProtocolState state,
        ISidecarProtocolMessage message) =>
        message switch
        {
            SidecarEffectRequest item => ValidateEffectShape(item),
            EventInterceptOutcome item => ValidateEventOutcomeShape(item),
            SidecarResultReplacement item => ValidateResultReplacementShape(item),
            HookOutcome item when state.Phase == SidecarProtocolPhase.Invoking =>
                ValidateDirectHookOutcomeShape(item),
            _ => null,
        };

    private static SidecarProtocolTransitionResult? ValidateResultReplacementShape(
        SidecarResultReplacement item) =>
        item.Result.ValueKind != JsonValueKind.Undefined &&
        !string.IsNullOrWhiteSpace(item.Reason)
            ? null
            : Reject(SidecarProtocolErrors.MalformedMessage, "The result replacement requires a result and a reason.");

    private static SidecarProtocolTransitionResult? ValidateDirectHookOutcomeShape(
        HookOutcome item) =>
        item.Kind == SidecarHookOutcomeKind.Failed &&
        item.Error is { } error &&
        !string.IsNullOrWhiteSpace(error.Code) &&
        !string.IsNullOrWhiteSpace(error.Message)
            ? null
            : Reject(SidecarProtocolErrors.MalformedMessage, "A direct hook failure requires a complete error.");

    private static SidecarProtocolTransitionResult? ValidateEffectShape(
        SidecarEffectRequest item)
    {
        var valid = item.Command switch
        {
            SidecarContinuationCommand.ContinueOriginal =>
                item.Value is null &&
                item.Reason is null &&
                item.Code is null &&
                item.Message is null &&
                item.Defer is null &&
                item.Backoff is null,
            SidecarContinuationCommand.ContinueReplacement =>
                item.Value is not null &&
                !string.IsNullOrWhiteSpace(item.Reason) &&
                item.Code is null &&
                item.Message is null &&
                item.Defer is null &&
                item.Backoff is null,
            SidecarContinuationCommand.Cancel =>
                item.Value is null &&
                item.Reason is null &&
                !string.IsNullOrWhiteSpace(item.Code) &&
                !string.IsNullOrWhiteSpace(item.Message) &&
                item.Defer is null &&
                item.Backoff is null,
            SidecarContinuationCommand.Defer =>
                item.Value is null &&
                item.Reason is null &&
                item.Code is null &&
                item.Message is null &&
                item.Defer is not null &&
                item.Backoff is null,
            SidecarContinuationCommand.Repeat =>
                item.Value is not null &&
                !string.IsNullOrWhiteSpace(item.Reason) &&
                item.Code is null &&
                item.Message is null &&
                item.Defer is null,
            _ => false,
        };

        return valid
            ? null
            : Reject(SidecarProtocolErrors.MalformedMessage, "The sidecar effect does not match the requested command shape.");
    }

    private static SidecarProtocolTransitionResult? ValidateEventOutcomeShape(
        EventInterceptOutcome item)
    {
        var valid = item.Kind switch
        {
            EventInterceptionKind.Continued or
            EventInterceptionKind.PropagationStopped => item.Payload is null && item.Error is null,
            EventInterceptionKind.Replaced =>
                item.Payload is not null &&
                item.Error is null &&
                !string.IsNullOrWhiteSpace(item.Reason),
            EventInterceptionKind.Cancelled or
            EventInterceptionKind.Failed => item.Payload is null && item.Error is not null,
            _ => false,
        };

        return valid
            ? null
            : Reject(SidecarProtocolErrors.MalformedMessage, "The event outcome does not match the selected outcome shape.");
    }

    private static bool AllowsEventOutcome(
        EventInterceptionCapabilities capabilities,
        EventInterceptionKind kind) =>
        kind switch
        {
            EventInterceptionKind.Continued or EventInterceptionKind.Failed =>
                capabilities.HasFlag(EventInterceptionCapabilities.Inspect),
            EventInterceptionKind.Replaced => capabilities.HasFlag(EventInterceptionCapabilities.Replace),
            EventInterceptionKind.Cancelled => capabilities.HasFlag(EventInterceptionCapabilities.Cancel),
            EventInterceptionKind.PropagationStopped => capabilities.HasFlag(EventInterceptionCapabilities.StopPropagation),
            _ => false,
        };

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
                    state.TraceId is not null && state.TraceId != item.TraceId ||
                    state.ActionKey is not null && state.ActionKey != item.ActionKey ||
                    state.ActionVersion is not null && state.ActionVersion != item.ActionVersion ||
                    state.ActionDescriptor is not null &&
                        (item.UntypedDescriptor is null || !SameActionDescriptor(state.ActionDescriptor, item.UntypedDescriptor)) ||
                    state.ActionGrant is not null && !Equals(state.ActionGrant, item.Grant) ||
                    state.HookId is not null && !string.Equals(state.HookId, item.HookId, StringComparison.Ordinal) ||
                    item.Continuation.InvocationId != item.InvocationId ||
                    !string.Equals(item.Continuation.HookId, item.HookId, StringComparison.Ordinal))
                    return Reject(SidecarProtocolErrors.ExchangeIdentityMismatch, "The action hook identity does not match the exchange.");
                break;
            case EventInterceptStart item when state.ExchangeKind != SidecarExchangeKind.EventIntercept:
                return Reject(SidecarProtocolErrors.ExchangeIdentityMismatch, "The message is not valid for this exchange kind.");
            case EventInterceptStart item:
                if (state.InvocationId != Guid.Empty && state.InvocationId != item.Continuation.InvocationId ||
                    state.ContinuationHandleId != Guid.Empty && state.ContinuationHandleId != item.Continuation.HandleId ||
                    state.EventKey is not null && state.EventKey != item.Envelope.Descriptor.Key ||
                    state.EventVersion is not null && state.EventVersion != item.Envelope.Descriptor.Version ||
                    state.EventDescriptor is not null && !SameEventDescriptor(state.EventDescriptor, item.Envelope.Descriptor) ||
                    state.EventGrant is not null && !Equals(state.EventGrant, item.Grant) ||
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
                     state.EventKey != item.EventKey ||
                     state.EventVersion != item.EventVersion ||
                     state.EventDescriptor is null ||
                     !SameSchema(state.EventDescriptor.PayloadSchema, item.EventSchema))
                    return Reject(SidecarProtocolErrors.ExchangeIdentityMismatch, "The event interception outcome identity does not match the exchange.");
                break;
            case SidecarEventListenerDelivery item:
                if (state.ExchangeKind != SidecarExchangeKind.EventListener ||
                    state.EventDescriptor is null ||
                    !SameEventDescriptor(state.EventDescriptor, item.Envelope.Descriptor) ||
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
                     state.Delivery != item.Delivery ||
                     state.EventDescriptor is null ||
                     !SameEventDescriptor(state.EventDescriptor, item.Descriptor))
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
            case HookOutcome or SidecarResultReplacement when state.Phase == SidecarProtocolPhase.Invoking:
                if (state.ExchangeKind != SidecarExchangeKind.ActionHook ||
                    state.InvocationId == Guid.Empty ||
                    state.ContinuationHandleId == Guid.Empty ||
                    string.IsNullOrWhiteSpace(state.HookId) ||
                    state.ActionKey is null ||
                    state.ActionVersion is null ||
                    state.TraceId is not { } traceId ||
                    traceId == Guid.Empty)
                {
                    return Reject(SidecarProtocolErrors.ExchangeIdentityMismatch, "The direct action outcome has no established action hook identity.");
                }
                break;
            case HookOutcome or SidecarResultReplacement or HookCompleted or SidecarHostTerminalCancellation:
            case SidecarEffectRequest or ContinuationAccepted or ContinuationOutcome:
                if (state.ExchangeKind != SidecarExchangeKind.ActionHook)
                    return Reject(SidecarProtocolErrors.ExchangeIdentityMismatch, "The continuation message is not valid for this exchange kind.");
                break;
        }

        return null;
    }

    private static SidecarProtocolTransitionResult? ValidateToolEntry(
        SidecarProtocolState state,
        SidecarToolHandlerInvokeStart message,
        DateTimeOffset now)
    {
        if (!message.IsWellFormed(now))
            return Reject(SidecarProtocolErrors.MalformedMessage, "The tool start does not carry a valid host entry context.");

        if (state.HostActionContext is { } expected && !SameHostActionContext(expected, message.HostActionContext))
            return Reject(SidecarProtocolErrors.ExchangeIdentityMismatch, "The tool start host entry context does not match the exchange.");

        return null;
    }

    private static bool SameHostActionContext(
        HostActionEntryRequestContext left,
        HostActionEntryRequestContext right) =>
        left.CapabilityId == right.CapabilityId &&
        string.Equals(left.CapabilityHandle, right.CapabilityHandle, StringComparison.Ordinal) &&
        left.Ingress == right.Ingress &&
        left.InvocationId == right.InvocationId &&
        left.RequestId == right.RequestId &&
        left.CancellationId == right.CancellationId &&
        SamePrincipal(left.Caller, right.Caller) &&
        SameFeatures(left.Features, right.Features) &&
        left.TraceId == right.TraceId &&
        left.IdempotencyKey == right.IdempotencyKey &&
        left.Deadline == right.Deadline &&
        left.ExpiresAt == right.ExpiresAt &&
        left.Contribution is not null &&
        right.Contribution is not null &&
        left.Contribution.IngressBinding == right.Contribution.IngressBinding &&
        SameLineage(left.Contribution.Lineage, right.Contribution.Lineage);

    private static bool SamePrincipal(RequestPrincipal left, RequestPrincipal right) =>
        string.Equals(left.SubjectId, right.SubjectId, StringComparison.Ordinal) &&
        string.Equals(left.DisplayName, right.DisplayName, StringComparison.Ordinal) &&
        left.IsAuthenticated == right.IsAuthenticated &&
        SameRoles(left.Roles, right.Roles);

    private static bool SameRoles(IReadOnlySet<string>? left, IReadOnlySet<string>? right)
    {
        if (left is null || right is null)
            return left is null && right is null;

        return left.Count == right.Count &&
            left.All(leftRole =>
                leftRole is not null &&
                right.Any(rightRole =>
                    rightRole is not null &&
                    string.Equals(leftRole, rightRole, StringComparison.Ordinal)));
    }

    private static bool SameFeatures(ExtensionFeatureSet left, ExtensionFeatureSet right) =>
        left.Items.Count == right.Items.Count &&
        left.Items.Zip(right.Items).All(pair =>
            string.Equals(pair.First.ContractName, pair.Second.ContractName, StringComparison.Ordinal) &&
            pair.First.SchemaVersion == pair.Second.SchemaVersion &&
            string.Equals(pair.First.OwnerModuleId, pair.Second.OwnerModuleId, StringComparison.Ordinal) &&
            pair.First.MaxBytes == pair.Second.MaxBytes &&
            string.Equals(pair.First.Value.GetRawText(), pair.Second.Value.GetRawText(), StringComparison.Ordinal));

    private static bool SameLineage(HostActionEntryLineage left, HostActionEntryLineage right) =>
        left.ActionKey == right.ActionKey &&
        left.ActionVersion == right.ActionVersion &&
        string.Equals(left.DescriptorHash, right.DescriptorHash, StringComparison.Ordinal) &&
        string.Equals(left.InputTypeIdentity, right.InputTypeIdentity, StringComparison.Ordinal) &&
        left.InputSchemaVersion == right.InputSchemaVersion &&
        string.Equals(left.InputSchemaHash, right.InputSchemaHash, StringComparison.Ordinal) &&
        string.Equals(left.PayloadContentHash, right.PayloadContentHash, StringComparison.Ordinal) &&
        left.PayloadByteLength == right.PayloadByteLength;

    private static bool SameActionDescriptor(
        UntypedActionDescriptor left,
        UntypedActionDescriptor right) =>
        left.Key == right.Key &&
        left.Version == right.Version &&
        string.Equals(left.Category, right.Category, StringComparison.Ordinal) &&
        left.Capabilities == right.Capabilities &&
        SameSchema(left.InputSchema, right.InputSchema) &&
        SameSchema(left.ResultSchema, right.ResultSchema) &&
        left.ContainsSensitiveData == right.ContainsSensitiveData &&
        Equals(left.ProtocolVersionRange, right.ProtocolVersionRange) &&
        left.AcceptsUnknownNonSensitiveSchemas == right.AcceptsUnknownNonSensitiveSchemas;

    private static bool SameEventDescriptor(
        UntypedEventDescriptor left,
        UntypedEventDescriptor right) =>
        left.Key == right.Key &&
        left.Version == right.Version &&
        string.Equals(left.Category, right.Category, StringComparison.Ordinal) &&
        left.Capabilities == right.Capabilities &&
        SameSchema(left.PayloadSchema, right.PayloadSchema) &&
        left.ContainsSensitiveData == right.ContainsSensitiveData &&
        Equals(left.ProtocolVersionRange, right.ProtocolVersionRange) &&
        left.AcceptsUnknownNonSensitiveSchemas == right.AcceptsUnknownNonSensitiveSchemas;

    private static bool SameSchema(JsonSchemaReference left, JsonSchemaReference right) =>
        string.Equals(left.ContractName, right.ContractName, StringComparison.Ordinal) &&
        left.Version == right.Version &&
        string.Equals(left.ContentHash, right.ContentHash, StringComparison.Ordinal);

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
    public const string ContinuationCommandMismatch = "continuation_command_mismatch";
    public const string MalformedMessage = "malformed_message";
    public const string Disconnected = "sidecar_disconnected";
}
