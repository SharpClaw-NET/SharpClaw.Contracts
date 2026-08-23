using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SharpClaw.Contracts.Modules;

public enum SidecarCapabilityKind
{
    Storage,
    Action,
}

public enum SidecarStorageOperationKind
{
    ListContracts,
    Invoke,
    CommitMutationAndOutbox,
    Claim,
    RenewClaim,
    RecoverClaim,
}

public enum SidecarActionInvocationKind
{
    Run,
    RunRequired,
    HostEntry,
    HostEntryCrossSidecar,
}

public sealed record SidecarAuthenticationProof(
    string Scheme,
    string KeyId,
    string Nonce,
    string Signature,
    string BindingHash,
    DateTimeOffset IssuedAt,
    DateTimeOffset ExpiresAt);

public sealed record SidecarConcurrencyLimits(
    int MaximumInFlightCalls,
    int MaximumCallsPerRequest)
{
    public bool IsValid => MaximumInFlightCalls > 0 && MaximumCallsPerRequest > 0;
}

public sealed record SidecarSafeFailureIdentity(
    Guid FailureId,
    string Code,
    string Message,
    bool Retryable = false)
{
    public bool IsValid =>
        FailureId != Guid.Empty &&
        !string.IsNullOrWhiteSpace(Code) &&
        !string.IsNullOrWhiteSpace(Message);
}

public sealed record SidecarCapabilityGrant(
    string GrantId,
    string ModuleId,
    string GraphId,
    IReadOnlyList<SidecarCapabilityKind> Capabilities,
    string AuthorizationHash,
    DateTimeOffset IssuedAt,
    DateTimeOffset ExpiresAt)
{
    public bool Allows(SidecarCapabilityKind capability) =>
        Capabilities.Contains(capability);
}

public sealed record SidecarCapabilitySessionBinding(
    string ModuleId,
    string GraphId,
    int ProtocolVersion,
    SidecarCapabilityGrant Grant,
    Guid SessionId,
    Guid RequestId,
    Guid CancellationId,
    DateTimeOffset ExpiresAt,
    SidecarPayloadLimits PayloadLimits,
    SidecarConcurrencyLimits ConcurrencyLimits,
    SidecarSafeFailureIdentity SafeFailure,
    string AuthenticationKeyId,
    SidecarAuthenticationProof Authentication);

public sealed record SidecarCapabilityAuthenticationAuthority(
    SidecarCapabilitySessionBinding Binding,
    string BindingHash);

public sealed record SidecarCapabilityCallIdentity(
    Guid SessionId,
    Guid RequestId,
    Guid CancellationId,
    Guid CallId,
    string ReplayNonce,
    string ModuleId,
    string GraphId,
    SidecarCapabilityKind Capability,
    long Sequence,
    DateTimeOffset Deadline)
{
    public bool IsValid =>
        SessionId != Guid.Empty &&
        RequestId != Guid.Empty &&
        CancellationId != Guid.Empty &&
        CallId != Guid.Empty &&
        !string.IsNullOrWhiteSpace(ReplayNonce) &&
        !string.IsNullOrWhiteSpace(ModuleId) &&
        !string.IsNullOrWhiteSpace(GraphId) &&
        Sequence > 0;
}

public sealed record SidecarPayloadTypeIdentity(
    string TypeIdentity,
    int SchemaVersion,
    string ContentHash)
{
    public bool IsValid =>
        !string.IsNullOrWhiteSpace(TypeIdentity) &&
        SchemaVersion >= 1 &&
        !string.IsNullOrWhiteSpace(ContentHash);
}

public sealed record SidecarSerializedPayload(
    string TypeIdentity,
    int SchemaVersion,
    string ContentHash,
    JsonElement Value,
    int ByteLength)
{
    public bool IsValid =>
        !string.IsNullOrWhiteSpace(TypeIdentity) &&
        SchemaVersion >= 1 &&
        !string.IsNullOrWhiteSpace(ContentHash) &&
        Value.ValueKind != JsonValueKind.Undefined &&
        ByteLength >= 0;
}

public sealed record SidecarTransportFrameIdentity(
    string ContentHash,
    int ByteLength)
{
    public bool IsValid => !string.IsNullOrWhiteSpace(ContentHash) && ByteLength >= 0;
}

public sealed record SidecarCapabilityValidationResult(
    bool Accepted,
    string Code,
    string Message)
{
    public static SidecarCapabilityValidationResult Accept() =>
        new(true, "accepted", "Accepted.");

    public static SidecarCapabilityValidationResult Reject(string code, string message) =>
        new(false, code, message);
}

public static class SidecarCapabilityErrors
{
    public const string Unauthenticated = "sidecar_unauthenticated";
    public const string InvalidBinding = "sidecar_invalid_binding";
    public const string Unauthorized = "sidecar_unauthorized";
    public const string Expired = "sidecar_expired";
    public const string SpoofedIdentity = "sidecar_spoofed_identity";
    public const string Replay = "sidecar_replay";
    public const string Duplicate = "sidecar_duplicate";
    public const string Disconnected = "sidecar_disconnected";
    public const string PayloadTooLarge = "sidecar_payload_too_large";
    public const string ConcurrencyLimit = "sidecar_concurrency_limit";
    public const string InvalidPayload = "sidecar_invalid_payload";
    public const string InvalidResponse = "sidecar_invalid_response";
    public const string TerminalAlreadyCalled = "sidecar_terminal_already_called";
}

public sealed class SidecarCapabilitySession : ISidecarExternalActionDispatchAuthorityVerifier
{
    private readonly object _sync = new();
    private readonly Func<SidecarCapabilityAuthenticationAuthority, bool> _authenticate;
    private readonly Func<SidecarHostTerminalAuthority, string, bool>? _authenticateHostTerminalAuthority;
    private readonly Func<string, bool> _registerAuthenticationNonce;
    private readonly Dictionary<Guid, SidecarCapabilityKind> _calls = [];
    private readonly Dictionary<Guid, SidecarCapabilityCallIdentity> _callIdentities = [];
    private readonly Dictionary<Guid, SidecarSerializedPayload?> _callPayloads = [];
    private readonly Dictionary<Guid, HostActionEntryRequestContext> _issuedEntryContexts = [];
    private readonly Dictionary<Guid, HostActionEntryCarrierAuthority> _activeEntryCarriers = [];
    private readonly Dictionary<Guid, Guid> _entryBudgetRoots = [];
    private readonly Dictionary<Guid, EntryBudgetReservation> _entryBudgetReservations = [];
    private readonly Dictionary<Guid, Guid> _peerParentBudgetRoots = [];
    private readonly Dictionary<Guid, Guid> _callBudgetRoots = [];
    private readonly Dictionary<Guid, Guid> _budgetExtensionClaims = [];
    private readonly Dictionary<Guid, NestedCarrierState> _nestedCarrierStates = [];
    private readonly Dictionary<Guid, CrossSidecarCarrierState> _crossSidecarStates = [];
    private readonly Dictionary<Guid, Guid> _crossSidecarParentChildren = [];
    private readonly List<(SidecarCapabilitySession Peer, Guid CarrierId)> _pendingCrossSidecarPeerCleanup = [];
    private readonly Dictionary<Guid, SidecarCapabilityCallIdentity> _reservedNestedCalls = [];
    private readonly HashSet<Guid> _nestedCarrierIds = [];
    private readonly Dictionary<Guid, Guid> _nestedCarrierParents = [];
    private readonly Dictionary<Guid, CarrierReplayTombstone> _completedEntryCarriers = [];
    private readonly HashSet<Guid> _consumedEntryCarriers = [];
    private readonly Dictionary<Guid, HostActionEntryRequestContext> _callEntryContexts = [];
    private readonly Dictionary<Guid, RootHostActionEntryState> _rootHostActionEntryStates = [];
    private readonly HashSet<Guid> _completedCalls = [];
    private readonly HashSet<string> _nonces = new(StringComparer.Ordinal);
    private readonly Dictionary<Guid, Guid> _terminalCalls = [];
    private readonly Dictionary<Guid, SidecarTerminalReceipt> _terminalReceipts = [];
    private readonly HashSet<Guid> _usedTerminalAuthorities = [];
    private readonly HashSet<Guid> _consumedExternalActionCalls = [];
    private long _lastSequence;
    private int _inFlight;
    private int _totalCalls;
    private long _bindingGeneration = 1;
    private bool _disconnected;

    private sealed record CarrierReplayTombstone(
        long BindingGeneration,
        DateTimeOffset RetainUntil);

    private sealed record EntryBudgetReservation(
        HostActionEntryRequestContext Context,
        long BindingGeneration,
        DateTimeOffset ExpiresAt,
        bool ExtensionAvailable);

    private sealed record RootHostActionEntryState(
        SidecarHostActionEntryRootRelay Relay,
        HostActionEntryRequestContext Context);

    private sealed record NestedCarrierState(
        SidecarNestedHostActionEntryCarrier Carrier,
        SidecarCapabilityCallIdentity ParentCall,
        SidecarCapabilityCallIdentity Call,
        SidecarActionDescriptorIdentity Descriptor,
        SidecarSerializedPayload Action,
        HostActionEntryRequestContext Context,
        HostActionEntryCarrierAuthority Authority);

    private sealed record CrossSidecarCarrierState(
        SidecarCrossSidecarActionEntryCarrier Carrier,
        SidecarCapabilityCallIdentity SourceParentCall,
        SidecarCapabilityCallIdentity TargetChildCall,
        SidecarModuleActionEntryDefinition TargetEntry,
        bool Active,
        SidecarActionTerminalRegistration? Terminal,
        SidecarCapabilitySession? PeerSession,
        bool IsSource);

    private static readonly TimeSpan CarrierReplayRetention = TimeSpan.FromMinutes(5);

    public SidecarCapabilitySession(
        SidecarCapabilitySessionBinding binding,
        Func<SidecarCapabilityAuthenticationAuthority, bool> authenticate,
        Func<string, bool> registerAuthenticationNonce,
        DateTimeOffset now,
        Func<SidecarHostTerminalAuthority, string, bool>? authenticateHostTerminalAuthority = null)
    {
        ArgumentNullException.ThrowIfNull(binding);
        ArgumentNullException.ThrowIfNull(authenticate);
        ArgumentNullException.ThrowIfNull(registerAuthenticationNonce);
        Binding = binding;
        _authenticate = authenticate;
        _registerAuthenticationNonce = registerAuthenticationNonce;
        _authenticateHostTerminalAuthority = authenticateHostTerminalAuthority;

        var result = SidecarCapabilitySessionValidator.Validate(
            binding,
            authenticate,
            registerAuthenticationNonce,
            now);
        if (!result.Accepted)
            throw new ArgumentException(result.Message, nameof(binding));
    }

    public SidecarCapabilitySessionBinding Binding { get; private set; }

    public long BindingGeneration
    {
        get
        {
            lock (_sync)
                return _bindingGeneration;
        }
    }

    public int ActiveHostActionEntryCarrierCount
    {
        get
        {
            lock (_sync)
                return _activeEntryCarriers.Count;
        }
    }

    public int IssuedHostActionEntryContextCount
    {
        get
        {
            lock (_sync)
                return _issuedEntryContexts.Count + _activeEntryCarriers.Count;
        }
    }

    public int CompletedHostActionEntryTombstoneCount
    {
        get
        {
            lock (_sync)
                return _completedEntryCarriers.Count;
        }
    }

    public SidecarCapabilityValidationResult ValidateAndConsume(
        SidecarExternalActionDispatchAuthority authority,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(authority);

        lock (_sync)
        {
            if (!authority.IsWellFormed)
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.InvalidBinding,
                    "The external action authority is incomplete.");

            if (_disconnected)
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.Disconnected,
                    "The sidecar capability session is disconnected.");

            if (_consumedExternalActionCalls.Contains(authority.Call.CallId))
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.Replay,
                    "The external action authority was already consumed.");

            var bindingResult = SidecarCapabilitySessionValidator.Validate(
                Binding,
                _authenticate,
                _registerAuthenticationNonce,
                now,
                RegisterAuthenticationNonce: false);
            if (!bindingResult.Accepted)
                return bindingResult;

            var hostAuthority = authority.EffectiveHostEntry?.Authority;
            var effectiveContext = authority.EffectiveHostEntry?.EffectiveContext;
            if (hostAuthority is null ||
                effectiveContext is null ||
                hostAuthority.AuthorityId == Guid.Empty ||
                string.IsNullOrWhiteSpace(hostAuthority.Proof) ||
                string.IsNullOrWhiteSpace(hostAuthority.CanonicalBindingHash) ||
                !string.Equals(
                    hostAuthority.CanonicalBindingHash,
                    SidecarCapabilityTransportValidation.ComputeTerminalAuthorityBindingHash(hostAuthority),
                    StringComparison.OrdinalIgnoreCase) ||
                hostAuthority.SessionId != authority.Call.SessionId ||
                hostAuthority.RequestId != authority.Call.RequestId ||
                hostAuthority.CancellationId != authority.Call.CancellationId ||
                hostAuthority.CallId != authority.Call.CallId ||
                !string.Equals(hostAuthority.ModuleId, authority.ModuleId, StringComparison.Ordinal) ||
                !string.Equals(hostAuthority.GraphId, authority.GraphId, StringComparison.Ordinal) ||
                hostAuthority.Invocation != effectiveContext.Invocation ||
                hostAuthority.ActionKey != authority.Descriptor.Key ||
                hostAuthority.ActionVersion != authority.Descriptor.Version ||
                !string.Equals(hostAuthority.DescriptorHash, authority.Descriptor.DescriptorHash, StringComparison.Ordinal) ||
                hostAuthority.TerminalId != authority.Terminal.TerminalId ||
                !string.Equals(hostAuthority.EffectiveActionTypeIdentity, authority.Action.TypeIdentity, StringComparison.Ordinal) ||
                hostAuthority.EffectiveActionSchemaVersion != authority.Action.SchemaVersion ||
                !string.Equals(hostAuthority.EffectiveActionContentHash, authority.Action.ContentHash, StringComparison.OrdinalIgnoreCase) ||
                hostAuthority.EffectiveActionByteLength != authority.Action.ByteLength ||
                !string.Equals(
                    hostAuthority.SnapshotContentHash,
                    SidecarCapabilityTransportValidation.ComputeSnapshotHash(effectiveContext.Snapshot),
                    StringComparison.OrdinalIgnoreCase) ||
                !string.Equals(
                    hostAuthority.HostContextBindingHash,
                    SidecarCapabilityTransportValidation.ComputeHostActionEntryContextBindingHash(
                        authority.InitiatingHostContext),
                    StringComparison.OrdinalIgnoreCase) ||
                _authenticateHostTerminalAuthority is null ||
                !_authenticateHostTerminalAuthority(
                    hostAuthority,
                    hostAuthority.CanonicalBindingHash))
            {
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.Unauthenticated,
                    "The host did not authenticate the external action authority.");
            }

            if (!string.Equals(authority.ModuleId, Binding.ModuleId, StringComparison.Ordinal) ||
                !string.Equals(authority.GraphId, Binding.GraphId, StringComparison.Ordinal) ||
                authority.Call.SessionId != Binding.SessionId ||
                authority.Call.RequestId != Binding.RequestId ||
                authority.Call.CancellationId != Binding.CancellationId ||
                !_calls.TryGetValue(authority.Call.CallId, out var capability) ||
                capability != SidecarCapabilityKind.Action ||
                !_callIdentities.TryGetValue(authority.Call.CallId, out var activeCall) ||
                activeCall != authority.Call ||
                !_callPayloads.TryGetValue(authority.Call.CallId, out var payload) ||
                payload is null ||
                !string.Equals(payload.ContentHash, authority.Action.ContentHash, StringComparison.OrdinalIgnoreCase) ||
                payload.ByteLength != authority.Action.ByteLength)
            {
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.SpoofedIdentity,
                    "The external action authority does not match the active session call.");
            }

            _consumedExternalActionCalls.Add(authority.Call.CallId);
            return SidecarCapabilityValidationResult.Accept();
        }
    }

    public SidecarCapabilityValidationResult ValidateHostActionEntry<TAction, TResult>(
        HostActionEntryTransportRequest<TAction, TResult> request,
        DateTimeOffset now,
        Func<HostActionEntryAuthority, bool> authenticateAuthority)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(authenticateAuthority);

        var requestResult = request.Validate(now, authenticateAuthority);
        if (!requestResult.Accepted)
        {
            return SidecarCapabilityValidationResult.Reject(
                requestResult.Code,
                requestResult.Message);
        }

        lock (_sync)
        {
            SweepCompletedEntryCarriers(now);
            if (_disconnected)
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.Disconnected,
                    "The sidecar capability session is disconnected.");

            var bindingResult = SidecarCapabilitySessionValidator.Validate(
                Binding,
                _authenticate,
                _registerAuthenticationNonce,
                now,
                RegisterAuthenticationNonce: false);
            if (!bindingResult.Accepted)
                return bindingResult;

            var authority = request.Authority;
            if (!_callEntryContexts.TryGetValue(authority.CallId, out var entryContext) ||
                !HostActionEntryAuthorityValidator.MatchesAuthorityContext(
                    authority,
                    entryContext) ||
                request.Request.Context is null ||
                !HostActionEntryAuthorityValidator.SameContextIgnoringPayload(
                    request.Request.Context,
                    entryContext) ||
                !_activeEntryCarriers.TryGetValue(
                    request.Request.Context.CapabilityId,
                    out var activeCarrier) ||
                !MatchesCarrierContext(request.Request.Context, activeCarrier))
            {
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.SpoofedIdentity,
                    "The host action entry authority does not match the host request context.");
            }

            if (!string.Equals(authority.ModuleId, Binding.ModuleId, StringComparison.Ordinal) ||
                !string.Equals(authority.GraphId, Binding.GraphId, StringComparison.Ordinal) ||
                authority.Deadline > Binding.ExpiresAt ||
                !_calls.TryGetValue(authority.CallId, out var capability) ||
                capability != SidecarCapabilityKind.Action ||
                !_callIdentities.TryGetValue(authority.CallId, out var activeCall) ||
                activeCall.SessionId != Binding.SessionId ||
                activeCall.RequestId != Binding.RequestId ||
                activeCall.CancellationId != Binding.CancellationId ||
                activeCall.CallId != authority.CallId ||
                !string.Equals(activeCall.ReplayNonce, authority.ReplayNonce, StringComparison.Ordinal) ||
                activeCall.Sequence != authority.Sequence ||
                activeCall.Deadline != authority.Deadline ||
                !_callPayloads.TryGetValue(authority.CallId, out var callPayload) ||
                callPayload is null ||
                !string.Equals(callPayload.TypeIdentity, authority.InputTypeIdentity, StringComparison.Ordinal) ||
                callPayload.SchemaVersion != authority.InputSchemaVersion ||
                !string.Equals(callPayload.ContentHash, authority.ActionContentHash, StringComparison.OrdinalIgnoreCase) ||
                callPayload.ByteLength != authority.ActionByteLength)
            {
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.SpoofedIdentity,
                    "The host action entry authority does not match the active sidecar call.");
            }

            return SidecarCapabilityValidationResult.Accept();
        }
    }

    public SidecarCapabilityValidationResult IssueHostActionEntryContext(
        HostActionEntryContextRequest request,
        DateTimeOffset now,
        out HostActionEntryRequestContext? context)
    {
        ArgumentNullException.ThrowIfNull(request);
        context = null;

        lock (_sync)
        {
            if (_disconnected)
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.Disconnected,
                    "The sidecar capability session is disconnected.");

            var bindingResult = SidecarCapabilitySessionValidator.Validate(
                Binding,
                _authenticate,
                _registerAuthenticationNonce,
                now,
                RegisterAuthenticationNonce: false);
            if (!bindingResult.Accepted)
                return bindingResult;

            if (!request.IsWellFormed(now) ||
                request.RequestId != Binding.RequestId ||
                request.CancellationId != Binding.CancellationId ||
                request.ExpiresAt > Binding.ExpiresAt)
            {
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.SpoofedIdentity,
                    "The host action entry context does not match the session authority.");
            }

            var capabilityId = Guid.NewGuid();
            var capabilityHandle = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
            context = new HostActionEntryRequestContext(
                capabilityId,
                capabilityHandle,
                request.Ingress,
                request.InvocationId,
                request.RequestId,
                request.CancellationId,
                request.Caller,
                request.Features,
                request.TraceId,
                request.IdempotencyKey,
                request.Deadline,
                request.ExpiresAt)
            {
                Contribution = request.Contribution,
                ParentInvocationId = request.ParentInvocationId,
                Depth = request.Depth,
                Attempt = request.Attempt,
            };
            _issuedEntryContexts.Add(capabilityId, context);
            _entryBudgetRoots.Add(capabilityId, capabilityId);
            _entryBudgetReservations.Add(
                capabilityId,
                new EntryBudgetReservation(
                    context,
                    _bindingGeneration,
                    context.ExpiresAt,
                    ExtensionAvailable: true));
            return SidecarCapabilityValidationResult.Accept();
        }
    }

    public SidecarCapabilityValidationResult BeginHostActionEntryCarrier(
        HostActionEntryRequestContext context,
        HostActionEntryCarrierIdentity carrier,
        DateTimeOffset now,
        out HostActionEntryCarrierAuthority? authority)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(carrier);
        authority = null;

        lock (_sync)
        {
            SweepExpiredEntryContexts(now);
            SweepCompletedEntryCarriers(now);
            if (_disconnected)
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.Disconnected,
                    "The sidecar capability session is disconnected.");

            var bindingResult = SidecarCapabilitySessionValidator.Validate(
                Binding,
                _authenticate,
                _registerAuthenticationNonce,
                now,
                RegisterAuthenticationNonce: false);
            if (!bindingResult.Accepted)
                return bindingResult;

            if (!context.IsWellFormed(now) ||
                !carrier.IsWellFormed ||
                context.RequestId != Binding.RequestId ||
                context.CancellationId != Binding.CancellationId ||
                !MatchesCarrier(context, carrier) ||
                !_issuedEntryContexts.TryGetValue(context.CapabilityId, out var issuedContext) ||
                !HostActionEntryAuthorityValidator.SameContext(context, issuedContext))
            {
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.SpoofedIdentity,
                    "The host action entry carrier does not match the issued context.");
            }

            authority = new HostActionEntryCarrierAuthority(
                Binding.ModuleId,
                Binding.GraphId,
                Binding.SessionId,
                Binding.RequestId,
                Binding.CancellationId,
                context.CapabilityId,
                carrier,
                _bindingGeneration,
                now,
                context.ExpiresAt,
                HostActionEntryAuthorityValidator.ComputeCapabilityHandleHash(context.CapabilityHandle));
            _issuedEntryContexts.Remove(context.CapabilityId);
            _activeEntryCarriers.Add(context.CapabilityId, authority);
            return SidecarCapabilityValidationResult.Accept();
        }
    }

    public SidecarCapabilityValidationResult IssueNestedHostActionEntryCarrier(
        SidecarCapabilityCallIdentity parentCall,
        SidecarCapabilityCallIdentity nestedCall,
        SidecarActionDescriptorIdentity descriptor,
        SidecarSerializedPayload action,
        HostActionEntryContribution contribution,
        DateTimeOffset now,
        out SidecarNestedHostActionEntryCarrier? carrier)
    {
        var result = IssueNestedHostActionEntryCarrierCore(
            parentCall,
            nestedCall,
            descriptor,
            action,
            contribution,
            now,
            0,
            out carrier);
        DrainCrossSidecarPeerCleanup(now);
        return result;
    }

    private SidecarCapabilityValidationResult IssueNestedHostActionEntryCarrierCore(
        SidecarCapabilityCallIdentity parentCall,
        SidecarCapabilityCallIdentity nestedCall,
        SidecarActionDescriptorIdentity descriptor,
        SidecarSerializedPayload action,
        HostActionEntryContribution contribution,
        DateTimeOffset now,
        long carrierBindingGeneration,
        out SidecarNestedHostActionEntryCarrier? carrier)
    {
        carrier = null;

        lock (_sync)
            {
                SweepExpiredEntryContexts(now);
                SweepCompletedEntryCarriers(now);
            if (_disconnected)
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.Disconnected,
                    "The sidecar capability session is disconnected.");

            var bindingResult = SidecarCapabilitySessionValidator.Validate(
                Binding,
                _authenticate,
                _registerAuthenticationNonce,
                now,
                RegisterAuthenticationNonce: false);
            if (!bindingResult.Accepted)
                return bindingResult;

            if (!_calls.TryGetValue(parentCall.CallId, out var parentCapability) ||
                parentCapability != SidecarCapabilityKind.Action ||
                !_callIdentities.TryGetValue(parentCall.CallId, out var activeParentCall) ||
                activeParentCall != parentCall ||
                !_callEntryContexts.TryGetValue(parentCall.CallId, out var parentContext) ||
                !_activeEntryCarriers.TryGetValue(parentContext.CapabilityId, out var parentCarrier) ||
                !MatchesCarrierContext(parentContext, parentCarrier))
            {
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.SpoofedIdentity,
                    "The nested host action parent call is not active and authenticated.");
            }

            var budgetRootId = ResolveEntryBudgetRoot(parentCall.CallId, parentContext.CapabilityId);
            var budgetExtensionAvailable =
                _totalCalls < Binding.ConcurrencyLimits.MaximumCallsPerRequest ||
                HasAvailableBudgetExtension(budgetRootId, now);

            if (!nestedCall.IsValid ||
                nestedCall.Capability != SidecarCapabilityKind.Action ||
                nestedCall.SessionId != Binding.SessionId ||
                nestedCall.RequestId != Binding.RequestId ||
                nestedCall.CancellationId != Binding.CancellationId ||
                !string.Equals(nestedCall.ModuleId, Binding.ModuleId, StringComparison.Ordinal) ||
                !string.Equals(nestedCall.GraphId, Binding.GraphId, StringComparison.Ordinal) ||
                nestedCall.Sequence != _lastSequence + 1 ||
                nestedCall.Deadline > parentCall.Deadline ||
                nestedCall.Deadline > parentContext.Deadline ||
                nestedCall.Deadline <= now ||
                !budgetExtensionAvailable ||
                _inFlight >= Binding.ConcurrencyLimits.MaximumInFlightCalls ||
                _nonces.Contains(nestedCall.ReplayNonce))
            {
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.SpoofedIdentity,
                    "The nested host action call is outside the parent authority.");
            }

            var payloadResult = SidecarCapabilityTransportValidation.ValidateSerializedPayload(
                action,
                required: true,
                Binding.PayloadLimits.ActionInputBytes);
            if (!payloadResult.Accepted)
                return payloadResult;

            if (descriptor is null ||
                descriptor.Key.Value is null ||
                string.IsNullOrWhiteSpace(descriptor.Key.Value) ||
                descriptor.Version < 1 ||
                string.IsNullOrWhiteSpace(descriptor.Category) ||
                string.IsNullOrWhiteSpace(descriptor.InputTypeIdentity) ||
                descriptor.InputSchemaVersion < 1 ||
                string.IsNullOrWhiteSpace(descriptor.InputSchemaHash) ||
                string.IsNullOrWhiteSpace(descriptor.ResultTypeIdentity) ||
                descriptor.ResultSchemaVersion < 1 ||
                string.IsNullOrWhiteSpace(descriptor.ResultSchemaHash) ||
                string.IsNullOrWhiteSpace(descriptor.DescriptorHash) ||
                !string.Equals(action.TypeIdentity, descriptor.InputTypeIdentity, StringComparison.Ordinal) ||
                action.SchemaVersion != descriptor.InputSchemaVersion ||
                !contribution.IsWellFormed ||
                !string.Equals(contribution.Lineage.ActionKey.Value, descriptor.Key.Value, StringComparison.Ordinal) ||
                contribution.Lineage.ActionVersion != descriptor.Version ||
                !string.Equals(contribution.Lineage.DescriptorHash, descriptor.DescriptorHash, StringComparison.Ordinal) ||
                !string.Equals(contribution.Lineage.InputTypeIdentity, descriptor.InputTypeIdentity, StringComparison.Ordinal) ||
                contribution.Lineage.InputSchemaVersion != descriptor.InputSchemaVersion ||
                !string.Equals(contribution.Lineage.InputSchemaHash, descriptor.InputSchemaHash, StringComparison.Ordinal))
            {
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.SpoofedIdentity,
                    "The nested host action descriptor is not authorized by its contribution.");
            }

            var expiresAt = new[]
            {
                nestedCall.Deadline,
                parentCall.Deadline,
                parentContext.ExpiresAt,
                Binding.ExpiresAt,
            }.Min();
            if (expiresAt <= now || parentContext.Depth == int.MaxValue)
            {
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.Expired,
                    "The nested host action carrier has no valid lifetime.");
            }

            var capabilityId = Guid.NewGuid();
            var handle = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
            var boundContribution = contribution with
            {
                Lineage = contribution.Lineage with
                {
                    PayloadContentHash = action.ContentHash,
                    PayloadByteLength = action.ByteLength,
                },
            };
            var childContext = new HostActionEntryRequestContext(
                capabilityId,
                handle,
                boundContribution.IngressBinding.Ingress,
                Guid.NewGuid(),
                Binding.RequestId,
                Binding.CancellationId,
                parentContext.Caller,
                parentContext.Features,
                parentContext.TraceId,
                parentContext.IdempotencyKey,
                expiresAt,
                expiresAt)
            {
                Contribution = boundContribution,
                ParentInvocationId = parentContext.InvocationId,
                Depth = parentContext.Depth + 1,
                Attempt = parentContext.Attempt,
            };
            var carrierIdentity = new HostActionEntryCarrierIdentity(
                childContext.Ingress,
                childContext.InvocationId,
                boundContribution.IngressBinding);
            var effectiveCarrierGeneration = carrierBindingGeneration > 0
                ? carrierBindingGeneration
                : _bindingGeneration;
            var carrierAuthority = new HostActionEntryCarrierAuthority(
                Binding.ModuleId,
                Binding.GraphId,
                Binding.SessionId,
                Binding.RequestId,
                Binding.CancellationId,
                capabilityId,
                carrierIdentity,
                effectiveCarrierGeneration,
                now,
                expiresAt,
                HostActionEntryAuthorityValidator.ComputeCapabilityHandleHash(handle));
            carrier = new SidecarNestedHostActionEntryCarrier(
                capabilityId,
                handle,
                parentCall.CallId,
                nestedCall.CallId,
                childContext.InvocationId,
                descriptor.Key,
                descriptor.Version,
                descriptor.DescriptorHash,
                action.ContentHash,
                action.ByteLength,
                descriptor,
                effectiveCarrierGeneration,
                expiresAt);
            var usesBudgetExtension =
                _totalCalls >= Binding.ConcurrencyLimits.MaximumCallsPerRequest;
            if (usesBudgetExtension)
            {
                ConsumeBudgetExtension(budgetRootId, capabilityId);
            }
            else
            {
                _totalCalls++;
            }
            _lastSequence = nestedCall.Sequence;
            _inFlight++;
            _nonces.Add(nestedCall.ReplayNonce);
            _reservedNestedCalls.Add(nestedCall.CallId, nestedCall);
            _entryBudgetRoots.Add(capabilityId, budgetRootId);
            _activeEntryCarriers.Add(capabilityId, carrierAuthority);
            _nestedCarrierStates.Add(
                capabilityId,
                new NestedCarrierState(
                    carrier,
                    parentCall,
                    nestedCall,
                    descriptor,
                    action,
                    childContext,
                    carrierAuthority));
            return SidecarCapabilityValidationResult.Accept();
        }
    }

    public SidecarCapabilityValidationResult IssueNestedHostActionEntryRelay(
        SidecarCapabilityCallIdentity parentCall,
        SidecarNestedHostActionEntryRequest request,
        SidecarActionDescriptorIdentity resolvedDescriptor,
        HostActionEntryContribution resolvedContribution,
        DateTimeOffset now,
        out SidecarNestedHostActionEntryRelay? relay)
        => IssueNestedHostActionEntryRelayCore(
            parentCall,
            request,
            resolvedDescriptor,
            resolvedContribution,
            peerBinding: null,
            peerBindingGeneration: 0,
            now,
            out relay);

    public SidecarCapabilityValidationResult IssueNestedHostActionEntryPeerRelay(
        SidecarCapabilityCallIdentity parentCall,
        SidecarNestedHostActionEntryRequest request,
        SidecarActionDescriptorIdentity resolvedDescriptor,
        HostActionEntryContribution resolvedContribution,
        SidecarCapabilitySession peerSession,
        DateTimeOffset now,
        out SidecarNestedHostActionEntryRelay? relay)
    {
        ArgumentNullException.ThrowIfNull(peerSession);

        return IssueNestedHostActionEntryRelayCore(
            parentCall,
            request,
            resolvedDescriptor,
            resolvedContribution,
            peerSession.Binding,
            peerSession.BindingGeneration,
            now,
            out relay);
    }

    private SidecarCapabilityValidationResult IssueNestedHostActionEntryRelayCore(
        SidecarCapabilityCallIdentity parentCall,
        SidecarNestedHostActionEntryRequest request,
        SidecarActionDescriptorIdentity resolvedDescriptor,
        HostActionEntryContribution resolvedContribution,
        SidecarCapabilitySessionBinding? peerBinding,
        long peerBindingGeneration,
        DateTimeOffset now,
        out SidecarNestedHostActionEntryRelay? relay)
    {
        relay = null;

        try
        {
        lock (_sync)
        {
            SweepExpiredEntryContexts(now);
            SweepCompletedEntryCarriers(now);
            if (_disconnected)
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.Disconnected,
                    "The sidecar capability session is disconnected.");

            if (!_terminalCalls.ContainsKey(parentCall.CallId))
            {
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.InvalidBinding,
                    "A nested host action relay requires an active parent terminal call.");
            }

            var resolution = SidecarCapabilityTransportValidation.ValidateResolvedNestedHostActionEntryRequest(
                request,
                resolvedDescriptor,
                resolvedContribution,
                Binding,
                now);
            if (!resolution.Accepted ||
                request.Deadline > parentCall.Deadline ||
                request.ExpiresAt > parentCall.Deadline)
            {
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.SpoofedIdentity,
                    "The nested host action relay request is outside the parent authority.");
            }

            var nestedCall = parentCall with
            {
                CallId = Guid.NewGuid(),
                ReplayNonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)),
                Sequence = _lastSequence + 1,
                Deadline = request.Deadline,
            };
            var result = IssueNestedHostActionEntryCarrierCore(
                parentCall,
                nestedCall,
                resolvedDescriptor,
                request.Action,
                resolvedContribution,
                now,
                peerBindingGeneration,
                out var carrier);
            if (!result.Accepted || carrier is null)
                return result;

            var peerCall = peerBinding is null
                ? null
                : nestedCall with
                {
                    SessionId = peerBinding.SessionId,
                    RequestId = peerBinding.RequestId,
                    CancellationId = peerBinding.CancellationId,
                    ModuleId = peerBinding.ModuleId,
                    GraphId = peerBinding.GraphId,
                };
            var boundContribution = BindNestedContribution(resolvedContribution, request.Action);
            relay = new SidecarNestedHostActionEntryRelay(nestedCall, carrier)
            {
                Contribution = boundContribution,
                RootBudgetId = ResolveEntryBudgetRoot(parentCall.CallId, parentCall.CallId),
                PeerCall = peerCall,
                PeerBindingGeneration = peerBindingGeneration,
            };
            if (relay.RootBudgetId == Guid.Empty)
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.InvalidBinding,
                    "The nested host action relay has no root budget authority.");
            return result;
        }
        }
        finally
        {
            DrainCrossSidecarPeerCleanup(now);
        }
    }

    public SidecarCapabilityValidationResult IssueHostActionEntryPeerRootRelay(
        SidecarCapabilityCallIdentity sourceCall,
        SidecarCapabilityCallIdentity peerCall,
        SidecarActionDescriptorIdentity descriptor,
        SidecarSerializedPayload action,
        SidecarActionTerminalRegistration terminal,
        ActionPipelineSnapshot snapshot,
        SidecarCapabilitySession peerSession,
        SidecarHostTerminalAuthority authority,
        DateTimeOffset now,
        out SidecarHostActionEntryRootRelay? relay)
    {
        ArgumentNullException.ThrowIfNull(sourceCall);
        ArgumentNullException.ThrowIfNull(peerCall);
        ArgumentNullException.ThrowIfNull(descriptor);
        ArgumentNullException.ThrowIfNull(action);
        ArgumentNullException.ThrowIfNull(terminal);
        ArgumentNullException.ThrowIfNull(snapshot);
        ArgumentNullException.ThrowIfNull(peerSession);
        ArgumentNullException.ThrowIfNull(authority);
        relay = null;

        if (peerSession == this)
            return SidecarCapabilityValidationResult.Reject(
                SidecarCapabilityErrors.InvalidBinding,
                "A root HostEntry relay requires a separate receiving session.");

        var peerBinding = peerSession.Binding;
        var peerGeneration = peerSession.BindingGeneration;
        lock (_sync)
        {
            SweepExpiredEntryContexts(now);
            SweepCompletedEntryCarriers(now);
            if (_disconnected)
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.Disconnected,
                    "The source capability session is disconnected.");

            if (_authenticateHostTerminalAuthority is null)
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.Unauthorized,
                    "The source capability session has no host proof verifier.");

            if (!peerCall.IsValid ||
                peerCall.Capability != SidecarCapabilityKind.Action ||
                peerCall.SessionId != peerBinding.SessionId ||
                peerCall.RequestId != peerBinding.RequestId ||
                peerCall.CancellationId != peerBinding.CancellationId ||
                !string.Equals(peerCall.ModuleId, peerBinding.ModuleId, StringComparison.Ordinal) ||
                !string.Equals(peerCall.GraphId, peerBinding.GraphId, StringComparison.Ordinal) ||
                peerCall.CallId != sourceCall.CallId ||
                peerCall.Deadline != sourceCall.Deadline ||
                peerGeneration <= 0)
            {
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.SpoofedIdentity,
                    "The receiving root call does not match the peer binding.");
            }

            if (!_calls.TryGetValue(sourceCall.CallId, out var capability) ||
                capability != SidecarCapabilityKind.Action ||
                !_callIdentities.TryGetValue(sourceCall.CallId, out var activeCall) ||
                activeCall != sourceCall ||
                !_callEntryContexts.TryGetValue(sourceCall.CallId, out var context) ||
                !_activeEntryCarriers.TryGetValue(context.CapabilityId, out var carrier) ||
                !MatchesCarrierContext(context, carrier) ||
                !_terminalCalls.TryGetValue(sourceCall.CallId, out var terminalAuthorityId) ||
                authority.TerminalId == Guid.Empty ||
                terminal.IsWellFormed is false ||
                authority.TerminalId != terminal.TerminalId ||
                terminalAuthorityId == Guid.Empty)
            {
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.InvalidBinding,
                    "The source root HostEntry call is not active and terminal-authorized.");
            }

            var payloadResult = SidecarCapabilityTransportValidation.ValidateSerializedPayload(
                action,
                required: true,
                Binding.PayloadLimits.ActionInputBytes);
            if (!payloadResult.Accepted ||
                !descriptor.IsWellFormed ||
                !string.Equals(action.TypeIdentity, descriptor.InputTypeIdentity, StringComparison.Ordinal) ||
                action.SchemaVersion != descriptor.InputSchemaVersion ||
                !MatchesDescriptorLineage(context.Contribution?.Lineage, descriptor, action) ||
                terminal.ActionTypeIdentity != descriptor.InputTypeIdentity ||
                terminal.ActionSchemaVersion != descriptor.InputSchemaVersion ||
                terminal.ResultTypeIdentity != descriptor.ResultTypeIdentity ||
                terminal.ResultSchemaVersion != descriptor.ResultSchemaVersion ||
                !string.Equals(terminal.DescriptorHash, descriptor.DescriptorHash, StringComparison.Ordinal) ||
                snapshot is null ||
                string.IsNullOrWhiteSpace(snapshot.ContractHash))
            {
                return payloadResult.Accepted
                    ? SidecarCapabilityValidationResult.Reject(
                        SidecarCapabilityErrors.SpoofedIdentity,
                        "The source root HostEntry authority does not match the descriptor or payload.")
                    : payloadResult;
            }

            var rootBudgetId = ResolveEntryBudgetRoot(sourceCall.CallId, context.CapabilityId);
            if (rootBudgetId == Guid.Empty ||
                authority.CallId != sourceCall.CallId ||
                authority.RootPeerCall != peerCall ||
                authority.SessionId != Binding.SessionId ||
                authority.RequestId != Binding.RequestId ||
                authority.CancellationId != Binding.CancellationId ||
                !string.Equals(authority.ModuleId, Binding.ModuleId, StringComparison.Ordinal) ||
                !string.Equals(authority.GraphId, Binding.GraphId, StringComparison.Ordinal) ||
                authority.Invocation != SidecarActionInvocationKind.HostEntry ||
                authority.ActionKey != descriptor.Key ||
                authority.ActionVersion != descriptor.Version ||
                !string.Equals(authority.DescriptorHash, descriptor.DescriptorHash, StringComparison.Ordinal) ||
                !string.Equals(authority.EffectiveActionTypeIdentity, action.TypeIdentity, StringComparison.Ordinal) ||
                authority.EffectiveActionSchemaVersion != action.SchemaVersion ||
                !string.Equals(authority.EffectiveActionContentHash, action.ContentHash, StringComparison.OrdinalIgnoreCase) ||
                authority.EffectiveActionByteLength != action.ByteLength ||
                !SidecarCapabilityTransportValidation.MatchesHostActionEntryContextBindingHash(
                    context,
                    authority.HostContextBindingHash) ||
                !string.Equals(authority.SnapshotContentHash, SidecarCapabilityTransportValidation.ComputeSnapshotHash(snapshot), StringComparison.OrdinalIgnoreCase) ||
                string.IsNullOrWhiteSpace(authority.Proof) ||
                !string.Equals(authority.CanonicalBindingHash, SidecarCapabilityTransportValidation.ComputeTerminalAuthorityBindingHash(authority), StringComparison.OrdinalIgnoreCase) ||
                !_authenticateHostTerminalAuthority(authority, authority.CanonicalBindingHash))
            {
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.SpoofedIdentity,
                    "The source root HostEntry proof does not bind the receiving session.");
            }

            var rootRelay = new SidecarHostActionEntryRootRelay(
                sourceCall,
                peerCall,
                context,
                descriptor,
                action,
                terminal,
                snapshot,
                authority,
                peerGeneration,
                rootBudgetId);
            if (!rootRelay.IsWellFormed ||
                _rootHostActionEntryStates.ContainsKey(context.CapabilityId) ||
                _completedEntryCarriers.ContainsKey(context.CapabilityId))
            {
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.Replay,
                    "The root HostEntry authority was already relayed.");
            }

            _rootHostActionEntryStates.Add(context.CapabilityId, new RootHostActionEntryState(rootRelay, context));
            relay = rootRelay;
            return SidecarCapabilityValidationResult.Accept();
        }
    }

    public SidecarCapabilityValidationResult ImportHostActionEntryPeerRootRelay(
        SidecarHostActionEntryRootRelay relay,
        DateTimeOffset now,
        out HostActionEntryRequestContext? hostContext)
    {
        ArgumentNullException.ThrowIfNull(relay);
        hostContext = null;

        lock (_sync)
        {
            SweepExpiredEntryContexts(now);
            SweepCompletedEntryCarriers(now);
            if (_disconnected)
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.Disconnected,
                    "The receiving capability session is disconnected.");

            if (_authenticateHostTerminalAuthority is null)
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.Unauthorized,
                    "The receiving capability session has no host proof verifier.");

            var validation = SidecarCapabilitySessionValidator.Validate(
                Binding,
                _authenticate,
                _registerAuthenticationNonce,
                now,
                RegisterAuthenticationNonce: false);
            if (!validation.Accepted)
                return validation;

            if (!relay.IsWellFormed ||
                relay.PeerBindingGeneration != _bindingGeneration ||
                relay.PeerCall.SessionId != Binding.SessionId ||
                relay.PeerCall.RequestId != Binding.RequestId ||
                relay.PeerCall.CancellationId != Binding.CancellationId ||
                !string.Equals(relay.PeerCall.ModuleId, Binding.ModuleId, StringComparison.Ordinal) ||
                !string.Equals(relay.PeerCall.GraphId, Binding.GraphId, StringComparison.Ordinal) ||
                relay.PeerCall.Sequence != _lastSequence + 1 ||
                relay.PeerCall.Deadline <= now ||
                relay.PeerCall.Deadline > Binding.ExpiresAt ||
                relay.PeerCall.Deadline > relay.Context.Deadline ||
                relay.RootBudgetId == Guid.Empty ||
                _calls.ContainsKey(relay.PeerCall.CallId) ||
                _reservedNestedCalls.ContainsKey(relay.PeerCall.CallId) ||
                _completedCalls.Contains(relay.PeerCall.CallId) ||
                _nonces.Contains(relay.PeerCall.ReplayNonce) ||
                _activeEntryCarriers.ContainsKey(relay.Context.CapabilityId) ||
                _issuedEntryContexts.ContainsKey(relay.Context.CapabilityId) ||
                _completedEntryCarriers.ContainsKey(relay.Context.CapabilityId) ||
                !string.Equals(relay.Authority.CanonicalBindingHash, SidecarCapabilityTransportValidation.ComputeTerminalAuthorityBindingHash(relay.Authority), StringComparison.OrdinalIgnoreCase) ||
                !_authenticateHostTerminalAuthority(relay.Authority, relay.Authority.CanonicalBindingHash))
            {
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.SpoofedIdentity,
                    "The receiving root HostEntry relay is not authorized for this session.");
            }

            var payloadResult = SidecarCapabilityTransportValidation.ValidateSerializedPayload(
                relay.Action,
                required: true,
                Binding.PayloadLimits.ActionInputBytes);
            if (!payloadResult.Accepted)
                return payloadResult;

            if (_inFlight >= Binding.ConcurrencyLimits.MaximumInFlightCalls ||
                _totalCalls >= Binding.ConcurrencyLimits.MaximumCallsPerRequest)
            {
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.ConcurrencyLimit,
                    "The receiving capability session cannot reserve the root HostEntry call.");
            }

            var peerContext = relay.Context with
            {
                RequestId = Binding.RequestId,
                CancellationId = Binding.CancellationId,
            };
            var carrierAuthority = new HostActionEntryCarrierAuthority(
                Binding.ModuleId,
                Binding.GraphId,
                Binding.SessionId,
                Binding.RequestId,
                Binding.CancellationId,
                peerContext.CapabilityId,
                new HostActionEntryCarrierIdentity(
                    peerContext.Ingress,
                    peerContext.InvocationId,
                    peerContext.Contribution!.IngressBinding),
                _bindingGeneration,
                now,
                peerContext.ExpiresAt,
                HostActionEntryAuthorityValidator.ComputeCapabilityHandleHash(peerContext.CapabilityHandle));

            _entryBudgetRoots[peerContext.CapabilityId] = relay.RootBudgetId;
            _peerParentBudgetRoots[relay.PeerCall.CallId] = relay.RootBudgetId;
            _entryBudgetReservations[relay.RootBudgetId] = new EntryBudgetReservation(
                peerContext,
                _bindingGeneration,
                new[] { peerContext.ExpiresAt, relay.PeerCall.Deadline, Binding.ExpiresAt }.Min(),
                ExtensionAvailable: true);
            _activeEntryCarriers.Add(peerContext.CapabilityId, carrierAuthority);
            _rootHostActionEntryStates.Add(
                peerContext.CapabilityId,
                new RootHostActionEntryState(relay, peerContext));
            _callEntryContexts[relay.PeerCall.CallId] = peerContext;
            _reservedNestedCalls.Add(relay.PeerCall.CallId, relay.PeerCall);
            _lastSequence = relay.PeerCall.Sequence;
            _totalCalls++;
            _inFlight++;
            _nonces.Add(relay.PeerCall.ReplayNonce);
            hostContext = peerContext;
            return SidecarCapabilityValidationResult.Accept();
        }
    }

    public SidecarCapabilityValidationResult RevokeNestedHostActionEntryRelay(
        Guid parentCallId,
        DateTimeOffset now)
    {
        try
        {
            lock (_sync)
            {
                SweepExpiredEntryContexts(now);
                SweepCompletedEntryCarriers(now);
                if (_disconnected)
                    return SidecarCapabilityValidationResult.Reject(
                        SidecarCapabilityErrors.Disconnected,
                        "The sidecar capability session is disconnected.");

            var found = false;
            foreach (var state in _nestedCarrierStates.Values
                .Where(state => state.ParentCall.CallId == parentCallId)
                .ToArray())
            {
                _nestedCarrierStates.Remove(state.Carrier.CarrierId);
                ReleaseNestedReservation(state.Carrier.CarrierId, state.Call.CallId);
                RemoveEntryCarrier(state.Carrier.CarrierId, now);
                found = true;
            }

            foreach (var pair in _nestedCarrierParents
                .Where(pair => pair.Value == parentCallId)
                .ToArray())
            {
                RemoveEntryCarrier(pair.Key, now);
                found = true;
            }

            return found
                ? SidecarCapabilityValidationResult.Accept()
                : SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.Duplicate,
                    "The nested host action relay was not pending.");
            }
        }
        finally
        {
            DrainCrossSidecarPeerCleanup(now);
        }
    }

    public SidecarCapabilityValidationResult BeginNestedHostActionEntryCall(
        SidecarNestedHostActionEntryCarrier carrier,
        SidecarCapabilityCallIdentity call,
        SidecarSerializedPayload action,
        int frameByteLength,
        DateTimeOffset now,
        out HostActionEntryRequestContext? hostContext)
    {
        hostContext = null;

        lock (_sync)
        {
            SweepExpiredEntryContexts(now);
            SweepCompletedEntryCarriers(now);
            if (_disconnected)
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.Disconnected,
                    "The sidecar capability session is disconnected.");

            if (carrier is null ||
                !carrier.IsWellFormed ||
                !_nestedCarrierStates.TryGetValue(carrier.CarrierId, out var state))
            {
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.Replay,
                    "The nested host action carrier is unknown or already consumed.");
            }

            if (state.Carrier != carrier ||
                state.Call != call ||
                action is null ||
                state.Descriptor.Key != carrier.ActionKey ||
                state.Descriptor.Version != carrier.ActionVersion ||
                !string.Equals(state.Descriptor.DescriptorHash, carrier.DescriptorHash, StringComparison.Ordinal) ||
                !string.Equals(state.Action.ContentHash, carrier.ActionContentHash, StringComparison.OrdinalIgnoreCase) ||
                state.Action.ByteLength != carrier.ActionByteLength ||
                !string.Equals(action.ContentHash, state.Action.ContentHash, StringComparison.OrdinalIgnoreCase) ||
                action.ByteLength != state.Action.ByteLength ||
                carrier.ExpiresAt <= now)
            {
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.SpoofedIdentity,
                    "The nested host action carrier does not match its issued authority.");
            }

            var result = BeginCall(
                call,
                SidecarCapabilityKind.Action,
                action,
                frameByteLength,
                now,
                state.Context);
            if (!result.Accepted)
                return result;

            _nestedCarrierStates.Remove(carrier.CarrierId);
            _nestedCarrierIds.Add(carrier.CarrierId);
            _nestedCarrierParents.Add(carrier.CarrierId, state.ParentCall.CallId);
            _budgetExtensionClaims.Remove(carrier.CarrierId);
            hostContext = _callEntryContexts[call.CallId];
            return result;
        }
    }

    public SidecarCapabilityValidationResult BeginActionCall(
        SidecarActionCapabilityRequest request,
        int frameByteLength,
        DateTimeOffset now,
        out HostActionEntryRequestContext? hostContext)
        => BeginActionCall(
            request,
            frameByteLength,
            now,
            out hostContext,
            static (_, _) => false,
            static (_, _) => false);

    public SidecarCapabilityValidationResult BeginActionCall(
        SidecarActionCapabilityRequest request,
        int frameByteLength,
        DateTimeOffset now,
        out HostActionEntryRequestContext? hostContext,
        Func<SidecarCrossSidecarActionEntryAuthority, string, bool> authenticateCrossSidecarAuthority)
        => BeginActionCall(
            request,
            frameByteLength,
            now,
            out hostContext,
            authenticateCrossSidecarAuthority,
            static (_, _) => false);

    public SidecarCapabilityValidationResult BeginActionCall(
        SidecarActionCapabilityRequest request,
        int frameByteLength,
        DateTimeOffset now,
        out HostActionEntryRequestContext? hostContext,
        Func<SidecarCrossSidecarActionEntryAuthority, string, bool> authenticateCrossSidecarAuthority,
        Func<SidecarHostTerminalAuthority, string, bool> authenticateEffectiveHostEntryContext)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(authenticateCrossSidecarAuthority);
        ArgumentNullException.ThrowIfNull(authenticateEffectiveHostEntryContext);
        hostContext = null;

        var requestResult = SidecarCapabilityTransportValidation.ValidateActionRequest(
            request,
            Binding,
            now,
            authenticateEffectiveHostEntryContext);
        if (!requestResult.Accepted)
            return requestResult;

        if (request.Invocation == SidecarActionInvocationKind.HostEntry &&
            request.NestedCarrier is not null)
        {
            return BeginNestedHostActionEntryCall(
                request.NestedCarrier,
                request.Call,
                request.Action,
                frameByteLength,
                now,
                out hostContext);
        }

        if (request.Invocation == SidecarActionInvocationKind.HostEntryCrossSidecar &&
            request.CrossSidecarCarrier is not null)
        {
            return BeginCrossSidecarActionEntryCall(
                request.CrossSidecarCarrier,
                request.Terminal!,
                frameByteLength,
                now,
                out hostContext,
                authenticateCrossSidecarAuthority);
        }

        var result = BeginCallCore(
            request.Call,
            SidecarCapabilityKind.Action,
            request.Action,
            frameByteLength,
            now,
            request.HostContext,
            allowImportedRoot: true);
        if (result.Accepted)
        {
            if (request.HostContext is not null)
                hostContext = request.HostContext;

        }

        return result;
    }

    public SidecarCapabilityValidationResult IssueCrossSidecarActionEntryRelay(
        SidecarCapabilityCallIdentity parentCall,
        SidecarCrossSidecarActionEntryRequest request,
        SidecarCapabilitySession targetSession,
        SidecarModuleActionEntryDefinition targetEntry,
        ActionPipelineSnapshot targetSnapshot,
        DateTimeOffset now,
        Func<SidecarCrossSidecarActionEntryAuthority, string, string> issueProof,
        out SidecarCrossSidecarActionEntryRelay? relay)
    {
        ArgumentNullException.ThrowIfNull(parentCall);
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(targetSession);
        ArgumentNullException.ThrowIfNull(targetEntry);
        ArgumentNullException.ThrowIfNull(targetSnapshot);
        ArgumentNullException.ThrowIfNull(issueProof);
        relay = null;

        HostActionEntryRequestContext? sourceContext = null;
        SidecarCapabilitySessionBinding sourceBinding;
        long sourceGeneration;
        lock (_sync)
        {
            SweepExpiredEntryContexts(now);
            SweepCompletedEntryCarriers(now);
            if (_disconnected)
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.Disconnected,
                    "The source capability session is disconnected.");

            if (!_calls.TryGetValue(parentCall.CallId, out var capability) ||
                capability != SidecarCapabilityKind.Action ||
                !_callIdentities.TryGetValue(parentCall.CallId, out var activeParent) ||
                activeParent != parentCall ||
                !_callEntryContexts.TryGetValue(parentCall.CallId, out sourceContext) ||
                !_terminalCalls.ContainsKey(parentCall.CallId))
            {
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.InvalidBinding,
                    "Cross-sidecar entry requires an active parent terminal call.");
            }

            var requestResult = SidecarCrossSidecarActionEntryValidation.ValidateRequest(
                request,
                parentCall,
                Binding,
                now);
            if (!requestResult.Accepted)
                return requestResult;

            if (targetSession == this ||
                !targetEntry.IsWellFormed ||
                !string.Equals(targetEntry.ModuleId, targetSession.Binding.ModuleId, StringComparison.Ordinal) ||
                !string.Equals(targetEntry.GraphId, targetSession.Binding.GraphId, StringComparison.Ordinal) ||
                targetSnapshot is null ||
                string.IsNullOrWhiteSpace(targetSnapshot.ContractHash))
            {
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.SpoofedIdentity,
                    "The target module action entry is not owned by the target session.");
            }

            sourceBinding = Binding;
            sourceGeneration = _bindingGeneration;
        }

        DrainCrossSidecarPeerCleanup(now);

        var reservation = targetSession.ReserveCrossSidecarActionEntry(
            this,
            parentCall,
            sourceContext!,
            sourceBinding,
            sourceGeneration,
            request,
            targetEntry,
            targetSnapshot,
            now,
            issueProof,
            out var reservedCarrier);
        if (!reservation.Accepted || reservedCarrier is null)
            return reservation;

        var commitReservation = false;
        lock (_sync)
        {
            commitReservation =
                !_disconnected &&
                _bindingGeneration == sourceGeneration &&
                _calls.TryGetValue(parentCall.CallId, out var currentCapability) &&
                currentCapability == SidecarCapabilityKind.Action &&
                _callIdentities.TryGetValue(parentCall.CallId, out var currentParent) &&
                currentParent == parentCall &&
                _callEntryContexts.ContainsKey(parentCall.CallId) &&
                _terminalCalls.ContainsKey(parentCall.CallId);

            if (commitReservation)
            {
                _crossSidecarStates.Add(
                    reservedCarrier.CarrierId,
                    new CrossSidecarCarrierState(
                        reservedCarrier,
                        parentCall,
                        reservedCarrier.Authority.TargetChildCall,
                        targetEntry,
                        Active: false,
                        Terminal: null,
                        PeerSession: targetSession,
                        IsSource: true));
                _crossSidecarParentChildren.Add(reservedCarrier.CarrierId, parentCall.CallId);
            }
        }

        if (!commitReservation)
        {
            targetSession.RevokeCrossSidecarActionEntry(reservedCarrier.CarrierId, now);
            return SidecarCapabilityValidationResult.Reject(
                SidecarCapabilityErrors.InvalidBinding,
                "The source parent changed while the child authority was issued.");
        }

        if (!targetSession.ConfirmCrossSidecarActionEntryReservation(
                reservedCarrier.CarrierId,
                parentCall,
                reservedCarrier.Authority.TargetChildCall,
                reservedCarrier.Authority.TargetBindingGeneration,
                now))
        {
            RemoveCrossSidecarPeerState(reservedCarrier.CarrierId, now);
            targetSession.RevokeCrossSidecarActionEntry(reservedCarrier.CarrierId, now);
            return SidecarCapabilityValidationResult.Reject(
                SidecarCapabilityErrors.InvalidBinding,
                "The target session did not confirm the child authority after source commit.");
        }

        relay = new SidecarCrossSidecarActionEntryRelay(reservedCarrier, targetEntry);
        return SidecarCapabilityValidationResult.Accept();
    }

    private SidecarCapabilityValidationResult ReserveCrossSidecarActionEntry(
        SidecarCapabilitySession sourceSession,
        SidecarCapabilityCallIdentity sourceParentCall,
        HostActionEntryRequestContext sourceContext,
        SidecarCapabilitySessionBinding sourceBinding,
        long sourceBindingGeneration,
        SidecarCrossSidecarActionEntryRequest request,
        SidecarModuleActionEntryDefinition targetEntry,
        ActionPipelineSnapshot targetSnapshot,
        DateTimeOffset now,
        Func<SidecarCrossSidecarActionEntryAuthority, string, string> issueProof,
        out SidecarCrossSidecarActionEntryCarrier? carrier)
    {
        carrier = null;

        try
        {
            lock (_sync)
            {
                SweepExpiredEntryContexts(now);
                SweepCompletedEntryCarriers(now);
            if (_disconnected)
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.Disconnected,
                    "The target capability session is disconnected.");

            var bindingResult = SidecarCapabilitySessionValidator.Validate(
                Binding,
                _authenticate,
                _registerAuthenticationNonce,
                now,
                RegisterAuthenticationNonce: false);
            if (!bindingResult.Accepted)
                return bindingResult;

            if (!sourceParentCall.IsValid ||
                sourceParentCall.Capability != SidecarCapabilityKind.Action ||
                sourceParentCall.SessionId != sourceBinding.SessionId ||
                sourceParentCall.RequestId != sourceBinding.RequestId ||
                sourceParentCall.CancellationId != sourceBinding.CancellationId ||
                !string.Equals(sourceParentCall.ModuleId, sourceBinding.ModuleId, StringComparison.Ordinal) ||
                !string.Equals(sourceParentCall.GraphId, sourceBinding.GraphId, StringComparison.Ordinal) ||
                sourceContext is null ||
                !sourceContext.IsWellFormed(now) ||
                !targetEntry.IsWellFormed ||
                !string.Equals(targetEntry.ModuleId, Binding.ModuleId, StringComparison.Ordinal) ||
                !string.Equals(targetEntry.GraphId, Binding.GraphId, StringComparison.Ordinal) ||
                !Binding.Grant.Allows(SidecarCapabilityKind.Action) ||
                targetSnapshot is null ||
                string.IsNullOrWhiteSpace(targetSnapshot.ContractHash))
            {
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.SpoofedIdentity,
                    "The cross-sidecar target authority is not valid.");
            }

            var expiresAt = new[]
            {
                request.Deadline,
                request.ExpiresAt,
                sourceParentCall.Deadline,
                sourceContext.ExpiresAt,
                sourceBinding.ExpiresAt,
                Binding.ExpiresAt,
            }.Min();
            if (expiresAt <= now)
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.Expired,
                    "The cross-sidecar child authority has no valid lifetime.");

            if (_totalCalls >= Binding.ConcurrencyLimits.MaximumCallsPerRequest ||
                _inFlight >= Binding.ConcurrencyLimits.MaximumInFlightCalls)
            {
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.ConcurrencyLimit,
                    "The target capability session cannot reserve another action.");
            }

            var childCall = new SidecarCapabilityCallIdentity(
                Binding.SessionId,
                Binding.RequestId,
                Binding.CancellationId,
                Guid.NewGuid(),
                Convert.ToHexString(RandomNumberGenerator.GetBytes(16)),
                Binding.ModuleId,
                Binding.GraphId,
                SidecarCapabilityKind.Action,
                _lastSequence + 1,
                request.Deadline);
            var childInvocationId = Guid.NewGuid();
            var capabilityId = Guid.NewGuid();
            var capabilityHandle = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
            var cancellation = new SidecarCancellationIdentity(
                Binding.CancellationId,
                SidecarCapabilitySessionValidator.ComputeBindingHash(Binding),
                expiresAt);
            var unsigned = new SidecarCrossSidecarActionEntryAuthority(
                sourceParentCall,
                childCall,
                sourceContext.InvocationId,
                childInvocationId,
                capabilityId,
                capabilityHandle,
                sourceBindingGeneration,
                _bindingGeneration,
                targetEntry,
                SidecarActionPayloadLineage.From(request.Action),
                sourceContext.Caller,
                sourceContext.Features,
                sourceContext.TraceId,
                sourceContext.IdempotencyKey,
                cancellation,
                request.Deadline,
                now,
                expiresAt,
                sourceContext.Depth + 1,
                sourceContext.Attempt,
                SidecarCapabilityTransportValidation.ComputeSnapshotHash(targetSnapshot),
                targetEntry.TerminalOwnerModuleId,
                targetEntry.TerminalOwnerGraphId,
                null,
                string.Empty)
            {
                CanonicalBindingHash = string.Empty,
            };
            var canonicalHash = SidecarCrossSidecarActionEntryValidation.ComputeAuthorityHash(unsigned);
            var signed = unsigned with
            {
                CanonicalBindingHash = canonicalHash,
                Proof = issueProof(unsigned, canonicalHash),
            };
            if (!signed.IsValid)
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.Unauthenticated,
                    "The host did not issue a valid cross-sidecar authority.");

            carrier = new SidecarCrossSidecarActionEntryCarrier(
                capabilityId,
                capabilityHandle,
                signed,
                request.Action,
                _bindingGeneration,
                expiresAt);
            _lastSequence = childCall.Sequence;
            _totalCalls++;
            _inFlight++;
            _nonces.Add(childCall.ReplayNonce);
            _reservedNestedCalls.Add(childCall.CallId, childCall);
            _crossSidecarStates.Add(
                carrier.CarrierId,
                    new CrossSidecarCarrierState(
                        carrier,
                        sourceParentCall,
                        childCall,
                        targetEntry,
                        Active: false,
                        Terminal: null,
                        PeerSession: sourceSession,
                        IsSource: false));
                return SidecarCapabilityValidationResult.Accept();
            }
        }
        finally
        {
            DrainCrossSidecarPeerCleanup(now);
        }
    }

    private bool ConfirmCrossSidecarActionEntryReservation(
        Guid carrierId,
        SidecarCapabilityCallIdentity sourceParentCall,
        SidecarCapabilityCallIdentity targetChildCall,
        long targetBindingGeneration,
        DateTimeOffset now)
    {
        bool confirmed;
        lock (_sync)
        {
            SweepExpiredEntryContexts(now);
            SweepCompletedEntryCarriers(now);
            confirmed =
                !_disconnected &&
                _crossSidecarStates.TryGetValue(carrierId, out var state) &&
                !state.Active &&
                state.IsSource == false &&
                state.SourceParentCall == sourceParentCall &&
                state.TargetChildCall == targetChildCall &&
                state.Carrier.Authority.TargetBindingGeneration == targetBindingGeneration &&
                state.Carrier.ExpiresAt > now;
        }

        DrainCrossSidecarPeerCleanup(now);
        return confirmed;
    }

    public SidecarCapabilityValidationResult BeginCrossSidecarActionEntryCall(
        SidecarCrossSidecarActionEntryCarrier carrier,
        SidecarActionTerminalRegistration terminal,
        int frameByteLength,
        DateTimeOffset now,
        out HostActionEntryRequestContext? hostContext)
        => BeginCrossSidecarActionEntryCall(
            carrier,
            terminal,
            frameByteLength,
            now,
            out hostContext,
            static (_, _) => false);

    public SidecarCapabilityValidationResult BeginCrossSidecarActionEntryCall(
        SidecarCrossSidecarActionEntryCarrier carrier,
        SidecarActionTerminalRegistration terminal,
        int frameByteLength,
        DateTimeOffset now,
        out HostActionEntryRequestContext? hostContext,
        Func<SidecarCrossSidecarActionEntryAuthority, string, bool> authenticate)
    {
        hostContext = null;
        ArgumentNullException.ThrowIfNull(carrier);
        ArgumentNullException.ThrowIfNull(terminal);
        ArgumentNullException.ThrowIfNull(authenticate);

        try
        {
        lock (_sync)
        {
            SweepExpiredEntryContexts(now);
            SweepCompletedEntryCarriers(now);
            if (_disconnected)
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.Disconnected,
                    "The target capability session is disconnected.");

            if (!_crossSidecarStates.TryGetValue(carrier.CarrierId, out var state) ||
                state.Active ||
                state.Carrier != carrier ||
                carrier.BindingGeneration != _bindingGeneration)
            {
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.Replay,
                    "The cross-sidecar carrier is unknown or already consumed.");
            }

            var carrierResult = SidecarCrossSidecarActionEntryValidation.ValidateCarrier(
                carrier,
                Binding,
                now,
                authenticate);
            if (!carrierResult.Accepted ||
                !terminal.IsWellFormed ||
                terminal.ActionTypeIdentity != state.TargetEntry.Descriptor.InputTypeIdentity ||
                terminal.ActionSchemaVersion != state.TargetEntry.Descriptor.InputSchemaVersion ||
                terminal.ResultTypeIdentity != state.TargetEntry.Descriptor.ResultTypeIdentity ||
                terminal.ResultSchemaVersion != state.TargetEntry.Descriptor.ResultSchemaVersion ||
                !string.Equals(terminal.DescriptorHash, state.TargetEntry.Descriptor.DescriptorHash, StringComparison.Ordinal))
            {
                return carrierResult.Accepted
                    ? SidecarCapabilityValidationResult.Reject(
                        SidecarCapabilityErrors.SpoofedIdentity,
                        "The target terminal does not match the resolved module action.")
                    : carrierResult;
            }

            var request = SidecarActionCapabilityRequest.HostEntryCrossSidecar(
                state.TargetChildCall,
                state.TargetEntry.Descriptor,
                carrier.Action,
                new SidecarCancellationIdentity(
                    Binding.CancellationId,
                    carrier.Authority.CanonicalBindingHash,
                    carrier.ExpiresAt),
                carrier.Authority.Deadline,
                carrier,
                terminal);
            var requestResult = SidecarCapabilityTransportValidation.ValidateActionRequest(
                request,
                Binding,
                now);
            if (!requestResult.Accepted)
                return requestResult;

            var beginResult = BeginCallCore(
                state.TargetChildCall,
                SidecarCapabilityKind.Action,
                carrier.Action,
                frameByteLength,
                now);
            if (!beginResult.Accepted)
                return beginResult;

            _crossSidecarStates[carrier.CarrierId] = state with { Active = true, Terminal = terminal };
            hostContext = new HostActionEntryRequestContext(
                carrier.Authority.CapabilityId,
                carrier.Authority.CapabilityHandle,
                HostActionEntryIngress.CrossModule,
                carrier.Authority.TargetChildInvocationId,
                Binding.RequestId,
                Binding.CancellationId,
                carrier.Authority.Caller,
                carrier.Authority.Features,
                carrier.Authority.TraceId,
                carrier.Authority.IdempotencyKey,
                carrier.Authority.Deadline,
                carrier.Authority.ExpiresAt)
            {
                Contribution = new HostActionEntryContribution(
                    new HostActionEntryIngressBinding(
                        HostActionEntryIngress.CrossModule,
                        state.TargetEntry.ModuleId,
                        state.TargetEntry.GraphId),
                    new HostActionEntryLineage(
                        state.TargetEntry.Descriptor.Key,
                        state.TargetEntry.Descriptor.Version,
                        state.TargetEntry.Descriptor.DescriptorHash,
                        state.TargetEntry.Descriptor.InputTypeIdentity,
                        state.TargetEntry.Descriptor.InputSchemaVersion,
                        state.TargetEntry.Descriptor.InputSchemaHash,
                        carrier.Action.ContentHash,
                        carrier.Action.ByteLength)),
                ParentInvocationId = carrier.Authority.SourceParentInvocationId,
                Depth = carrier.Authority.Depth,
                Attempt = carrier.Authority.Attempt,
            };
            _callEntryContexts[state.TargetChildCall.CallId] = hostContext;
            return beginResult;
        }
        }
        finally
        {
            DrainCrossSidecarPeerCleanup(now);
        }
    }

    public SidecarCapabilityValidationResult CompleteCrossSidecarActionEntry(
        SidecarCrossSidecarActionEntryCarrier carrier,
        SidecarActionOutcomeEnvelope outcome,
        SidecarTerminalReceipt receipt,
        SidecarTerminalExecutionResult execution,
        SidecarActionResultIdentity? resultIdentity,
        SidecarSafeFailureIdentity responseSafeFailure,
        DateTimeOffset now,
        Func<SidecarCrossSidecarActionEntryAuthority, string, string> issueProof,
        out SidecarCrossSidecarActionEntryOutcome? completed)
    {
        ArgumentNullException.ThrowIfNull(carrier);
        ArgumentNullException.ThrowIfNull(outcome);
        ArgumentNullException.ThrowIfNull(receipt);
        ArgumentNullException.ThrowIfNull(execution);
        ArgumentNullException.ThrowIfNull(responseSafeFailure);
        ArgumentNullException.ThrowIfNull(issueProof);
        completed = null;
        SidecarCapabilitySession? peerSession = null;
        SidecarCapabilityValidationResult result;

        lock (_sync)
        {
            if (_disconnected)
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.Disconnected,
                    "The target capability session is disconnected.");

            if (!_crossSidecarStates.TryGetValue(carrier.CarrierId, out var state) ||
                !state.Active ||
                state.Carrier != carrier)
            {
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.Replay,
                    "The cross-sidecar carrier is not active.");
            }

            if (state.Terminal is null)
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.InvalidBinding,
                    "The cross-sidecar child has no registered terminal authority.");

            var receiptResult = SidecarCapabilityTransportValidation.ValidateReceipt(
                receipt,
                state.TargetChildCall.CallId,
                state.TargetEntry.Descriptor,
                required: true);
            if (!receiptResult.Accepted ||
                outcome.TerminalCallCount != 1 ||
                outcome.Receipt != receipt ||
                outcome.Kind is not (ActionOutcomeKind.Completed or ActionOutcomeKind.Failed or ActionOutcomeKind.Cancelled))
            {
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.InvalidResponse,
                    "The cross-sidecar child outcome does not bind to the target call.");
            }

            var resultPayload = outcome.Kind == ActionOutcomeKind.Completed
                ? outcome.Result
                : null;
            var failureShape = outcome.Kind == ActionOutcomeKind.Completed
                ? resultPayload is not null && outcome.Error is null && outcome.Uncertainty is null
                : resultPayload is null &&
                  (outcome.Kind == ActionOutcomeKind.Cancelled
                      ? outcome.Error is null && outcome.Uncertainty is null
                      : outcome.Error is not null && outcome.Uncertainty is null);
            if (!failureShape)
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.InvalidResponse,
                    "The cross-sidecar child outcome has an invalid terminal shape.");

            if (state.Terminal.TerminalId == Guid.Empty ||
                !execution.Completed ||
                execution.Result != outcome.Result ||
                execution.Failure != (outcome.Kind == ActionOutcomeKind.Completed ? null : responseSafeFailure) ||
                outcome.SafeFailure != responseSafeFailure ||
                (outcome.Kind == ActionOutcomeKind.Completed
                    ? execution.Failure is not null
                    : execution.Result is not null))
            {
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.InvalidResponse,
                    "The cross-sidecar terminal envelope does not match the child outcome.");
            }

            if (resultPayload is not null)
            {
                var payloadResult = SidecarCapabilityTransportValidation.ValidateSerializedPayload(
                    resultPayload,
                    required: true,
                    Binding.PayloadLimits.ActionResultBytes);
                if (!payloadResult.Accepted ||
                    resultPayload.TypeIdentity != state.TargetEntry.Descriptor.ResultTypeIdentity ||
                    resultPayload.SchemaVersion != state.TargetEntry.Descriptor.ResultSchemaVersion)
                    return payloadResult.Accepted
                        ? SidecarCapabilityValidationResult.Reject(
                            SidecarCapabilityErrors.InvalidResponse,
                            "The cross-sidecar child result does not match the target descriptor.")
                    : payloadResult;
            }

            if (outcome.Kind == ActionOutcomeKind.Completed)
            {
                if (resultIdentity is null ||
                    resultIdentity.ResultId == Guid.Empty ||
                    resultIdentity.CallId != state.TargetChildCall.CallId ||
                    resultIdentity.ActionKey != state.TargetEntry.Descriptor.Key ||
                    resultIdentity.ActionVersion != state.TargetEntry.Descriptor.Version ||
                    resultIdentity.ResultTypeIdentity != resultPayload!.TypeIdentity ||
                    resultIdentity.ContentHash != resultPayload.ContentHash)
                {
                    return SidecarCapabilityValidationResult.Reject(
                        SidecarCapabilityErrors.InvalidResponse,
                        "The cross-sidecar result identity does not match the child result.");
                }
            }
            else if (resultIdentity is not null)
            {
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.InvalidResponse,
                    "A non-completed cross-sidecar outcome cannot carry a result identity.");
            }

            var unsigned = carrier.Authority with
            {
                ResultReceipt = receipt,
                TerminalId = state.Terminal.TerminalId,
                OutcomeEnvelope = outcome,
                ResultIdentity = resultIdentity,
                Execution = execution,
                ResponseSafeFailure = responseSafeFailure,
                CanonicalBindingHash = string.Empty,
                Proof = string.Empty,
            };
            var canonicalHash = SidecarCrossSidecarActionEntryValidation.ComputeAuthorityHash(unsigned);
            var signed = unsigned with
            {
                CanonicalBindingHash = canonicalHash,
                Proof = issueProof(unsigned, canonicalHash),
            };
            if (!signed.IsValid)
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.Unauthenticated,
                    "The host did not issue a valid cross-sidecar result authority.");

            var kind = outcome.Kind switch
            {
                ActionOutcomeKind.Completed => SidecarCrossSidecarActionEntryOutcomeKind.Completed,
                ActionOutcomeKind.Cancelled => SidecarCrossSidecarActionEntryOutcomeKind.Cancelled,
                _ => SidecarCrossSidecarActionEntryOutcomeKind.Failed,
            };
            result = CompleteCall(state.TargetChildCall.CallId, 1);
            if (!result.Accepted)
                return result;

            _crossSidecarStates.Remove(carrier.CarrierId);
            RecordCarrierTombstone(carrier.CarrierId, _bindingGeneration, now, carrier.ExpiresAt);
            peerSession = state.PeerSession;
            completed = new SidecarCrossSidecarActionEntryOutcome(
                kind,
                outcome,
                receipt,
                responseSafeFailure,
                signed);
        }

        peerSession?.RemoveCrossSidecarPeerState(carrier.CarrierId, now);
        return SidecarCapabilityValidationResult.Accept();
    }

    public SidecarCapabilityValidationResult CompleteCrossSidecarActionEntry(
        SidecarCrossSidecarActionEntryCarrier carrier,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(carrier);
        SidecarCapabilitySession? peerSession;

        lock (_sync)
        {
            var removedRelation = _crossSidecarParentChildren.Remove(carrier.CarrierId);
            var removedState = _crossSidecarStates.Remove(carrier.CarrierId, out var state);
            if (!removedRelation && !removedState)
            {
                if (_completedEntryCarriers.ContainsKey(carrier.CarrierId))
                    return SidecarCapabilityValidationResult.Accept();

                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.Duplicate,
                    "The source cross-sidecar child is already completed.");
            }

            peerSession = removedState ? state!.PeerSession : null;
            RecordCarrierTombstone(carrier.CarrierId, _bindingGeneration, now, carrier.ExpiresAt);
        }

        peerSession?.RemoveCrossSidecarPeerState(carrier.CarrierId, now);
        return SidecarCapabilityValidationResult.Accept();
    }

    private void AbortCrossSidecarCall(Guid callId)
    {
        if (!_calls.Remove(callId))
            return;

        _callIdentities.Remove(callId);
        _callPayloads.Remove(callId);
        _callEntryContexts.Remove(callId);
        _terminalCalls.Remove(callId);
        _terminalReceipts.Remove(callId);
        _completedCalls.Add(callId);
        _inFlight = Math.Max(0, _inFlight - 1);
    }

    public SidecarCapabilityValidationResult RevokeCrossSidecarActionEntry(
        Guid carrierId,
        DateTimeOffset now)
    {
        SidecarCapabilitySession? peerSession;
        lock (_sync)
        {
            if (!_crossSidecarStates.Remove(carrierId, out var state))
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.Duplicate,
                    "The cross-sidecar carrier is not active.");

            _crossSidecarParentChildren.Remove(carrierId);
            if (_reservedNestedCalls.Remove(state.TargetChildCall.CallId))
                _inFlight = Math.Max(0, _inFlight - 1);
            else
                AbortCrossSidecarCall(state.TargetChildCall.CallId);
            RecordCarrierTombstone(carrierId, _bindingGeneration, now, state.Carrier.ExpiresAt);
            peerSession = state.PeerSession;
        }

        peerSession?.RemoveCrossSidecarPeerState(carrierId, now);
        return SidecarCapabilityValidationResult.Accept();
    }

    private void RemoveCrossSidecarPeerState(Guid carrierId, DateTimeOffset now)
    {
        lock (_sync)
        {
            if (!_crossSidecarStates.Remove(carrierId, out var state))
                return;

            _crossSidecarParentChildren.Remove(carrierId);
            if (!state.IsSource)
            {
                if (_reservedNestedCalls.Remove(state.TargetChildCall.CallId))
                    _inFlight = Math.Max(0, _inFlight - 1);
                else
                    AbortCrossSidecarCall(state.TargetChildCall.CallId);
            }

            RecordCarrierTombstone(carrierId, _bindingGeneration, now, state.Carrier.ExpiresAt);
        }
    }

    public SidecarCapabilityValidationResult CompleteHostActionEntryCarrier(
        HostActionEntryCarrierAuthority authority,
        HostActionEntryCarrierCompletionKind completion,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(authority);

        lock (_sync)
        {
            SweepCompletedEntryCarriers(now);
            if (_disconnected)
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.Disconnected,
                    "The sidecar capability session is disconnected.");

            if (!Enum.IsDefined(completion))
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.InvalidBinding,
                    "The carrier completion state is invalid.");

            if (!_activeEntryCarriers.TryGetValue(authority.CapabilityId, out var activeAuthority))
                return SidecarCapabilityValidationResult.Reject(
                    _completedEntryCarriers.ContainsKey(authority.CapabilityId)
                        ? SidecarCapabilityErrors.Replay
                        : SidecarCapabilityErrors.SpoofedIdentity,
                    "The host action entry carrier is not active.");

            if (!MatchesCarrierAuthority(authority, activeAuthority))
            {
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.SpoofedIdentity,
                    "The host action entry carrier authority does not match the active carrier.");
            }

            if (activeAuthority.ExpiresAt <= now)
            {
                RemoveEntryCarrier(authority.CapabilityId, now);
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.Expired,
                    "The host action entry carrier has expired.");
            }

            if (_callEntryContexts.Values.Any(context =>
                context.CapabilityId == authority.CapabilityId))
            {
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.InvalidBinding,
                    "The host action entry carrier has an active HostEntry call.");
            }

            RemoveEntryCarrier(authority.CapabilityId, now);
            return SidecarCapabilityValidationResult.Accept();
        }
    }

    public int SweepExpiredHostActionEntryCarriers(DateTimeOffset now)
    {
        int removed;
        lock (_sync)
        {
            removed = SweepExpiredEntryContexts(now);
            SweepCompletedEntryCarriers(now);
        }

        DrainCrossSidecarPeerCleanup(now);
        return removed;
    }

    public bool TryGetActiveHostActionEntryCarrier(
        Guid capabilityId,
        out HostActionEntryCarrierAuthority? authority)
    {
        lock (_sync)
            return _activeEntryCarriers.TryGetValue(capabilityId, out authority);
    }

    public SidecarCapabilityValidationResult RotateBinding(
        SidecarCapabilitySessionBinding replacement,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(replacement);

        lock (_sync)
        {
            if (_disconnected)
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.Disconnected,
                    "The sidecar capability session is disconnected.");

            var validation = SidecarCapabilitySessionValidator.Validate(
                replacement,
                _authenticate,
                _registerAuthenticationNonce,
                now,
                RegisterAuthenticationNonce: false);
            if (!validation.Accepted)
                return validation;

            var identityMatches =
                string.Equals(replacement.ModuleId, Binding.ModuleId, StringComparison.Ordinal) &&
                string.Equals(replacement.GraphId, Binding.GraphId, StringComparison.Ordinal) &&
                replacement.ProtocolVersion == Binding.ProtocolVersion &&
                replacement.SessionId != Binding.SessionId &&
                replacement.RequestId != Binding.RequestId &&
                replacement.CancellationId != Binding.CancellationId;
            if (!identityMatches)
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.SpoofedIdentity,
                    "The rotated binding does not advance the authenticated request identity.");

            if (_calls.Count != 0)
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.InvalidBinding,
                    "The capability session cannot rotate while a capability call is active.");

            if (_issuedEntryContexts.Count != 0 ||
                _rootHostActionEntryStates.Count != 0 ||
                _nestedCarrierStates.Count != 0 ||
                _reservedNestedCalls.Count != 0 ||
                _crossSidecarStates.Count != 0 ||
                _crossSidecarParentChildren.Count != 0)
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.InvalidBinding,
                    "The capability session cannot rotate while a carrier context is pending activation.");

            var requiredExpiry = _activeEntryCarriers.Count == 0
                ? now
                : _activeEntryCarriers.Values.Max(value => value.ExpiresAt);
            if (replacement.ExpiresAt < requiredExpiry ||
                (_activeEntryCarriers.Count > 0 && !replacement.Grant.Allows(SidecarCapabilityKind.Action)) ||
                replacement.PayloadLimits.ActionInputBytes < Binding.PayloadLimits.ActionInputBytes ||
                replacement.PayloadLimits.ActionResultBytes < Binding.PayloadLimits.ActionResultBytes ||
                replacement.PayloadLimits.ProtocolMessageBytes < Binding.PayloadLimits.ProtocolMessageBytes ||
                replacement.ConcurrencyLimits.MaximumInFlightCalls < Binding.ConcurrencyLimits.MaximumInFlightCalls ||
                replacement.ConcurrencyLimits.MaximumCallsPerRequest < Binding.ConcurrencyLimits.MaximumCallsPerRequest)
            {
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.InvalidBinding,
                    "The rotated binding would strand active carrier authority.");
            }

            validation = SidecarCapabilitySessionValidator.Validate(
                replacement,
                _authenticate,
                _registerAuthenticationNonce,
                now);
            if (!validation.Accepted)
                return validation;

            Binding = replacement;
            _bindingGeneration++;
            _lastSequence = 0;
            _totalCalls = 0;
            _nonces.Clear();
            _completedCalls.Clear();
            _completedEntryCarriers.Clear();
            _nestedCarrierStates.Clear();
            _crossSidecarStates.Clear();
            _crossSidecarParentChildren.Clear();
            _rootHostActionEntryStates.Clear();
            _reservedNestedCalls.Clear();
            _nestedCarrierIds.Clear();
            _nestedCarrierParents.Clear();
            _entryBudgetReservations.Clear();
            _peerParentBudgetRoots.Clear();
            _budgetExtensionClaims.Clear();
            return SidecarCapabilityValidationResult.Accept();
        }
    }

    public SidecarCapabilityValidationResult IssueHostActionEntry<TAction, TResult>(
        HostActionEntryRequest<TAction, TResult> request,
        Guid callId,
        DateTimeOffset now,
        Func<HostActionEntryAuthority, string> issueProof,
        out HostActionEntryTransportRequest<TAction, TResult>? transport)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(issueProof);
        transport = null;

        lock (_sync)
        {
            if (_disconnected)
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.Disconnected,
                    "The sidecar capability session is disconnected.");

            var bindingResult = SidecarCapabilitySessionValidator.Validate(
                Binding,
                _authenticate,
                _registerAuthenticationNonce,
                now,
                RegisterAuthenticationNonce: false);
            if (!bindingResult.Accepted)
                return bindingResult;

            if (!request.IsWellFormed(now) ||
                callId == Guid.Empty ||
                !_calls.TryGetValue(callId, out var capability) ||
                 capability != SidecarCapabilityKind.Action ||
                 !_callIdentities.TryGetValue(callId, out var activeCall) ||
                 !_callEntryContexts.TryGetValue(callId, out var entryContext) ||
                 !HostActionEntryAuthorityValidator.SameContextIgnoringPayload(request.Context, entryContext) ||
                 !_activeEntryCarriers.TryGetValue(request.Context.CapabilityId, out var carrierAuthority) ||
                 !MatchesCarrierContext(request.Context, carrierAuthority) ||
                 !HostActionEntryAuthorityValidator.MatchesLineage(
                     entryContext.Contribution?.Lineage,
                     request.Descriptor,
                     request.Action) ||
                 !_callPayloads.TryGetValue(callId, out var callPayload) ||
                callPayload is null)
            {
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.SpoofedIdentity,
                    "The host action entry request does not match the issued context.");
            }

            if (activeCall.Deadline != request.Context.Deadline ||
                activeCall.SessionId != Binding.SessionId ||
                activeCall.RequestId != Binding.RequestId ||
                activeCall.CancellationId != Binding.CancellationId)
            {
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.SpoofedIdentity,
                    "The host action entry request does not match the active call identity.");
            }

            var actionBytes = SidecarCapabilityTransportCodec.Serialize(request.Action);
            var actionHash = SidecarCapabilityTransportCodec.ComputeSha256(actionBytes);
            var inputSchema = request.Descriptor.InputSchema;
            var resultSchema = request.Descriptor.ResultSchema;
            if (inputSchema is null || resultSchema is null ||
                !string.Equals(callPayload.TypeIdentity, typeof(TAction).AssemblyQualifiedName ?? typeof(TAction).FullName, StringComparison.Ordinal) ||
                callPayload.SchemaVersion != inputSchema.Version ||
                !string.Equals(callPayload.ContentHash, actionHash, StringComparison.OrdinalIgnoreCase) ||
                callPayload.ByteLength != actionBytes.Length)
            {
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.InvalidPayload,
                    "The active sidecar payload does not match the typed host action.");
            }

            var authority = new HostActionEntryAuthority(
                Binding.ModuleId,
                Binding.GraphId,
                carrierAuthority.SessionId,
                carrierAuthority.RequestId,
                carrierAuthority.CancellationId,
                activeCall.CallId,
                activeCall.ReplayNonce,
                activeCall.Sequence,
                request.Context.Caller,
                request.Context.Features,
                request.Context.TraceId,
                request.Context.IdempotencyKey,
                request.Descriptor.Key,
                request.Descriptor.Version,
                request.Descriptor.Category,
                typeof(TAction).AssemblyQualifiedName ?? typeof(TAction).FullName ?? typeof(TAction).Name,
                typeof(TResult).AssemblyQualifiedName ?? typeof(TResult).FullName ?? typeof(TResult).Name,
                HostActionEntryAuthorityValidator.ComputeDescriptorHash(request.Descriptor),
                inputSchema.ContentHash!,
                inputSchema.Version,
                resultSchema.ContentHash!,
                resultSchema.Version,
                actionHash,
                actionBytes.Length,
                activeCall.Deadline,
                now,
                request.Context.ExpiresAt,
                string.Empty)
            {
                Ingress = request.Context.Ingress,
                InvocationId = request.Context.InvocationId,
                ParentInvocationId = request.Context.ParentInvocationId,
                Depth = request.Context.Depth,
                Attempt = request.Context.Attempt,
                CapabilityId = request.Context.CapabilityId,
                CapabilityHandleHash = HostActionEntryAuthorityValidator.ComputeCapabilityHandleHash(
                    request.Context.CapabilityHandle),
            };
            var proof = issueProof(authority);
            if (string.IsNullOrWhiteSpace(proof))
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.Unauthenticated,
                    "The host did not issue a host action entry proof.");

            transport = new HostActionEntryTransportRequest<TAction, TResult>(
                request,
                authority with { Proof = proof });
            return SidecarCapabilityValidationResult.Accept();
        }
    }

    public SidecarCapabilityValidationResult BeginCall(
        SidecarCapabilityCallIdentity identity,
        SidecarCapabilityKind capability,
        SidecarSerializedPayload? payload,
        int frameByteLength,
        DateTimeOffset now,
        HostActionEntryRequestContext? hostContext = null)
    {
        var result = BeginCallCore(identity, capability, payload, frameByteLength, now, hostContext, allowImportedRoot: false);
        DrainCrossSidecarPeerCleanup(now);
        return result;
    }

    private SidecarCapabilityValidationResult BeginCallCore(
        SidecarCapabilityCallIdentity identity,
        SidecarCapabilityKind capability,
        SidecarSerializedPayload? payload,
        int frameByteLength,
        DateTimeOffset now,
        HostActionEntryRequestContext? hostContext = null,
        bool allowImportedRoot = false)
    {
        lock (_sync)
            {
                SweepExpiredEntryContexts(now);
                SweepCompletedEntryCarriers(now);
                if (_disconnected)
                    return SidecarCapabilityValidationResult.Reject(
                        SidecarCapabilityErrors.Disconnected,
                        "The sidecar capability session is disconnected.");

            var bindingResult = SidecarCapabilitySessionValidator.Validate(
                Binding,
                _authenticate,
                _registerAuthenticationNonce,
                now,
                RegisterAuthenticationNonce: false);
            if (!bindingResult.Accepted)
                return bindingResult;

            if (identity.Capability != capability || !Binding.Grant.Allows(capability))
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.Unauthorized,
                    "The session grant does not allow this capability.");

            if (capability != SidecarCapabilityKind.Action && hostContext is not null)
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.InvalidBinding,
                    "Only action calls can carry a host action entry context.");

            if (hostContext is not null &&
                (!hostContext.IsWellFormed(now) ||
                 !_activeEntryCarriers.TryGetValue(hostContext.CapabilityId, out var activeCarrier) ||
                 !MatchesCarrierContext(hostContext, activeCarrier)))
            {
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.SpoofedIdentity,
                    "The host action entry context is not active for this carrier.");
            }

            if (hostContext is not null &&
                _consumedEntryCarriers.Contains(hostContext.CapabilityId))
            {
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.Replay,
                    "The host action entry carrier was already consumed.");
            }

            if (hostContext is not null &&
                _rootHostActionEntryStates.TryGetValue(hostContext.CapabilityId, out var rootState))
            {
                if (!allowImportedRoot ||
                    rootState.Relay.PeerCall != identity ||
                    !HostActionEntryAuthorityValidator.SameContext(hostContext, rootState.Context) ||
                    payload is null ||
                    !string.Equals(payload.ContentHash, rootState.Relay.Action.ContentHash, StringComparison.OrdinalIgnoreCase) ||
                    payload.ByteLength != rootState.Relay.Action.ByteLength)
                {
                    return SidecarCapabilityValidationResult.Reject(
                        SidecarCapabilityErrors.SpoofedIdentity,
                        "The imported root HostEntry authority must use its authenticated call and payload.");
                }
            }

            if (!identity.IsValid ||
                identity.SessionId != Binding.SessionId ||
                identity.RequestId != Binding.RequestId ||
                identity.CancellationId != Binding.CancellationId ||
                !string.Equals(identity.ModuleId, Binding.ModuleId, StringComparison.Ordinal) ||
                !string.Equals(identity.GraphId, Binding.GraphId, StringComparison.Ordinal))
            {
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.SpoofedIdentity,
                    "The call identity does not match the capability session.");
            }

            if (identity.Deadline <= now || identity.Deadline > Binding.ExpiresAt)
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.Expired,
                    "The call deadline is outside the active session lifetime.");

            var reservedNestedCall = _reservedNestedCalls.TryGetValue(identity.CallId, out var reservedIdentity) &&
                reservedIdentity == identity;

            var budgetRootId = hostContext is null
                ? Guid.Empty
                : ResolveEntryBudgetRoot(identity.CallId, hostContext.CapabilityId);
            var usesBudgetExtension =
                !reservedNestedCall &&
                hostContext is not null &&
                _totalCalls >= Binding.ConcurrencyLimits.MaximumCallsPerRequest;
            if (usesBudgetExtension && !HasAvailableBudgetExtension(budgetRootId, now))
            {
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.ConcurrencyLimit,
                    "The host action entry has no reserved continuation credit.");
            }

            if (!reservedNestedCall && identity.Sequence != _lastSequence + 1)
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.Replay,
                    "The call sequence is not the next session sequence.");

            var payloadLimit = capability == SidecarCapabilityKind.Action
                ? Binding.PayloadLimits.ActionInputBytes
                : Binding.PayloadLimits.ProtocolMessageBytes;
            var payloadResult = SidecarCapabilityTransportValidation.ValidateSerializedPayload(
                payload,
                capability == SidecarCapabilityKind.Action,
                payloadLimit);
            if (!payloadResult.Accepted)
                return payloadResult;

            if (hostContext is not null &&
                (hostContext.Contribution?.Lineage is null ||
                 payload is null ||
                 !string.Equals(hostContext.Contribution.Lineage.InputTypeIdentity, payload.TypeIdentity, StringComparison.Ordinal) ||
                 hostContext.Contribution.Lineage.InputSchemaVersion != payload.SchemaVersion))
            {
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.SpoofedIdentity,
                    "The action payload does not match the issued host entry lineage.");
            }

            if (frameByteLength < (payload is null ? 0 : payload.ByteLength) ||
                frameByteLength > Binding.PayloadLimits.ProtocolMessageBytes)
            {
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.PayloadTooLarge,
                    "The canonical transport frame exceeds the session limit.");
            }

            if (_calls.ContainsKey(identity.CallId) ||
                _completedCalls.Contains(identity.CallId) ||
                (!reservedNestedCall && !_nonces.Add(identity.ReplayNonce)))
            {
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.Replay,
                    "The call identity or replay nonce was already used.");
            }

            if (!reservedNestedCall && _inFlight >= Binding.ConcurrencyLimits.MaximumInFlightCalls)
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.ConcurrencyLimit,
                    "The session concurrency limit was reached.");

            if (!reservedNestedCall &&
                !usesBudgetExtension &&
                _totalCalls >= Binding.ConcurrencyLimits.MaximumCallsPerRequest)
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.ConcurrencyLimit,
                    "The session request call limit was reached.");

            if (usesBudgetExtension)
                ConsumeBudgetExtension(budgetRootId, identity.CallId);

            _calls.Add(identity.CallId, capability);
            _callIdentities.Add(identity.CallId, identity);
            _callPayloads.Add(identity.CallId, payload);
            if (hostContext is not null)
            {
                var capturedLineage = hostContext.Contribution!.Lineage with
                {
                    PayloadContentHash = payload!.ContentHash,
                    PayloadByteLength = payload.ByteLength,
                };
                _callEntryContexts[identity.CallId] =
                    hostContext with
                    {
                        Contribution = hostContext.Contribution with { Lineage = capturedLineage },
                    };
                _rootHostActionEntryStates.Remove(hostContext.CapabilityId);
                _entryBudgetRoots[hostContext.CapabilityId] = budgetRootId;
                _callBudgetRoots[identity.CallId] = budgetRootId;
                _consumedEntryCarriers.Add(hostContext.CapabilityId);
            }
            if (reservedNestedCall)
                _reservedNestedCalls.Remove(identity.CallId);
            else
            {
                _lastSequence = identity.Sequence;
                if (!usesBudgetExtension)
                    _totalCalls++;
                _inFlight++;
            }
                return SidecarCapabilityValidationResult.Accept();
        }
    }

    public SidecarCapabilityValidationResult RecordTerminal(
        Guid callId,
        Guid authorityId,
        SidecarTerminalReceipt receipt)
    {
        lock (_sync)
        {
            if (_disconnected)
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.Disconnected,
                    "The sidecar capability session is disconnected.");

            if (authorityId == Guid.Empty ||
                receipt is null ||
                receipt.CallId != callId ||
                string.IsNullOrWhiteSpace(receipt.ReceiptId) ||
                receipt.Attempt < 1 ||
                string.IsNullOrWhiteSpace(receipt.IdempotencyScope) ||
                string.IsNullOrWhiteSpace(receipt.ContentHash) ||
                !_calls.TryGetValue(callId, out var capability) ||
                capability != SidecarCapabilityKind.Action)
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.InvalidBinding,
                    "Only an active action call can record a terminal outcome.");

            if (_terminalCalls.ContainsKey(callId) || !_usedTerminalAuthorities.Add(authorityId))
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.TerminalAlreadyCalled,
                    "The call already recorded a terminal outcome.");

            _terminalCalls.Add(callId, authorityId);
            _terminalReceipts.Add(callId, receipt);
            return SidecarCapabilityValidationResult.Accept();
        }
    }

    public bool TryGetTerminalReceipt(Guid callId, out SidecarTerminalReceipt? receipt)
    {
        lock (_sync)
            return _terminalReceipts.TryGetValue(callId, out receipt);
    }

    public SidecarCapabilityValidationResult CompleteCall(Guid callId, int terminalCallCount)
    {
        lock (_sync)
        {
            if (_disconnected)
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.Disconnected,
                    "The sidecar capability session is disconnected.");

            if (!_calls.TryGetValue(callId, out var capability))
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.Duplicate,
                    "The call was already completed or was never active.");

            if (terminalCallCount is < 0 or > 1)
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.InvalidBinding,
                    "The terminal call count must be zero or one.");

            if (_nestedCarrierParents.Values.Contains(callId) ||
                _nestedCarrierStates.Values.Any(state => state.ParentCall.CallId == callId) ||
                _crossSidecarParentChildren.Values.Contains(callId) ||
                _crossSidecarStates.Values.Any(state => state.SourceParentCall.CallId == callId))
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.InvalidBinding,
                    "A parent action cannot complete while a nested action is active.");

            if (capability == SidecarCapabilityKind.Action &&
                _terminalCalls.ContainsKey(callId) != (terminalCallCount == 1))
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.TerminalAlreadyCalled,
                    "The action completion count does not match the recorded terminal authority.");

            if (capability == SidecarCapabilityKind.Storage && terminalCallCount != 0)
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.InvalidBinding,
                    "Storage calls cannot complete with a terminal callback.");

            if (_callEntryContexts.TryGetValue(callId, out var completedContext))
            {
                RevokeNestedCarriersForParent(callId, DateTimeOffset.UtcNow);
                if (_nestedCarrierIds.Remove(completedContext.CapabilityId))
                    RemoveEntryCarrier(completedContext.CapabilityId, DateTimeOffset.UtcNow);
                _nestedCarrierParents.Remove(completedContext.CapabilityId);
            }

            _calls.Remove(callId);
            _callIdentities.Remove(callId);

            _completedCalls.Add(callId);
            _terminalCalls.Remove(callId);
            _terminalReceipts.Remove(callId);
            _callPayloads.Remove(callId);
            _callEntryContexts.Remove(callId);
            var rootsToClean = new HashSet<Guid>();
            if (_callBudgetRoots.Remove(callId, out var budgetRootId))
                rootsToClean.Add(budgetRootId);
            if (_peerParentBudgetRoots.Remove(callId, out var peerRootId))
                rootsToClean.Add(peerRootId);
            _budgetExtensionClaims.Remove(callId);
            foreach (var rootId in rootsToClean)
                MaybeRemoveBudgetReservation(rootId);
            _inFlight--;
            return SidecarCapabilityValidationResult.Accept();
        }
    }

    private int SweepExpiredEntryContexts(DateTimeOffset now)
    {
        var removed = 0;
        foreach (var capabilityId in _issuedEntryContexts
            .Where(pair => pair.Value.ExpiresAt <= now)
            .Select(pair => pair.Key)
            .ToArray())
        {
            RemoveEntryCarrier(capabilityId, now);
            removed++;
        }

        foreach (var capabilityId in _activeEntryCarriers
            .Where(pair => pair.Value.ExpiresAt <= now)
            .Select(pair => pair.Key)
            .ToArray())
        {
            if (_nestedCarrierStates.TryGetValue(capabilityId, out var expiredState))
                ReleaseNestedReservation(expiredState.Carrier.CarrierId, expiredState.Call.CallId);
            _nestedCarrierStates.Remove(capabilityId);
            RemoveEntryCarrier(capabilityId, now);
            removed++;
        }

        foreach (var state in _nestedCarrierStates.Values
            .Where(state => state.Carrier.ExpiresAt <= now)
            .ToArray())
        {
            _nestedCarrierStates.Remove(state.Carrier.CarrierId);
            ReleaseNestedReservation(state.Carrier.CarrierId, state.Call.CallId);
            RemoveEntryCarrier(state.Carrier.CarrierId, now);
            removed++;
        }

        foreach (var state in _crossSidecarStates.Values
            .Where(state => state.Carrier.ExpiresAt <= now)
            .ToArray())
        {
            _crossSidecarStates.Remove(state.Carrier.CarrierId);
            _crossSidecarParentChildren.Remove(state.Carrier.CarrierId);
            if (_reservedNestedCalls.Remove(state.TargetChildCall.CallId))
                _inFlight = Math.Max(0, _inFlight - 1);
            else
                AbortCrossSidecarCall(state.TargetChildCall.CallId);
            RecordCarrierTombstone(
                state.Carrier.CarrierId,
                _bindingGeneration,
                now,
                state.Carrier.ExpiresAt);
            if (state.PeerSession is not null)
                _pendingCrossSidecarPeerCleanup.Add((state.PeerSession, state.Carrier.CarrierId));
            removed++;
        }

        return removed;
    }

    private void RevokeNestedCarriersForParent(Guid parentCallId, DateTimeOffset now)
    {
        foreach (var state in _nestedCarrierStates.Values
            .Where(state => state.ParentCall.CallId == parentCallId)
            .ToArray())
        {
            _nestedCarrierStates.Remove(state.Carrier.CarrierId);
            ReleaseNestedReservation(state.Carrier.CarrierId, state.Call.CallId);
            RemoveEntryCarrier(state.Carrier.CarrierId, now);
        }
    }

    private void ReleaseNestedReservation(Guid carrierId, Guid callId)
    {
        if (_reservedNestedCalls.Remove(callId))
            _inFlight--;

        if (_budgetExtensionClaims.Remove(carrierId, out var rootId) &&
            _entryBudgetReservations.TryGetValue(rootId, out var reservation))
        {
            _entryBudgetReservations[rootId] = reservation with
            {
                ExtensionAvailable = true,
            };
        }
    }

    public SidecarCapabilityValidationResult ImportNestedHostActionEntryRelay(
        SidecarNestedHostActionEntryRelay relay,
        SidecarNestedHostActionEntryRequest request,
        SidecarHostTerminalAuthority authority,
        SidecarCapabilityCallIdentity parentCall,
        DateTimeOffset now,
        out SidecarNestedHostActionEntryCarrier? importedCarrier)
    {
        ArgumentNullException.ThrowIfNull(relay);
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(authority);
        ArgumentNullException.ThrowIfNull(parentCall);
        importedCarrier = null;

        lock (_sync)
        {
            SweepExpiredEntryContexts(now);
            SweepCompletedEntryCarriers(now);
            if (_disconnected)
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.Disconnected,
                    "The receiving capability session is disconnected.");

            if (_authenticateHostTerminalAuthority is null)
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.Unauthorized,
                    "The receiving capability session has no host proof verifier.");

            var validation = SidecarCapabilitySessionValidator.Validate(
                Binding,
                _authenticate,
                _registerAuthenticationNonce,
                now,
                RegisterAuthenticationNonce: false);
            if (!validation.Accepted)
                return validation;

            var peerCall = relay.PeerCall;
            var expectedFingerprint = SidecarCapabilityTransportValidation.ComputeNestedCarrierRequestFingerprint(request);
            if (!relay.IsWellFormed ||
                relay.Contribution is null ||
                peerCall is null ||
                relay.RootBudgetId == Guid.Empty ||
                relay.PeerBindingGeneration != _bindingGeneration ||
                relay.Carrier.BindingGeneration != _bindingGeneration ||
                authority.NestedCarrierRelay != relay ||
                authority.NestedCarrierOutcomeKind != SidecarNestedHostActionEntryRelayOutcomeKind.Issued ||
                !string.Equals(authority.NestedCarrierRequestFingerprint, expectedFingerprint, StringComparison.OrdinalIgnoreCase) ||
                !string.Equals(authority.CanonicalBindingHash, SidecarCapabilityTransportValidation.ComputeTerminalAuthorityBindingHash(authority), StringComparison.OrdinalIgnoreCase) ||
                !_authenticateHostTerminalAuthority(authority, authority.CanonicalBindingHash) ||
                !MatchesPeerBinding(peerCall) ||
                !MatchesImportedParent(authority, parentCall) ||
                !MatchesImportedRequest(relay, request, authority, now))
            {
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.SpoofedIdentity,
                    "The nested host action relay is not authorized for this receiving session.");
            }

            if (!_calls.TryGetValue(parentCall.CallId, out var parentCapability) ||
                parentCapability != SidecarCapabilityKind.Action ||
                !_callIdentities.TryGetValue(parentCall.CallId, out var activeParent) ||
                activeParent != parentCall ||
                !_callEntryContexts.TryGetValue(parentCall.CallId, out var parentContext) ||
                !_terminalCalls.ContainsKey(parentCall.CallId))
            {
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.InvalidBinding,
                    "A nested relay requires an active receiving-session parent terminal call.");
            }

            if (authority.InvocationId != parentContext.InvocationId ||
                authority.ParentInvocationId != parentContext.ParentInvocationId ||
                authority.Depth != parentContext.Depth ||
                authority.Attempt != parentContext.Attempt ||
                authority.TraceId != parentContext.TraceId ||
                authority.IdempotencyKey != parentContext.IdempotencyKey ||
                authority.Deadline != parentCall.Deadline ||
                !SamePrincipal(authority.Caller, parentContext.Caller) ||
                !SameFeatures(authority.Features, parentContext.Features))
            {
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.SpoofedIdentity,
                    "The nested host action relay does not match the receiving parent context.");
            }

            if (_calls.ContainsKey(peerCall.CallId) ||
                _reservedNestedCalls.ContainsKey(peerCall.CallId) ||
                _completedCalls.Contains(peerCall.CallId) ||
                _nonces.Contains(peerCall.ReplayNonce) ||
                peerCall.Sequence != _lastSequence + 1 ||
                peerCall.Deadline > parentCall.Deadline ||
                peerCall.Deadline > parentContext.Deadline ||
                peerCall.Deadline <= now ||
                _inFlight >= Binding.ConcurrencyLimits.MaximumInFlightCalls)
            {
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.Replay,
                    "The nested host action relay call is already used or outside the receiving budget.");
            }

            var payloadResult = SidecarCapabilityTransportValidation.ValidateSerializedPayload(
                request.Action,
                required: true,
                Binding.PayloadLimits.ActionInputBytes);
            if (!payloadResult.Accepted)
                return payloadResult;

            var rootBudgetId = relay.RootBudgetId;
            if (_peerParentBudgetRoots.TryGetValue(parentCall.CallId, out var existingRoot) &&
                existingRoot != rootBudgetId)
            {
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.SpoofedIdentity,
                    "The nested host action relay changed its root budget authority.");
            }

            _peerParentBudgetRoots[parentCall.CallId] = rootBudgetId;
            if (!_entryBudgetReservations.ContainsKey(rootBudgetId))
            {
                _entryBudgetReservations[rootBudgetId] = new EntryBudgetReservation(
                    parentContext,
                    _bindingGeneration,
                    new[] { parentContext.ExpiresAt, relay.Carrier.ExpiresAt, Binding.ExpiresAt }.Min(),
                    ExtensionAvailable: true);
            }

            var usesBudgetExtension = _totalCalls >= Binding.ConcurrencyLimits.MaximumCallsPerRequest;
            if (usesBudgetExtension)
            {
                if (!HasAvailableBudgetExtension(rootBudgetId, now))
                    return SidecarCapabilityValidationResult.Reject(
                        SidecarCapabilityErrors.ConcurrencyLimit,
                        "The nested host action relay has no receiving-session continuation credit.");

                ConsumeBudgetExtension(rootBudgetId, relay.Carrier.CarrierId);
            }
            else
            {
                _totalCalls++;
            }

            var contribution = relay.Contribution;
            var childContext = new HostActionEntryRequestContext(
                relay.Carrier.CarrierId,
                relay.Carrier.Handle,
                contribution.IngressBinding.Ingress,
                relay.Carrier.InvocationId,
                Binding.RequestId,
                Binding.CancellationId,
                authority.Caller!,
                authority.Features!,
                authority.TraceId,
                authority.IdempotencyKey,
                peerCall.Deadline,
                relay.Carrier.ExpiresAt)
            {
                Contribution = contribution,
                ParentInvocationId = parentContext.InvocationId,
                Depth = parentContext.Depth + 1,
                Attempt = parentContext.Attempt,
            };
            var carrierAuthority = new HostActionEntryCarrierAuthority(
                Binding.ModuleId,
                Binding.GraphId,
                Binding.SessionId,
                Binding.RequestId,
                Binding.CancellationId,
                relay.Carrier.CarrierId,
                new HostActionEntryCarrierIdentity(
                    childContext.Ingress,
                    childContext.InvocationId,
                    contribution.IngressBinding),
                _bindingGeneration,
                now,
                relay.Carrier.ExpiresAt,
                HostActionEntryAuthorityValidator.ComputeCapabilityHandleHash(relay.Carrier.Handle));

            _lastSequence = peerCall.Sequence;
            _inFlight++;
            _nonces.Add(peerCall.ReplayNonce);
            _reservedNestedCalls.Add(peerCall.CallId, peerCall);
            _entryBudgetRoots[relay.Carrier.CarrierId] = rootBudgetId;
            _activeEntryCarriers[relay.Carrier.CarrierId] = carrierAuthority;
            _nestedCarrierStates[relay.Carrier.CarrierId] = new NestedCarrierState(
                relay.Carrier,
                parentCall,
                peerCall,
                relay.Descriptor,
                request.Action,
                childContext,
                carrierAuthority);
            importedCarrier = relay.Carrier;
            return SidecarCapabilityValidationResult.Accept();
        }
    }

    private void RemoveEntryCarrier(Guid capabilityId, DateTimeOffset now)
    {
        _issuedEntryContexts.Remove(capabilityId);
        if (_rootHostActionEntryStates.Remove(capabilityId, out var rootState))
        {
            if (_reservedNestedCalls.Remove(rootState.Relay.PeerCall.CallId))
                _inFlight = Math.Max(0, _inFlight - 1);

            _callEntryContexts.Remove(rootState.Relay.PeerCall.CallId);
            if (_peerParentBudgetRoots.Remove(rootState.Relay.PeerCall.CallId, out var peerRootId))
                MaybeRemoveBudgetReservation(peerRootId);
        }

        if (_activeEntryCarriers.Remove(capabilityId, out var authority))
        {
            RecordCarrierTombstone(
                capabilityId,
                authority.BindingGeneration,
                now,
                authority.ExpiresAt);
        }
        else
        {
            RecordCarrierTombstone(capabilityId, _bindingGeneration, now, now);
        }

        _consumedEntryCarriers.Remove(capabilityId);
        if (_entryBudgetRoots.Remove(capabilityId, out var budgetRootId))
        {
            if (_budgetExtensionClaims.Remove(capabilityId, out var claimedRootId) &&
                _entryBudgetReservations.TryGetValue(claimedRootId, out var reservation))
            {
                _entryBudgetReservations[claimedRootId] = reservation with
                {
                    ExtensionAvailable = true,
                };
            }

            MaybeRemoveBudgetReservation(budgetRootId);
        }
        if (!_callEntryContexts.Values.Any(context => context.CapabilityId == capabilityId))
            _nestedCarrierParents.Remove(capabilityId);
    }

    private Guid ResolveEntryBudgetRoot(Guid callId, Guid capabilityId) =>
        _callBudgetRoots.TryGetValue(callId, out var callRoot)
            ? callRoot
            : _entryBudgetRoots.TryGetValue(capabilityId, out var contextRoot)
                ? contextRoot
                : Guid.Empty;

    private bool HasAvailableBudgetExtension(Guid rootId, DateTimeOffset now) =>
        rootId != Guid.Empty &&
        _entryBudgetReservations.TryGetValue(rootId, out var reservation) &&
        reservation.BindingGeneration == _bindingGeneration &&
        reservation.ExpiresAt > now &&
        reservation.Context.IsWellFormed(now) &&
        reservation.ExtensionAvailable;

    private void ConsumeBudgetExtension(Guid rootId, Guid claimId)
    {
        if (!_entryBudgetReservations.TryGetValue(rootId, out var reservation) ||
            !reservation.ExtensionAvailable)
        {
            throw new InvalidOperationException(
                "The host action entry continuation credit is not available.");
        }

        _entryBudgetReservations[rootId] = reservation with
        {
            ExtensionAvailable = false,
        };
        _budgetExtensionClaims[claimId] = rootId;
    }

    private void MaybeRemoveBudgetReservation(Guid rootId)
    {
        if (rootId == Guid.Empty ||
            _entryBudgetRoots.Values.Contains(rootId) ||
            _callBudgetRoots.Values.Contains(rootId) ||
            _peerParentBudgetRoots.Values.Contains(rootId) ||
            _budgetExtensionClaims.Values.Contains(rootId))
        {
            return;
        }

        _entryBudgetReservations.Remove(rootId);
    }

    private void RecordCarrierTombstone(
        Guid capabilityId,
        long generation,
        DateTimeOffset now,
        DateTimeOffset expiry)
    {
        var retainUntil = expiry > now
            ? expiry
            : now + CarrierReplayRetention;
        _completedEntryCarriers[capabilityId] = new CarrierReplayTombstone(
            generation,
            retainUntil);
    }

    private void SweepCompletedEntryCarriers(DateTimeOffset now)
    {
        foreach (var capabilityId in _completedEntryCarriers
            .Where(pair => pair.Value.RetainUntil <= now)
            .Select(pair => pair.Key)
            .ToArray())
        {
            _completedEntryCarriers.Remove(capabilityId);
        }
    }

    private void DrainCrossSidecarPeerCleanup(DateTimeOffset now)
    {
        List<(SidecarCapabilitySession Peer, Guid CarrierId)> pending;
        lock (_sync)
        {
            pending = [.. _pendingCrossSidecarPeerCleanup];
            _pendingCrossSidecarPeerCleanup.Clear();
        }

        foreach (var (peer, carrierId) in pending)
            peer.RemoveCrossSidecarPeerState(carrierId, now);
    }

    private static HostActionEntryContribution BindNestedContribution(
        HostActionEntryContribution contribution,
        SidecarSerializedPayload action) =>
        contribution with
        {
            Lineage = contribution.Lineage with
            {
                PayloadContentHash = action.ContentHash,
                PayloadByteLength = action.ByteLength,
            },
        };

    private static bool SamePrincipal(
        RequestPrincipal? left,
        RequestPrincipal right) =>
        left is not null &&
        string.Equals(
            SidecarCapabilityTransportCodec.ComputeSha256(
                SidecarCapabilityTransportCodec.Serialize(left)),
            SidecarCapabilityTransportCodec.ComputeSha256(
                SidecarCapabilityTransportCodec.Serialize(right)),
            StringComparison.OrdinalIgnoreCase);

    private static bool SameFeatures(
        ExtensionFeatureSet? left,
        ExtensionFeatureSet right) =>
        left is not null &&
        string.Equals(
            SidecarCapabilityTransportCodec.ComputeSha256(
                SidecarCapabilityTransportCodec.Serialize(left)),
            SidecarCapabilityTransportCodec.ComputeSha256(
                SidecarCapabilityTransportCodec.Serialize(right)),
            StringComparison.OrdinalIgnoreCase);

    private bool MatchesPeerBinding(SidecarCapabilityCallIdentity peerCall) =>
        peerCall.SessionId == Binding.SessionId &&
        peerCall.RequestId == Binding.RequestId &&
        peerCall.CancellationId == Binding.CancellationId &&
        string.Equals(peerCall.ModuleId, Binding.ModuleId, StringComparison.Ordinal) &&
        string.Equals(peerCall.GraphId, Binding.GraphId, StringComparison.Ordinal);

    private static bool MatchesImportedParent(
        SidecarHostTerminalAuthority authority,
        SidecarCapabilityCallIdentity parentCall) =>
        authority.CallId == parentCall.CallId &&
        authority.Invocation == SidecarActionInvocationKind.HostEntry &&
        authority.Caller is not null &&
        authority.Features is not null &&
        authority.InvocationId != Guid.Empty;

    private static bool MatchesImportedRequest(
        SidecarNestedHostActionEntryRelay relay,
        SidecarNestedHostActionEntryRequest request,
        SidecarHostTerminalAuthority authority,
        DateTimeOffset now) =>
        request.IsWellFormed &&
        relay.Contribution is not null &&
        relay.Contribution.IsWellFormed &&
        relay.Carrier.ExpiresAt > now &&
        relay.Carrier.ExpiresAt <= authority.ExpiresAt &&
        relay.Call.Deadline == request.Deadline &&
        relay.Carrier.ParentCallId == authority.CallId &&
        relay.Carrier.ActionKey == request.ActionKey &&
        relay.Carrier.ActionVersion == request.ActionVersion &&
        relay.Descriptor.Key == request.ActionKey &&
        relay.Descriptor.Version == request.ActionVersion &&
        string.Equals(relay.Descriptor.InputTypeIdentity, request.Action.TypeIdentity, StringComparison.Ordinal) &&
        relay.Descriptor.InputSchemaVersion == request.Action.SchemaVersion &&
        string.Equals(relay.Carrier.ActionContentHash, request.Action.ContentHash, StringComparison.OrdinalIgnoreCase) &&
        relay.Carrier.ActionByteLength == request.Action.ByteLength &&
        string.Equals(relay.Contribution.Lineage.PayloadContentHash, request.Action.ContentHash, StringComparison.OrdinalIgnoreCase) &&
        relay.Contribution.Lineage.PayloadByteLength == request.Action.ByteLength;

    private static bool MatchesCarrier(
        HostActionEntryRequestContext context,
        HostActionEntryCarrierIdentity carrier) =>
        context.Ingress == carrier.Ingress &&
        context.InvocationId == carrier.InvocationId &&
        context.Contribution is not null &&
        SameIngressBinding(context.Contribution.IngressBinding, carrier.Contribution);

    private static bool MatchesDescriptorLineage(
        HostActionEntryLineage? lineage,
        SidecarActionDescriptorIdentity descriptor,
        SidecarSerializedPayload action) =>
        lineage is not null &&
        lineage.ActionKey == descriptor.Key &&
        lineage.ActionVersion == descriptor.Version &&
        string.Equals(lineage.DescriptorHash, descriptor.DescriptorHash, StringComparison.Ordinal) &&
        string.Equals(lineage.InputTypeIdentity, descriptor.InputTypeIdentity, StringComparison.Ordinal) &&
        lineage.InputSchemaVersion == descriptor.InputSchemaVersion &&
        string.Equals(lineage.InputSchemaHash, descriptor.InputSchemaHash, StringComparison.Ordinal) &&
        string.Equals(lineage.PayloadContentHash, action.ContentHash, StringComparison.OrdinalIgnoreCase) &&
        lineage.PayloadByteLength == action.ByteLength;

    private static bool MatchesCarrierContext(
        HostActionEntryRequestContext context,
        HostActionEntryCarrierAuthority authority) =>
        authority.IsValid &&
        authority.CapabilityId == context.CapabilityId &&
        MatchesCarrier(context, authority.Carrier) &&
        string.Equals(
            authority.CapabilityHandleHash,
            HostActionEntryAuthorityValidator.ComputeCapabilityHandleHash(context.CapabilityHandle),
            StringComparison.OrdinalIgnoreCase);

    private static bool MatchesCarrierAuthority(
        HostActionEntryCarrierAuthority candidate,
        HostActionEntryCarrierAuthority active) =>
        candidate.IsValid &&
        active.IsValid &&
        string.Equals(candidate.ModuleId, active.ModuleId, StringComparison.Ordinal) &&
        string.Equals(candidate.GraphId, active.GraphId, StringComparison.Ordinal) &&
        candidate.SessionId == active.SessionId &&
        candidate.RequestId == active.RequestId &&
        candidate.CancellationId == active.CancellationId &&
        candidate.CapabilityId == active.CapabilityId &&
        candidate.BindingGeneration == active.BindingGeneration &&
        candidate.IssuedAt == active.IssuedAt &&
        candidate.ExpiresAt == active.ExpiresAt &&
        string.Equals(candidate.CapabilityHandleHash, active.CapabilityHandleHash, StringComparison.OrdinalIgnoreCase) &&
        candidate.Carrier.Ingress == active.Carrier.Ingress &&
        candidate.Carrier.InvocationId == active.Carrier.InvocationId &&
        SameIngressBinding(candidate.Carrier.Contribution, active.Carrier.Contribution);

    private static bool SameIngressBinding(
        HostActionEntryIngressBinding left,
        HostActionEntryIngressBinding right) =>
        left is not null &&
        right is not null &&
        left.Ingress == right.Ingress &&
        string.Equals(left.PrimaryIdentity, right.PrimaryIdentity, StringComparison.Ordinal) &&
        string.Equals(left.SecondaryIdentity, right.SecondaryIdentity, StringComparison.Ordinal);

    public void Disconnect()
    {
        lock (_sync)
        {
            _disconnected = true;
            foreach (var peer in _crossSidecarStates.Values
                .Where(state => state.PeerSession is not null)
                .Select(state => (state.PeerSession!, state.Carrier.CarrierId))
                .ToArray())
            {
                if (!_pendingCrossSidecarPeerCleanup.Contains(peer))
                    _pendingCrossSidecarPeerCleanup.Add(peer);
            }
            _calls.Clear();
            _callIdentities.Clear();
            _callPayloads.Clear();
            _callEntryContexts.Clear();
            _issuedEntryContexts.Clear();
            _activeEntryCarriers.Clear();
            _entryBudgetRoots.Clear();
            _entryBudgetReservations.Clear();
            _peerParentBudgetRoots.Clear();
            _callBudgetRoots.Clear();
            _budgetExtensionClaims.Clear();
            _nestedCarrierStates.Clear();
            _crossSidecarStates.Clear();
            _crossSidecarParentChildren.Clear();
            _rootHostActionEntryStates.Clear();
            _reservedNestedCalls.Clear();
            _nestedCarrierIds.Clear();
            _nestedCarrierParents.Clear();
            _completedEntryCarriers.Clear();
            _consumedEntryCarriers.Clear();
            _terminalCalls.Clear();
            _terminalReceipts.Clear();
            _consumedExternalActionCalls.Clear();
            _inFlight = 0;
        }

        DrainCrossSidecarPeerCleanup(DateTimeOffset.UtcNow);
    }
}

public static class SidecarCapabilitySessionValidator
{
    public static string ComputeBindingHash(SidecarCapabilitySessionBinding binding)
    {
        ArgumentNullException.ThrowIfNull(binding);
        var authority = new SidecarCapabilityBindingAuthorityData(
            binding.ModuleId,
            binding.GraphId,
            binding.ProtocolVersion,
            binding.Grant,
            binding.SessionId,
            binding.RequestId,
            binding.CancellationId,
            binding.ExpiresAt,
            binding.PayloadLimits,
            binding.ConcurrencyLimits,
            binding.SafeFailure,
            binding.AuthenticationKeyId);
        return SidecarCapabilityTransportCodec.ComputeSha256(
            SidecarCapabilityTransportCodec.Serialize(authority));
    }

    public static SidecarCapabilityValidationResult Validate(
        SidecarCapabilitySessionBinding binding,
        Func<SidecarCapabilityAuthenticationAuthority, bool> authenticate,
        Func<string, bool> registerAuthenticationNonce,
        DateTimeOffset now,
        bool RegisterAuthenticationNonce = true)
    {
        ArgumentNullException.ThrowIfNull(binding);
        ArgumentNullException.ThrowIfNull(authenticate);
        ArgumentNullException.ThrowIfNull(registerAuthenticationNonce);

        if (binding.ProtocolVersion < 1 ||
            string.IsNullOrWhiteSpace(binding.ModuleId) ||
            string.IsNullOrWhiteSpace(binding.GraphId) ||
            string.IsNullOrWhiteSpace(binding.AuthenticationKeyId) ||
            binding.SessionId == Guid.Empty ||
            binding.RequestId == Guid.Empty ||
            binding.CancellationId == Guid.Empty ||
            binding.Grant is null ||
            binding.PayloadLimits is null ||
            !binding.PayloadLimits.IsValid ||
            binding.ConcurrencyLimits is null ||
            !binding.ConcurrencyLimits.IsValid ||
            binding.SafeFailure is null ||
            !binding.SafeFailure.IsValid ||
            binding.Authentication is null)
        {
            return SidecarCapabilityValidationResult.Reject(
                SidecarCapabilityErrors.InvalidBinding,
                "The sidecar capability binding is incomplete.");
        }

        if (binding.ExpiresAt <= now)
            return SidecarCapabilityValidationResult.Reject(
                SidecarCapabilityErrors.Expired,
                "The sidecar capability session has expired.");

        var proof = binding.Authentication;
        if (!string.Equals(proof.KeyId, binding.AuthenticationKeyId, StringComparison.Ordinal) ||
            string.IsNullOrWhiteSpace(proof.Scheme) ||
            string.IsNullOrWhiteSpace(proof.Nonce) ||
            string.IsNullOrWhiteSpace(proof.Signature) ||
            proof.IssuedAt > now ||
            proof.ExpiresAt != binding.ExpiresAt ||
            proof.ExpiresAt <= now ||
            !string.Equals(proof.BindingHash, ComputeBindingHash(binding), StringComparison.Ordinal))
        {
            return SidecarCapabilityValidationResult.Reject(
                SidecarCapabilityErrors.InvalidBinding,
                "The authentication proof does not bind to the immutable session authority.");
        }

        var authority = new SidecarCapabilityAuthenticationAuthority(
            binding,
            proof.BindingHash);
        if (!authenticate(authority) ||
            RegisterAuthenticationNonce && !registerAuthenticationNonce(proof.Nonce))
            return SidecarCapabilityValidationResult.Reject(
                SidecarCapabilityErrors.Unauthenticated,
                "The sidecar authentication proof was not accepted or was replayed.");

        if (!string.Equals(binding.Grant.ModuleId, binding.ModuleId, StringComparison.Ordinal) ||
            !string.Equals(binding.Grant.GraphId, binding.GraphId, StringComparison.Ordinal) ||
            binding.Grant.ExpiresAt != binding.ExpiresAt ||
            binding.Grant.IssuedAt > now ||
            binding.Grant.ExpiresAt <= now ||
            binding.Grant.Capabilities is null ||
            string.IsNullOrWhiteSpace(binding.Grant.GrantId) ||
            string.IsNullOrWhiteSpace(binding.Grant.AuthorizationHash))
        {
            return SidecarCapabilityValidationResult.Reject(
                SidecarCapabilityErrors.Unauthorized,
                "The session grant does not bind to the session identity.");
        }

        return SidecarCapabilityValidationResult.Accept();
    }

    private sealed record SidecarCapabilityBindingAuthorityData(
        string ModuleId,
        string GraphId,
        int ProtocolVersion,
        SidecarCapabilityGrant Grant,
        Guid SessionId,
        Guid RequestId,
        Guid CancellationId,
        DateTimeOffset ExpiresAt,
        SidecarPayloadLimits PayloadLimits,
        SidecarConcurrencyLimits ConcurrencyLimits,
        SidecarSafeFailureIdentity SafeFailure,
        string AuthenticationKeyId);
}

public sealed record SidecarStorageCapabilityRequest(
    SidecarCapabilityCallIdentity Call,
    string ModuleId,
    string StorageName,
    SidecarStorageOperationKind Operation,
    SidecarSerializedPayload? RequestPayload,
    SidecarPayloadTypeIdentity ResultPayloadType,
    SidecarCancellationIdentity Cancellation,
    DateTimeOffset Deadline)
{
    public static SidecarStorageCapabilityRequest ListContracts(
        SidecarCapabilityCallIdentity call,
        string moduleId,
        SidecarPayloadTypeIdentity resultPayloadType,
        SidecarCancellationIdentity cancellation,
        DateTimeOffset deadline) =>
        new(call, moduleId, string.Empty, SidecarStorageOperationKind.ListContracts, null, resultPayloadType, cancellation, deadline);

    public static SidecarStorageCapabilityRequest Invoke(
        SidecarCapabilityCallIdentity call,
        string moduleId,
        string storageName,
        SidecarSerializedPayload requestPayload,
        SidecarPayloadTypeIdentity resultPayloadType,
        SidecarCancellationIdentity cancellation,
        DateTimeOffset deadline) =>
        new(call, moduleId, storageName, SidecarStorageOperationKind.Invoke, requestPayload, resultPayloadType, cancellation, deadline);

    public static SidecarStorageCapabilityRequest CommitMutationAndOutbox(
        SidecarCapabilityCallIdentity call,
        string moduleId,
        string storageName,
        SidecarSerializedPayload requestPayload,
        SidecarPayloadTypeIdentity resultPayloadType,
        SidecarCancellationIdentity cancellation,
        DateTimeOffset deadline) =>
        new(call, moduleId, storageName, SidecarStorageOperationKind.CommitMutationAndOutbox, requestPayload, resultPayloadType, cancellation, deadline);

    public static SidecarStorageCapabilityRequest Claim(
        SidecarCapabilityCallIdentity call,
        string moduleId,
        string storageName,
        SidecarSerializedPayload requestPayload,
        SidecarPayloadTypeIdentity resultPayloadType,
        SidecarCancellationIdentity cancellation,
        DateTimeOffset deadline) =>
        new(call, moduleId, storageName, SidecarStorageOperationKind.Claim, requestPayload, resultPayloadType, cancellation, deadline);

    public static SidecarStorageCapabilityRequest RenewClaim(
        SidecarCapabilityCallIdentity call,
        string moduleId,
        string storageName,
        SidecarSerializedPayload requestPayload,
        SidecarPayloadTypeIdentity resultPayloadType,
        SidecarCancellationIdentity cancellation,
        DateTimeOffset deadline) =>
        new(call, moduleId, storageName, SidecarStorageOperationKind.RenewClaim, requestPayload, resultPayloadType, cancellation, deadline);

    public static SidecarStorageCapabilityRequest RecoverClaim(
        SidecarCapabilityCallIdentity call,
        string moduleId,
        string storageName,
        SidecarSerializedPayload requestPayload,
        SidecarPayloadTypeIdentity resultPayloadType,
        SidecarCancellationIdentity cancellation,
        DateTimeOffset deadline) =>
        new(call, moduleId, storageName, SidecarStorageOperationKind.RecoverClaim, requestPayload, resultPayloadType, cancellation, deadline);
}

public sealed record SidecarStorageResultIdentity(
    Guid ResultId,
    Guid CallId,
    string ContentHash,
    bool AlreadyCommitted = false);

public sealed record SidecarStorageCapabilityResponse(
    SidecarStorageResultIdentity ResultIdentity,
    SidecarSerializedPayload? ResultPayload,
    ModuleStorageContractFailure? Error,
    SidecarSafeFailureIdentity SafeFailure,
    bool Completed);

public sealed record SidecarActionDescriptorIdentity(
    SharpClawActionKey Key,
    int Version,
    string Category,
    string InputTypeIdentity,
    string InputSchemaHash,
    int InputSchemaVersion,
    string ResultTypeIdentity,
    string ResultSchemaHash,
    int ResultSchemaVersion,
    string DescriptorHash)
{
    public bool IsWellFormed =>
        !string.IsNullOrWhiteSpace(Key.Value) &&
        Version >= 1 &&
        !string.IsNullOrWhiteSpace(Category) &&
        !string.IsNullOrWhiteSpace(InputTypeIdentity) &&
        !string.IsNullOrWhiteSpace(InputSchemaHash) &&
        InputSchemaVersion >= 1 &&
        !string.IsNullOrWhiteSpace(ResultTypeIdentity) &&
        !string.IsNullOrWhiteSpace(ResultSchemaHash) &&
        ResultSchemaVersion >= 1 &&
        !string.IsNullOrWhiteSpace(DescriptorHash);
}

public sealed record SidecarCancellationIdentity(
    Guid CancellationId,
    string AuthorityHash,
    DateTimeOffset ExpiresAt);

public sealed record SidecarTerminalReceipt(
    string ReceiptId,
    SharpClawActionKey ActionKey,
    int ActionVersion,
    Guid CallId,
    int Attempt,
    string IdempotencyScope,
    string ContentHash);

public sealed record SidecarActionTerminalRegistration(
    Guid TerminalId,
    string ActionTypeIdentity,
    int ActionSchemaVersion,
    string ResultTypeIdentity,
    int ResultSchemaVersion,
    string DescriptorHash)
{
    public bool IsWellFormed =>
        TerminalId != Guid.Empty &&
        !string.IsNullOrWhiteSpace(ActionTypeIdentity) &&
        ActionSchemaVersion >= 1 &&
        !string.IsNullOrWhiteSpace(ResultTypeIdentity) &&
        ResultSchemaVersion >= 1 &&
        !string.IsNullOrWhiteSpace(DescriptorHash);
}

public sealed record SidecarTerminalContinuationRequest(
    Guid ContinuationRequestId,
    bool Proceed,
    SidecarSerializedPayload? ReplacementResult,
    SidecarTerminalReceipt? Receipt,
    DateTimeOffset Deadline);

public sealed record SidecarActionOutcomeEnvelope(
    ActionOutcomeKind Kind,
    SidecarSerializedPayload? Result,
    ContinuationToken? Continuation,
    ExecutionError? Error,
    ActionUncertainty? Uncertainty,
    SidecarTerminalReceipt? Receipt,
    SidecarSafeFailureIdentity SafeFailure,
    int TerminalCallCount);

/// <summary>Opaque, one-use carrier issued by the host for one nested action.</summary>
public sealed record SidecarNestedHostActionEntryCarrier(
    Guid CarrierId,
    string Handle,
    Guid ParentCallId,
    Guid CallId,
    Guid InvocationId,
    SharpClawActionKey ActionKey,
    int ActionVersion,
    string DescriptorHash,
    string ActionContentHash,
    int ActionByteLength,
    SidecarActionDescriptorIdentity Descriptor,
    long BindingGeneration,
    DateTimeOffset ExpiresAt)
{
    public bool IsWellFormed =>
        CarrierId != Guid.Empty &&
        !string.IsNullOrWhiteSpace(Handle) &&
        ParentCallId != Guid.Empty &&
        CallId != Guid.Empty &&
        InvocationId != Guid.Empty &&
        !string.IsNullOrWhiteSpace(ActionKey.Value) &&
        ActionVersion >= 1 &&
        !string.IsNullOrWhiteSpace(DescriptorHash) &&
        !string.IsNullOrWhiteSpace(ActionContentHash) &&
        ActionByteLength > 0 &&
        Descriptor is not null &&
        Descriptor.IsWellFormed &&
        Descriptor.Key == ActionKey &&
        Descriptor.Version == ActionVersion &&
        string.Equals(Descriptor.DescriptorHash, DescriptorHash, StringComparison.Ordinal) &&
        BindingGeneration > 0 &&
        ExpiresAt > DateTimeOffset.MinValue;
}

public sealed record SidecarNestedHostActionEntryRequest(
    SharpClawActionKey ActionKey,
    int ActionVersion,
    SidecarSerializedPayload Action,
    DateTimeOffset Deadline,
    DateTimeOffset ExpiresAt)
{
    public bool IsWellFormed =>
        !string.IsNullOrWhiteSpace(ActionKey.Value) &&
        ActionVersion >= 1 &&
        Action is not null &&
        Action.IsValid &&
        Deadline > DateTimeOffset.MinValue &&
        ExpiresAt >= Deadline;
}

public sealed record SidecarNestedHostActionEntryRelay(
    SidecarCapabilityCallIdentity Call,
    SidecarNestedHostActionEntryCarrier Carrier)
{
    public HostActionEntryContribution? Contribution { get; init; }
    public Guid RootBudgetId { get; init; }
    public SidecarCapabilityCallIdentity? PeerCall { get; init; }
    public long PeerBindingGeneration { get; init; }

    public SidecarActionDescriptorIdentity Descriptor => Carrier.Descriptor;

    public bool IsWellFormed =>
        Call is not null &&
        Call.IsValid &&
        Carrier is not null &&
        Descriptor is not null &&
        Descriptor.IsWellFormed &&
        Carrier.IsWellFormed &&
        Carrier.CallId == Call.CallId &&
        Descriptor.Key == Carrier.ActionKey &&
        Descriptor.Version == Carrier.ActionVersion &&
        string.Equals(Descriptor.DescriptorHash, Carrier.DescriptorHash, StringComparison.Ordinal) &&
        Contribution is not null &&
        Contribution.IsWellFormed &&
        RootBudgetId != Guid.Empty &&
        (PeerCall is null
            ? PeerBindingGeneration == 0
            : PeerCall.IsValid &&
              PeerBindingGeneration > 0 &&
              PeerCall.CallId == Carrier.CallId &&
              PeerCall.Deadline == Call.Deadline &&
               PeerCall.Sequence == Call.Sequence);
}

public sealed record SidecarHostActionEntryRootRelay(
    SidecarCapabilityCallIdentity Call,
    SidecarCapabilityCallIdentity PeerCall,
    HostActionEntryRequestContext Context,
    SidecarActionDescriptorIdentity Descriptor,
    SidecarSerializedPayload Action,
    SidecarActionTerminalRegistration Terminal,
    ActionPipelineSnapshot Snapshot,
    SidecarHostTerminalAuthority Authority,
    long PeerBindingGeneration,
    Guid RootBudgetId)
{
    public bool IsWellFormed =>
        Call is not null &&
        Call.IsValid &&
        PeerCall is not null &&
        PeerCall.IsValid &&
        Context is not null &&
        Context.CapabilityId != Guid.Empty &&
        !string.IsNullOrWhiteSpace(Context.CapabilityHandle) &&
        Context.Caller is not null &&
        Context.Features is not null &&
        Context.Contribution is not null &&
        Context.Contribution.IsWellFormed &&
        Descriptor is not null &&
        Descriptor.IsWellFormed &&
        Action is not null &&
        Action.IsValid &&
        string.Equals(Action.TypeIdentity, Descriptor.InputTypeIdentity, StringComparison.Ordinal) &&
        Action.SchemaVersion == Descriptor.InputSchemaVersion &&
        Terminal is not null &&
        Terminal.IsWellFormed &&
        Terminal.ActionTypeIdentity == Descriptor.InputTypeIdentity &&
        Terminal.ActionSchemaVersion == Descriptor.InputSchemaVersion &&
        Terminal.ResultTypeIdentity == Descriptor.ResultTypeIdentity &&
        Terminal.ResultSchemaVersion == Descriptor.ResultSchemaVersion &&
        string.Equals(Terminal.DescriptorHash, Descriptor.DescriptorHash, StringComparison.Ordinal) &&
        Snapshot is not null &&
        !string.IsNullOrWhiteSpace(Snapshot.ContractHash) &&
        Authority is not null &&
        Authority.AuthorityId != Guid.Empty &&
        Authority.CallId == Call.CallId &&
        Authority.RootPeerCall == PeerCall &&
        Authority.TerminalId == Terminal.TerminalId &&
        Authority.ActionKey == Descriptor.Key &&
        Authority.ActionVersion == Descriptor.Version &&
        string.Equals(Authority.DescriptorHash, Descriptor.DescriptorHash, StringComparison.Ordinal) &&
        string.Equals(Authority.EffectiveActionTypeIdentity, Action.TypeIdentity, StringComparison.Ordinal) &&
        Authority.EffectiveActionSchemaVersion == Action.SchemaVersion &&
        string.Equals(Authority.EffectiveActionContentHash, Action.ContentHash, StringComparison.OrdinalIgnoreCase) &&
        Authority.EffectiveActionByteLength == Action.ByteLength &&
        SidecarCapabilityTransportValidation.MatchesHostActionEntryContextBindingHash(
            Context,
            Authority.HostContextBindingHash) &&
        string.Equals(
            Authority.SnapshotContentHash,
            SidecarCapabilityTransportValidation.ComputeSnapshotHash(Snapshot),
            StringComparison.OrdinalIgnoreCase) &&
        !string.IsNullOrWhiteSpace(Authority.Proof) &&
        !string.IsNullOrWhiteSpace(Authority.CanonicalBindingHash) &&
        string.Equals(
            Authority.CanonicalBindingHash,
            SidecarCapabilityTransportValidation.ComputeTerminalAuthorityBindingHash(Authority),
            StringComparison.OrdinalIgnoreCase) &&
        PeerBindingGeneration > 0 &&
        RootBudgetId != Guid.Empty;
}

public enum SidecarNestedHostActionEntryRelayOutcomeKind
{
    Issued = 0,
    Failed = 1,
    Cancelled = 2,
}

public sealed record SidecarNestedHostActionEntryRelayOutcome(
    SidecarNestedHostActionEntryRelayOutcomeKind Kind,
    SidecarSafeFailureIdentity? Failure)
{
    public bool IsWellFormed =>
        Enum.IsDefined(Kind) &&
        (Kind == SidecarNestedHostActionEntryRelayOutcomeKind.Issued
            ? Failure is null
            : Failure is not null && Failure.IsValid);
}

public sealed record SidecarTerminalContinuationResponse(
    Guid ContinuationRequestId,
    bool Accepted,
    SidecarActionOutcomeEnvelope? Outcome,
    SidecarSafeFailureIdentity SafeFailure);

public sealed record SidecarActionCapabilityRequest(
    SidecarCapabilityCallIdentity Call,
    SidecarActionInvocationKind Invocation,
    SidecarActionDescriptorIdentity Descriptor,
    SidecarSerializedPayload Action,
    ActionPipelineSnapshot? Snapshot,
    SidecarCancellationIdentity Cancellation,
    SidecarTerminalContinuationRequest? Continuation,
    DateTimeOffset Deadline)
{
    public HostActionEntryRequestContext? HostContext { get; init; }
    public SidecarNestedHostActionEntryCarrier? NestedCarrier { get; init; }
    public SidecarCrossSidecarActionEntryCarrier? CrossSidecarCarrier { get; init; }
    public SidecarActionTerminalRegistration? Terminal { get; init; }
    public SidecarActionEffectiveHostEntryContext? EffectiveHostEntryContext { get; init; }

    public static SidecarActionCapabilityRequest HostEntry(
        SidecarCapabilityCallIdentity call,
        SidecarActionDescriptorIdentity descriptor,
        SidecarSerializedPayload action,
        SidecarCancellationIdentity cancellation,
        DateTimeOffset deadline,
        HostActionEntryRequestContext hostContext,
        SidecarActionTerminalRegistration terminal) =>
        new(
            call,
            SidecarActionInvocationKind.HostEntry,
            descriptor,
            action,
            null,
            cancellation,
            null,
            deadline)
        {
            HostContext = hostContext,
            Terminal = terminal,
        };

    public static SidecarActionCapabilityRequest HostEntryNested(
        SidecarCapabilityCallIdentity call,
        SidecarActionDescriptorIdentity descriptor,
        SidecarSerializedPayload action,
        SidecarCancellationIdentity cancellation,
        DateTimeOffset deadline,
        SidecarNestedHostActionEntryCarrier carrier,
        SidecarActionTerminalRegistration terminal) =>
        new(
            call,
            SidecarActionInvocationKind.HostEntry,
            descriptor,
            action,
            null,
            cancellation,
            null,
            deadline)
        {
            NestedCarrier = carrier,
            Terminal = terminal,
        };

    public static SidecarActionCapabilityRequest HostEntryCrossSidecar(
        SidecarCapabilityCallIdentity call,
        SidecarActionDescriptorIdentity descriptor,
        SidecarSerializedPayload action,
        SidecarCancellationIdentity cancellation,
        DateTimeOffset deadline,
        SidecarCrossSidecarActionEntryCarrier carrier,
        SidecarActionTerminalRegistration terminal) =>
        new(
            call,
            SidecarActionInvocationKind.HostEntryCrossSidecar,
            descriptor,
            action,
            null,
            cancellation,
            null,
            deadline)
        {
            CrossSidecarCarrier = carrier,
            Terminal = terminal,
        };
}

/// <summary>Authenticated host-to-module context for one effective HostEntry dispatch.</summary>
public sealed record SidecarActionEffectiveHostEntryContext(
    HostActionEntryRequestContext InitiatingContext,
    SidecarActionTerminalExecutionContext EffectiveContext,
    SidecarHostTerminalAuthority Authority)
{
    public bool IsWellFormed =>
        InitiatingContext is not null &&
        EffectiveContext is not null &&
        Authority is not null &&
        EffectiveContext.IsWellFormed;
}

public sealed record SidecarActionResultIdentity(
    Guid ResultId,
    Guid CallId,
    SharpClawActionKey ActionKey,
    int ActionVersion,
    string ResultTypeIdentity,
    string ContentHash);

public sealed record SidecarActionCapabilityResponse(
    SidecarActionResultIdentity? ResultIdentity,
    SidecarActionOutcomeEnvelope Outcome,
    SidecarTerminalContinuationResponse? Continuation,
    SidecarSafeFailureIdentity SafeFailure,
    bool Completed);

public sealed record SidecarHostTerminalAuthority(
    Guid AuthorityId,
    Guid SessionId,
    Guid RequestId,
    Guid CancellationId,
    Guid CallId,
    string ModuleId,
    string GraphId,
    SidecarActionInvocationKind Invocation,
    SharpClawActionKey ActionKey,
    int ActionVersion,
    string DescriptorHash,
    string EffectiveActionTypeIdentity,
    int EffectiveActionSchemaVersion,
    string EffectiveActionContentHash,
    int EffectiveActionByteLength,
    string ReceiptId,
    SharpClawActionKey ReceiptActionKey,
    int ReceiptActionVersion,
    Guid ReceiptCallId,
    int ReceiptAttempt,
    string ReceiptIdempotencyScope,
    string ReceiptContentHash,
    DateTimeOffset Deadline,
    DateTimeOffset IssuedAt,
    DateTimeOffset ExpiresAt,
    string Proof)
{
    public Guid TerminalId { get; init; }
    public string CanonicalBindingHash { get; init; } = string.Empty;
    public string SnapshotContentHash { get; init; } = string.Empty;
    public RequestPrincipal? Caller { get; init; }
    public ExtensionFeatureSet? Features { get; init; }
    public Guid TraceId { get; init; }
    public Guid IdempotencyKey { get; init; }
    public Guid InvocationId { get; init; }
    public Guid? ParentInvocationId { get; init; }
    public int Depth { get; init; }
    public int Attempt { get; init; }
    public SidecarCapabilityCallIdentity? RootPeerCall { get; init; }
    public SidecarNestedHostActionEntryRelay? NestedCarrierRelay { get; init; }
    public SidecarNestedHostActionEntryRelayOutcomeKind? NestedCarrierOutcomeKind { get; init; }
    public string NestedCarrierRequestFingerprint { get; init; } = string.Empty;
    public string HostContextBindingHash { get; init; } = string.Empty;
}

public sealed record SidecarActionTerminalExecutionContext(
    SidecarCapabilityCallIdentity Call,
    SidecarActionInvocationKind Invocation,
    SidecarActionDescriptorIdentity Descriptor,
    SidecarSerializedPayload EffectiveAction,
    ActionPipelineSnapshot Snapshot,
    Guid InvocationId,
    Guid? ParentInvocationId,
    int Depth,
    int Attempt,
    RequestPrincipal Caller,
    ExtensionFeatureSet Features,
    Guid TraceId,
    Guid IdempotencyKey,
    SidecarCancellationIdentity Cancellation,
    SidecarTerminalReceipt Receipt,
    DateTimeOffset Deadline)
{
    public bool IsWellFormed =>
        Call is not null &&
        Call.IsValid &&
        Enum.IsDefined(Invocation) &&
        Descriptor is not null &&
        EffectiveAction is not null &&
        Snapshot is not null &&
        !string.IsNullOrWhiteSpace(Snapshot.ContractHash) &&
        InvocationId != Guid.Empty &&
        Depth >= 0 &&
        Attempt >= 1 &&
        Caller is not null &&
        !string.IsNullOrWhiteSpace(Caller.SubjectId) &&
        Features is not null &&
        Features.Items is not null &&
        TraceId != Guid.Empty &&
        IdempotencyKey != Guid.Empty &&
        Cancellation is not null &&
        Receipt is not null &&
        Deadline > DateTimeOffset.MinValue;
}

public sealed record SidecarActionTerminalTransportRequest(
    SidecarCapabilityCallIdentity Call,
    SidecarActionInvocationKind Invocation,
    SidecarActionDescriptorIdentity Descriptor,
    SidecarSerializedPayload EffectiveAction,
    SidecarHostTerminalAuthority Authority,
    SidecarTerminalReceipt Receipt,
    SidecarCancellationIdentity Cancellation,
    DateTimeOffset Deadline)
{
    public SidecarActionTerminalExecutionContext? Context { get; init; }
    public SidecarNestedHostActionEntryRequest? NestedCarrierRequest { get; init; }
    public SidecarCrossSidecarActionEntryRequest? CrossSidecarActionRequest { get; init; }
    public Guid TerminalId { get; init; }
}

public sealed record SidecarTerminalExecutionResult(
    SidecarSerializedPayload? Result,
    SidecarSafeFailureIdentity? Failure,
    bool Completed);

public sealed record SidecarActionTerminalTransportResponse(
    SidecarActionResultIdentity? ResultIdentity,
    SidecarTerminalExecutionResult Execution,
    SidecarTerminalReceipt Receipt,
    SidecarSafeFailureIdentity SafeFailure)
{
    public Guid TerminalId { get; init; }
    public SidecarNestedHostActionEntryRelay? NestedCarrierRelay { get; init; }
    public SidecarHostTerminalAuthority? NestedCarrierAuthority { get; init; }
    public SidecarNestedHostActionEntryRelayOutcome? NestedCarrierOutcome { get; init; }
    public SidecarCrossSidecarActionEntryRelay? CrossSidecarRelay { get; init; }
    public SidecarCrossSidecarActionEntryOutcome? CrossSidecarOutcome { get; init; }
}

public static class SidecarCapabilityTransportValidation
{
    public static SidecarCapabilityValidationResult ValidateSerializedPayload(
        SidecarSerializedPayload? payload,
        bool required,
        int maximumBytes)
    {
        if (payload is null)
        {
            return required
                ? SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.InvalidPayload,
                    "The transport payload is required.")
                : SidecarCapabilityValidationResult.Accept();
        }

        if (!payload.IsValid || maximumBytes < 0)
            return SidecarCapabilityValidationResult.Reject(
                SidecarCapabilityErrors.InvalidPayload,
                "The transport payload identity is incomplete.");

        byte[] canonicalBytes;
        try
        {
            canonicalBytes = SidecarCapabilityTransportCodec.Serialize(payload.Value);
        }
        catch (JsonException)
        {
            return SidecarCapabilityValidationResult.Reject(
                SidecarCapabilityErrors.InvalidPayload,
                "The transport payload is not canonical JSON.");
        }

        if (payload.ByteLength != canonicalBytes.Length ||
            !string.Equals(
                payload.ContentHash,
                SidecarCapabilityTransportCodec.ComputeSha256(canonicalBytes),
                StringComparison.OrdinalIgnoreCase))
        {
            return SidecarCapabilityValidationResult.Reject(
                SidecarCapabilityErrors.InvalidPayload,
                "The transport payload hash or byte length is invalid.");
        }

        if (canonicalBytes.Length > maximumBytes)
            return SidecarCapabilityValidationResult.Reject(
                SidecarCapabilityErrors.PayloadTooLarge,
                "The transport payload exceeds its capability limit.");

        return SidecarCapabilityValidationResult.Accept();
    }

    public static SidecarCapabilityValidationResult ValidateFrame(
        ReadOnlySpan<byte> canonicalFrame,
        SidecarTransportFrameIdentity frameIdentity,
        int maximumBytes)
    {
        ArgumentNullException.ThrowIfNull(frameIdentity);

        if (!frameIdentity.IsValid ||
            frameIdentity.ByteLength != canonicalFrame.Length ||
            !string.Equals(
                frameIdentity.ContentHash,
                SidecarCapabilityTransportCodec.ComputeSha256(canonicalFrame),
                StringComparison.OrdinalIgnoreCase))
        {
            return SidecarCapabilityValidationResult.Reject(
                SidecarCapabilityErrors.InvalidPayload,
                "The canonical transport frame hash or byte length is invalid.");
        }

        if (canonicalFrame.Length > maximumBytes)
            return SidecarCapabilityValidationResult.Reject(
                SidecarCapabilityErrors.PayloadTooLarge,
                "The canonical transport frame exceeds its capability limit.");

        try
        {
            _ = JsonDocument.Parse(canonicalFrame.ToArray());
            return SidecarCapabilityValidationResult.Accept();
        }
        catch (JsonException)
        {
            return SidecarCapabilityValidationResult.Reject(
                SidecarCapabilityErrors.InvalidPayload,
                "The canonical transport frame is not valid JSON.");
        }
    }

    public static SidecarCapabilityValidationResult ValidateStorageRequest(
        SidecarStorageCapabilityRequest request,
        SidecarCapabilitySessionBinding binding,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(binding);

        if (!MatchesBinding(request.Call, binding, SidecarCapabilityKind.Storage) ||
            !string.Equals(request.ModuleId, request.Call.ModuleId, StringComparison.Ordinal) ||
            request.Cancellation.CancellationId != request.Call.CancellationId)
        {
            return SidecarCapabilityValidationResult.Reject(
                SidecarCapabilityErrors.SpoofedIdentity,
                "The storage request does not bind to the call identity.");
        }

        if (request.Deadline != request.Call.Deadline ||
            request.Deadline <= now ||
            request.Cancellation.ExpiresAt < request.Deadline)
        {
            return SidecarCapabilityValidationResult.Reject(
                SidecarCapabilityErrors.Expired,
                "The storage request deadline is not within the call authority.");
        }

        if (!request.ResultPayloadType.IsValid ||
            (request.Operation == SidecarStorageOperationKind.ListContracts &&
             (request.RequestPayload is not null || !string.IsNullOrEmpty(request.StorageName))) ||
            (request.Operation != SidecarStorageOperationKind.ListContracts &&
             (string.IsNullOrWhiteSpace(request.StorageName) || request.RequestPayload is null)))
        {
            return SidecarCapabilityValidationResult.Reject(
                SidecarCapabilityErrors.InvalidPayload,
                "The storage request payload does not match its operation.");
        }

        return ValidateSerializedPayload(
            request.RequestPayload,
            request.Operation != SidecarStorageOperationKind.ListContracts,
            binding.PayloadLimits.ProtocolMessageBytes);
    }

    public static SidecarCapabilityValidationResult ValidateStorageResponse(
        SidecarStorageCapabilityRequest request,
        SidecarStorageCapabilityResponse response,
        SidecarCapabilitySessionBinding binding)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(response);
        ArgumentNullException.ThrowIfNull(binding);

        if (response.ResultIdentity is null ||
            response.ResultIdentity.ResultId == Guid.Empty ||
            response.ResultIdentity.CallId != request.Call.CallId ||
            response.SafeFailure is null ||
            !SameSafeFailure(response.SafeFailure, binding.SafeFailure) ||
            (response.Completed && response.Error is not null))
        {
            return SidecarCapabilityValidationResult.Reject(
                SidecarCapabilityErrors.InvalidResponse,
                "The storage response does not bind to the request authority.");
        }

        var payloadResult = ValidateSerializedPayload(
            response.ResultPayload,
            false,
            binding.PayloadLimits.ProtocolMessageBytes);
        if (!payloadResult.Accepted)
            return payloadResult;

        if (response.ResultPayload is not null &&
            (!string.Equals(
                 response.ResultPayload.TypeIdentity,
                 request.ResultPayloadType.TypeIdentity,
                 StringComparison.Ordinal) ||
             response.ResultPayload.SchemaVersion != request.ResultPayloadType.SchemaVersion ||
             !string.Equals(
                 response.ResultIdentity.ContentHash,
                 response.ResultPayload.ContentHash,
                 StringComparison.OrdinalIgnoreCase)))
        {
            return SidecarCapabilityValidationResult.Reject(
                SidecarCapabilityErrors.InvalidResponse,
                "The storage result hash does not match the result payload.");
        }

        return SidecarCapabilityValidationResult.Accept();
    }

    public static SidecarCapabilityValidationResult ValidateResolvedNestedHostActionEntryRequest(
        SidecarNestedHostActionEntryRequest request,
        SidecarActionDescriptorIdentity resolvedDescriptor,
        HostActionEntryContribution resolvedContribution,
        SidecarCapabilitySessionBinding binding,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(resolvedDescriptor);
        ArgumentNullException.ThrowIfNull(resolvedContribution);
        ArgumentNullException.ThrowIfNull(binding);

        if (!request.IsWellFormed ||
            !IsValidDescriptor(resolvedDescriptor) ||
            !resolvedContribution.IsWellFormed ||
            request.Deadline <= now ||
            request.ExpiresAt < request.Deadline ||
            request.ExpiresAt > binding.ExpiresAt ||
            request.ActionKey != resolvedDescriptor.Key ||
            request.ActionVersion != resolvedDescriptor.Version ||
            !string.Equals(request.Action.TypeIdentity, resolvedDescriptor.InputTypeIdentity, StringComparison.Ordinal) ||
            request.Action.SchemaVersion != resolvedDescriptor.InputSchemaVersion ||
            resolvedContribution.Lineage.IsPayloadBound ||
            resolvedContribution.Lineage.ActionKey != resolvedDescriptor.Key ||
            resolvedContribution.Lineage.ActionVersion != resolvedDescriptor.Version ||
            !string.Equals(resolvedContribution.Lineage.DescriptorHash, resolvedDescriptor.DescriptorHash, StringComparison.Ordinal) ||
            !string.Equals(resolvedContribution.Lineage.InputTypeIdentity, resolvedDescriptor.InputTypeIdentity, StringComparison.Ordinal) ||
            resolvedContribution.Lineage.InputSchemaVersion != resolvedDescriptor.InputSchemaVersion ||
            !string.Equals(resolvedContribution.Lineage.InputSchemaHash, resolvedDescriptor.InputSchemaHash, StringComparison.Ordinal))
        {
            return SidecarCapabilityValidationResult.Reject(
                SidecarCapabilityErrors.SpoofedIdentity,
                "The resolved nested host action descriptor is not authorized for the request.");
        }

        return ValidateSerializedPayload(
            request.Action,
            required: true,
            binding.PayloadLimits.ActionInputBytes);
    }

    public static SidecarCapabilityValidationResult ValidateActionRequest(
        SidecarActionCapabilityRequest request,
        SidecarCapabilitySessionBinding binding,
        DateTimeOffset now,
        Func<SidecarHostTerminalAuthority, string, bool>? authenticateEffectiveHostEntryContext = null)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(binding);

        if (!MatchesBinding(request.Call, binding, SidecarCapabilityKind.Action) ||
            request.Cancellation.CancellationId != request.Call.CancellationId ||
            request.Deadline != request.Call.Deadline ||
            request.Deadline <= now ||
            request.Cancellation.ExpiresAt < request.Deadline)
        {
            return SidecarCapabilityValidationResult.Reject(
                SidecarCapabilityErrors.SpoofedIdentity,
                "The action request does not bind to the call authority.");
        }

        var requiresSnapshot = request.Invocation is SidecarActionInvocationKind.Run or SidecarActionInvocationKind.RunRequired;
        var hostEntry = request.Invocation == SidecarActionInvocationKind.HostEntry;
        var crossSidecarEntry = request.Invocation == SidecarActionInvocationKind.HostEntryCrossSidecar;
        var requiresEntryAuthority = hostEntry || crossSidecarEntry;
        if (!Enum.IsDefined(request.Invocation) ||
            !IsValidDescriptor(request.Descriptor) ||
            request.Action is null ||
            !string.Equals(request.Action.TypeIdentity, request.Descriptor.InputTypeIdentity, StringComparison.Ordinal) ||
            request.Action.SchemaVersion != request.Descriptor.InputSchemaVersion ||
            requiresSnapshot &&
            (request.Snapshot is null || string.IsNullOrWhiteSpace(request.Snapshot.ContractHash)) ||
            requiresEntryAuthority &&
            (request.Snapshot is not null ||
             (request.HostContext is null ? 0 : 1) +
                 (request.NestedCarrier is null ? 0 : 1) +
                 (request.CrossSidecarCarrier is null ? 0 : 1) != 1 ||
             request.HostContext is not null && !request.HostContext.IsWellFormed(now) ||
             request.NestedCarrier is not null && !request.NestedCarrier.IsWellFormed ||
             request.CrossSidecarCarrier is not null && !request.CrossSidecarCarrier.IsWellFormed ||
             crossSidecarEntry && request.CrossSidecarCarrier is null ||
             crossSidecarEntry && request.HostContext is not null ||
             crossSidecarEntry && request.NestedCarrier is not null ||
             crossSidecarEntry && request.Terminal is null ||
             crossSidecarEntry && request.CrossSidecarCarrier is not null &&
                 (request.CrossSidecarCarrier.Authority.TargetChildCall != request.Call ||
                  request.CrossSidecarCarrier.Descriptor != request.Descriptor) ||
               request.Terminal is null ||
               !request.Terminal.IsWellFormed) ||
             !requiresEntryAuthority &&
             (request.HostContext is not null ||
              request.Terminal is not null ||
               request.NestedCarrier is not null ||
               request.CrossSidecarCarrier is not null))
        {
            return SidecarCapabilityValidationResult.Reject(
                SidecarCapabilityErrors.InvalidPayload,
                "The action request does not contain a complete descriptor and payload identity.");
        }

        var payloadResult = ValidateSerializedPayload(
            request.Action,
            true,
            binding.PayloadLimits.ActionInputBytes);
        if (!payloadResult.Accepted)
            return payloadResult;

        if (crossSidecarEntry &&
            (request.CrossSidecarCarrier is null ||
             !string.Equals(request.CrossSidecarCarrier.Action.ContentHash, request.Action.ContentHash, StringComparison.OrdinalIgnoreCase) ||
             request.CrossSidecarCarrier.Action.ByteLength != request.Action.ByteLength ||
             request.CrossSidecarCarrier.Authority.TargetEntry.Descriptor != request.Descriptor))
        {
            return SidecarCapabilityValidationResult.Reject(
                SidecarCapabilityErrors.SpoofedIdentity,
                "The cross-sidecar action request does not match its host-issued carrier.");
        }

        if (hostEntry && request.HostContext is not null &&
            (request.HostContext.Contribution?.Lineage is null ||
             !string.Equals(request.HostContext.Contribution.Lineage.ActionKey.Value, request.Descriptor.Key.Value, StringComparison.Ordinal) ||
             request.HostContext.Contribution.Lineage.ActionVersion != request.Descriptor.Version ||
             !string.Equals(request.HostContext.Contribution.Lineage.DescriptorHash, request.Descriptor.DescriptorHash, StringComparison.Ordinal) ||
             !string.Equals(request.HostContext.Contribution.Lineage.InputTypeIdentity, request.Descriptor.InputTypeIdentity, StringComparison.Ordinal) ||
             request.HostContext.Contribution.Lineage.InputSchemaVersion != request.Descriptor.InputSchemaVersion ||
             !string.Equals(request.HostContext.Contribution.Lineage.InputSchemaHash, request.Descriptor.InputSchemaHash, StringComparison.Ordinal) ||
              request.EffectiveHostEntryContext is null &&
              request.HostContext.Contribution.Lineage.IsPayloadBound &&
             (!string.Equals(
                 request.HostContext.Contribution.Lineage.PayloadContentHash,
                 request.Action.ContentHash,
                 StringComparison.OrdinalIgnoreCase) ||
              request.HostContext.Contribution.Lineage.PayloadByteLength != request.Action.ByteLength)))
        {
            return SidecarCapabilityValidationResult.Reject(
                SidecarCapabilityErrors.SpoofedIdentity,
                "The host action entry context does not bind to the descriptor and payload.");
        }

        if (hostEntry && request.NestedCarrier is not null &&
            (request.NestedCarrier.CallId != request.Call.CallId ||
             request.NestedCarrier.Descriptor != request.Descriptor ||
             request.NestedCarrier.ActionKey != request.Descriptor.Key ||
             request.NestedCarrier.ActionVersion != request.Descriptor.Version ||
             !string.Equals(
                 request.NestedCarrier.DescriptorHash,
                 request.Descriptor.DescriptorHash,
                 StringComparison.Ordinal) ||
             !string.Equals(
                 request.NestedCarrier.ActionContentHash,
                 request.Action.ContentHash,
                 StringComparison.OrdinalIgnoreCase) ||
             request.NestedCarrier.ActionByteLength != request.Action.ByteLength))
        {
            return SidecarCapabilityValidationResult.Reject(
                SidecarCapabilityErrors.SpoofedIdentity,
                "The nested host action carrier does not bind to the descriptor and payload.");
        }

        if (hostEntry &&
            (request.Terminal!.ActionTypeIdentity != request.Descriptor.InputTypeIdentity ||
             request.Terminal.ActionSchemaVersion != request.Descriptor.InputSchemaVersion ||
             request.Terminal.ResultTypeIdentity != request.Descriptor.ResultTypeIdentity ||
             request.Terminal.ResultSchemaVersion != request.Descriptor.ResultSchemaVersion ||
             !string.Equals(
                 request.Terminal.DescriptorHash,
                 request.Descriptor.DescriptorHash,
                 StringComparison.Ordinal)))
        {
            return SidecarCapabilityValidationResult.Reject(
                SidecarCapabilityErrors.SpoofedIdentity,
                "The host action terminal does not bind to the descriptor.");
        }

        if (request.Continuation is not null &&
            (request.Continuation.ContinuationRequestId == Guid.Empty ||
             request.Continuation.Deadline > request.Deadline ||
             (request.Continuation.ReplacementResult is not null &&
              (!string.Equals(
                   request.Continuation.ReplacementResult.TypeIdentity,
                   request.Descriptor.ResultTypeIdentity,
                   StringComparison.Ordinal) ||
               request.Continuation.ReplacementResult.SchemaVersion != request.Descriptor.ResultSchemaVersion ||
               !ValidateSerializedPayload(
                   request.Continuation.ReplacementResult,
                   false,
                   binding.PayloadLimits.ActionResultBytes).Accepted))))
        {
            return SidecarCapabilityValidationResult.Reject(
                SidecarCapabilityErrors.InvalidPayload,
                "The terminal continuation request is outside the action authority.");
        }

        if (request.EffectiveHostEntryContext is not null)
        {
            var effectiveContextResult = ValidateEffectiveHostEntryContext(
                request,
                request.EffectiveHostEntryContext,
                binding,
                now,
                authenticateEffectiveHostEntryContext);
            if (!effectiveContextResult.Accepted)
                return effectiveContextResult;
        }

        return SidecarCapabilityValidationResult.Accept();
    }

    public static SidecarCapabilityValidationResult ValidateEffectiveHostEntryContext(
        SidecarActionCapabilityRequest request,
        SidecarActionEffectiveHostEntryContext context,
        SidecarCapabilitySessionBinding binding,
        DateTimeOffset now,
        Func<SidecarHostTerminalAuthority, string, bool>? authenticate)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(binding);

        if (request.Invocation != SidecarActionInvocationKind.HostEntry ||
            request.HostContext is null ||
            !context.IsWellFormed ||
            !HostActionEntryAuthorityValidator.SameContext(
                request.HostContext,
                context.InitiatingContext))
        {
            return SidecarCapabilityValidationResult.Reject(
                SidecarCapabilityErrors.SpoofedIdentity,
                "The effective HostEntry context does not bind to the initiating context.");
        }

        var effective = context.EffectiveContext;
        if (effective.Call != request.Call ||
            effective.Invocation != request.Invocation ||
            effective.Descriptor != request.Descriptor ||
            !SamePayload(effective.EffectiveAction, request.Action) ||
            effective.Cancellation != request.Cancellation ||
            effective.Deadline != request.Deadline ||
            effective.InvocationId != context.InitiatingContext.InvocationId ||
            effective.ParentInvocationId != context.InitiatingContext.ParentInvocationId ||
            effective.Depth != context.InitiatingContext.Depth ||
            effective.Attempt != context.InitiatingContext.Attempt ||
            !SamePrincipal(effective.Caller, context.InitiatingContext.Caller) ||
            !SameFeatures(effective.Features, context.InitiatingContext.Features) ||
            effective.TraceId != context.InitiatingContext.TraceId ||
            effective.IdempotencyKey != context.InitiatingContext.IdempotencyKey ||
            effective.Receipt is null ||
            effective.Receipt.CallId != request.Call.CallId ||
            effective.Receipt.ActionKey != request.Descriptor.Key ||
            effective.Receipt.ActionVersion != request.Descriptor.Version ||
            !string.Equals(
                ComputeSnapshotHash(effective.Snapshot),
                context.Authority.SnapshotContentHash,
                StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(
                context.Authority.HostContextBindingHash,
                ComputeHostActionEntryContextBindingHash(context.InitiatingContext),
                StringComparison.OrdinalIgnoreCase))
        {
            return SidecarCapabilityValidationResult.Reject(
                SidecarCapabilityErrors.SpoofedIdentity,
                "The effective HostEntry context does not bind to the dispatcher result.");
        }

        var terminalRequest = new SidecarActionTerminalTransportRequest(
            effective.Call,
            effective.Invocation,
            effective.Descriptor,
            effective.EffectiveAction,
            context.Authority,
            effective.Receipt,
            effective.Cancellation,
            effective.Deadline)
        {
            Context = effective,
            TerminalId = context.Authority.TerminalId,
        };
        if (authenticate is null ||
            !ValidateHostTerminalAuthority(
                terminalRequest,
                binding,
                now,
                authenticate))
        {
            return SidecarCapabilityValidationResult.Reject(
                SidecarCapabilityErrors.Unauthorized,
                "The effective HostEntry context proof was not accepted.");
        }

        return SidecarCapabilityValidationResult.Accept();
    }

    public static SidecarCapabilityValidationResult ValidateActionResponse(
        SidecarActionCapabilityRequest request,
        SidecarActionCapabilityResponse response,
        SidecarCapabilitySessionBinding binding,
        SidecarCapabilitySession session)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(response);
        ArgumentNullException.ThrowIfNull(binding);
        ArgumentNullException.ThrowIfNull(session);

        if (response.Outcome is null ||
            response.SafeFailure is null ||
            !SameSafeFailure(response.SafeFailure, binding.SafeFailure) ||
            !response.Completed)
        {
            return SidecarCapabilityValidationResult.Reject(
                SidecarCapabilityErrors.InvalidResponse,
                "The action response does not bind to the action request.");
        }

        var expectedReceipt = request.Continuation?.Receipt;
        if (response.Outcome.TerminalCallCount == 1)
        {
            session.TryGetTerminalReceipt(request.Call.CallId, out var recordedReceipt);
            if (recordedReceipt is not null)
            {
                if (expectedReceipt is not null && !SameReceipt(expectedReceipt, recordedReceipt))
                {
                    return SidecarCapabilityValidationResult.Reject(
                        SidecarCapabilityErrors.InvalidResponse,
                        "The action response receipt differs from the recorded host receipt.");
                }

                expectedReceipt ??= recordedReceipt;
            }

            if (expectedReceipt is null)
            {
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.InvalidResponse,
                    "The action response has no host receipt authority.");
            }
        }

        var outcomeResult = ValidateActionOutcome(
            response.Outcome,
            request.Descriptor,
            binding,
            request.Call.CallId,
            expectedReceipt);
        if (!outcomeResult.Accepted)
            return outcomeResult;

        if (response.Outcome.Result is null && response.ResultIdentity is not null ||
            response.Outcome.Result is not null &&
            (response.ResultIdentity is null ||
             response.ResultIdentity.ResultId == Guid.Empty ||
             response.ResultIdentity.CallId != request.Call.CallId ||
             response.ResultIdentity.ActionKey != request.Descriptor.Key ||
             response.ResultIdentity.ActionVersion != request.Descriptor.Version ||
             !string.Equals(response.ResultIdentity.ResultTypeIdentity, request.Descriptor.ResultTypeIdentity, StringComparison.Ordinal) ||
             response.Outcome.Result.SchemaVersion != request.Descriptor.ResultSchemaVersion ||
             !string.Equals(response.ResultIdentity.ContentHash, response.Outcome.Result.ContentHash, StringComparison.OrdinalIgnoreCase)))
        {
            return SidecarCapabilityValidationResult.Reject(
                SidecarCapabilityErrors.InvalidResponse,
                "The action result identity does not match the outcome.");
        }

        if (response.Continuation?.Outcome is not null)
        {
            var nestedOutcome = ValidateNestedOutcome(
                response.Continuation.Outcome,
                request.Descriptor,
                binding,
                request.Call.CallId,
                expectedReceipt);
            if (!nestedOutcome.Accepted)
                return nestedOutcome;
        }

        if (request.Continuation is null && response.Continuation is not null ||
            request.Continuation is not null &&
            (response.Continuation is null ||
             response.Continuation.ContinuationRequestId != request.Continuation.ContinuationRequestId ||
             response.Continuation.SafeFailure is null ||
             !SameSafeFailure(response.Continuation.SafeFailure, binding.SafeFailure) ||
             response.Continuation.Outcome is not null &&
             (response.Continuation.Outcome.SafeFailure is null ||
              !SameSafeFailure(response.Continuation.Outcome.SafeFailure, binding.SafeFailure)) ||
             response.Continuation.Accepted != (response.Continuation.Outcome is not null)))
        {
            return SidecarCapabilityValidationResult.Reject(
                SidecarCapabilityErrors.InvalidResponse,
                "The action continuation response does not bind to the request.");
        }

        return SidecarCapabilityValidationResult.Accept();
    }

    public static SidecarCapabilityValidationResult ValidateActionTerminalRequest(
        SidecarActionCapabilityRequest initiatingRequest,
        SidecarActionTerminalTransportRequest request,
        SidecarCapabilitySessionBinding binding,
        DateTimeOffset now,
        Func<SidecarHostTerminalAuthority, string, bool> authenticateHostTerminalAuthority)
    {
        ArgumentNullException.ThrowIfNull(initiatingRequest);
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(binding);
        ArgumentNullException.ThrowIfNull(authenticateHostTerminalAuthority);

        if (!MatchesBinding(request.Call, binding, SidecarCapabilityKind.Action) ||
            request.Call != initiatingRequest.Call ||
            request.Invocation != initiatingRequest.Invocation ||
            request.Descriptor != initiatingRequest.Descriptor ||
            request.Cancellation != initiatingRequest.Cancellation ||
            request.Deadline != initiatingRequest.Deadline ||
            initiatingRequest.Invocation is SidecarActionInvocationKind.HostEntry or SidecarActionInvocationKind.HostEntryCrossSidecar &&
            (initiatingRequest.Terminal is null ||
             !initiatingRequest.Terminal.IsWellFormed ||
             !string.Equals(initiatingRequest.Terminal.ActionTypeIdentity, initiatingRequest.Descriptor.InputTypeIdentity, StringComparison.Ordinal) ||
             initiatingRequest.Terminal.ActionSchemaVersion != initiatingRequest.Descriptor.InputSchemaVersion ||
             !string.Equals(initiatingRequest.Terminal.ResultTypeIdentity, initiatingRequest.Descriptor.ResultTypeIdentity, StringComparison.Ordinal) ||
             initiatingRequest.Terminal.ResultSchemaVersion != initiatingRequest.Descriptor.ResultSchemaVersion ||
             !string.Equals(initiatingRequest.Terminal.DescriptorHash, initiatingRequest.Descriptor.DescriptorHash, StringComparison.Ordinal) ||
             request.TerminalId != initiatingRequest.Terminal.TerminalId ||
             initiatingRequest.HostContext is null && initiatingRequest.NestedCarrier is null && initiatingRequest.CrossSidecarCarrier is null ||
             initiatingRequest.HostContext is not null &&
             (request.Context is null ||
              !MatchesInitiatingHostContext(initiatingRequest.HostContext, request) ||
              !string.Equals(
                  request.Authority.HostContextBindingHash,
                  ComputeHostActionEntryContextBindingHash(initiatingRequest.HostContext),
                  StringComparison.OrdinalIgnoreCase)) ||
             initiatingRequest.NestedCarrier is not null &&
             (request.Context is null ||
              request.Context.InvocationId != initiatingRequest.NestedCarrier.InvocationId) ||
             initiatingRequest.CrossSidecarCarrier is not null &&
             (request.Context is null ||
              !MatchesCrossSidecarContext(request.Context, initiatingRequest.CrossSidecarCarrier))) ||
            initiatingRequest.Invocation is not (SidecarActionInvocationKind.HostEntry or SidecarActionInvocationKind.HostEntryCrossSidecar) &&
            request.TerminalId != Guid.Empty ||
             request.NestedCarrierRequest is not null &&
             (initiatingRequest.Invocation != SidecarActionInvocationKind.HostEntry ||
              !MatchesNestedRequest(initiatingRequest, request, request.NestedCarrierRequest, binding)) ||
            !ValidateHostTerminalAuthority(
                request,
                binding,
                now,
                authenticateHostTerminalAuthority))
        {
            return SidecarCapabilityValidationResult.Reject(
                SidecarCapabilityErrors.SpoofedIdentity,
                "The terminal request does not bind to the initiating action request.");
        }

        if (initiatingRequest.EffectiveHostEntryContext is { } effectiveHostEntryContext &&
            (!MatchesEffectiveDispatcherContext(
                 effectiveHostEntryContext.EffectiveContext,
                 request.Context!) ||
             !SameTerminalAuthority(
                 effectiveHostEntryContext.Authority,
                 request.Authority)))
        {
            return SidecarCapabilityValidationResult.Reject(
                SidecarCapabilityErrors.SpoofedIdentity,
                "The terminal request does not match the authenticated dispatcher context.");
        }

        if (
            request.Deadline != request.Call.Deadline ||
            request.Deadline <= now ||
            request.Cancellation.CancellationId != request.Call.CancellationId ||
            request.Cancellation.ExpiresAt < request.Deadline ||
            !IsValidDescriptor(request.Descriptor) ||
            request.EffectiveAction is null ||
            request.Receipt is null ||
            request.Context is null ||
            !request.Context.IsWellFormed ||
            request.Context.Call != request.Call ||
            request.Context.Invocation != request.Invocation ||
            request.Context.Descriptor != request.Descriptor ||
            !SamePayload(request.Context.EffectiveAction, request.EffectiveAction) ||
            request.Context.Cancellation != request.Cancellation ||
            request.Context.Receipt != request.Receipt ||
            request.Context.Deadline != request.Deadline ||
            request.Context.Attempt != request.Receipt.Attempt ||
            !string.Equals(request.EffectiveAction.TypeIdentity, request.Descriptor.InputTypeIdentity, StringComparison.Ordinal) ||
            request.EffectiveAction.SchemaVersion != request.Descriptor.InputSchemaVersion ||
            request.Receipt.CallId != request.Call.CallId ||
            request.Receipt.ActionKey != request.Descriptor.Key ||
            request.Receipt.ActionVersion != request.Descriptor.Version)
        {
            return SidecarCapabilityValidationResult.Reject(
                SidecarCapabilityErrors.InvalidPayload,
                "The terminal request does not bind to the effective action.");
        }

        var payloadResult = ValidateSerializedPayload(
            request.EffectiveAction,
            true,
            binding.PayloadLimits.ActionInputBytes);
        if (!payloadResult.Accepted)
            return payloadResult;

        return ValidateReceipt(request.Receipt, request.Call.CallId, request.Descriptor, required: true);
    }

    public static SidecarCapabilityValidationResult ValidateActionTerminalResponse(
        SidecarActionTerminalTransportRequest request,
        SidecarActionTerminalTransportResponse response,
        SidecarCapabilitySessionBinding binding,
        Func<SidecarHostTerminalAuthority, string, bool>? authenticateNestedCarrierAuthority = null)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(response);
        ArgumentNullException.ThrowIfNull(binding);

        if (request.CrossSidecarActionRequest is not null ||
            response.CrossSidecarRelay is not null ||
            response.CrossSidecarOutcome is not null)
        {
            return SidecarCapabilityValidationResult.Reject(
                SidecarCapabilityErrors.InvalidResponse,
                "Cross-sidecar terminal responses require target-session validation.");
        }

        var nestedOutcome = response.NestedCarrierOutcome;
        var nestedKind = nestedOutcome?.Kind;
        var nestedAuthority = response.NestedCarrierAuthority;
        var nestedRelayValid = request.NestedCarrierRequest is null
            ? response.NestedCarrierRelay is null &&
              nestedAuthority is null &&
              nestedOutcome is null
            : nestedOutcome is not null &&
              nestedOutcome.IsWellFormed &&
              request.NestedCarrierRequest.IsWellFormed &&
              nestedAuthority is not null &&
              nestedAuthority.NestedCarrierOutcomeKind == nestedKind &&
              SameNestedCarrierAuthorityBinding(request, response.NestedCarrierRelay, nestedKind!.Value, nestedAuthority) &&
              authenticateNestedCarrierAuthority is not null &&
              authenticateNestedCarrierAuthority(
                  nestedAuthority,
                  ComputeTerminalAuthorityBindingHash(nestedAuthority)) &&
              (nestedKind == SidecarNestedHostActionEntryRelayOutcomeKind.Issued
                  ? response.NestedCarrierRelay is not null &&
                    MatchesNestedRelay(request, response.NestedCarrierRelay, binding) &&
                    nestedOutcome.Failure is null
                  : response.NestedCarrierRelay is null &&
                    nestedOutcome.Failure is not null &&
                    SameSafeFailure(nestedOutcome.Failure, binding.SafeFailure));

        var nestedExecutionValid = request.NestedCarrierRequest is null ||
            (nestedKind == SidecarNestedHostActionEntryRelayOutcomeKind.Issued
                ? response.Execution?.Result is not null &&
                  response.Execution.Failure is null &&
                  response.ResultIdentity is not null
                : response.Execution?.Result is null &&
                  response.Execution?.Failure is not null &&
                  response.ResultIdentity is null &&
                  SameSafeFailure(response.Execution.Failure, binding.SafeFailure));

        if (!nestedRelayValid ||
            !nestedExecutionValid ||
            response.TerminalId != request.TerminalId ||
            response.Execution is null ||
            !response.Execution.Completed ||
            response.Receipt != request.Receipt ||
            response.SafeFailure is null ||
            !SameSafeFailure(response.SafeFailure, binding.SafeFailure) ||
            response.Execution.Result is not null && response.Execution.Failure is not null ||
            response.Execution.Result is null && response.Execution.Failure is null ||
            response.Execution.Failure is not null && response.ResultIdentity is not null)
        {
            return SidecarCapabilityValidationResult.Reject(
                SidecarCapabilityErrors.InvalidResponse,
                "The terminal response does not bind to the terminal request.");
        }

        var payloadResult = ValidateSerializedPayload(
            response.Execution.Result,
            false,
            binding.PayloadLimits.ActionResultBytes);
        if (!payloadResult.Accepted)
            return payloadResult;

        if (response.Execution.Result is not null &&
            (response.ResultIdentity is null ||
             response.ResultIdentity.ResultId == Guid.Empty ||
             response.ResultIdentity.CallId != request.Call.CallId ||
             response.ResultIdentity.ActionKey != request.Descriptor.Key ||
             response.ResultIdentity.ActionVersion != request.Descriptor.Version ||
             !string.Equals(response.ResultIdentity.ResultTypeIdentity, request.Descriptor.ResultTypeIdentity, StringComparison.Ordinal) ||
             !string.Equals(response.Execution.Result.TypeIdentity, request.Descriptor.ResultTypeIdentity, StringComparison.Ordinal) ||
             response.Execution.Result.SchemaVersion != request.Descriptor.ResultSchemaVersion ||
             !string.Equals(response.ResultIdentity.ContentHash, response.Execution.Result.ContentHash, StringComparison.OrdinalIgnoreCase)))
        {
            return SidecarCapabilityValidationResult.Reject(
                SidecarCapabilityErrors.InvalidResponse,
                "The terminal result does not match the terminal receipt, descriptor, or payload.");
        }

        if (response.Execution.Failure is not null &&
            !SameSafeFailure(response.Execution.Failure, binding.SafeFailure))
        {
            return SidecarCapabilityValidationResult.Reject(
                SidecarCapabilityErrors.InvalidResponse,
                "The terminal failure is not the session safe-failure identity.");
        }

        return SidecarCapabilityValidationResult.Accept();
    }

    public static SidecarCapabilityValidationResult ValidateActionTerminalResponse(
        SidecarActionTerminalTransportRequest request,
        SidecarActionTerminalTransportResponse response,
        SidecarCapabilitySessionBinding sourceBinding,
        SidecarCapabilitySessionBinding targetBinding,
        DateTimeOffset now,
        Func<SidecarCrossSidecarActionEntryAuthority, string, bool> authenticate)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(response);

        if (request.CrossSidecarActionRequest is null)
        {
            return ValidateActionTerminalResponse(
                request,
                response,
                sourceBinding,
                authenticateNestedCarrierAuthority: null);
        }

        return ValidateCrossSidecarActionTerminalResponse(
            request,
            response,
            sourceBinding,
            targetBinding,
            now,
            authenticate);
    }

    public static SidecarCapabilityValidationResult ValidateCrossSidecarActionTerminalResponse(
        SidecarActionTerminalTransportRequest request,
        SidecarActionTerminalTransportResponse response,
        SidecarCapabilitySessionBinding sourceBinding,
        SidecarCapabilitySessionBinding targetBinding,
        DateTimeOffset now,
        Func<SidecarCrossSidecarActionEntryAuthority, string, bool> authenticate)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(response);
        ArgumentNullException.ThrowIfNull(sourceBinding);
        ArgumentNullException.ThrowIfNull(targetBinding);
        ArgumentNullException.ThrowIfNull(authenticate);

        var childRequest = request.CrossSidecarActionRequest;
        var relay = response.CrossSidecarRelay;
        if (!MatchesBinding(request.Call, sourceBinding, SidecarCapabilityKind.Action) ||
            request.TerminalId == Guid.Empty ||
            request.Receipt is null ||
            request.Receipt.CallId != request.Call.CallId ||
            response.TerminalId != request.TerminalId ||
            response.Receipt != request.Receipt ||
            childRequest is null ||
            relay is null ||
            !relay.IsWellFormed)
        {
            return SidecarCapabilityValidationResult.Reject(
                SidecarCapabilityErrors.InvalidResponse,
                "The cross-sidecar terminal response has no authenticated child relay.");
        }

        var requestResult = SidecarCrossSidecarActionEntryValidation.ValidateRequest(
            childRequest,
            request.Call,
            sourceBinding,
            now);
        if (!requestResult.Accepted ||
            relay.Carrier.Authority.SourceParentCall != request.Call ||
            relay.TargetEntry.Descriptor.Key != childRequest.ActionKey ||
            relay.TargetEntry.Descriptor.Version != childRequest.ActionVersion ||
            !string.Equals(
                relay.Carrier.Action.ContentHash,
                childRequest.Action.ContentHash,
                StringComparison.OrdinalIgnoreCase) ||
            relay.Carrier.Action.ByteLength != childRequest.Action.ByteLength)
        {
            return SidecarCapabilityValidationResult.Reject(
                SidecarCapabilityErrors.SpoofedIdentity,
                "The cross-sidecar relay does not bind to the parent terminal request.");
        }

        var carrierResult = SidecarCrossSidecarActionEntryValidation.ValidateCarrier(
            relay.Carrier,
            targetBinding,
            now,
            authenticate);
        if (!carrierResult.Accepted)
            return carrierResult;

        if (response.CrossSidecarOutcome is not null)
        {
            if (!response.CrossSidecarOutcome.IsWellFormed ||
                response.CrossSidecarOutcome.Authority is null)
            {
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.InvalidResponse,
                    "The cross-sidecar outcome authority is missing or malformed.");
            }

            var outcomeAuthority = response.CrossSidecarOutcome.Authority;
            if (outcomeAuthority.TargetChildCall != relay.Carrier.Authority.TargetChildCall ||
                response.ResultIdentity != outcomeAuthority.ResultIdentity ||
                response.Execution != outcomeAuthority.Execution ||
                response.SafeFailure != outcomeAuthority.ResponseSafeFailure ||
                response.CrossSidecarOutcome.Outcome != outcomeAuthority.OutcomeEnvelope)
            {
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.SpoofedIdentity,
                    "The cross-sidecar outcome does not bind to its authenticated terminal authority.");
            }

            return SidecarCrossSidecarActionEntryValidation.ValidateOutcome(
                response.CrossSidecarOutcome,
                targetBinding,
                now,
                authenticate);
        }

        if (response.CrossSidecarOutcome is not null)
        {
            return SidecarCapabilityValidationResult.Reject(
                SidecarCapabilityErrors.InvalidResponse,
                "The cross-sidecar relay response has an invalid completion shape.");
        }

        if (response.Execution is null ||
            response.ResultIdentity is not null ||
            response.Execution.Completed ||
            response.Execution.Result is not null ||
            response.Execution.Failure is not null ||
            response.SafeFailure != sourceBinding.SafeFailure)
        {
            return SidecarCapabilityValidationResult.Reject(
                SidecarCapabilityErrors.InvalidResponse,
                "A relay-only cross-sidecar response must use the neutral terminal envelope.");
        }

        return SidecarCapabilityValidationResult.Accept();
    }

    private static bool IsValidDescriptor(SidecarActionDescriptorIdentity descriptor) =>
        descriptor is not null && descriptor.IsWellFormed;

    private static bool MatchesCrossSidecarContext(
        SidecarActionTerminalExecutionContext context,
        SidecarCrossSidecarActionEntryCarrier carrier) =>
        context.InvocationId == carrier.Authority.TargetChildInvocationId &&
        context.ParentInvocationId == carrier.Authority.SourceParentInvocationId &&
        context.Call == carrier.Authority.TargetChildCall &&
        context.Descriptor == carrier.Authority.Descriptor &&
        context.Caller == carrier.Authority.Caller &&
        context.Features == carrier.Authority.Features &&
        context.TraceId == carrier.Authority.TraceId &&
        context.IdempotencyKey == carrier.Authority.IdempotencyKey &&
        context.Depth == carrier.Authority.Depth &&
        context.Attempt == carrier.Authority.Attempt &&
        context.Deadline == carrier.Authority.Deadline &&
        context.Cancellation.CancellationId == carrier.Authority.Cancellation.CancellationId &&
        string.Equals(
            context.Cancellation.AuthorityHash,
            carrier.Authority.Cancellation.AuthorityHash,
            StringComparison.OrdinalIgnoreCase) &&
        string.Equals(
            SidecarCapabilityTransportValidation.ComputeSnapshotHash(context.Snapshot),
            carrier.Authority.SnapshotContentHash,
            StringComparison.OrdinalIgnoreCase);

    private static bool MatchesBinding(
        SidecarCapabilityCallIdentity call,
        SidecarCapabilitySessionBinding binding,
        SidecarCapabilityKind capability) =>
        call.IsValid &&
        call.Capability == capability &&
        call.SessionId == binding.SessionId &&
        call.RequestId == binding.RequestId &&
        call.CancellationId == binding.CancellationId &&
        string.Equals(call.ModuleId, binding.ModuleId, StringComparison.Ordinal) &&
        string.Equals(call.GraphId, binding.GraphId, StringComparison.Ordinal);

    public static SidecarCapabilityValidationResult ValidateReceipt(
        SidecarTerminalReceipt? receipt,
        Guid callId,
        SidecarActionDescriptorIdentity descriptor,
        bool required = false)
    {
        if (receipt is null)
            return required
                ? SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.InvalidResponse,
                    "The terminal receipt is required for this outcome.")
                : SidecarCapabilityValidationResult.Accept();

        if (string.IsNullOrWhiteSpace(receipt.ReceiptId) ||
            receipt.CallId != callId ||
            receipt.ActionKey != descriptor.Key ||
            receipt.ActionVersion != descriptor.Version ||
            receipt.Attempt < 1 ||
            string.IsNullOrWhiteSpace(receipt.IdempotencyScope) ||
            string.IsNullOrWhiteSpace(receipt.ContentHash))
        {
            return SidecarCapabilityValidationResult.Reject(
                SidecarCapabilityErrors.InvalidResponse,
                "The terminal receipt does not bind to the action call.");
        }

        return SidecarCapabilityValidationResult.Accept();
    }

    private static SidecarCapabilityValidationResult ValidateActionOutcome(
        SidecarActionOutcomeEnvelope outcome,
        SidecarActionDescriptorIdentity descriptor,
        SidecarCapabilitySessionBinding binding,
        Guid callId,
        SidecarTerminalReceipt? expectedReceipt)
    {
        if (outcome.TerminalCallCount is < 0 or > 1 ||
            outcome.SafeFailure is null ||
            !SameSafeFailure(outcome.SafeFailure, binding.SafeFailure))
        {
            return SidecarCapabilityValidationResult.Reject(
                SidecarCapabilityErrors.InvalidResponse,
                "The action outcome has invalid terminal or safe-failure state.");
        }

        var hasResult = outcome.Result is not null;
        var hasError = outcome.Error is not null;
        var hasUncertainty = outcome.Uncertainty is not null;
        var validShape = outcome.Kind switch
        {
            ActionOutcomeKind.Completed => hasResult && !hasError && !hasUncertainty && outcome.Continuation is null,
            ActionOutcomeKind.Cancelled => !hasResult && !hasUncertainty && outcome.Continuation is null,
            ActionOutcomeKind.Deferred => !hasResult && !hasError && !hasUncertainty && outcome.Continuation is not null,
            ActionOutcomeKind.Failed => !hasResult && hasError && !hasUncertainty && outcome.Continuation is null,
            ActionOutcomeKind.Uncertain => !hasResult && !hasError && hasUncertainty && outcome.Continuation is null,
            _ => false,
        };
        if (!validShape || outcome.TerminalCallCount == 0 && outcome.Receipt is not null)
        {
            return SidecarCapabilityValidationResult.Reject(
                SidecarCapabilityErrors.InvalidResponse,
                "The action outcome shape does not match its outcome kind and terminal stage.");
        }

        var payloadResult = ValidateSerializedPayload(
            outcome.Result,
            false,
            binding.PayloadLimits.ActionResultBytes);
        if (!payloadResult.Accepted)
            return payloadResult;

        if (outcome.Result is not null &&
            (!string.Equals(outcome.Result.TypeIdentity, descriptor.ResultTypeIdentity, StringComparison.Ordinal) ||
             outcome.Result.SchemaVersion != descriptor.ResultSchemaVersion))
        {
            return SidecarCapabilityValidationResult.Reject(
                SidecarCapabilityErrors.InvalidResponse,
                "The action result type does not match the descriptor.");
        }

        if (outcome.TerminalCallCount == 1)
        {
            var receiptResult = ValidateReceipt(outcome.Receipt, callId, descriptor, required: true);
            if (!receiptResult.Accepted ||
                expectedReceipt is null ||
                !SameReceipt(outcome.Receipt!, expectedReceipt))
            {
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.InvalidResponse,
                    "The action receipt does not match host receipt authority.");
            }
        }

        return SidecarCapabilityValidationResult.Accept();
    }

    public static string ComputeTerminalAuthorityBindingHash(
        SidecarHostTerminalAuthority authority)
    {
        ArgumentNullException.ThrowIfNull(authority);

        var canonical = new
        {
            authority.AuthorityId,
            authority.TerminalId,
            authority.SessionId,
            authority.RequestId,
            authority.CancellationId,
            authority.CallId,
            authority.ModuleId,
            authority.GraphId,
            authority.Invocation,
            ActionKey = authority.ActionKey.Value,
            authority.ActionVersion,
            authority.DescriptorHash,
            authority.EffectiveActionTypeIdentity,
            authority.EffectiveActionSchemaVersion,
            authority.EffectiveActionContentHash,
            authority.EffectiveActionByteLength,
            authority.ReceiptId,
            ReceiptActionKey = authority.ReceiptActionKey.Value,
            authority.ReceiptActionVersion,
            authority.ReceiptCallId,
            authority.ReceiptAttempt,
            authority.ReceiptIdempotencyScope,
            authority.ReceiptContentHash,
            authority.Deadline,
            authority.IssuedAt,
            authority.ExpiresAt,
            authority.SnapshotContentHash,
            authority.HostContextBindingHash,
            Caller = authority.Caller is null
                ? null
                : Convert.ToBase64String(SidecarCapabilityTransportCodec.Serialize(authority.Caller)),
            Features = authority.Features is null
                ? null
                : Convert.ToBase64String(SidecarCapabilityTransportCodec.Serialize(authority.Features)),
            authority.TraceId,
            authority.IdempotencyKey,
            authority.InvocationId,
            authority.ParentInvocationId,
            authority.Depth,
            authority.Attempt,
            RootPeerCall = authority.RootPeerCall is null
                ? null
                : new
                {
                    authority.RootPeerCall.SessionId,
                    authority.RootPeerCall.RequestId,
                    authority.RootPeerCall.CancellationId,
                    authority.RootPeerCall.CallId,
                    authority.RootPeerCall.ReplayNonce,
                    authority.RootPeerCall.ModuleId,
                    authority.RootPeerCall.GraphId,
                    authority.RootPeerCall.Capability,
                    authority.RootPeerCall.Sequence,
                    authority.RootPeerCall.Deadline,
                },
            authority.NestedCarrierOutcomeKind,
            authority.NestedCarrierRequestFingerprint,
            NestedCarrierRelay = authority.NestedCarrierRelay is null
                ? null
                : new
                {
                    Call = new
                    {
                        authority.NestedCarrierRelay.Call.SessionId,
                        authority.NestedCarrierRelay.Call.RequestId,
                        authority.NestedCarrierRelay.Call.CancellationId,
                        authority.NestedCarrierRelay.Call.CallId,
                        authority.NestedCarrierRelay.Call.ReplayNonce,
                        authority.NestedCarrierRelay.Call.ModuleId,
                        authority.NestedCarrierRelay.Call.GraphId,
                        authority.NestedCarrierRelay.Call.Capability,
                        authority.NestedCarrierRelay.Call.Sequence,
                        authority.NestedCarrierRelay.Call.Deadline,
                    },
                    Carrier = new
                    {
                        authority.NestedCarrierRelay.Carrier.CarrierId,
                        authority.NestedCarrierRelay.Carrier.ParentCallId,
                        authority.NestedCarrierRelay.Carrier.CallId,
                        authority.NestedCarrierRelay.Carrier.InvocationId,
                        ActionKey = authority.NestedCarrierRelay.Carrier.ActionKey.Value,
                        authority.NestedCarrierRelay.Carrier.ActionVersion,
                        authority.NestedCarrierRelay.Carrier.DescriptorHash,
                        authority.NestedCarrierRelay.Carrier.ActionContentHash,
                        authority.NestedCarrierRelay.Carrier.ActionByteLength,
                        authority.NestedCarrierRelay.Carrier.BindingGeneration,
                        authority.NestedCarrierRelay.Carrier.ExpiresAt,
                        HandleHash = SidecarCapabilityTransportCodec.ComputeSha256(
                            Encoding.UTF8.GetBytes(authority.NestedCarrierRelay.Carrier.Handle)),
                    },
                     Descriptor = new
                     {
                        ActionKey = authority.NestedCarrierRelay.Descriptor.Key.Value,
                        authority.NestedCarrierRelay.Descriptor.Version,
                        authority.NestedCarrierRelay.Descriptor.Category,
                        authority.NestedCarrierRelay.Descriptor.InputTypeIdentity,
                        authority.NestedCarrierRelay.Descriptor.InputSchemaHash,
                        authority.NestedCarrierRelay.Descriptor.InputSchemaVersion,
                        authority.NestedCarrierRelay.Descriptor.ResultTypeIdentity,
                        authority.NestedCarrierRelay.Descriptor.ResultSchemaHash,
                        authority.NestedCarrierRelay.Descriptor.ResultSchemaVersion,
                         authority.NestedCarrierRelay.Descriptor.DescriptorHash,
                     },
                     RootBudgetId = authority.NestedCarrierRelay.RootBudgetId,
                     PeerBindingGeneration = authority.NestedCarrierRelay.PeerBindingGeneration,
                     PeerCall = authority.NestedCarrierRelay.PeerCall is null
                         ? null
                         : new
                         {
                             authority.NestedCarrierRelay.PeerCall.SessionId,
                             authority.NestedCarrierRelay.PeerCall.RequestId,
                             authority.NestedCarrierRelay.PeerCall.CancellationId,
                             authority.NestedCarrierRelay.PeerCall.CallId,
                             authority.NestedCarrierRelay.PeerCall.ReplayNonce,
                             authority.NestedCarrierRelay.PeerCall.ModuleId,
                             authority.NestedCarrierRelay.PeerCall.GraphId,
                             authority.NestedCarrierRelay.PeerCall.Capability,
                             authority.NestedCarrierRelay.PeerCall.Sequence,
                             authority.NestedCarrierRelay.PeerCall.Deadline,
                         },
                     Contribution = authority.NestedCarrierRelay.Contribution is null
                         ? null
                         : Convert.ToBase64String(
                             SidecarCapabilityTransportCodec.Serialize(
                                 authority.NestedCarrierRelay.Contribution)),
                 },
        };

        return SidecarCapabilityTransportCodec.ComputeSha256(
            SidecarCapabilityTransportCodec.Serialize(canonical));
    }

    public static string ComputeNestedCarrierRequestFingerprint(
        SidecarNestedHostActionEntryRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        return SidecarCapabilityTransportCodec.ComputeSha256(
            SidecarCapabilityTransportCodec.Serialize(request));
    }

    private static bool MatchesInitiatingHostContext(
        HostActionEntryRequestContext expected,
        SidecarActionTerminalTransportRequest actual)
    {
        var context = actual.Context;
        var lineage = expected.Contribution?.Lineage;
        return context is not null &&
            lineage is not null &&
            SamePrincipal(expected.Caller, context.Caller) &&
            SameFeatures(expected.Features, context.Features) &&
            expected.InvocationId == context.InvocationId &&
            expected.ParentInvocationId == context.ParentInvocationId &&
            expected.Depth == context.Depth &&
            expected.Attempt == context.Attempt &&
            expected.TraceId == context.TraceId &&
            expected.IdempotencyKey == context.IdempotencyKey &&
            expected.Deadline == context.Deadline &&
            lineage.ActionKey == actual.Descriptor.Key &&
            lineage.ActionVersion == actual.Descriptor.Version &&
            string.Equals(lineage.DescriptorHash, actual.Descriptor.DescriptorHash, StringComparison.Ordinal) &&
            string.Equals(lineage.InputTypeIdentity, actual.EffectiveAction.TypeIdentity, StringComparison.Ordinal) &&
            lineage.InputSchemaVersion == actual.EffectiveAction.SchemaVersion &&
            string.Equals(lineage.InputSchemaHash, actual.Descriptor.InputSchemaHash, StringComparison.Ordinal);
    }

    private static bool ValidateHostTerminalAuthority(
        SidecarActionTerminalTransportRequest request,
        SidecarCapabilitySessionBinding binding,
        DateTimeOffset now,
        Func<SidecarHostTerminalAuthority, string, bool> authenticate)
    {
        var authority = request.Authority;
        var context = request.Context;
        return authority is not null &&
            context is not null &&
            context.IsWellFormed &&
            authority.AuthorityId != Guid.Empty &&
            authority.TerminalId == request.TerminalId &&
            authority.SessionId == binding.SessionId &&
            authority.RequestId == binding.RequestId &&
            authority.CancellationId == binding.CancellationId &&
            authority.CallId == request.Call.CallId &&
            string.Equals(authority.ModuleId, binding.ModuleId, StringComparison.Ordinal) &&
            string.Equals(authority.GraphId, binding.GraphId, StringComparison.Ordinal) &&
            authority.Invocation == request.Invocation &&
            authority.ActionKey == request.Descriptor.Key &&
            authority.ActionVersion == request.Descriptor.Version &&
            string.Equals(authority.DescriptorHash, request.Descriptor.DescriptorHash, StringComparison.Ordinal) &&
            string.Equals(
                authority.SnapshotContentHash,
                ComputeSnapshotHash(context.Snapshot),
                StringComparison.OrdinalIgnoreCase) &&
            SamePrincipal(authority.Caller, context.Caller) &&
            SameFeatures(authority.Features, context.Features) &&
            authority.TraceId == context.TraceId &&
            authority.IdempotencyKey == context.IdempotencyKey &&
            authority.InvocationId == context.InvocationId &&
            authority.ParentInvocationId == context.ParentInvocationId &&
            authority.Depth == context.Depth &&
            authority.Attempt == context.Attempt &&
            request.EffectiveAction is not null &&
            SamePayload(context.EffectiveAction, request.EffectiveAction) &&
            string.Equals(request.EffectiveAction.TypeIdentity, request.Descriptor.InputTypeIdentity, StringComparison.Ordinal) &&
            request.EffectiveAction.SchemaVersion == request.Descriptor.InputSchemaVersion &&
            string.Equals(authority.EffectiveActionTypeIdentity, request.EffectiveAction.TypeIdentity, StringComparison.Ordinal) &&
            authority.EffectiveActionSchemaVersion == request.EffectiveAction.SchemaVersion &&
            string.Equals(authority.EffectiveActionContentHash, request.EffectiveAction.ContentHash, StringComparison.OrdinalIgnoreCase) &&
            authority.EffectiveActionByteLength == request.EffectiveAction.ByteLength &&
            request.Receipt is not null &&
            string.Equals(authority.ReceiptId, request.Receipt.ReceiptId, StringComparison.Ordinal) &&
            authority.ReceiptActionKey == request.Receipt.ActionKey &&
            authority.ReceiptActionVersion == request.Receipt.ActionVersion &&
            authority.ReceiptCallId == request.Receipt.CallId &&
            authority.ReceiptAttempt == request.Receipt.Attempt &&
            string.Equals(authority.ReceiptIdempotencyScope, request.Receipt.IdempotencyScope, StringComparison.Ordinal) &&
            string.Equals(authority.ReceiptContentHash, request.Receipt.ContentHash, StringComparison.OrdinalIgnoreCase) &&
            authority.Deadline == request.Deadline &&
            authority.IssuedAt <= now &&
            authority.ExpiresAt >= request.Deadline &&
            authority.ExpiresAt <= binding.ExpiresAt &&
            !string.IsNullOrWhiteSpace(authority.Proof) &&
            !string.IsNullOrWhiteSpace(authority.CanonicalBindingHash) &&
            string.Equals(
                authority.CanonicalBindingHash,
                ComputeTerminalAuthorityBindingHash(authority),
                StringComparison.OrdinalIgnoreCase) &&
            authenticate(authority, authority.CanonicalBindingHash);
    }

    private static SidecarCapabilityValidationResult ValidateNestedOutcome(
        SidecarActionOutcomeEnvelope outcome,
        SidecarActionDescriptorIdentity descriptor,
        SidecarCapabilitySessionBinding binding,
        Guid callId,
        SidecarTerminalReceipt? expectedReceipt)
    {
        return ValidateActionOutcome(outcome, descriptor, binding, callId, expectedReceipt);
    }

    private static bool MatchesNestedRequest(
        SidecarActionCapabilityRequest initiatingRequest,
        SidecarActionTerminalTransportRequest terminalRequest,
        SidecarNestedHostActionEntryRequest nestedRequest,
        SidecarCapabilitySessionBinding binding) =>
        nestedRequest.IsWellFormed &&
        nestedRequest.Deadline <= terminalRequest.Deadline &&
        nestedRequest.ExpiresAt <= terminalRequest.Deadline &&
        nestedRequest.ActionKey.Value is not null &&
        nestedRequest.ActionVersion >= 1 &&
        ValidateSerializedPayload(nestedRequest.Action, true, binding.PayloadLimits.ActionInputBytes).Accepted &&
        initiatingRequest.Invocation == SidecarActionInvocationKind.HostEntry;

    private static bool MatchesNestedRelay(
        SidecarActionTerminalTransportRequest request,
        SidecarNestedHostActionEntryRelay relay,
        SidecarCapabilitySessionBinding binding) =>
        request.NestedCarrierRequest is not null &&
        request.Context is not null &&
        relay.IsWellFormed &&
        relay.Carrier.ParentCallId == request.Call.CallId &&
        relay.Call.SessionId == request.Call.SessionId &&
        relay.Call.RequestId == request.Call.RequestId &&
        relay.Call.CancellationId == request.Call.CancellationId &&
        string.Equals(relay.Call.ModuleId, request.Call.ModuleId, StringComparison.Ordinal) &&
        string.Equals(relay.Call.GraphId, request.Call.GraphId, StringComparison.Ordinal) &&
        relay.Call.Deadline == request.NestedCarrierRequest.Deadline &&
        relay.Carrier.ActionKey == request.NestedCarrierRequest.ActionKey &&
        relay.Carrier.ActionVersion == request.NestedCarrierRequest.ActionVersion &&
        relay.Descriptor.Key == request.NestedCarrierRequest.ActionKey &&
        relay.Descriptor.Version == request.NestedCarrierRequest.ActionVersion &&
        string.Equals(relay.Descriptor.InputTypeIdentity, request.NestedCarrierRequest.Action.TypeIdentity, StringComparison.Ordinal) &&
        relay.Descriptor.InputSchemaVersion == request.NestedCarrierRequest.Action.SchemaVersion &&
        string.Equals(relay.Descriptor.DescriptorHash, relay.Carrier.DescriptorHash, StringComparison.Ordinal) &&
        string.Equals(relay.Carrier.ActionContentHash, request.NestedCarrierRequest.Action.ContentHash, StringComparison.OrdinalIgnoreCase) &&
         relay.Carrier.ActionByteLength == request.NestedCarrierRequest.Action.ByteLength &&
         relay.Contribution is not null &&
         relay.Contribution.IsWellFormed &&
         relay.Contribution.Lineage.ActionKey == request.NestedCarrierRequest.ActionKey &&
         relay.Contribution.Lineage.ActionVersion == request.NestedCarrierRequest.ActionVersion &&
         string.Equals(relay.Contribution.Lineage.PayloadContentHash, request.NestedCarrierRequest.Action.ContentHash, StringComparison.OrdinalIgnoreCase) &&
         relay.Contribution.Lineage.PayloadByteLength == request.NestedCarrierRequest.Action.ByteLength &&
         relay.Carrier.ExpiresAt == new[]
        {
            request.NestedCarrierRequest.Deadline,
            request.Call.Deadline,
            request.Authority.ExpiresAt,
            binding.ExpiresAt,
        }.Min() &&
        relay.Call.CallId == relay.Carrier.CallId;

    private static bool SameNestedRelay(
        SidecarNestedHostActionEntryRelay left,
        SidecarNestedHostActionEntryRelay right) =>
        left == right;

    private static bool SameNestedCarrierAuthorityBinding(
        SidecarActionTerminalTransportRequest request,
        SidecarNestedHostActionEntryRelay? relay,
        SidecarNestedHostActionEntryRelayOutcomeKind outcomeKind,
        SidecarHostTerminalAuthority authority)
    {
        var expected = request.Authority with
        {
            NestedCarrierRelay = relay,
            NestedCarrierOutcomeKind = outcomeKind,
            NestedCarrierRequestFingerprint = ComputeNestedCarrierRequestFingerprint(
                request.NestedCarrierRequest!),
        };
        expected = expected with
        {
            CanonicalBindingHash = ComputeTerminalAuthorityBindingHash(expected),
        };
        return expected.AuthorityId == authority.AuthorityId &&
            expected.SessionId == authority.SessionId &&
            expected.RequestId == authority.RequestId &&
            expected.CancellationId == authority.CancellationId &&
            expected.CallId == authority.CallId &&
            string.Equals(expected.ModuleId, authority.ModuleId, StringComparison.Ordinal) &&
            string.Equals(expected.GraphId, authority.GraphId, StringComparison.Ordinal) &&
            expected.Invocation == authority.Invocation &&
            expected.ActionKey == authority.ActionKey &&
            expected.ActionVersion == authority.ActionVersion &&
            string.Equals(expected.DescriptorHash, authority.DescriptorHash, StringComparison.Ordinal) &&
            string.Equals(expected.EffectiveActionTypeIdentity, authority.EffectiveActionTypeIdentity, StringComparison.Ordinal) &&
            expected.EffectiveActionSchemaVersion == authority.EffectiveActionSchemaVersion &&
            string.Equals(expected.EffectiveActionContentHash, authority.EffectiveActionContentHash, StringComparison.OrdinalIgnoreCase) &&
            expected.EffectiveActionByteLength == authority.EffectiveActionByteLength &&
            string.Equals(expected.ReceiptId, authority.ReceiptId, StringComparison.Ordinal) &&
            expected.ReceiptActionKey == authority.ReceiptActionKey &&
            expected.ReceiptActionVersion == authority.ReceiptActionVersion &&
            expected.ReceiptCallId == authority.ReceiptCallId &&
            expected.ReceiptAttempt == authority.ReceiptAttempt &&
            string.Equals(expected.ReceiptIdempotencyScope, authority.ReceiptIdempotencyScope, StringComparison.Ordinal) &&
            string.Equals(expected.ReceiptContentHash, authority.ReceiptContentHash, StringComparison.OrdinalIgnoreCase) &&
            expected.Deadline == authority.Deadline &&
            expected.IssuedAt == authority.IssuedAt &&
            expected.ExpiresAt == authority.ExpiresAt &&
            expected.TerminalId == authority.TerminalId &&
            string.Equals(expected.CanonicalBindingHash, authority.CanonicalBindingHash, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(expected.SnapshotContentHash, authority.SnapshotContentHash, StringComparison.OrdinalIgnoreCase) &&
            SamePrincipal(expected.Caller, authority.Caller!) &&
            SameFeatures(expected.Features, authority.Features!) &&
            expected.TraceId == authority.TraceId &&
            expected.IdempotencyKey == authority.IdempotencyKey &&
            expected.InvocationId == authority.InvocationId &&
            expected.ParentInvocationId == authority.ParentInvocationId &&
            expected.Depth == authority.Depth &&
            expected.Attempt == authority.Attempt &&
            expected.RootPeerCall == authority.RootPeerCall &&
            expected.NestedCarrierOutcomeKind == authority.NestedCarrierOutcomeKind &&
            string.Equals(
                expected.NestedCarrierRequestFingerprint,
                authority.NestedCarrierRequestFingerprint,
                StringComparison.OrdinalIgnoreCase) &&
            (expected.NestedCarrierRelay is null
                ? authority.NestedCarrierRelay is null
                : authority.NestedCarrierRelay is not null &&
                  SameNestedRelay(expected.NestedCarrierRelay, authority.NestedCarrierRelay));
    }

    private static bool SameReceipt(
        SidecarTerminalReceipt left,
        SidecarTerminalReceipt right) =>
        string.Equals(left.ReceiptId, right.ReceiptId, StringComparison.Ordinal) &&
        left.ActionKey == right.ActionKey &&
        left.ActionVersion == right.ActionVersion &&
        left.CallId == right.CallId &&
        left.Attempt == right.Attempt &&
        string.Equals(left.IdempotencyScope, right.IdempotencyScope, StringComparison.Ordinal) &&
        string.Equals(left.ContentHash, right.ContentHash, StringComparison.OrdinalIgnoreCase);

    private static bool SamePayload(
        SidecarSerializedPayload left,
        SidecarSerializedPayload right) =>
        left is not null &&
        right is not null &&
        string.Equals(left.TypeIdentity, right.TypeIdentity, StringComparison.Ordinal) &&
        left.SchemaVersion == right.SchemaVersion &&
        string.Equals(left.ContentHash, right.ContentHash, StringComparison.OrdinalIgnoreCase) &&
        left.ByteLength == right.ByteLength;

    private static bool SamePrincipal(
        RequestPrincipal? left,
        RequestPrincipal right) =>
        left is not null &&
        right is not null &&
        string.Equals(
            SidecarCapabilityTransportCodec.ComputeSha256(
                SidecarCapabilityTransportCodec.Serialize(left)),
            SidecarCapabilityTransportCodec.ComputeSha256(
                SidecarCapabilityTransportCodec.Serialize(right)),
            StringComparison.OrdinalIgnoreCase);

    private static bool SameFeatures(
        ExtensionFeatureSet? left,
        ExtensionFeatureSet right) =>
        left is not null &&
        right is not null &&
        string.Equals(
            SidecarCapabilityTransportCodec.ComputeSha256(
                SidecarCapabilityTransportCodec.Serialize(left)),
            SidecarCapabilityTransportCodec.ComputeSha256(
                SidecarCapabilityTransportCodec.Serialize(right)),
            StringComparison.OrdinalIgnoreCase);

    public static string ComputeSnapshotHash(ActionPipelineSnapshot snapshot) =>
        SidecarCapabilityTransportCodec.ComputeSha256(
            SidecarCapabilityTransportCodec.Serialize(snapshot));

    public static string ComputeHostActionEntryContextBindingHash(
        HostActionEntryRequestContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var canonical = new
        {
            context.CapabilityId,
            CapabilityHandleHash = SidecarCapabilityTransportCodec.ComputeSha256(
                Encoding.UTF8.GetBytes(context.CapabilityHandle)),
            context.Ingress,
            context.InvocationId,
            context.RequestId,
            context.CancellationId,
            Caller = Convert.ToBase64String(
                SidecarCapabilityTransportCodec.Serialize(context.Caller)),
            Features = Convert.ToBase64String(
                SidecarCapabilityTransportCodec.Serialize(context.Features)),
            context.TraceId,
            context.IdempotencyKey,
            context.Deadline,
            context.ExpiresAt,
            Contribution = context.Contribution is null
                ? null
                : Convert.ToBase64String(
                    SidecarCapabilityTransportCodec.Serialize(context.Contribution)),
            context.ParentInvocationId,
            context.Depth,
            context.Attempt,
        };
        return SidecarCapabilityTransportCodec.ComputeSha256(
            SidecarCapabilityTransportCodec.Serialize(canonical));
    }

    public static bool MatchesHostActionEntryContextBindingHash(
        HostActionEntryRequestContext context,
        string? expectedHash)
    {
        if (context is null || string.IsNullOrWhiteSpace(expectedHash))
            return false;

        if (string.Equals(
                expectedHash,
                ComputeHostActionEntryContextBindingHash(context),
                StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var lineage = context.Contribution?.Lineage;
        if (lineage is null || !lineage.IsPayloadBound)
            return false;

        var unboundContext = context with
        {
            Contribution = context.Contribution! with
            {
                Lineage = lineage with
                {
                    PayloadContentHash = null,
                    PayloadByteLength = null,
                },
            },
        };

        return string.Equals(
            expectedHash,
            ComputeHostActionEntryContextBindingHash(unboundContext),
            StringComparison.OrdinalIgnoreCase);
    }

    private static bool SameSafeFailure(
        SidecarSafeFailureIdentity left,
        SidecarSafeFailureIdentity right) =>
        left.FailureId == right.FailureId &&
        string.Equals(left.Code, right.Code, StringComparison.Ordinal) &&
        string.Equals(left.Message, right.Message, StringComparison.Ordinal) &&
        left.Retryable == right.Retryable;

    private static bool MatchesEffectiveDispatcherContext(
        SidecarActionTerminalExecutionContext expected,
        SidecarActionTerminalExecutionContext actual) =>
        expected is not null &&
        actual is not null &&
        expected.Call == actual.Call &&
        expected.Invocation == actual.Invocation &&
        expected.Descriptor == actual.Descriptor &&
        SamePayload(expected.EffectiveAction, actual.EffectiveAction) &&
        string.Equals(
            ComputeSnapshotHash(expected.Snapshot),
            ComputeSnapshotHash(actual.Snapshot),
            StringComparison.OrdinalIgnoreCase) &&
        expected.InvocationId == actual.InvocationId &&
        expected.ParentInvocationId == actual.ParentInvocationId &&
        expected.Depth == actual.Depth &&
        expected.Attempt == actual.Attempt &&
        SamePrincipal(expected.Caller, actual.Caller) &&
        SameFeatures(expected.Features, actual.Features) &&
        expected.TraceId == actual.TraceId &&
        expected.IdempotencyKey == actual.IdempotencyKey &&
        expected.Cancellation == actual.Cancellation &&
        SameReceipt(expected.Receipt, actual.Receipt) &&
        expected.Deadline == actual.Deadline;

    private static bool SameTerminalAuthority(
        SidecarHostTerminalAuthority expected,
        SidecarHostTerminalAuthority actual) =>
        expected is not null &&
        actual is not null &&
        expected.AuthorityId == actual.AuthorityId &&
        string.Equals(
            expected.CanonicalBindingHash,
            actual.CanonicalBindingHash,
            StringComparison.OrdinalIgnoreCase) &&
        string.Equals(expected.Proof, actual.Proof, StringComparison.Ordinal);

}

public interface ISidecarCapabilityTransport
{
    ValueTask<SidecarStorageCapabilityResponse> InvokeStorageAsync(
        SidecarStorageCapabilityRequest request,
        CancellationToken ct = default);

    ValueTask<SidecarActionCapabilityResponse> InvokeActionAsync(
        SidecarActionCapabilityRequest request,
        CancellationToken ct = default);

    ValueTask<SidecarActionTerminalTransportResponse> InvokeActionTerminalAsync(
        SidecarActionTerminalTransportRequest request,
        CancellationToken ct = default);
}

public static class SidecarCapabilityTransportCodec
{
    public static JsonSerializerOptions CreateJsonOptions()
    {
        var options = new JsonSerializerOptions(JsonSerializerDefaults.Web)
        {
            PropertyNameCaseInsensitive = false,
            UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
            WriteIndented = false,
        };
        options.Converters.Add(new OrdinalRoleSetJsonConverter());
        return options;
    }

    public static byte[] Serialize<T>(T value)
    {
        ArgumentNullException.ThrowIfNull(value);
        return JsonSerializer.SerializeToUtf8Bytes(value, CreateJsonOptions());
    }

    public static T Deserialize<T>(ReadOnlySpan<byte> payload) =>
        JsonSerializer.Deserialize<T>(payload, CreateJsonOptions()) ??
        throw new JsonException($"The sidecar payload could not be deserialized as {typeof(T).Name}.");

    public static string ComputeSha256(ReadOnlySpan<byte> payload) =>
        Convert.ToHexString(SHA256.HashData(payload));

    private sealed class OrdinalRoleSetJsonConverter : JsonConverter<IReadOnlySet<string>>
    {
        public override bool HandleNull => true;

        public override IReadOnlySet<string>? Read(
            ref Utf8JsonReader reader,
            Type typeToConvert,
            JsonSerializerOptions options)
        {
            if (reader.TokenType == JsonTokenType.Null)
                return null;

            if (reader.TokenType != JsonTokenType.StartArray)
                throw new JsonException("Roles must be encoded as a JSON array.");

            var roles = new HashSet<string>(StringComparer.Ordinal);
            while (reader.Read() && reader.TokenType != JsonTokenType.EndArray)
            {
                if (reader.TokenType != JsonTokenType.String)
                    throw new JsonException("Each role must be a JSON string.");

                var role = reader.GetString();
                if (string.IsNullOrWhiteSpace(role) || !roles.Add(role))
                    throw new JsonException("Roles must be nonempty and unique under ordinal comparison.");
            }

            if (reader.TokenType != JsonTokenType.EndArray)
                throw new JsonException("The roles JSON array is incomplete.");

            return roles;
        }

        public override void Write(
            Utf8JsonWriter writer,
            IReadOnlySet<string> value,
            JsonSerializerOptions options)
        {
            if (value is null)
            {
                writer.WriteNullValue();
                return;
            }

            var roles = new HashSet<string>(StringComparer.Ordinal);
            foreach (var role in value)
            {
                if (string.IsNullOrWhiteSpace(role) || !roles.Add(role))
                    throw new JsonException("Roles must be nonempty and unique under ordinal comparison.");
            }

            writer.WriteStartArray();
            foreach (var role in roles.OrderBy(item => item, StringComparer.Ordinal))
                writer.WriteStringValue(role);
            writer.WriteEndArray();
        }
    }
}
