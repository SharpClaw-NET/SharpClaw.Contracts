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

public sealed class SidecarCapabilitySession
{
    private readonly object _sync = new();
    private readonly Func<SidecarCapabilityAuthenticationAuthority, bool> _authenticate;
    private readonly Func<string, bool> _registerAuthenticationNonce;
    private readonly Dictionary<Guid, SidecarCapabilityKind> _calls = [];
    private readonly Dictionary<Guid, SidecarCapabilityCallIdentity> _callIdentities = [];
    private readonly Dictionary<Guid, SidecarSerializedPayload?> _callPayloads = [];
    private readonly Dictionary<Guid, HostActionEntryRequestContext> _issuedEntryContexts = [];
    private readonly Dictionary<Guid, HostActionEntryCarrierAuthority> _activeEntryCarriers = [];
    private readonly Dictionary<Guid, NestedCarrierState> _nestedCarrierStates = [];
    private readonly Dictionary<Guid, SidecarCapabilityCallIdentity> _reservedNestedCalls = [];
    private readonly HashSet<Guid> _nestedCarrierIds = [];
    private readonly Dictionary<Guid, Guid> _nestedCarrierParents = [];
    private readonly Dictionary<Guid, CarrierReplayTombstone> _completedEntryCarriers = [];
    private readonly HashSet<Guid> _consumedEntryCarriers = [];
    private readonly Dictionary<Guid, HostActionEntryRequestContext> _callEntryContexts = [];
    private readonly HashSet<Guid> _completedCalls = [];
    private readonly HashSet<string> _nonces = new(StringComparer.Ordinal);
    private readonly Dictionary<Guid, Guid> _terminalCalls = [];
    private readonly Dictionary<Guid, SidecarTerminalReceipt> _terminalReceipts = [];
    private readonly HashSet<Guid> _usedTerminalAuthorities = [];
    private long _lastSequence;
    private int _inFlight;
    private int _totalCalls;
    private long _bindingGeneration = 1;
    private bool _disconnected;

    private sealed record CarrierReplayTombstone(
        long BindingGeneration,
        DateTimeOffset RetainUntil);

    private sealed record NestedCarrierState(
        SidecarNestedHostActionEntryCarrier Carrier,
        SidecarCapabilityCallIdentity ParentCall,
        SidecarCapabilityCallIdentity Call,
        SidecarActionDescriptorIdentity Descriptor,
        SidecarSerializedPayload Action,
        HostActionEntryRequestContext Context,
        HostActionEntryCarrierAuthority Authority);

    private static readonly TimeSpan CarrierReplayRetention = TimeSpan.FromMinutes(5);

    public SidecarCapabilitySession(
        SidecarCapabilitySessionBinding binding,
        Func<SidecarCapabilityAuthenticationAuthority, bool> authenticate,
        Func<string, bool> registerAuthenticationNonce,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(binding);
        ArgumentNullException.ThrowIfNull(authenticate);
        ArgumentNullException.ThrowIfNull(registerAuthenticationNonce);
        Binding = binding;
        _authenticate = authenticate;
        _registerAuthenticationNonce = registerAuthenticationNonce;

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
                _totalCalls >= Binding.ConcurrencyLimits.MaximumCallsPerRequest ||
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
            var carrierAuthority = new HostActionEntryCarrierAuthority(
                Binding.ModuleId,
                Binding.GraphId,
                Binding.SessionId,
                Binding.RequestId,
                Binding.CancellationId,
                capabilityId,
                carrierIdentity,
                _bindingGeneration,
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
                _bindingGeneration,
                expiresAt);
            _lastSequence = nestedCall.Sequence;
            _totalCalls++;
            _inFlight++;
            _nonces.Add(nestedCall.ReplayNonce);
            _reservedNestedCalls.Add(nestedCall.CallId, nestedCall);
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
    {
        relay = null;

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
            var result = IssueNestedHostActionEntryCarrier(
                parentCall,
                nestedCall,
                resolvedDescriptor,
                request.Action,
                resolvedContribution,
                now,
                out var carrier);
            if (!result.Accepted || carrier is null)
                return result;

            relay = new SidecarNestedHostActionEntryRelay(nestedCall, carrier);
            return result;
        }
    }

    public SidecarCapabilityValidationResult RevokeNestedHostActionEntryRelay(
        Guid parentCallId,
        DateTimeOffset now)
    {
        lock (_sync)
        {
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
                ReleaseNestedReservation(state.Call.CallId);
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
            hostContext = _callEntryContexts[call.CallId];
            return result;
        }
    }

    public SidecarCapabilityValidationResult BeginActionCall(
        SidecarActionCapabilityRequest request,
        int frameByteLength,
        DateTimeOffset now,
        out HostActionEntryRequestContext? hostContext)
    {
        ArgumentNullException.ThrowIfNull(request);
        hostContext = null;

        var requestResult = SidecarCapabilityTransportValidation.ValidateActionRequest(
            request,
            Binding,
            now);
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

        var result = BeginCall(
            request.Call,
            SidecarCapabilityKind.Action,
            request.Action,
            frameByteLength,
            now,
            request.HostContext);
        if (result.Accepted)
        {
            if (request.HostContext is not null)
                hostContext = request.HostContext;

        }

        return result;
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
        lock (_sync)
        {
            var removed = SweepExpiredEntryContexts(now);
            SweepCompletedEntryCarriers(now);
            return removed;
        }
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
                _nestedCarrierStates.Count != 0 ||
                _reservedNestedCalls.Count != 0)
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
            _reservedNestedCalls.Clear();
            _nestedCarrierIds.Clear();
            _nestedCarrierParents.Clear();
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

            if (!reservedNestedCall && _totalCalls >= Binding.ConcurrencyLimits.MaximumCallsPerRequest)
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.ConcurrencyLimit,
                    "The session request call limit was reached.");

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
                _callEntryContexts.Add(
                    identity.CallId,
                    hostContext with
                    {
                        Contribution = hostContext.Contribution with { Lineage = capturedLineage },
                    });
                _consumedEntryCarriers.Add(hostContext.CapabilityId);
            }
            if (reservedNestedCall)
                _reservedNestedCalls.Remove(identity.CallId);
            else
            {
                _lastSequence = identity.Sequence;
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
                _nestedCarrierStates.Values.Any(state => state.ParentCall.CallId == callId))
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
            _issuedEntryContexts.Remove(capabilityId);
            RecordCarrierTombstone(capabilityId, _bindingGeneration, now, now);
            removed++;
        }

        foreach (var capabilityId in _activeEntryCarriers
            .Where(pair => pair.Value.ExpiresAt <= now)
            .Select(pair => pair.Key)
            .ToArray())
        {
            if (_nestedCarrierStates.TryGetValue(capabilityId, out var expiredState))
                ReleaseNestedReservation(expiredState.Call.CallId);
            _nestedCarrierStates.Remove(capabilityId);
            RemoveEntryCarrier(capabilityId, now);
            removed++;
        }

        foreach (var state in _nestedCarrierStates.Values
            .Where(state => state.Carrier.ExpiresAt <= now)
            .ToArray())
        {
            _nestedCarrierStates.Remove(state.Carrier.CarrierId);
            ReleaseNestedReservation(state.Call.CallId);
            RemoveEntryCarrier(state.Carrier.CarrierId, now);
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
            ReleaseNestedReservation(state.Call.CallId);
            RemoveEntryCarrier(state.Carrier.CarrierId, now);
        }
    }

    private void ReleaseNestedReservation(Guid callId)
    {
        if (_reservedNestedCalls.Remove(callId))
            _inFlight--;
    }

    private void RemoveEntryCarrier(Guid capabilityId, DateTimeOffset now)
    {
        _issuedEntryContexts.Remove(capabilityId);
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
        if (!_callEntryContexts.Values.Any(context => context.CapabilityId == capabilityId))
            _nestedCarrierParents.Remove(capabilityId);
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

    private static bool MatchesCarrier(
        HostActionEntryRequestContext context,
        HostActionEntryCarrierIdentity carrier) =>
        context.Ingress == carrier.Ingress &&
        context.InvocationId == carrier.InvocationId &&
        context.Contribution is not null &&
        SameIngressBinding(context.Contribution.IngressBinding, carrier.Contribution);

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
            _calls.Clear();
            _callIdentities.Clear();
            _callPayloads.Clear();
            _callEntryContexts.Clear();
            _issuedEntryContexts.Clear();
            _activeEntryCarriers.Clear();
            _nestedCarrierStates.Clear();
            _reservedNestedCalls.Clear();
            _nestedCarrierIds.Clear();
            _nestedCarrierParents.Clear();
            _completedEntryCarriers.Clear();
            _consumedEntryCarriers.Clear();
            _terminalCalls.Clear();
            _terminalReceipts.Clear();
            _inFlight = 0;
        }
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
    string DescriptorHash);

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
    public bool IsWellFormed =>
        Call is not null &&
        Call.IsValid &&
        Carrier is not null &&
        Carrier.IsWellFormed &&
        Carrier.CallId == Call.CallId;
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
    public SidecarActionTerminalRegistration? Terminal { get; init; }

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
    public SidecarNestedHostActionEntryRelay? NestedCarrierRelay { get; init; }
    public SidecarNestedHostActionEntryRelayOutcomeKind? NestedCarrierOutcomeKind { get; init; }
    public string NestedCarrierRequestFingerprint { get; init; } = string.Empty;
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
        DateTimeOffset now)
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
        if (!Enum.IsDefined(request.Invocation) ||
            !IsValidDescriptor(request.Descriptor) ||
            request.Action is null ||
            !string.Equals(request.Action.TypeIdentity, request.Descriptor.InputTypeIdentity, StringComparison.Ordinal) ||
            request.Action.SchemaVersion != request.Descriptor.InputSchemaVersion ||
            requiresSnapshot &&
            (request.Snapshot is null || string.IsNullOrWhiteSpace(request.Snapshot.ContractHash)) ||
            hostEntry &&
            (request.Snapshot is not null ||
             (request.HostContext is null) == (request.NestedCarrier is null) ||
             request.HostContext is not null && !request.HostContext.IsWellFormed(now) ||
             request.NestedCarrier is not null && !request.NestedCarrier.IsWellFormed ||
              request.Terminal is null ||
              !request.Terminal.IsWellFormed) ||
             !hostEntry &&
             (request.HostContext is not null ||
              request.Terminal is not null ||
               request.NestedCarrier is not null))
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

        if (hostEntry && request.HostContext is not null &&
            (request.HostContext.Contribution?.Lineage is null ||
             !string.Equals(request.HostContext.Contribution.Lineage.ActionKey.Value, request.Descriptor.Key.Value, StringComparison.Ordinal) ||
             request.HostContext.Contribution.Lineage.ActionVersion != request.Descriptor.Version ||
             !string.Equals(request.HostContext.Contribution.Lineage.DescriptorHash, request.Descriptor.DescriptorHash, StringComparison.Ordinal) ||
             !string.Equals(request.HostContext.Contribution.Lineage.InputTypeIdentity, request.Descriptor.InputTypeIdentity, StringComparison.Ordinal) ||
             request.HostContext.Contribution.Lineage.InputSchemaVersion != request.Descriptor.InputSchemaVersion ||
             !string.Equals(request.HostContext.Contribution.Lineage.InputSchemaHash, request.Descriptor.InputSchemaHash, StringComparison.Ordinal) ||
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
            initiatingRequest.Invocation == SidecarActionInvocationKind.HostEntry &&
            (initiatingRequest.Terminal is null ||
             !initiatingRequest.Terminal.IsWellFormed ||
             !string.Equals(initiatingRequest.Terminal.ActionTypeIdentity, initiatingRequest.Descriptor.InputTypeIdentity, StringComparison.Ordinal) ||
             initiatingRequest.Terminal.ActionSchemaVersion != initiatingRequest.Descriptor.InputSchemaVersion ||
             !string.Equals(initiatingRequest.Terminal.ResultTypeIdentity, initiatingRequest.Descriptor.ResultTypeIdentity, StringComparison.Ordinal) ||
             initiatingRequest.Terminal.ResultSchemaVersion != initiatingRequest.Descriptor.ResultSchemaVersion ||
             !string.Equals(initiatingRequest.Terminal.DescriptorHash, initiatingRequest.Descriptor.DescriptorHash, StringComparison.Ordinal) ||
             request.TerminalId != initiatingRequest.Terminal.TerminalId ||
             initiatingRequest.HostContext is null && initiatingRequest.NestedCarrier is null ||
             initiatingRequest.HostContext is not null &&
             (request.Context is null ||
              !MatchesInitiatingHostContext(initiatingRequest.HostContext, request)) ||
             initiatingRequest.NestedCarrier is not null &&
             (request.Context is null ||
              request.Context.InvocationId != initiatingRequest.NestedCarrier.InvocationId)) ||
            initiatingRequest.Invocation != SidecarActionInvocationKind.HostEntry &&
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

    private static bool IsValidDescriptor(SidecarActionDescriptorIdentity descriptor) =>
        descriptor is not null &&
        !string.IsNullOrWhiteSpace(descriptor.Key.Value) &&
        descriptor.Version >= 1 &&
        !string.IsNullOrWhiteSpace(descriptor.Category) &&
        !string.IsNullOrWhiteSpace(descriptor.InputTypeIdentity) &&
        !string.IsNullOrWhiteSpace(descriptor.InputSchemaHash) &&
        descriptor.InputSchemaVersion >= 1 &&
        !string.IsNullOrWhiteSpace(descriptor.ResultTypeIdentity) &&
        !string.IsNullOrWhiteSpace(descriptor.ResultSchemaHash) &&
        descriptor.ResultSchemaVersion >= 1 &&
        !string.IsNullOrWhiteSpace(descriptor.DescriptorHash);

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

    private static SidecarCapabilityValidationResult ValidateReceipt(
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
        string.Equals(relay.Carrier.ActionContentHash, request.NestedCarrierRequest.Action.ContentHash, StringComparison.OrdinalIgnoreCase) &&
        relay.Carrier.ActionByteLength == request.NestedCarrierRequest.Action.ByteLength &&
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

    private static string ComputeSnapshotHash(ActionPipelineSnapshot snapshot) =>
        SidecarCapabilityTransportCodec.ComputeSha256(
            SidecarCapabilityTransportCodec.Serialize(snapshot));

    private static bool SameSafeFailure(
        SidecarSafeFailureIdentity left,
        SidecarSafeFailureIdentity right) =>
        left.FailureId == right.FailureId &&
        string.Equals(left.Code, right.Code, StringComparison.Ordinal) &&
        string.Equals(left.Message, right.Message, StringComparison.Ordinal) &&
        left.Retryable == right.Retryable;

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
