using System.Security.Cryptography;
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
    private readonly HashSet<Guid> _completedEntryCarriers = [];
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
                    entryContext))
            {
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.SpoofedIdentity,
                    "The host action entry authority does not match the host request context.");
            }

            if (authority.SessionId != Binding.SessionId ||
                authority.RequestId != Binding.RequestId ||
                authority.CancellationId != Binding.CancellationId ||
                !string.Equals(authority.ModuleId, Binding.ModuleId, StringComparison.Ordinal) ||
                !string.Equals(authority.GraphId, Binding.GraphId, StringComparison.Ordinal) ||
                authority.Deadline > Binding.ExpiresAt ||
                !_calls.TryGetValue(authority.CallId, out var capability) ||
                capability != SidecarCapabilityKind.Action ||
                !_callIdentities.TryGetValue(authority.CallId, out var activeCall) ||
                activeCall.SessionId != authority.SessionId ||
                activeCall.RequestId != authority.RequestId ||
                activeCall.CancellationId != authority.CancellationId ||
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

    public SidecarCapabilityValidationResult CompleteHostActionEntryCarrier(
        HostActionEntryCarrierAuthority authority,
        HostActionEntryCarrierCompletionKind completion,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(authority);

        lock (_sync)
        {
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
                    _completedEntryCarriers.Contains(authority.CapabilityId)
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
                RemoveEntryCarrier(authority.CapabilityId);
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

            RemoveEntryCarrier(authority.CapabilityId);
            return SidecarCapabilityValidationResult.Accept();
        }
    }

    public int SweepExpiredHostActionEntryCarriers(DateTimeOffset now)
    {
        lock (_sync)
            return SweepExpiredEntryContexts(now);
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

            var identityMatches =
                string.Equals(replacement.ModuleId, Binding.ModuleId, StringComparison.Ordinal) &&
                string.Equals(replacement.GraphId, Binding.GraphId, StringComparison.Ordinal) &&
                replacement.ProtocolVersion == Binding.ProtocolVersion &&
                replacement.SessionId == Binding.SessionId &&
                replacement.RequestId == Binding.RequestId &&
                replacement.CancellationId == Binding.CancellationId;
            if (!identityMatches)
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.SpoofedIdentity,
                    "The rotated binding does not preserve session identity.");

            var validation = SidecarCapabilitySessionValidator.Validate(
                replacement,
                _authenticate,
                _registerAuthenticationNonce,
                now);
            if (!validation.Accepted)
                return validation;

            var requiredExpiry = _activeEntryCarriers.Count == 0
                ? now
                : _activeEntryCarriers.Values.Max(value => value.ExpiresAt);
            if (replacement.ExpiresAt < requiredExpiry ||
                _activeEntryCarriers.Count > 0 && !replacement.Grant.Allows(SidecarCapabilityKind.Action) ||
                replacement.PayloadLimits.ActionInputBytes < Binding.PayloadLimits.ActionInputBytes ||
                replacement.PayloadLimits.ProtocolMessageBytes < Binding.PayloadLimits.ProtocolMessageBytes ||
                replacement.ConcurrencyLimits.MaximumInFlightCalls < Binding.ConcurrencyLimits.MaximumInFlightCalls ||
                replacement.ConcurrencyLimits.MaximumCallsPerRequest < Binding.ConcurrencyLimits.MaximumCallsPerRequest)
            {
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.InvalidBinding,
                    "The rotated binding would strand active carrier authority.");
            }

            Binding = replacement;
            _bindingGeneration++;
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
                Binding.SessionId,
                Binding.RequestId,
                Binding.CancellationId,
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
                 !MatchesCarrierContext(hostContext, activeCarrier) ||
                 hostContext.RequestId != Binding.RequestId ||
                 hostContext.CancellationId != Binding.CancellationId))
            {
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.SpoofedIdentity,
                    "The host action entry context is not active for this carrier.");
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

            if (identity.Sequence != _lastSequence + 1)
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
                !_nonces.Add(identity.ReplayNonce))
            {
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.Replay,
                    "The call identity or replay nonce was already used.");
            }

            if (_inFlight >= Binding.ConcurrencyLimits.MaximumInFlightCalls)
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.ConcurrencyLimit,
                    "The session concurrency limit was reached.");

            if (_totalCalls >= Binding.ConcurrencyLimits.MaximumCallsPerRequest)
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
                _issuedEntryContexts.Remove(hostContext.CapabilityId);
            }
            _lastSequence = identity.Sequence;
            _totalCalls++;
            _inFlight++;
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

            if (capability == SidecarCapabilityKind.Action &&
                _terminalCalls.ContainsKey(callId) != (terminalCallCount == 1))
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.TerminalAlreadyCalled,
                    "The action completion count does not match the recorded terminal authority.");

            if (capability == SidecarCapabilityKind.Storage && terminalCallCount != 0)
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.InvalidBinding,
                    "Storage calls cannot complete with a terminal callback.");

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
            _completedEntryCarriers.Add(capabilityId);
            removed++;
        }

        foreach (var capabilityId in _activeEntryCarriers
            .Where(pair => pair.Value.ExpiresAt <= now)
            .Select(pair => pair.Key)
            .ToArray())
        {
            RemoveEntryCarrier(capabilityId);
            removed++;
        }

        return removed;
    }

    private void RemoveEntryCarrier(Guid capabilityId)
    {
        _issuedEntryContexts.Remove(capabilityId);
        _activeEntryCarriers.Remove(capabilityId);
        _completedEntryCarriers.Add(capabilityId);
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
            _completedEntryCarriers.Clear();
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

    public static SidecarActionCapabilityRequest HostEntry(
        SidecarCapabilityCallIdentity call,
        SidecarActionDescriptorIdentity descriptor,
        SidecarSerializedPayload action,
        SidecarCancellationIdentity cancellation,
        DateTimeOffset deadline,
        HostActionEntryRequestContext hostContext) =>
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
    string Proof);

public sealed record SidecarActionTerminalTransportRequest(
    SidecarCapabilityCallIdentity Call,
    SidecarActionInvocationKind Invocation,
    SidecarActionDescriptorIdentity Descriptor,
    SidecarSerializedPayload EffectiveAction,
    SidecarHostTerminalAuthority Authority,
    SidecarTerminalReceipt Receipt,
    SidecarCancellationIdentity Cancellation,
    DateTimeOffset Deadline);

public sealed record SidecarTerminalExecutionResult(
    SidecarSerializedPayload? Result,
    SidecarSafeFailureIdentity? Failure,
    bool Completed);

public sealed record SidecarActionTerminalTransportResponse(
    SidecarActionResultIdentity? ResultIdentity,
    SidecarTerminalExecutionResult Execution,
    SidecarTerminalReceipt Receipt,
    SidecarSafeFailureIdentity SafeFailure);

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
             request.HostContext is null ||
             !request.HostContext.IsWellFormed(now)) ||
            !hostEntry && request.HostContext is not null)
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

        if (hostEntry &&
            (request.HostContext!.Contribution?.Lineage is null ||
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
        Func<SidecarHostTerminalAuthority, bool> authenticateHostTerminalAuthority)
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
        SidecarCapabilitySessionBinding binding)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(response);
        ArgumentNullException.ThrowIfNull(binding);

        if (response.Execution is null ||
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

    private static bool ValidateHostTerminalAuthority(
        SidecarActionTerminalTransportRequest request,
        SidecarCapabilitySessionBinding binding,
        DateTimeOffset now,
        Func<SidecarHostTerminalAuthority, bool> authenticate)
    {
        var authority = request.Authority;
        return authority is not null &&
            authority.AuthorityId != Guid.Empty &&
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
            request.EffectiveAction is not null &&
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
            authenticate(authority);
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
