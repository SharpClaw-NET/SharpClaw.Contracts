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
    private readonly HashSet<Guid> _completedCalls = [];
    private readonly HashSet<string> _nonces = new(StringComparer.Ordinal);
    private readonly Dictionary<Guid, Guid> _terminalCalls = [];
    private readonly HashSet<Guid> _usedTerminalAuthorities = [];
    private long _lastSequence;
    private int _inFlight;
    private int _totalCalls;
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

    public SidecarCapabilitySessionBinding Binding { get; }

    public SidecarCapabilityValidationResult BeginCall(
        SidecarCapabilityCallIdentity identity,
        SidecarCapabilityKind capability,
        SidecarSerializedPayload? payload,
        int frameByteLength,
        DateTimeOffset now)
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
            _lastSequence = identity.Sequence;
            _totalCalls++;
            _inFlight++;
            return SidecarCapabilityValidationResult.Accept();
        }
    }

    public SidecarCapabilityValidationResult RecordTerminal(Guid callId, Guid authorityId)
    {
        lock (_sync)
        {
            if (_disconnected)
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.Disconnected,
                    "The sidecar capability session is disconnected.");

            if (authorityId == Guid.Empty ||
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
            return SidecarCapabilityValidationResult.Accept();
        }
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

            _completedCalls.Add(callId);
            _terminalCalls.Remove(callId);
            _inFlight--;
            return SidecarCapabilityValidationResult.Accept();
        }
    }

    public void Disconnect()
    {
        lock (_sync)
        {
            _disconnected = true;
            _calls.Clear();
            _terminalCalls.Clear();
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
    ActionPipelineSnapshot Snapshot,
    SidecarCancellationIdentity Cancellation,
    SidecarTerminalContinuationRequest? Continuation,
    DateTimeOffset Deadline);

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

        if (!IsValidDescriptor(request.Descriptor) ||
            request.Action is null ||
            !string.Equals(request.Action.TypeIdentity, request.Descriptor.InputTypeIdentity, StringComparison.Ordinal) ||
            request.Action.SchemaVersion != request.Descriptor.InputSchemaVersion ||
            request.Snapshot is null ||
            string.IsNullOrWhiteSpace(request.Snapshot.ContractHash))
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
        SidecarCapabilitySessionBinding binding)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(response);
        ArgumentNullException.ThrowIfNull(binding);

        if (response.Outcome is null ||
            response.SafeFailure is null ||
            !SameSafeFailure(response.SafeFailure, binding.SafeFailure) ||
            !response.Completed)
        {
            return SidecarCapabilityValidationResult.Reject(
                SidecarCapabilityErrors.InvalidResponse,
                "The action response does not bind to the action request.");
        }

        var outcomeResult = ValidateActionOutcome(
            response.Outcome,
            request.Descriptor,
            binding,
            request.Call.CallId);
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
                request.Call.CallId);
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
        Guid callId)
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
            !string.Equals(outcome.Result.TypeIdentity, descriptor.ResultTypeIdentity, StringComparison.Ordinal))
        {
            return SidecarCapabilityValidationResult.Reject(
                SidecarCapabilityErrors.InvalidResponse,
                "The action result type does not match the descriptor.");
        }

        return outcome.TerminalCallCount == 1
            ? ValidateReceipt(outcome.Receipt, callId, descriptor, required: true)
            : SidecarCapabilityValidationResult.Accept();
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
        Guid callId)
    {
        return ValidateActionOutcome(outcome, descriptor, binding, callId);
    }

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
    public static JsonSerializerOptions CreateJsonOptions() =>
        new(JsonSerializerDefaults.Web)
        {
            PropertyNameCaseInsensitive = false,
            UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
            WriteIndented = false,
        };

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
}
