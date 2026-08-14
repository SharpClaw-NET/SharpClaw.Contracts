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
    DateTimeOffset IssuedAt);

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
    SidecarAuthenticationProof Authentication);

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
    public const string TerminalAlreadyCalled = "sidecar_terminal_already_called";
}

public sealed class SidecarCapabilitySession
{
    private readonly object _sync = new();
    private readonly Func<SidecarAuthenticationProof, bool> _authenticate;
    private readonly HashSet<Guid> _calls = [];
    private readonly HashSet<string> _nonces = new(StringComparer.Ordinal);
    private readonly HashSet<Guid> _terminalCalls = [];
    private int _inFlight;
    private int _totalCalls;
    private bool _disconnected;

    public SidecarCapabilitySession(
        SidecarCapabilitySessionBinding binding,
        Func<SidecarAuthenticationProof, bool> authenticate,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(binding);
        ArgumentNullException.ThrowIfNull(authenticate);
        Binding = binding;
        _authenticate = authenticate;

        var result = SidecarCapabilitySessionValidator.Validate(binding, authenticate, now);
        if (!result.Accepted)
            throw new ArgumentException(result.Message, nameof(binding));
    }

    public SidecarCapabilitySessionBinding Binding { get; }

    public SidecarCapabilityValidationResult BeginCall(
        SidecarCapabilityCallIdentity identity,
        SidecarCapabilityKind capability,
        int payloadBytes,
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
                now);
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

            if (payloadBytes < 0 || payloadBytes > Binding.PayloadLimits.ProtocolMessageBytes)
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.PayloadTooLarge,
                    "The call payload exceeds the session limit.");

            if (_calls.Contains(identity.CallId) || !_nonces.Add(identity.ReplayNonce))
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.Replay,
                    "The call identity or replay nonce was already used.");

            if (_inFlight >= Binding.ConcurrencyLimits.MaximumInFlightCalls)
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.ConcurrencyLimit,
                    "The session concurrency limit was reached.");

            if (_totalCalls >= Binding.ConcurrencyLimits.MaximumCallsPerRequest)
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.ConcurrencyLimit,
                    "The session request call limit was reached.");

            _calls.Add(identity.CallId);
            _totalCalls++;
            _inFlight++;
            return SidecarCapabilityValidationResult.Accept();
        }
    }

    public SidecarCapabilityValidationResult RecordTerminal(Guid callId)
    {
        lock (_sync)
        {
            if (_disconnected)
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.Disconnected,
                    "The sidecar capability session is disconnected.");

            if (!_calls.Contains(callId))
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.InvalidBinding,
                    "The call is not active in this session.");

            if (!_terminalCalls.Add(callId))
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.TerminalAlreadyCalled,
                    "The call already recorded a terminal outcome.");

            return SidecarCapabilityValidationResult.Accept();
        }
    }

    public SidecarCapabilityValidationResult CompleteCall(Guid callId)
    {
        lock (_sync)
        {
            if (_disconnected)
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.Disconnected,
                    "The sidecar capability session is disconnected.");

            if (!_calls.Remove(callId))
                return SidecarCapabilityValidationResult.Reject(
                    SidecarCapabilityErrors.Duplicate,
                    "The call was already completed or was never active.");

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
    public static SidecarCapabilityValidationResult Validate(
        SidecarCapabilitySessionBinding binding,
        Func<SidecarAuthenticationProof, bool> authenticate,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(binding);
        ArgumentNullException.ThrowIfNull(authenticate);

        if (binding.Authentication is null || !authenticate(binding.Authentication))
            return SidecarCapabilityValidationResult.Reject(
                SidecarCapabilityErrors.Unauthenticated,
                "The sidecar authentication proof was not accepted.");

        if (binding.ExpiresAt <= now)
            return SidecarCapabilityValidationResult.Reject(
                SidecarCapabilityErrors.Expired,
                "The sidecar capability session has expired.");

        if (binding.ProtocolVersion < 1 ||
            string.IsNullOrWhiteSpace(binding.ModuleId) ||
            string.IsNullOrWhiteSpace(binding.GraphId) ||
            binding.SessionId == Guid.Empty ||
            binding.RequestId == Guid.Empty ||
            binding.CancellationId == Guid.Empty ||
            binding.Grant is null ||
            binding.PayloadLimits is null ||
            !binding.PayloadLimits.IsValid ||
            binding.ConcurrencyLimits is null ||
            !binding.ConcurrencyLimits.IsValid ||
            binding.SafeFailure is null ||
            !binding.SafeFailure.IsValid)
        {
            return SidecarCapabilityValidationResult.Reject(
                SidecarCapabilityErrors.InvalidBinding,
                "The sidecar capability binding is incomplete or expired.");
        }

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
    string ResultTypeIdentity,
    string ResultSchemaHash,
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

public sealed record SidecarActionCapabilityResponse(
    Guid ResultId,
    SidecarActionOutcomeEnvelope Outcome,
    SidecarTerminalContinuationResponse? Continuation,
    SidecarSafeFailureIdentity SafeFailure,
    bool Completed);

public static class SidecarCapabilityTransportValidation
{
    public static SidecarCapabilityValidationResult ValidateStorageRequest(
        SidecarStorageCapabilityRequest request,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (!string.Equals(request.ModuleId, request.Call.ModuleId, StringComparison.Ordinal) ||
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
            (request.Operation == SidecarStorageOperationKind.ListContracts && request.RequestPayload is not null) ||
            (request.Operation != SidecarStorageOperationKind.ListContracts &&
             (string.IsNullOrWhiteSpace(request.StorageName) || request.RequestPayload is null || !request.RequestPayload.IsValid)))
        {
            return SidecarCapabilityValidationResult.Reject(
                SidecarCapabilityErrors.InvalidPayload,
                "The storage request payload does not match its operation.");
        }

        return SidecarCapabilityValidationResult.Accept();
    }

    public static SidecarCapabilityValidationResult ValidateActionRequest(
        SidecarActionCapabilityRequest request,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (!request.Call.IsValid ||
            request.Cancellation.CancellationId != request.Call.CancellationId ||
            request.Deadline != request.Call.Deadline ||
            request.Deadline <= now ||
            request.Cancellation.ExpiresAt < request.Deadline)
        {
            return SidecarCapabilityValidationResult.Reject(
                SidecarCapabilityErrors.SpoofedIdentity,
                "The action request does not bind to the call authority.");
        }

        if (request.Descriptor.Key.Value is null ||
            string.IsNullOrWhiteSpace(request.Descriptor.Key.Value) ||
            request.Descriptor.Version < 1 ||
            string.IsNullOrWhiteSpace(request.Descriptor.Category) ||
            string.IsNullOrWhiteSpace(request.Descriptor.InputTypeIdentity) ||
            string.IsNullOrWhiteSpace(request.Descriptor.InputSchemaHash) ||
            string.IsNullOrWhiteSpace(request.Descriptor.ResultTypeIdentity) ||
            string.IsNullOrWhiteSpace(request.Descriptor.ResultSchemaHash) ||
            string.IsNullOrWhiteSpace(request.Descriptor.DescriptorHash) ||
            !request.Action.IsValid ||
            !string.Equals(request.Action.TypeIdentity, request.Descriptor.InputTypeIdentity, StringComparison.Ordinal) ||
            request.Snapshot is null ||
            string.IsNullOrWhiteSpace(request.Snapshot.ContractHash))
        {
            return SidecarCapabilityValidationResult.Reject(
                SidecarCapabilityErrors.InvalidPayload,
                "The action request does not contain a complete descriptor and payload identity.");
        }

        if (request.Continuation is not null &&
            (request.Continuation.ContinuationRequestId == Guid.Empty ||
             request.Continuation.Deadline > request.Deadline))
        {
            return SidecarCapabilityValidationResult.Reject(
                SidecarCapabilityErrors.InvalidPayload,
                "The terminal continuation request is outside the action deadline.");
        }

        return SidecarCapabilityValidationResult.Accept();
    }

    public static SidecarCapabilityValidationResult ValidateActionResponse(
        SidecarActionCapabilityResponse response)
    {
        ArgumentNullException.ThrowIfNull(response);

        if (response.ResultId == Guid.Empty ||
            response.Outcome is null ||
            response.Outcome.TerminalCallCount != 1 ||
            response.SafeFailure is null ||
            !response.SafeFailure.IsValid)
        {
            return SidecarCapabilityValidationResult.Reject(
                SidecarCapabilityErrors.TerminalAlreadyCalled,
                "The action response does not contain exactly one terminal outcome.");
        }

        return SidecarCapabilityValidationResult.Accept();
    }
}

public interface ISidecarCapabilityTransport
{
    ValueTask<SidecarStorageCapabilityResponse> InvokeStorageAsync(
        SidecarStorageCapabilityRequest request,
        CancellationToken ct = default);

    ValueTask<SidecarActionCapabilityResponse> InvokeActionAsync(
        SidecarActionCapabilityRequest request,
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
