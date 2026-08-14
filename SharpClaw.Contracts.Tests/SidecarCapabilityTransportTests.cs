using System.Text;
using System.Text.Json;
using SharpClaw.Contracts.Modules;

namespace SharpClaw.Contracts.Tests;

public sealed class SidecarCapabilityTransportTests
{
    [Fact]
    public void Session_binding_is_canonical_and_rejects_unknown_fields()
    {
        var fixture = CreateFixture();
        var first = SidecarCapabilityTransportCodec.Serialize(fixture.Binding);
        var second = SidecarCapabilityTransportCodec.Serialize(fixture.Binding);

        Assert.Equal(first, second);
        var roundTrip = SidecarCapabilityTransportCodec.Deserialize<SidecarCapabilitySessionBinding>(first);
        Assert.Equal(fixture.Binding.ModuleId, roundTrip.ModuleId);
        Assert.Equal(fixture.Binding.Authentication.BindingHash, roundTrip.Authentication.BindingHash);
        Assert.Equal(first, SidecarCapabilityTransportCodec.Serialize(roundTrip));

        var json = Encoding.UTF8.GetString(first);
        var withUnknown = Encoding.UTF8.GetBytes(json[..^1] + ",\"unexpected\":true}");
        Assert.Throws<JsonException>(() =>
            SidecarCapabilityTransportCodec.Deserialize<SidecarCapabilitySessionBinding>(withUnknown));
    }

    [Fact]
    public void Session_authentication_binds_the_proof_to_immutable_authority_and_rejects_nonce_replay()
    {
        var fixture = CreateFixture();
        Assert.Throws<ArgumentException>(() =>
            new SidecarCapabilitySession(
                fixture.Binding with { ModuleId = "spoofed.module" },
                _ => true,
                new HashSet<string>(StringComparer.Ordinal).Add,
                fixture.Now));

        Assert.Throws<ArgumentException>(() =>
            new SidecarCapabilitySession(
                fixture.Binding,
                _ => true,
                fixture.Nonces.Add,
                fixture.Now));

        var expired = fixture.Binding with
        {
            ExpiresAt = fixture.Now.AddSeconds(-1),
            Grant = fixture.Binding.Grant with { ExpiresAt = fixture.Now.AddSeconds(-1) },
        };
        Assert.Throws<ArgumentException>(() =>
            new SidecarCapabilitySession(
                expired,
                _ => true,
                new HashSet<string>(StringComparer.Ordinal).Add,
                fixture.Now));
    }

    [Fact]
    public void Session_enforces_sequence_replay_completed_call_and_disconnect_rules()
    {
        var fixture = CreateFixture();
        Assert.True(fixture.Session.BeginCall(fixture.Call, SidecarCapabilityKind.Storage, null, 0, fixture.Now).Accepted);
        Assert.True(fixture.Session.RecordTerminal(fixture.Call.CallId).Accepted);
        Assert.True(fixture.Session.CompleteCall(fixture.Call.CallId).Accepted);

        var reusedCall = fixture.Call with { ReplayNonce = "new-nonce", Sequence = 2 };
        var reused = fixture.Session.BeginCall(reusedCall, SidecarCapabilityKind.Storage, null, 0, fixture.Now);
        Assert.Equal(SidecarCapabilityErrors.Replay, reused.Code);

        var skipped = fixture.Session.BeginCall(
            fixture.Call with { CallId = Guid.NewGuid(), ReplayNonce = "skipped", Sequence = 4 },
            SidecarCapabilityKind.Storage,
            null,
            0,
            fixture.Now);
        Assert.Equal(SidecarCapabilityErrors.Replay, skipped.Code);

        fixture.Session.Disconnect();
        var afterDisconnect = fixture.Session.BeginCall(
            fixture.Call with { CallId = Guid.NewGuid(), ReplayNonce = "after-disconnect", Sequence = 2 },
            SidecarCapabilityKind.Storage,
            null,
            0,
            fixture.Now);
        Assert.Equal(SidecarCapabilityErrors.Disconnected, afterDisconnect.Code);
    }

    [Fact]
    public void Session_enforces_payload_hash_length_frame_size_and_capability_limits()
    {
        var fixture = CreateFixture(maxInFlight: 1, maxCalls: 2);
        var payload = Payload("storage.request", new { key = "job-1" });
        Assert.True(fixture.Session.BeginCall(
            fixture.Call,
            SidecarCapabilityKind.Storage,
            payload,
            payload.ByteLength,
            fixture.Now).Accepted);

        var invalidPayload = payload with { ContentHash = "forged", ByteLength = 0 };
        var invalid = fixture.Session.BeginCall(
            fixture.Call with { CallId = Guid.NewGuid(), ReplayNonce = "invalid", Sequence = 2 },
            SidecarCapabilityKind.Storage,
            invalidPayload,
            invalidPayload.ByteLength,
            fixture.Now);
        Assert.Equal(SidecarCapabilityErrors.InvalidPayload, invalid.Code);

        var concurrent = fixture.Session.BeginCall(
            fixture.Call with { CallId = Guid.NewGuid(), ReplayNonce = "concurrent", Sequence = 2 },
            SidecarCapabilityKind.Storage,
            payload,
            fixture.Binding.PayloadLimits.ProtocolMessageBytes + 1,
            fixture.Now);
        Assert.Equal(SidecarCapabilityErrors.PayloadTooLarge, concurrent.Code);

        var frame = SidecarCapabilityTransportCodec.Serialize(new { frame = "valid" });
        var frameIdentity = new SidecarTransportFrameIdentity(
            SidecarCapabilityTransportCodec.ComputeSha256(frame),
            frame.Length);
        Assert.True(SidecarCapabilityTransportValidation.ValidateFrame(frame, frameIdentity, 1024).Accepted);
        Assert.Equal(
            SidecarCapabilityErrors.PayloadTooLarge,
            SidecarCapabilityTransportValidation.ValidateFrame(frame, frameIdentity, frame.Length - 1).Code);
        Assert.Equal(
            SidecarCapabilityErrors.InvalidPayload,
            SidecarCapabilityTransportValidation.ValidateFrame(
                "not-json"u8.ToArray(),
                new SidecarTransportFrameIdentity("forged", 8),
                1024).Code);
    }

    [Fact]
    public void Session_rejects_capabilities_missing_from_the_grant()
    {
        var fixture = CreateFixture(capabilities: [SidecarCapabilityKind.Storage]);
        var result = fixture.Session.BeginCall(
            fixture.Call with { Capability = SidecarCapabilityKind.Action },
            SidecarCapabilityKind.Action,
            Payload("sample.input", new { value = 1 }),
            64,
            fixture.Now);

        Assert.Equal(SidecarCapabilityErrors.Unauthorized, result.Code);
    }

    [Fact]
    public void Storage_transport_represents_all_gateway_operations_and_validates_payloads()
    {
        var fixture = CreateFixture();
        var type = PayloadType("storage.result");
        var request = Payload("storage.request", new { key = "job-1" });
        var cancellation = Cancellation(fixture);
        var calls = new SidecarStorageCapabilityRequest[]
        {
            SidecarStorageCapabilityRequest.ListContracts(fixture.Call, "module-a", type, cancellation, fixture.Call.Deadline),
            SidecarStorageCapabilityRequest.Invoke(fixture.Call, "module-a", "jobs", request, type, cancellation, fixture.Call.Deadline),
            SidecarStorageCapabilityRequest.CommitMutationAndOutbox(fixture.Call, "module-a", "jobs", request, type, cancellation, fixture.Call.Deadline),
            SidecarStorageCapabilityRequest.Claim(fixture.Call, "module-a", "jobs", request, type, cancellation, fixture.Call.Deadline),
            SidecarStorageCapabilityRequest.RenewClaim(fixture.Call, "module-a", "jobs", request, type, cancellation, fixture.Call.Deadline),
            SidecarStorageCapabilityRequest.RecoverClaim(fixture.Call, "module-a", "jobs", request, type, cancellation, fixture.Call.Deadline),
        };

        Assert.Equal(Enum.GetValues<SidecarStorageOperationKind>(), calls.Select(item => item.Operation).ToArray());
        Assert.All(calls, call =>
            Assert.True(SidecarCapabilityTransportValidation.ValidateStorageRequest(call, fixture.Binding, fixture.Now).Accepted));
    }

    [Fact]
    public void Storage_response_binds_call_result_payload_safe_failure_and_error()
    {
        var fixture = CreateFixture();
        var request = SidecarStorageCapabilityRequest.Invoke(
            fixture.Call,
            "module-a",
            "jobs",
            Payload("storage.request", new { key = "job-1" }),
            PayloadType("storage.result"),
            Cancellation(fixture),
            fixture.Call.Deadline);
        var resultPayload = Payload("storage.claim.result", new { revision = 4 });
        var response = new SidecarStorageCapabilityResponse(
            new SidecarStorageResultIdentity(Guid.NewGuid(), fixture.Call.CallId, resultPayload.ContentHash, true),
            resultPayload,
            new ModuleStorageContractFailure(ModuleStorageErrors.RevisionConflict, "The revision is stale.", "job-1", 3, 4),
            fixture.SafeFailure,
            Completed: false);

        Assert.True(SidecarCapabilityTransportValidation.ValidateStorageResponse(request, response, fixture.Binding).Accepted);
        var spoofed = response with
        {
            ResultIdentity = response.ResultIdentity with { CallId = Guid.NewGuid() },
        };
        Assert.Equal(
            SidecarCapabilityErrors.InvalidResponse,
            SidecarCapabilityTransportValidation.ValidateStorageResponse(request, spoofed, fixture.Binding).Code);
    }

    [Fact]
    public void Action_transport_validates_request_response_and_replacement_terminal_exchange()
    {
        var fixture = CreateFixture();
        var key = new SharpClawActionKey("sample.action");
        var snapshot = new ActionPipelineSnapshot("graph-hash", [new ActionCapabilityGrant(key, 1, ActionInterceptionCapabilities.Inspect)]);
        var descriptor = new SidecarActionDescriptorIdentity(
            key, 1, "sample", "sample.input", "input-schema-hash", "sample.result", "result-schema-hash", "descriptor-hash");
        var receipt = new SidecarTerminalReceipt("receipt-1", key, 1, fixture.Call.CallId, 1, "sample.scope", "receipt-hash");
        var replacement = Payload("sample.input", new { value = 2 });
        var request = new SidecarActionCapabilityRequest(
            fixture.Call with { Capability = SidecarCapabilityKind.Action },
            SidecarActionInvocationKind.RunRequired,
            descriptor,
            Payload("sample.input", new { value = 1 }),
            snapshot,
            new SidecarCancellationIdentity(fixture.Call.CancellationId, "cancel-authority-hash", fixture.Call.Deadline),
            new SidecarTerminalContinuationRequest(Guid.NewGuid(), true, replacement, receipt, fixture.Call.Deadline),
            fixture.Call.Deadline);
        var outcomePayload = Payload("sample.result", new { value = 3 });
        var outcome = new SidecarActionOutcomeEnvelope(
            ActionOutcomeKind.Completed,
            outcomePayload,
            new ContinuationToken(Guid.NewGuid(), "secret"),
            null,
            null,
            receipt,
            fixture.SafeFailure,
            1);
        var resultIdentity = new SidecarActionResultIdentity(
            Guid.NewGuid(), fixture.Call.CallId, key, 1, "sample.result", outcomePayload.ContentHash);
        var continuationResponse = new SidecarTerminalContinuationResponse(
            request.Continuation!.ContinuationRequestId, true, outcome, fixture.SafeFailure);
        var response = new SidecarActionCapabilityResponse(
            resultIdentity, outcome, continuationResponse, fixture.SafeFailure, true);

        Assert.True(SidecarCapabilityTransportValidation.ValidateActionRequest(request, fixture.Binding, fixture.Now).Accepted);
        Assert.True(SidecarCapabilityTransportValidation.ValidateActionResponse(request, response, fixture.Binding).Accepted);

        var terminalRequest = new SidecarActionTerminalTransportRequest(
            request.Call,
            request.Invocation,
            descriptor,
            replacement,
            receipt,
            request.Cancellation,
            request.Deadline);
        var terminalResponse = new SidecarActionTerminalTransportResponse(
            resultIdentity,
            outcome,
            receipt,
            fixture.SafeFailure,
            true);
        Assert.True(SidecarCapabilityTransportValidation.ValidateActionTerminalRequest(terminalRequest, fixture.Binding, fixture.Now).Accepted);
        Assert.True(SidecarCapabilityTransportValidation.ValidateActionTerminalResponse(terminalRequest, terminalResponse, fixture.Binding).Accepted);

        var actionCall = fixture.Call with { Capability = SidecarCapabilityKind.Action };
        Assert.True(fixture.Session.BeginCall(actionCall, SidecarCapabilityKind.Action, request.Action, request.Action.ByteLength, fixture.Now).Accepted);
        Assert.True(fixture.Session.RecordTerminal(actionCall.CallId).Accepted);
        Assert.Equal(
            SidecarCapabilityErrors.TerminalAlreadyCalled,
            fixture.Session.RecordTerminal(actionCall.CallId).Code);
        Assert.Equal("sample.input", terminalRequest.EffectiveAction.TypeIdentity);
        Assert.NotEqual(request.Action.Value.GetProperty("value").GetInt32(), terminalRequest.EffectiveAction.Value.GetProperty("value").GetInt32());
    }

    [Fact]
    public void Action_response_rejects_wrong_call_descriptor_result_and_safe_failure_bindings()
    {
        var fixture = CreateFixture();
        var key = new SharpClawActionKey("sample.action");
        var descriptor = new SidecarActionDescriptorIdentity(key, 1, "sample", "sample.input", "input", "sample.result", "result", "descriptor");
        var request = new SidecarActionCapabilityRequest(
            fixture.Call with { Capability = SidecarCapabilityKind.Action },
            SidecarActionInvocationKind.Run,
            descriptor,
            Payload("sample.input", new { value = 1 }),
            new ActionPipelineSnapshot("graph", []),
            new SidecarCancellationIdentity(fixture.Call.CancellationId, "cancel", fixture.Call.Deadline),
            null,
            fixture.Call.Deadline);
        var result = Payload("sample.result", new { value = 2 });
        var outcome = new SidecarActionOutcomeEnvelope(ActionOutcomeKind.Completed, result, null, null, null, null, fixture.SafeFailure, 1);
        var response = new SidecarActionCapabilityResponse(
            new SidecarActionResultIdentity(Guid.NewGuid(), Guid.NewGuid(), key, 1, "sample.result", result.ContentHash),
            outcome,
            null,
            fixture.SafeFailure,
            true);

        Assert.Equal(
            SidecarCapabilityErrors.InvalidResponse,
            SidecarCapabilityTransportValidation.ValidateActionResponse(request, response, fixture.Binding).Code);
        Assert.Equal(
            SidecarCapabilityErrors.InvalidResponse,
            SidecarCapabilityTransportValidation.ValidateActionResponse(
                request,
                response with { ResultIdentity = response.ResultIdentity with { CallId = fixture.Call.CallId, ActionKey = new SharpClawActionKey("other.action") } },
                fixture.Binding).Code);

        var tamperedResult = response with
        {
            ResultIdentity = response.ResultIdentity with { CallId = fixture.Call.CallId, ContentHash = "forged" },
            Outcome = response.Outcome with
            {
                Result = response.Outcome.Result! with { ContentHash = "forged" },
            },
        };
        Assert.Equal(
            SidecarCapabilityErrors.InvalidPayload,
            SidecarCapabilityTransportValidation.ValidateActionResponse(request, tamperedResult, fixture.Binding).Code);
    }

    [Fact]
    public void Transport_interface_exposes_storage_action_and_duplex_terminal_paths()
    {
        var methods = typeof(ISidecarCapabilityTransport).GetMethods();
        Assert.Equal(3, methods.Length);
        Assert.Contains(methods, method => method.Name == nameof(ISidecarCapabilityTransport.InvokeStorageAsync));
        Assert.Contains(methods, method => method.Name == nameof(ISidecarCapabilityTransport.InvokeActionAsync));
        Assert.Contains(methods, method => method.Name == nameof(ISidecarCapabilityTransport.InvokeActionTerminalAsync));
    }

    private static Fixture CreateFixture(
        int maxInFlight = 2,
        int maxCalls = 4,
        IReadOnlyList<SidecarCapabilityKind>? capabilities = null)
    {
        var now = new DateTimeOffset(2026, 8, 14, 12, 0, 0, TimeSpan.Zero);
        var expires = now.AddMinutes(5);
        var safeFailure = new SidecarSafeFailureIdentity(Guid.NewGuid(), "sidecar.test.failure", "The test failure is safe.");
        var proof = new SidecarAuthenticationProof("hmac-sha256", "host-a", "nonce-a", "signature", "", now, expires);
        var binding = new SidecarCapabilitySessionBinding(
            "module-a",
            "graph-a",
            1,
            new SidecarCapabilityGrant(
                "grant-a",
                "module-a",
                "graph-a",
                capabilities ?? [SidecarCapabilityKind.Storage, SidecarCapabilityKind.Action],
                "authorization-hash",
                now.AddMinutes(-1),
                expires),
            Guid.NewGuid(),
            Guid.NewGuid(),
            Guid.NewGuid(),
            expires,
            new SidecarPayloadLimits(1024, 1024, 1024, 2048, 512),
            new SidecarConcurrencyLimits(maxInFlight, maxCalls),
            safeFailure,
            "host-a",
            proof);
        binding = binding with
        {
            Authentication = proof with
            {
                BindingHash = SidecarCapabilitySessionValidator.ComputeBindingHash(binding),
            },
        };
        var nonces = new HashSet<string>(StringComparer.Ordinal);
        var session = new SidecarCapabilitySession(
            binding,
            authority => authority.BindingHash == binding.Authentication.BindingHash,
            nonces.Add,
            now);
        var call = new SidecarCapabilityCallIdentity(
            binding.SessionId,
            binding.RequestId,
            binding.CancellationId,
            Guid.NewGuid(),
            "call-nonce-1",
            binding.ModuleId,
            binding.GraphId,
            SidecarCapabilityKind.Storage,
            1,
            now.AddMinutes(1));
        return new Fixture(now, binding, session, call, safeFailure, nonces);
    }

    private static SidecarSerializedPayload Payload<T>(string typeIdentity, T value)
    {
        var bytes = SidecarCapabilityTransportCodec.Serialize(value);
        using var document = JsonDocument.Parse(bytes);
        return new SidecarSerializedPayload(
            typeIdentity,
            1,
            SidecarCapabilityTransportCodec.ComputeSha256(bytes),
            document.RootElement.Clone(),
            bytes.Length);
    }

    private static SidecarPayloadTypeIdentity PayloadType(string typeIdentity) =>
        new(typeIdentity, 1, $"{typeIdentity}-hash");

    private static SidecarCancellationIdentity Cancellation(Fixture fixture) =>
        new(fixture.Binding.CancellationId, "cancellation-authority-hash", fixture.Call.Deadline);

    private sealed record Fixture(
        DateTimeOffset Now,
        SidecarCapabilitySessionBinding Binding,
        SidecarCapabilitySession Session,
        SidecarCapabilityCallIdentity Call,
        SidecarSafeFailureIdentity SafeFailure,
        HashSet<string> Nonces);
}
