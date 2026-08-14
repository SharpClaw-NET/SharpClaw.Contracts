using System.Text;
using System.Text.Json;
using SharpClaw.Contracts.Modules;

namespace SharpClaw.Contracts.Tests;

public sealed class SidecarCapabilityTransportTests
{
    [Fact]
    public void SessionBinding_serializes_canonically_and_rejects_unknown_fields()
    {
        var fixture = CreateFixture();
        var first = SidecarCapabilityTransportCodec.Serialize(fixture.Binding);
        var second = SidecarCapabilityTransportCodec.Serialize(fixture.Binding);

        Assert.Equal(first, second);
        var roundTrip = SidecarCapabilityTransportCodec.Deserialize<SidecarCapabilitySessionBinding>(first);
        Assert.Equal(fixture.Binding.ModuleId, roundTrip.ModuleId);
        Assert.Equal(fixture.Binding.GraphId, roundTrip.GraphId);
        Assert.Equal(fixture.Binding.SessionId, roundTrip.SessionId);
        Assert.Equal(fixture.Binding.Grant.Capabilities, roundTrip.Grant.Capabilities);
        Assert.Equal(first, SidecarCapabilityTransportCodec.Serialize(roundTrip));

        var json = Encoding.UTF8.GetString(first);
        var withUnknown = Encoding.UTF8.GetBytes(json[..^1] + ",\"unexpected\":true}");
        Assert.Throws<JsonException>(() =>
            SidecarCapabilityTransportCodec.Deserialize<SidecarCapabilitySessionBinding>(withUnknown));
    }

    [Fact]
    public void Session_rejects_unauthenticated_and_invalid_bindings()
    {
        var fixture = CreateFixture();
        Assert.Throws<ArgumentException>(() =>
            new SidecarCapabilitySession(
                fixture.Binding,
                _ => false,
                fixture.Now));

        var expired = fixture.Binding with { ExpiresAt = fixture.Now.AddSeconds(-1) };
        Assert.Throws<ArgumentException>(() =>
            new SidecarCapabilitySession(expired, _ => true, fixture.Now));
    }

    [Fact]
    public void Session_rejects_spoofing_replay_duplicate_and_disconnect()
    {
        var fixture = CreateFixture();
        var session = fixture.Session;
        var accepted = session.BeginCall(fixture.Call, SidecarCapabilityKind.Storage, 32, fixture.Now);
        Assert.True(accepted.Accepted);

        var spoofed = fixture.Call with
        {
            CallId = Guid.NewGuid(),
            ReplayNonce = "spoofed",
            ModuleId = "other.module",
        };
        var spoofResult = session.BeginCall(spoofed, SidecarCapabilityKind.Storage, 32, fixture.Now);
        Assert.False(spoofResult.Accepted);
        Assert.Equal(SidecarCapabilityErrors.SpoofedIdentity, spoofResult.Code);

        var replayResult = session.BeginCall(fixture.Call, SidecarCapabilityKind.Storage, 32, fixture.Now);
        Assert.False(replayResult.Accepted);
        Assert.Equal(SidecarCapabilityErrors.Replay, replayResult.Code);

        Assert.True(session.RecordTerminal(fixture.Call.CallId).Accepted);
        var duplicateTerminal = session.RecordTerminal(fixture.Call.CallId);
        Assert.False(duplicateTerminal.Accepted);
        Assert.Equal(SidecarCapabilityErrors.TerminalAlreadyCalled, duplicateTerminal.Code);
        Assert.True(session.CompleteCall(fixture.Call.CallId).Accepted);
        Assert.Equal(
            SidecarCapabilityErrors.Duplicate,
            session.CompleteCall(fixture.Call.CallId).Code);

        session.Disconnect();
        var afterDisconnect = session.BeginCall(
            fixture.Call with { CallId = Guid.NewGuid(), ReplayNonce = "after-disconnect" },
            SidecarCapabilityKind.Storage,
            32,
            fixture.Now);
        Assert.False(afterDisconnect.Accepted);
        Assert.Equal(SidecarCapabilityErrors.Disconnected, afterDisconnect.Code);
    }

    [Fact]
    public void Session_enforces_grant_expiry_payload_and_concurrency_limits()
    {
        var fixture = CreateFixture(maxInFlight: 1, maxCalls: 2);
        var session = fixture.Session;
        Assert.True(session.BeginCall(fixture.Call, SidecarCapabilityKind.Storage, 32, fixture.Now).Accepted);

        var concurrent = session.BeginCall(
            fixture.Call with { CallId = Guid.NewGuid(), ReplayNonce = "concurrent" },
            SidecarCapabilityKind.Storage,
            32,
            fixture.Now);
        Assert.Equal(SidecarCapabilityErrors.ConcurrencyLimit, concurrent.Code);

        var oversized = session.BeginCall(
            fixture.Call with { CallId = Guid.NewGuid(), ReplayNonce = "oversized" },
            SidecarCapabilityKind.Storage,
            fixture.Binding.PayloadLimits.ProtocolMessageBytes + 1,
            fixture.Now);
        Assert.Equal(SidecarCapabilityErrors.PayloadTooLarge, oversized.Code);

        Assert.True(session.CompleteCall(fixture.Call.CallId).Accepted);
        var secondCall = fixture.Call with { CallId = Guid.NewGuid(), ReplayNonce = "second" };
        Assert.True(session.BeginCall(
            secondCall,
            SidecarCapabilityKind.Storage,
            32,
            fixture.Now).Accepted);

        var limit = session.BeginCall(
            fixture.Call with { CallId = Guid.NewGuid(), ReplayNonce = "third" },
            SidecarCapabilityKind.Storage,
            32,
            fixture.Now);
        Assert.Equal(SidecarCapabilityErrors.ConcurrencyLimit, limit.Code);
        Assert.True(session.CompleteCall(secondCall.CallId).Accepted);

        var expired = session.BeginCall(
            fixture.Call with { CallId = Guid.NewGuid(), ReplayNonce = "expired" },
            SidecarCapabilityKind.Storage,
            32,
            fixture.Binding.ExpiresAt.AddSeconds(1));
        Assert.Equal(SidecarCapabilityErrors.Expired, expired.Code);
    }

    [Fact]
    public void Session_rejects_capabilities_missing_from_the_grant()
    {
        var fixture = CreateFixture(capabilities: [SidecarCapabilityKind.Storage]);
        var result = fixture.Session.BeginCall(
            fixture.Call,
            SidecarCapabilityKind.Action,
            32,
            fixture.Now);

        Assert.False(result.Accepted);
        Assert.Equal(SidecarCapabilityErrors.Unauthorized, result.Code);
    }

    [Fact]
    public void Storage_transport_represents_all_gateway_operations()
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

        Assert.Equal(
            Enum.GetValues<SidecarStorageOperationKind>(),
            calls.Select(item => item.Operation).ToArray());
        Assert.Null(calls[0].RequestPayload);
        Assert.Equal("storage.request", calls[1].RequestPayload!.TypeIdentity);
        Assert.Equal("storage.result", calls[5].ResultPayloadType.TypeIdentity);
        Assert.All(calls, call =>
            Assert.True(SidecarCapabilityTransportValidation.ValidateStorageRequest(call, fixture.Now).Accepted));
    }

    [Fact]
    public void Storage_transport_preserves_result_identity_claims_revisions_and_exact_errors()
    {
        var safeFailure = SafeFailure();
        var resultIdentity = new SidecarStorageResultIdentity(
            Guid.NewGuid(),
            Guid.NewGuid(),
            "result-hash",
            AlreadyCommitted: true);
        var failure = new ModuleStorageContractFailure(
            ModuleStorageErrors.RevisionConflict,
            "The revision is stale.",
            "job-1",
            ExpectedRevision: 3,
            ActualRevision: 4);
        var response = new SidecarStorageCapabilityResponse(
            resultIdentity,
            Payload("storage.claim.result", new
            {
                revision = 4,
                owner = "host-a",
                generation = 2,
            }),
            failure,
            safeFailure,
            Completed: false);

        Assert.Equal("result-hash", response.ResultIdentity.ContentHash);
        Assert.Equal(3, response.Error!.ExpectedRevision);
        Assert.Equal("storage.claim.result", response.ResultPayload!.TypeIdentity);
        Assert.False(response.Completed);
    }

    [Fact]
    public void Action_transport_preserves_descriptor_snapshot_cancellation_continuation_and_outcome()
    {
        var fixture = CreateFixture();
        var key = new SharpClawActionKey("sample.action");
        var grant = new ActionCapabilityGrant(key, 1, ActionInterceptionCapabilities.Inspect);
        var snapshot = new ActionPipelineSnapshot("graph-hash", [grant]);
        var descriptor = new SidecarActionDescriptorIdentity(
            key,
            1,
            "sample",
            "sample.input",
            "input-schema-hash",
            "sample.result",
            "result-schema-hash",
            "descriptor-hash");
        var receipt = new SidecarTerminalReceipt(
            "receipt-1",
            key,
            1,
            fixture.Call.CallId,
            1,
            "sample.scope",
            "receipt-hash");
        var continuation = new SidecarTerminalContinuationRequest(
            Guid.NewGuid(),
            Proceed: true,
            Payload("sample.replacement", new { value = 2 }),
            receipt,
            fixture.Call.Deadline);
        var request = new SidecarActionCapabilityRequest(
            fixture.Call with { Capability = SidecarCapabilityKind.Action },
            SidecarActionInvocationKind.RunRequired,
            descriptor,
            Payload("sample.input", new { value = 1 }),
            snapshot,
            new SidecarCancellationIdentity(
                fixture.Call.CancellationId,
                "cancel-authority-hash",
                fixture.Call.Deadline),
            continuation,
            fixture.Call.Deadline);
        var outcome = new SidecarActionOutcomeEnvelope(
            ActionOutcomeKind.Completed,
            Payload("sample.result", new { value = 3 }),
            new ContinuationToken(Guid.NewGuid(), "secret"),
            null,
            null,
            receipt,
            SafeFailure(),
            TerminalCallCount: 1);
        var response = new SidecarActionCapabilityResponse(
            Guid.NewGuid(),
            outcome,
            new SidecarTerminalContinuationResponse(
                continuation.ContinuationRequestId,
                Accepted: true,
                outcome,
                SafeFailure()),
            SafeFailure(),
            Completed: true);

        Assert.Equal(key, request.Descriptor.Key);
        Assert.Equal("graph-hash", request.Snapshot.ContractHash);
        Assert.Equal(fixture.Call.CancellationId, request.Cancellation.CancellationId);
        Assert.Equal("sample.replacement", request.Continuation!.ReplacementResult!.TypeIdentity);
        Assert.Equal(receipt, response.Outcome.Receipt);
        Assert.Equal(ActionOutcomeKind.Completed, response.Outcome.Kind);
        Assert.Equal(1, response.Outcome.TerminalCallCount);
        Assert.True(SidecarCapabilityTransportValidation.ValidateActionRequest(request, fixture.Now).Accepted);
        Assert.True(SidecarCapabilityTransportValidation.ValidateActionResponse(response).Accepted);
    }

    [Fact]
    public void Transport_interface_exposes_one_storage_and_one_action_path()
    {
        var methods = typeof(ISidecarCapabilityTransport).GetMethods();
        Assert.Equal(2, methods.Length);
        Assert.Contains(methods, method => method.Name == nameof(ISidecarCapabilityTransport.InvokeStorageAsync));
        Assert.Contains(methods, method => method.Name == nameof(ISidecarCapabilityTransport.InvokeActionAsync));
    }

    private static Fixture CreateFixture(
        int maxInFlight = 2,
        int maxCalls = 4,
        IReadOnlyList<SidecarCapabilityKind>? capabilities = null)
    {
        var now = new DateTimeOffset(2026, 8, 14, 12, 0, 0, TimeSpan.Zero);
        var expires = now.AddMinutes(5);
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
            SafeFailure(),
            new SidecarAuthenticationProof("hmac-sha256", "host-a", "nonce-a", "signature", now));
        var session = new SidecarCapabilitySession(binding, proof => proof.Signature == "signature", now);
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
        return new Fixture(now, binding, session, call);
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

    private static SidecarSafeFailureIdentity SafeFailure() =>
        new(Guid.NewGuid(), "sidecar.test.failure", "The test failure is safe.");

    private static SidecarCancellationIdentity Cancellation(Fixture fixture) =>
        new(fixture.Binding.CancellationId, "cancellation-authority-hash", fixture.Call.Deadline);

    private sealed record Fixture(
        DateTimeOffset Now,
        SidecarCapabilitySessionBinding Binding,
        SidecarCapabilitySession Session,
        SidecarCapabilityCallIdentity Call);
}
