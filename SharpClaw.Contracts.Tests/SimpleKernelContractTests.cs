using System.Text.Json;
using SharpClaw.Contracts.Modules;

namespace SharpClaw.Contracts.Tests;

public sealed class SimpleKernelContractTests
{
    private static readonly JsonSerializerOptions JsonOptions =
        new(JsonSerializerDefaults.Web);

    [Fact]
    public void ActionDescriptorRoundTripsCapabilitiesContinuationAndSafePoints()
    {
        var descriptor = new ActionDescriptor<string, string>(
            new SharpClawActionKey("demo.action"),
            3,
            "demo",
            ActionInterceptionCapabilities.Inspect |
            ActionInterceptionCapabilities.ReplaceInput |
            ActionInterceptionCapabilities.Defer,
            ContainsSensitiveData: true,
            HasIrreversibleEffects: false,
            new ActionRepeatPolicy(ActionRepeatKind.Idempotent, 3, TimeSpan.FromSeconds(1), "demo"),
            new ActionContinuationPolicy(TimeSpan.FromHours(1), Durable: true, SingleClaim: true),
            TimeSpan.FromSeconds(5))
        {
            SafePoints = [ActionSafePoint.BeforeTerminal, ActionSafePoint.BeforeCommit],
            ProtocolVersionRange = new ContractVersionRange(1, 2),
        };

        var json = JsonSerializer.Serialize(descriptor, JsonOptions);
        var roundTrip = JsonSerializer.Deserialize<ActionDescriptor<string, string>>(json, JsonOptions)!;

        Assert.Equal("demo.action", roundTrip.Key.Value);
        Assert.Equal(3, roundTrip.Version);
        Assert.True(roundTrip.ContainsSensitiveData);
        Assert.Equal(ActionRepeatKind.Idempotent, roundTrip.RepeatPolicy.Kind);
        Assert.Equal([ActionSafePoint.BeforeTerminal, ActionSafePoint.BeforeCommit], roundTrip.SafePoints);
        Assert.Equal(2, roundTrip.ProtocolVersionRange.Maximum);
    }

    [Fact]
    public void TypedAndWildcardActionContextsPreserveInvocationIdentity()
    {
        var invocationId = Guid.NewGuid();
        var traceId = Guid.NewGuid();
        var idempotencyKey = Guid.NewGuid();
        var snapshot = new ActionPipelineSnapshot("hash", []);
        var caller = new RequestPrincipal("user-1");

        var typed = new ActionContext<string>(
            invocationId,
            null,
            traceId,
            idempotencyKey,
            1,
            2,
            DateTimeOffset.UtcNow.AddMinutes(1),
            new SharpClawActionKey("demo.action"),
            "demo.module",
            caller,
            "value",
            ExtensionFeatureSet.Empty,
            snapshot);

        var untyped = new UntypedActionContext(
            invocationId,
            null,
            traceId,
            idempotencyKey,
            typed.Depth,
            typed.Attempt,
            typed.Deadline,
            typed.OwnerModuleId,
            caller,
            ExtensionFeatureSet.Empty,
            snapshot.ContractHash,
            new UntypedActionDescriptor(
                new SharpClawActionKey("demo.action"),
                1,
                "demo",
                ActionInterceptionCapabilities.Inspect,
                new JsonSchemaReference("demo.input", 1),
                new JsonSchemaReference("demo.result", 1),
                false),
            CreateElement(new { value = "value" }));

        Assert.Equal(typed.InvocationId, untyped.InvocationId);
        Assert.Equal(typed.TraceId, untyped.TraceId);
        Assert.Equal(typed.IdempotencyKey, untyped.IdempotencyKey);
        Assert.Equal(typed.ActionKey.Value, untyped.Descriptor.Key.Value);
    }

    [Fact]
    public void TypedAndWildcardEventEnvelopesPreserveCompleteDescriptor()
    {
        var key = new SharpClawEventKey("demo.event");
        var descriptor = new UntypedEventDescriptor(
            key,
            2,
            "demo",
            EventInterceptionCapabilities.Inspect | EventInterceptionCapabilities.Observe,
            new JsonSchemaReference("demo.event", 2, "hash"),
            ContainsSensitiveData: true);
        var envelope = new UntypedEventEnvelope(
            descriptor,
            Guid.NewGuid(),
            Guid.NewGuid(),
            Guid.NewGuid(),
            DateTimeOffset.UtcNow,
            "demo.module",
            CreateElement(new { value = 7 }));

        var json = JsonSerializer.Serialize(envelope, JsonOptions);
        var roundTrip = JsonSerializer.Deserialize<UntypedEventEnvelope>(json, JsonOptions)!;

        Assert.Equal(key.Value, roundTrip.Descriptor.Key.Value);
        Assert.Equal(2, roundTrip.Descriptor.Version);
        Assert.Equal("demo.event", roundTrip.Descriptor.PayloadSchema.ContractName);
        Assert.True(roundTrip.Descriptor.ContainsSensitiveData);
        Assert.Equal(7, roundTrip.Payload.GetProperty("value").GetInt32());
    }

    [Fact]
    public void UncertaintyCarriesRecoveryAndIsNotRetryable()
    {
        var uncertainty = new ActionUncertainty(
            "external_unknown",
            "The external result is not known.",
            ActionExecutionStage.TerminalReturned,
            "receipt-7",
            new ActionRecoveryReference(
                Guid.NewGuid(),
                new SharpClawActionKey("demo.external"),
                4,
                Guid.NewGuid()),
            DateTimeOffset.UtcNow);

        var exception = new ActionOutcomeUncertainException(uncertainty);

        Assert.False(uncertainty.AutomaticRepeatAllowed);
        Assert.False(exception.IsRetryable);
        Assert.Equal(uncertainty.Recovery.RecoveryId, exception.Uncertainty.Recovery.RecoveryId);
    }

    [Fact]
    public void SensitiveWildcardApprovalRequiresExactActionAndEventVersion()
    {
        var approval = new SensitiveWildcardApproval(
            "trusted.module",
            new Dictionary<string, int> { ["security.secret.read"] = 2 },
            new Dictionary<string, int> { ["security.changed"] = 1 });

        Assert.True(approval.CoversAction(new SharpClawActionKey("security.secret.read"), 2));
        Assert.False(approval.CoversAction(new SharpClawActionKey("security.secret.read"), 3));
        Assert.True(approval.CoversEvent(new SharpClawEventKey("security.changed"), 1));
        Assert.False(approval.CoversEvent(new SharpClawEventKey("security.changed"), 2));
    }

    [Fact]
    public void JobsCatalogHas46FamiliesAnd138UniqueKeys()
    {
        Assert.Equal(46, JobsActionCoverageManifest.FamilyCount);
        Assert.Equal(138, JobsActionCoverageManifest.KeyCount);
        Assert.Equal(138, JobsActionCoverageManifest.Keys.Select(key => key.Value).Distinct().Count());

        foreach (var family in JobsActionCoverageManifest.Families)
        {
            Assert.Contains(new SharpClawActionKey(family), JobsActionCoverageManifest.Keys);
            Assert.Contains(new SharpClawActionKey($"{family}.before"), JobsActionCoverageManifest.Keys);
            Assert.Contains(new SharpClawActionKey($"{family}.after"), JobsActionCoverageManifest.Keys);
        }
    }

    [Fact]
    public void SidecarContinuationExchangePreservesAllOutcomeState()
    {
        var handle = new ContinuationHandle(
            Guid.NewGuid(),
            Guid.NewGuid(),
            "hook-1",
            DateTimeOffset.UtcNow.AddMinutes(1),
            4);
        var start = new HookInvokeStart(
            1,
            4,
            handle.InvocationId,
            null,
            Guid.NewGuid(),
            handle.HookId,
            new SharpClawActionKey("jobs.external_call"),
            1,
            SidecarPayloadMode.Untyped,
            CreateElement(new { value = 1 }),
            new UntypedActionDescriptor(
                new SharpClawActionKey("jobs.external_call"),
                1,
                "jobs",
                ActionInterceptionCapabilities.Inspect | ActionInterceptionCapabilities.Wrap,
                new JsonSchemaReference("jobs.external_call.input", 1),
                new JsonSchemaReference("jobs.external_call.result", 1),
                false),
            new ActionCapabilityGrant(
                new SharpClawActionKey("jobs.external_call"),
                1,
                ActionInterceptionCapabilities.Inspect | ActionInterceptionCapabilities.Wrap),
            new RequestPrincipal("user-1"),
            ExtensionFeatureSet.Empty,
            DateTimeOffset.UtcNow.AddSeconds(30),
            handle);
        var replacement = new ContinueReplacement(
            handle.HandleId,
            5,
            CreateElement(new { value = 2 }),
            "bounded replacement");
        var outcome = new ContinuationOutcome(
            handle.HandleId,
            6,
            ActionOutcomeKind.Uncertain,
            ActionSafePoint.AfterTerminal,
            Uncertainty: new ActionUncertainty(
                "external_unknown",
                "Unknown.",
                ActionExecutionStage.TerminalReturned,
                "receipt-1",
                new ActionRecoveryReference(
                    Guid.NewGuid(),
                    new SharpClawActionKey("jobs.external_call"),
                    1,
                    Guid.NewGuid()),
                DateTimeOffset.UtcNow));

        var json = JsonSerializer.Serialize(
            new SidecarExchangeFixture(start, replacement, outcome),
            JsonOptions);
        var roundTrip = JsonSerializer.Deserialize<SidecarExchangeFixture>(json, JsonOptions)!;

        Assert.Equal(start.Continuation.HandleId, roundTrip.Start.Continuation.HandleId);
        Assert.Equal(2, roundTrip.Replacement.Replacement.GetProperty("value").GetInt32());
        Assert.Equal(ActionOutcomeKind.Uncertain, roundTrip.Outcome.Kind);
        Assert.Equal("receipt-1", roundTrip.Outcome.Uncertainty!.ReceiptReference);
        Assert.Equal(ActionSafePoint.AfterTerminal, roundTrip.Outcome.SafePoint);
    }

    [Fact]
    public void VersionNegotiationRejectsDisjointRanges()
    {
        var host = new ProtocolVersionNegotiation(1, 2);
        var sidecar = new ProtocolVersionNegotiation(3, 4);

        Assert.Null(host.Select(sidecar));
        Assert.Equal(2, host.Select(new ProtocolVersionNegotiation(2, 4)));
    }

    [Fact]
    public void DirectChatAndToolContractsUseOneInvocationShape()
    {
        var invocation = new ToolInvocation(
            Guid.NewGuid(),
            Guid.NewGuid(),
            "call-1",
            "clock_now",
            CreateElement(new { }),
            new RequestPrincipal("user-1"),
            ExtensionFeatureSet.Empty);
        var turn = new ChatTurnInput(
            "What time is it?",
            invocation.ConversationId,
            invocation.Caller,
            invocation.Features);
        var contribution = new ChatContextContribution(
            [new SystemPromptSegment("demo", "Use the clock tool.")],
            [],
            []);
        var result = ToolInvocationOutcome.Completed(ToolResult.Text("12:00"));

        Assert.Equal(invocation.ConversationId, turn.ConversationId);
        Assert.Single(contribution.SystemPromptSegments);
        Assert.Equal(ActionOutcomeKind.Completed, result.Kind);
        Assert.Equal("12:00", result.Result!.Content);
    }

    [Fact]
    public void UnsupportedEffectIsRepresentedAsGraphCompilationFailure()
    {
        var error = new GraphCompilationError(
            "unsupported_effect",
            "trusted.module",
            "jobs.external_call",
            "replace_result",
            "The selected grant does not support this effect.");

        Assert.Equal("unsupported_effect", error.Code);
        Assert.Equal("replace_result", error.RequestedEffect);
    }

    private static JsonElement CreateElement<T>(T value) =>
        JsonSerializer.SerializeToElement(value, JsonOptions);

    private sealed record SidecarExchangeFixture(
        HookInvokeStart Start,
        ContinueReplacement Replacement,
        ContinuationOutcome Outcome);
}
