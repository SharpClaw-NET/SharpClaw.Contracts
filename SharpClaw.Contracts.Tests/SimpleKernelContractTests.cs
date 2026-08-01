using System.Text.Json;
using System.Text.Json.Serialization;
using System.Reflection;
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
        Assert.Equal(46, SharpClawActionCatalog.JobsFamilies.Count);
        Assert.Equal(138, SharpClawActionCatalog.Jobs.Count);
        Assert.Equal(138, SharpClawActionCatalog.Jobs.Select(key => key.Value).Distinct().Count());

        foreach (var family in SharpClawActionCatalog.JobsFamilies)
        {
            Assert.Contains(new SharpClawActionKey(family), SharpClawActionCatalog.Jobs);
            Assert.Contains(new SharpClawActionKey($"{family}.before"), SharpClawActionCatalog.Jobs);
            Assert.Contains(new SharpClawActionKey($"{family}.after"), SharpClawActionCatalog.Jobs);
        }
    }

    [Fact]
    public void EveryTypedActionAndCheckpointKeyIsInCatalog()
    {
        var typedKeys = typeof(SharpClawActions)
            .GetNestedTypes(BindingFlags.Public)
            .SelectMany(type => type.GetFields(BindingFlags.Public | BindingFlags.Static))
            .Where(field => field.FieldType == typeof(SharpClawActionKey))
            .Select(field => (SharpClawActionKey)field.GetValue(null)!)
            .Concat(typeof(SharpClawCheckpoints)
                .GetNestedTypes(BindingFlags.Public)
                .SelectMany(type => type.GetFields(BindingFlags.Public | BindingFlags.Static))
                .Where(field => field.FieldType == typeof(SharpClawActionKey))
                .Select(field => (SharpClawActionKey)field.GetValue(null)!))
            .ToArray();

        Assert.NotEmpty(typedKeys);
        Assert.All(typedKeys, key => Assert.Contains(key, SharpClawActionCatalog.All));
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
            Header(4),
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
            handle);
        var replacement = new SidecarEffectRequest(
            Header(5),
            handle.HandleId,
            SidecarContinuationCommand.ContinueReplacement,
            CreateElement(new { value = 2 }),
            "bounded replacement");
        var outcome = new ContinuationOutcome(
            Header(6),
            handle.HandleId,
            ActionOutcomeKind.Uncertain,
            ActionOutcomeCertainty.Uncertain,
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
        Assert.Equal(2, roundTrip.Replacement.Value!.Value.GetProperty("value").GetInt32());
        Assert.Equal(ActionOutcomeKind.Uncertain, roundTrip.Outcome.Kind);
        Assert.Equal("receipt-1", roundTrip.Outcome.Uncertainty!.ReceiptReference);
        Assert.Equal(ActionSafePoint.AfterTerminal, roundTrip.Outcome.SafePoint);
    }

    [Fact]
    public void SidecarDiscoveryCarriesDefinitionsAndRejectsSchemaMismatch()
    {
        var header = Header();
        var definition = new SidecarActionDefinition(
            new SharpClawActionKey("demo.action"),
            1,
            "demo",
            new JsonSchemaReference("demo.input", 1, "input-hash"),
            new JsonSchemaReference("demo.result", 1, "result-hash"),
            ActionInterceptionCapabilities.Inspect,
            ContainsSensitiveData: false,
            HasIrreversibleEffects: false,
            new ActionRepeatPolicy(ActionRepeatKind.None, 1, TimeSpan.Zero, "demo"),
            null,
            [ActionSafePoint.BeforeTerminal],
            ContractVersionRange.Exact(1));
        var discovery = new SidecarDiscoveryEnvelope(
            header,
            "demo.module",
            "contract-hash",
            new SidecarProtocolOffer(1, 1, [SidecarPayloadMode.Untyped], new SidecarPayloadLimits()),
            [new SidecarActionSubscription(
                SidecarHookTargetKind.Exact,
                definition.ActionKey,
                null,
                ContractVersionRange.Exact(1),
                new JsonSchemaReference("demo.input", 1, "wrong-input-hash"),
                definition.ResultSchema,
                ActionInterceptionCapabilities.Inspect,
                SidecarPayloadMode.Untyped,
                new HookOrdering("demo"))],
            [],
            [definition],
            [],
            [new SidecarToolHandlerDefinition(
                "demo.tool",
                "handler-1",
                "Demo tool",
                new JsonSchemaReference("demo.tool.input", 1),
                new JsonSchemaReference("demo.tool.result", 1),
                SupportsStreaming: true,
                Durable: false,
                RequiresApproval: false)],
            [new SidecarLifecycleHandlerDefinition(
                SidecarLifecycleCallKind.Start,
                "start-1",
                null,
                new JsonSchemaReference("demo.start.result", 1),
                ContractVersionRange.Exact(1),
                TimeSpan.FromSeconds(5))],
            [new ModuleFeatureDescriptor("demo.feature", 1, "demo.module", 1024)]);

        var validation = SidecarDiscoveryValidator.Validate(discovery);

        Assert.False(validation.Accepted);
        Assert.Equal(SidecarProtocolErrors.SchemaMismatch, validation.ErrorCode);
        Assert.DoesNotContain(
            typeof(SidecarDiscoveryEnvelope).GetProperties(),
            property => property.Name.Contains("Approval", StringComparison.Ordinal));
    }

    [Fact]
    public void SidecarEffectsAndMessagesUseHeaderAndSupportTerminalCancellation()
    {
        var effect = new SidecarEffectRequest(
            Header(8),
            Guid.NewGuid(),
            SidecarContinuationCommand.Cancel,
            Code: "user_cancelled",
            Message: "The caller cancelled the action.");

        Assert.Equal(1, effect.Header.ProtocolVersion);
        Assert.Equal(8, effect.Header.Sequence);
        Assert.True(effect.Header.Size.IsWithinLimit);
        Assert.True(SidecarProtocolStateMachine.CanApply(
            SidecarProtocolPhase.Invoking,
            SidecarProtocolMessageKind.EffectRequest,
            SidecarContinuationCommand.Cancel));
        Assert.True(SidecarProtocolStateMachine.CanApply(
            SidecarProtocolPhase.EffectAccepted,
            SidecarProtocolMessageKind.ContinuationOutcome));
        Assert.True(SidecarProtocolStateMachine.CanApply(
            SidecarProtocolPhase.OutcomeSent,
            SidecarProtocolMessageKind.HookOutcome));
    }

    [Fact]
    public void SidecarEffectCatalogCoversEveryPreTerminalEffectAndPhase()
    {
        var handle = Guid.NewGuid();
        var sequence = 10L;

        foreach (var command in Enum.GetValues<SidecarContinuationCommand>())
        {
            var request = new SidecarEffectRequest(
                Header(sequence++),
                handle,
                command,
                Value: CreateElement(new { value = 1 }),
                Reason: "conformance",
                Code: "test",
                Message: "test",
                Defer: new ActionDeferRequest(
                    DateTimeOffset.UtcNow.AddMinutes(1),
                    "conformance"),
                Backoff: TimeSpan.FromMilliseconds(5));

            Assert.Equal(command, request.Command);
            Assert.True(SidecarProtocolStateMachine.CanApply(
                SidecarProtocolPhase.Invoking,
                request.MessageKind,
                command));
        }

        Assert.True(SidecarProtocolStateMachine.CanApply(
            SidecarProtocolPhase.EffectRequested,
            SidecarProtocolMessageKind.EffectAccepted));
        Assert.True(SidecarProtocolStateMachine.CanApply(
            SidecarProtocolPhase.OutcomeSent,
            SidecarProtocolMessageKind.HookCompleted));
        Assert.False(SidecarProtocolStateMachine.CanApply(
            SidecarProtocolPhase.Completed,
            SidecarProtocolMessageKind.EffectRequest,
            SidecarContinuationCommand.Repeat));
        Assert.True(SidecarProtocolStateMachine.CanApply(
            SidecarProtocolPhase.Invoking,
            SidecarProtocolMessageKind.Error));
        var disconnected = new SidecarProtocolError(
            Header(20),
            SidecarProtocolErrors.Disconnected,
            "The sidecar disconnected.");
        Assert.Equal(SidecarProtocolErrors.Disconnected, disconnected.Code);
    }

    [Fact]
    public void ForgedSensitiveApprovalIsRejectedByStrictDiscoveryDeserialization()
    {
        const string forged = "{\"moduleId\":\"module\",\"sensitiveApproval\":{\"moduleId\":\"module\"}}";
        var options = new JsonSerializerOptions(JsonSerializerDefaults.Web)
        {
            UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        };

        Assert.Throws<JsonException>(() =>
            JsonSerializer.Deserialize<SidecarDiscoveryEnvelope>(forged, options));
    }

    [Fact]
    public void DuplexStreamCarriesMutationCancellationAcknowledgementAndCredit()
    {
        var streamId = Guid.NewGuid();
        var chunk = new SidecarStreamChunk(
            Header(),
            streamId,
            3,
            CreateElement(new { token = "hello" }),
            IsFinal: false,
            new SidecarStreamMutation(
                SidecarStreamMutationKind.Transform,
                CreateElement(new { token = "HELLO" }),
                "uppercase"));
        var control = new SidecarStreamControl(
            Header(4),
            streamId,
            SidecarStreamControlKind.GrantCredit,
            AcknowledgeSequence: 3,
            CreditBytes: 4096,
            CreditChunks: 4);
        var acknowledgement = new SidecarStreamAcknowledgement(
            Header(5),
            streamId,
            AcknowledgeSequence: 3,
            GrantedBytes: 4096,
            GrantedChunks: 4);

        Assert.Equal(SidecarStreamMutationKind.Transform, chunk.Mutation!.Kind);
        Assert.Equal(SidecarStreamControlKind.GrantCredit, control.Control);
        Assert.Equal(3, acknowledgement.AcknowledgeSequence);
        Assert.True(SidecarProtocolStateMachine.CanApply(
            SidecarProtocolPhase.Invoking,
            SidecarProtocolMessageKind.StreamControl));
    }

    [Fact]
    public void StorageContractsCarryRevisionFenceAndAtomicOutbox()
    {
        var fence = new ModuleStorageClaimFence(
            Guid.NewGuid(),
            Guid.NewGuid(),
            DateTimeOffset.UtcNow.AddMinutes(1),
            ExpectedRevision: 7);
        var request = new ModuleStorageMutationAndOutboxRequest(
            [new ModuleStorageMutation(
                ModuleStorageOperations.Upsert,
                "job-1",
                JsonSerializer.SerializeToElement(new { status = "complete" }),
                ExpectedRevision: 7)],
            [new ModuleStorageOutboxMessage(
                "job.completed",
                "idempotency-1",
                JsonSerializer.SerializeToElement(new { id = "job-1" }))],
            fence);

        var json = JsonSerializer.Serialize(request, JsonOptions);
        var roundTrip = JsonSerializer.Deserialize<ModuleStorageMutationAndOutboxRequest>(json, JsonOptions)!;

        Assert.Equal(7, roundTrip.Fence!.ExpectedRevision);
        Assert.Equal(7, roundTrip.Mutations[0].ExpectedRevision);
        Assert.Equal("idempotency-1", roundTrip.Outbox[0].IdempotencyKey);
        Assert.Equal("revision_conflict", ModuleStorageErrors.RevisionConflict);
        Assert.Equal("stale_claim", ModuleStorageErrors.StaleClaim);
        Assert.Equal("fencing_rejected", ModuleStorageErrors.FencingRejected);
    }

    [Fact]
    public void StorageClaimsExposeExpectedRevisionAndFencingData()
    {
        var fence = new ModuleStorageClaimFence(
            Guid.NewGuid(),
            Guid.NewGuid(),
            DateTimeOffset.UtcNow.AddMinutes(1),
            ExpectedRevision: 12);
        var payload = new ModuleDocumentClaimPayload(
            [],
            null,
            1,
            new { status = "running" },
            ExpectedRevision: 12,
            Fence: fence);
        var write = new ModuleDocumentWrite<string>(
            "job-1",
            "complete",
            ExpectedRevision: 12);
        var delete = new ModuleDocumentDelete(
            "job-1",
            ExpectedRevision: 13,
            Fence: fence);

        var json = JsonSerializer.Serialize(new { payload, write, delete }, JsonOptions);

        Assert.Contains("expectedRevision", json, StringComparison.Ordinal);
        Assert.Contains(fence.FencingToken.ToString(), json, StringComparison.Ordinal);
        Assert.Equal(12, payload.ExpectedRevision);
        Assert.Equal(12, write.ExpectedRevision);
        Assert.Equal(13, delete.ExpectedRevision);
    }

    [Fact]
    public void StorageConflictAndAtomicCommitSurfacesPreserveRecoveryData()
    {
        var conflict = new ModuleStorageRevisionConflict("job-1", 6, 7);
        var result = new ModuleStorageMutationAndOutboxResult(
            [new ModuleStorageRevision("job-1", 8)],
            ["outbox-1"],
            CommitRevision: 8);

        var json = JsonSerializer.Serialize(new { conflict, result }, JsonOptions);
        var roundTrip = JsonSerializer.Deserialize<JsonElement>(json, JsonOptions);

        Assert.Equal(6, roundTrip.GetProperty("conflict").GetProperty("expectedRevision").GetInt64());
        Assert.Equal(7, roundTrip.GetProperty("conflict").GetProperty("actualRevision").GetInt64());
        Assert.Equal(8, roundTrip.GetProperty("result").GetProperty("commitRevision").GetInt64());
        Assert.Equal("outbox-1", roundTrip.GetProperty("result").GetProperty("outboxMessageIds")[0].GetString());
        Assert.Equal("atomic_commit_rejected", ModuleStorageErrors.AtomicCommitRejected);
    }

    [Fact]
    public void RetiredLookupCliAndJobsFeatureTypesAreAbsent()
    {
        var names = typeof(ISharpClawModule).Assembly
            .GetTypes()
            .Select(type => type.FullName ?? type.Name)
            .ToArray();

        Assert.DoesNotContain(names, name => name.EndsWith("ModuleCliCommand", StringComparison.Ordinal));
        Assert.DoesNotContain(names, name => name.EndsWith("ModuleCliScope", StringComparison.Ordinal));
        Assert.DoesNotContain(names, name => name.EndsWith("JobsContracts", StringComparison.Ordinal));
        Assert.DoesNotContain(names, name => name.EndsWith("JobStatus", StringComparison.Ordinal));
        Assert.DoesNotContain(names, name => name.EndsWith("JobDocument", StringComparison.Ordinal));
        Assert.DoesNotContain(names, name => name.EndsWith("JobHandlerResult", StringComparison.Ordinal));
        Assert.DoesNotContain(typeof(IModuleLifecycleManager).GetMethods(), method =>
            method.Name is "FindToolByName" or "IsToolPrefixRegistered");
        Assert.Contains(typeof(ICliContributionBuilder).GetMethods(), method =>
            method.GetParameters().Any(parameter => parameter.ParameterType == typeof(ModuleCliCommandDescriptor)));
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

    private static SidecarMessageHeader Header(long sequence = 1) =>
        new(1, sequence, DateTimeOffset.UtcNow.AddMinutes(1), new SidecarMessageSizeAuthority(128, 1024));

    private sealed record SidecarExchangeFixture(
        HookInvokeStart Start,
        SidecarEffectRequest Replacement,
        ContinuationOutcome Outcome);
}
