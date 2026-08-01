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
            new SharpClawActionKey("module.action"),
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
                new SharpClawActionKey("demo.action"),
                "demo",
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

        var validation = SidecarDiscoveryValidator.Validate(
            discovery,
            new SidecarHostDescriptorCatalog(
                [new SidecarHostActionDescriptor(
                    new SharpClawActionKey("demo.action"),
                    1,
                    "demo",
                    definition.InputSchema,
                    definition.ResultSchema,
                    ActionInterceptionCapabilities.Inspect,
                    ContainsSensitiveData: false,
                    ContractVersionRange.Exact(1))],
                []));

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
    public void SidecarTerminalHandlersAndEventListenersCarryBoundedPhases()
    {
        var invocationId = Guid.NewGuid();
        var input = CreateElement(new { value = 1 });
        var toolStart = new SidecarToolHandlerInvokeStart(
            Header(1),
            invocationId,
            "demo.tool",
            "tool-handler",
            input,
            new JsonSchemaReference("demo.tool.input", 1, "input-hash"),
            new RequestPrincipal("user-1"));
        var toolResult = new SidecarToolHandlerResult(
            Header(2),
            invocationId,
            CreateElement(new { value = 2 }),
            new JsonSchemaReference("demo.tool.result", 1, "result-hash"));
        var toolCancelled = new SidecarToolHandlerCancelled(
            Header(3),
            invocationId,
            "cancelled",
            "The caller cancelled the tool.");
        var toolFailed = new SidecarToolHandlerFailed(
            Header(4),
            invocationId,
            new ExecutionError("tool_failed", "The tool failed."));
        var lifecycleStart = new SidecarLifecycleHandlerInvokeStart(
            Header(5),
            Guid.NewGuid(),
            SidecarLifecycleCallKind.Start,
            "lifecycle-handler",
            input);
        var lifecycleResult = new SidecarLifecycleHandlerResult(
            Header(6),
            lifecycleStart.InvocationId,
            SidecarLifecycleCallKind.Start,
            CreateElement(new { started = true }));
        var lifecycleCancelled = new SidecarLifecycleHandlerCancelled(
            Header(7),
            lifecycleStart.InvocationId,
            SidecarLifecycleCallKind.Stop,
            "cancelled",
            "The lifecycle call was cancelled.");
        var lifecycleFailed = new SidecarLifecycleHandlerFailed(
            Header(8),
            lifecycleStart.InvocationId,
            SidecarLifecycleCallKind.HealthCheck,
            new ExecutionError("health_failed", "The health check failed."));
        var envelope = new UntypedEventEnvelope(
            new UntypedEventDescriptor(
                new SharpClawEventKey("demo.event"),
                1,
                "demo",
                EventInterceptionCapabilities.Inspect,
                new JsonSchemaReference("demo.event", 1, "event-hash"),
                false),
            Guid.NewGuid(),
            Guid.NewGuid(),
            Guid.NewGuid(),
            DateTimeOffset.UtcNow,
            "demo.module",
            input);
        var deliveries = Enum.GetValues<EventDelivery>()
            .Select((delivery, index) => (ISidecarProtocolMessage)new SidecarEventListenerDelivery(
                Header(9 + index),
                Guid.NewGuid(),
                "listener-1",
                envelope,
                delivery,
                RequiresAcknowledgement: true))
            .ToArray();
        var acknowledgements = deliveries
            .Select((delivery, index) => (ISidecarProtocolMessage)new SidecarEventListenerAcknowledgement(
                Header(12 + index),
                ((SidecarEventListenerDelivery)delivery).DeliveryId,
                ((SidecarEventListenerDelivery)delivery).Delivery,
                Accepted: true))
            .ToArray();

        var terminalMessages = new ISidecarProtocolMessage[]
        {
            toolStart, toolResult, toolCancelled, toolFailed,
            lifecycleStart, lifecycleResult, lifecycleCancelled, lifecycleFailed,
        };

        Assert.All(terminalMessages.Concat(deliveries).Concat(acknowledgements), message =>
        {
            Assert.True(message.Header.Size.IsWithinLimit);
            Assert.True(message.Header.Deadline > DateTimeOffset.UtcNow);
        });
        Assert.Equal(SidecarProtocolMessageKind.ToolHandlerResult, toolResult.MessageKind);
        Assert.Equal(SidecarProtocolMessageKind.LifecycleHandlerFailed, lifecycleFailed.MessageKind);
        Assert.True(SidecarProtocolStateMachine.CanApply(
            SidecarProtocolPhase.Negotiated,
            toolStart.MessageKind));
        Assert.True(SidecarProtocolStateMachine.CanApply(
            SidecarProtocolPhase.Invoking,
            toolResult.MessageKind));
        Assert.True(SidecarProtocolStateMachine.CanApply(
            SidecarProtocolPhase.Invoking,
            toolCancelled.MessageKind));
        Assert.True(SidecarProtocolStateMachine.CanApply(
            SidecarProtocolPhase.Invoking,
            toolFailed.MessageKind));
        Assert.True(SidecarProtocolStateMachine.CanApply(
            SidecarProtocolPhase.Negotiated,
            lifecycleStart.MessageKind));
        Assert.True(SidecarProtocolStateMachine.CanApply(
            SidecarProtocolPhase.Invoking,
            lifecycleResult.MessageKind));
        Assert.True(SidecarProtocolStateMachine.CanApply(
            SidecarProtocolPhase.Invoking,
            lifecycleCancelled.MessageKind));
        Assert.True(SidecarProtocolStateMachine.CanApply(
            SidecarProtocolPhase.Invoking,
            lifecycleFailed.MessageKind));
        Assert.True(SidecarProtocolStateMachine.CanApply(
            SidecarProtocolPhase.Negotiated,
            SidecarProtocolMessageKind.EventListenerAcknowledgement));
        Assert.Equal(
            [EventDelivery.Inline, EventDelivery.Queued, EventDelivery.Durable],
            deliveries.Cast<SidecarEventListenerDelivery>().Select(item => item.Delivery));
    }

    [Fact]
    public void SidecarDiscoveryRejectsMatchingForgedHostDefinitions()
    {
        var key = new SharpClawActionKey("forged.action");
        var schema = new JsonSchemaReference("forged.input", 1, "forged-hash");
        var definition = new SidecarActionDefinition(
            key,
            1,
            "forged",
            schema,
            new JsonSchemaReference("forged.result", 1, "result-hash"),
            ActionInterceptionCapabilities.Inspect,
            ContainsSensitiveData: false,
            HasIrreversibleEffects: false,
            new ActionRepeatPolicy(ActionRepeatKind.None, 1, TimeSpan.Zero, "forged"),
            null,
            [ActionSafePoint.BeforeTerminal],
            ContractVersionRange.Exact(1));
        var discovery = new SidecarDiscoveryEnvelope(
            Header(),
            "forged.module",
            "contract-hash",
            new SidecarProtocolOffer(1, 1, [SidecarPayloadMode.Untyped], new SidecarPayloadLimits()),
            [new SidecarActionSubscription(
                SidecarHookTargetKind.Exact,
                key,
                "forged",
                ContractVersionRange.Exact(1),
                schema,
                definition.ResultSchema,
                ActionInterceptionCapabilities.Inspect,
                SidecarPayloadMode.Untyped,
                new HookOrdering("forged"))],
            [],
            [definition],
            [],
            [],
            [],
            []);

        var validation = SidecarDiscoveryValidator.Validate(
            discovery,
            new SidecarHostDescriptorCatalog(
                [new SidecarHostActionDescriptor(
                    new SharpClawActionKey("host.action"),
                    1,
                    "host",
                    schema,
                    definition.ResultSchema,
                    ActionInterceptionCapabilities.Inspect,
                    ContainsSensitiveData: false,
                    ContractVersionRange.Exact(1))],
                []));

        Assert.False(validation.Accepted);
        Assert.Equal(SidecarProtocolErrors.UnknownHostDescriptor, validation.ErrorCode);
    }

    [Fact]
    public void SidecarStateRejectsDuplicateUseExpiryCancellationAndLateStream()
    {
        var now = DateTimeOffset.UtcNow;
        var handle = Guid.NewGuid();
        var state = new SidecarProtocolState(
            Guid.NewGuid(),
            handle,
            SidecarProtocolPhase.Invoking,
            LastSequence: 1,
            now.AddMinutes(1));
        var effect = new SidecarEffectRequest(
            Header(2),
            handle,
            SidecarContinuationCommand.ContinueOriginal);
        var accepted = SidecarProtocolStateMachine.Validate(state, effect, now);

        Assert.True(accepted.Accepted);
        var effectAccepted = new ContinuationAccepted(
            Header(3),
            handle,
            SidecarContinuationCommand.ContinueOriginal,
            ActionSafePoint.BeforeTerminal,
            ContinuationState.Pending);
        var effectAcceptance = SidecarProtocolStateMachine.Validate(accepted.State!, effectAccepted, now);
        Assert.True(effectAcceptance.Accepted);
        var continuation = new ContinuationOutcome(
            Header(4),
            handle,
            ActionOutcomeKind.Completed,
            ActionOutcomeCertainty.Certain,
            ActionSafePoint.BeforeTerminal);
        var outcome = SidecarProtocolStateMachine.Validate(effectAcceptance.State!, continuation, now);
        Assert.True(outcome.Accepted);
        Assert.Equal(SidecarProtocolPhase.OutcomeSent, outcome.State!.Phase);

        var duplicate = SidecarProtocolStateMachine.Validate(
            outcome.State,
            effect with { Header = Header(5) },
            now);
        Assert.False(duplicate.Accepted);
        Assert.Equal(SidecarProtocolErrors.ContinuationAlreadyUsed, duplicate.ErrorCode);

        var replacement = new SidecarResultReplacement(
            Header(6),
            handle,
            CreateElement(new { value = 4 }),
            "validated replacement");
        var completed = SidecarProtocolStateMachine.Validate(outcome.State, replacement, now);
        Assert.True(completed.Accepted);
        Assert.Equal(SidecarProtocolPhase.Completed, completed.State!.Phase);

        var lateStream = SidecarProtocolStateMachine.Validate(
            completed.State,
            new SidecarStreamAcknowledgement(Header(7), Guid.NewGuid(), 1, 1, 1),
            now);
        Assert.False(lateStream.Accepted);
        Assert.Equal(SidecarProtocolErrors.LateMessage, lateStream.ErrorCode);

        var expired = SidecarProtocolStateMachine.Validate(
            state with { Deadline = now.AddSeconds(-1) },
            effect with { Header = Header(8) },
            now);
        Assert.False(expired.Accepted);
        Assert.Equal(SidecarProtocolErrors.DeadlineExceeded, expired.ErrorCode);

        var cancelled = SidecarProtocolStateMachine.Validate(
            state,
            new SidecarHostTerminalCancellation(
                Header(9),
                handle,
                ActionSafePoint.BeforeTerminal,
                "cancelled",
                "The host cancelled the continuation."),
            now);
        Assert.True(cancelled.Accepted);
        Assert.Equal(SidecarProtocolPhase.Cancelled, cancelled.State!.Phase);
        var disconnected = SidecarProtocolStateMachine.Validate(
            state,
            new SidecarProtocolError(Header(10), SidecarProtocolErrors.Disconnected, "The sidecar disconnected."),
            now);
        Assert.True(disconnected.Accepted);
        Assert.Equal(SidecarProtocolPhase.Rejected, disconnected.State!.Phase);
        Assert.DoesNotContain(typeof(HookOutcome).GetProperties(), property =>
            property.Name is "Uncertainty" or "RequestedEffect");
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
    public void StorageContractsCarryHostClaimAuthorityAndAtomicOutboxIdentity()
    {
        var authority = new ModuleStorageClaimAuthority(
            "module-a",
            Guid.NewGuid(),
            DateTimeOffset.UtcNow.AddMinutes(1),
            Generation: 3,
            Revision: 7);
        var commit = new ModuleStorageCommitIdentity(Guid.NewGuid(), "idempotency-1");
        var eventEnvelope = new ModuleStorageEventEnvelope(
            Guid.NewGuid(),
            new SharpClawEventKey("jobs.completed"),
            1,
            new JsonSchemaReference("jobs.completed", 1, "event-hash"),
            EventDelivery.Durable,
            "module-a",
            "module-a.jobs",
            JsonSerializer.SerializeToElement(new { id = "job-1" }));
        var request = new ModuleStorageMutationAndOutboxRequest(
            commit,
            [new ModuleStorageMutation(
                ModuleStorageOperations.Upsert,
                "job-1",
                JsonSerializer.SerializeToElement(new { status = "complete" }),
                ExpectedRevision: 7)],
            [new ModuleStorageOutboxMessage(
                commit,
                eventEnvelope)],
            authority);

        var json = JsonSerializer.Serialize(request, JsonOptions);
        var roundTrip = JsonSerializer.Deserialize<ModuleStorageMutationAndOutboxRequest>(json, JsonOptions)!;

        Assert.Equal(commit.OperationId, roundTrip.Commit.OperationId);
        Assert.Equal("module-a", roundTrip.Authority!.OwnerId);
        Assert.Equal(3, roundTrip.Authority.Generation);
        Assert.Equal(7, roundTrip.Mutations[0].ExpectedRevision);
        Assert.Equal("idempotency-1", roundTrip.Outbox[0].Commit.IdempotencyKey);
        Assert.Equal("jobs.completed", roundTrip.Outbox[0].Event.EventKey.Value);
        Assert.Equal(EventDelivery.Durable, roundTrip.Outbox[0].Event.Delivery);
        Assert.Equal("revision_conflict", ModuleStorageErrors.RevisionConflict);
        Assert.Equal("stale_claim", ModuleStorageErrors.StaleClaim);
        Assert.Equal("fencing_rejected", ModuleStorageErrors.FencingRejected);
        Assert.Equal("commit_identity_conflict", ModuleStorageErrors.CommitIdentityConflict);
    }

    [Fact]
    public void StorageClaimsExposeHostAuthorityRenewalAndRecoveryData()
    {
        var authority = new ModuleStorageClaimAuthority(
            "module-a",
            Guid.NewGuid(),
            DateTimeOffset.UtcNow.AddMinutes(1),
            Generation: 4,
            Revision: 12);
        var payload = new ModuleDocumentClaimPayload(
            [],
            null,
            1,
            new { status = "running" },
            ExpectedRevision: 12,
            Authority: authority,
            OwnerId: "module-a");
        var write = new ModuleDocumentWrite<string>(
            "job-1",
            "complete",
            ExpectedRevision: 12);
        var delete = new ModuleDocumentDelete(
            "job-1",
            ExpectedRevision: 13,
            Authority: authority);
        var renewal = new ModuleStorageClaimRenewalRequest(
            authority.OwnerId,
            authority.HostToken,
            authority.Generation,
            DateTimeOffset.UtcNow.AddMinutes(2));
        var recovery = new ModuleStorageClaimRecoveryRequest(
            authority.OwnerId,
            authority.HostToken,
            authority.Generation,
            DateTimeOffset.UtcNow);

        var json = JsonSerializer.Serialize(new { payload, write, delete, renewal, recovery }, JsonOptions);

        Assert.Contains("expectedRevision", json, StringComparison.Ordinal);
        Assert.Contains(authority.HostToken.ToString(), json, StringComparison.Ordinal);
        Assert.Equal(12, payload.ExpectedRevision);
        Assert.Equal("module-a", payload.OwnerId);
        Assert.Equal(12, write.ExpectedRevision);
        Assert.Equal(13, delete.ExpectedRevision);
        Assert.True(authority.HasFiniteLease);
        Assert.True(authority.IsActiveAt(DateTimeOffset.UtcNow));
        Assert.Equal(4, renewal.Generation);
        Assert.Equal(authority.HostToken, recovery.HostToken);
    }

    [Fact]
    public void StorageConflictAndAtomicCommitSurfacesPreserveRecoveryData()
    {
        var conflict = new ModuleStorageRevisionConflict("job-1", 6, 7);
        var commit = new ModuleStorageCommitIdentity(Guid.NewGuid(), "retry-1");
        var result = new ModuleStorageMutationAndOutboxResult(
            commit,
            [new ModuleStorageRevision("job-1", 8)],
            ["outbox-1"],
            CommitRevision: 8,
            AlreadyCommitted: true);

        var json = JsonSerializer.Serialize(new { conflict, result }, JsonOptions);
        var roundTrip = JsonSerializer.Deserialize<JsonElement>(json, JsonOptions);

        Assert.Equal(6, roundTrip.GetProperty("conflict").GetProperty("expectedRevision").GetInt64());
        Assert.Equal(7, roundTrip.GetProperty("conflict").GetProperty("actualRevision").GetInt64());
        Assert.Equal(8, roundTrip.GetProperty("result").GetProperty("commitRevision").GetInt64());
        Assert.True(roundTrip.GetProperty("result").GetProperty("alreadyCommitted").GetBoolean());
        Assert.Equal("outbox-1", roundTrip.GetProperty("result").GetProperty("outboxMessageIds")[0].GetString());
        Assert.Equal("atomic_commit_rejected", ModuleStorageErrors.AtomicCommitRejected);
    }

    [Fact]
    public async Task StorageRejectsMalformedGetListQueryAndClaimResponses()
    {
        var missingGetKey = new StubStorageGateway(_ =>
            JsonSerializer.SerializeToElement(new { found = true, value = "value", revision = 1 }));
        var getStore = new ModuleDocumentStore<string>(missingGetKey, "module-a", "documents");
        var getFailure = await Assert.ThrowsAsync<ModuleStorageContractException>(() =>
            getStore.GetRecordAsync("job-1"));
        Assert.Equal(ModuleStorageErrors.MissingRecordKey, getFailure.Failure.Code);

        var missingListRevision = new StubStorageGateway(_ =>
            JsonSerializer.SerializeToElement(new
            {
                records = new[] { new { key = "job-1", value = "value" } },
            }));
        var listStore = new ModuleDocumentStore<string>(missingListRevision, "module-a", "documents");
        var listFailure = await Assert.ThrowsAsync<ModuleStorageContractException>(() =>
            listStore.ListAsync());
        Assert.Equal(ModuleStorageErrors.MissingRevision, listFailure.Failure.Code);

        var negativeQueryRevision = new StubStorageGateway(_ =>
            JsonSerializer.SerializeToElement(new
            {
                records = new[] { new { key = "job-1", value = "value", revision = -1 } },
            }));
        var queryStore = new ModuleDocumentStore<string>(negativeQueryRevision, "module-a", "documents");
        var queryFailure = await Assert.ThrowsAsync<ModuleStorageContractException>(() =>
            queryStore.Query().ToRecordsAsync());
        Assert.Equal(ModuleStorageErrors.InvalidRevision, queryFailure.Failure.Code);

        var missingClaimAuthority = new StubStorageGateway(_ =>
            JsonSerializer.SerializeToElement(new
            {
                records = Array.Empty<object>(),
            }));
        var claimStore = new ModuleDocumentStore<string>(missingClaimAuthority, "module-a", "documents");
        var claimFailure = await Assert.ThrowsAsync<ModuleStorageContractException>(() =>
            claimStore.Claim()
                .Patch(new { status = "claimed" })
                .ToClaimRecordsAsync());
        Assert.Equal(ModuleStorageErrors.MalformedResponse, claimFailure.Failure.Code);
    }

    [Fact]
    public void StorageClaimResultPreservesOwnerLeaseGenerationAndRevision()
    {
        var authority = new ModuleStorageClaimAuthority(
            "module-a",
            Guid.NewGuid(),
            DateTimeOffset.UtcNow.AddMinutes(1),
            Generation: 9,
            Revision: 21);
        var result = new ModuleStorageClaimResult<string>(
            [new ModuleStorageClaimRecord<string>("job-1", "claimed", 21, authority)],
            authority);
        var expired = authority with { LeaseExpiresAt = DateTimeOffset.UtcNow.AddSeconds(-1) };
        var json = JsonSerializer.Serialize(result, JsonOptions);
        var roundTrip = JsonSerializer.Deserialize<ModuleStorageClaimResult<string>>(json, JsonOptions)!;

        Assert.Equal("module-a", roundTrip.Authority.OwnerId);
        Assert.Equal(9, roundTrip.Authority.Generation);
        Assert.Equal(21, roundTrip.Records[0].Revision);
        Assert.False(expired.IsActiveAt(DateTimeOffset.UtcNow));
        Assert.NotEqual(authority.HostToken, Guid.Empty);
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

    private sealed class StubStorageGateway(
        Func<string, JsonElement> responseFactory) : IModuleStorageGateway
    {
        public IReadOnlyList<ModuleStorageContractDescriptor> ListContracts() => [];

        public Task<JsonElement> InvokeAsync(
            string moduleId,
            string storageName,
            string operation,
            JsonElement parameters,
            CancellationToken ct = default) =>
            Task.FromResult(responseFactory(operation));

        public Task<ModuleStorageMutationAndOutboxResult> CommitMutationAndOutboxAsync(
            string moduleId,
            string storageName,
            ModuleStorageMutationAndOutboxRequest request,
            CancellationToken ct = default) =>
            throw new NotSupportedException();

        public Task<ModuleStorageClaimResult<T>> ClaimAsync<T>(
            string moduleId,
            string storageName,
            ModuleDocumentClaimPayload request,
            CancellationToken ct = default) =>
            throw new NotSupportedException();

        public Task<ModuleStorageClaimRenewalResult> RenewClaimAsync(
            string moduleId,
            string storageName,
            ModuleStorageClaimRenewalRequest request,
            CancellationToken ct = default) =>
            throw new NotSupportedException();

        public Task<ModuleStorageClaimRecoveryResult> RecoverClaimAsync(
            string moduleId,
            string storageName,
            ModuleStorageClaimRecoveryRequest request,
            CancellationToken ct = default) =>
            throw new NotSupportedException();
    }

    private sealed record SidecarExchangeFixture(
        HookInvokeStart Start,
        SidecarEffectRequest Replacement,
        ContinuationOutcome Outcome);
}
