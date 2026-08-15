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
    public async Task HostActionEntryRequiresHostIssuedAuthorityWithoutSnapshotAuthority()
    {
        var now = DateTimeOffset.UtcNow;
        var descriptor = new ActionDescriptor<string, string>(
            new SharpClawActionKey("demo.entry"),
            1,
            "demo",
            ActionInterceptionCapabilities.Inspect,
            ContainsSensitiveData: false,
            HasIrreversibleEffects: false,
            new ActionRepeatPolicy(ActionRepeatKind.None, 1, TimeSpan.Zero, "demo.entry"),
            ContinuationPolicy: null,
            TimeSpan.FromSeconds(5))
        {
            InputSchema = new JsonSchemaReference("demo.entry.input", 1, "demo-entry-input-schema"),
            ResultSchema = new JsonSchemaReference("demo.entry.result", 1, "demo-entry-result-schema"),
        };
        var caller = new RequestPrincipal("caller-1", Roles: new HashSet<string>(["reader"]));
        var features = new ExtensionFeatureSet([]);
        var traceId = Guid.NewGuid();
        var idempotencyKey = Guid.NewGuid();
        var deadline = now.AddMinutes(1);
        var context = CreateHostActionEntryContext(
            caller, features, traceId, idempotencyKey, deadline, now,
            Lineage(descriptor, "input"));
        var request = new HostActionEntryRequest<string, string>(
            descriptor,
            "input",
            context);
        var transport = new HostActionEntryTransportRequest<string, string>(
            request,
            CreateHostActionAuthority(
                descriptor,
                "input",
                caller,
                features,
                traceId,
                idempotencyKey,
                deadline,
                now,
                context));
        var cancellation = new CancellationTokenSource().Token;
        var entry = new RecordingHostActionEntry();

        var outcome = await entry.InvokeAsync(request, cancellation);
        var json = JsonSerializer.Serialize(request, JsonOptions);

        Assert.True(transport.Validate(now, authority =>
            authority.Proof == HostActionEntryAuthorityValidator.ComputeAuthorityHash(authority)).Accepted);
        Assert.Equal(ActionOutcomeKind.Completed, outcome.Kind);
        Assert.Same(request, entry.Request);
        Assert.Equal(cancellation, entry.CancellationToken);
        Assert.DoesNotContain("Snapshot", json, StringComparison.Ordinal);
        Assert.DoesNotContain("ActionGrants", json, StringComparison.Ordinal);
        Assert.DoesNotContain("EventGrants", json, StringComparison.Ordinal);
        Assert.NotNull(typeof(IHostActionEntry).GetMethod(nameof(IHostActionEntry.InvokeAsync)));
    }

    [Fact]
    public void HostActionEntryRejectsForgedCallerFeaturesRequestAndPayloadAuthority()
    {
        var now = DateTimeOffset.UtcNow;
        var descriptor = new ActionDescriptor<string, string>(
            new SharpClawActionKey("demo.entry"),
            1,
            "demo",
            ActionInterceptionCapabilities.Inspect,
            ContainsSensitiveData: false,
            HasIrreversibleEffects: false,
            new ActionRepeatPolicy(ActionRepeatKind.None, 1, TimeSpan.Zero, "demo.entry"),
            ContinuationPolicy: null,
            TimeSpan.FromSeconds(5))
        {
            InputSchema = new JsonSchemaReference("demo.entry.input", 1, "demo-entry-input-schema"),
            ResultSchema = new JsonSchemaReference("demo.entry.result", 1, "demo-entry-result-schema"),
        };
        var caller = new RequestPrincipal("caller-1", Roles: new HashSet<string>(["reader"]));
        var features = new ExtensionFeatureSet([]);
        var traceId = Guid.NewGuid();
        var idempotencyKey = Guid.NewGuid();
        var deadline = now.AddMinutes(1);
        var context = CreateHostActionEntryContext(
            caller, features, traceId, idempotencyKey, deadline, now,
            Lineage(descriptor, "input"));
        var request = new HostActionEntryRequest<string, string>(
            descriptor,
            "input",
            context);
        var authority = CreateHostActionAuthority(
                descriptor,
                "input",
                caller,
                features,
                traceId,
                idempotencyKey,
                deadline,
                now,
                context);
        var transport = new HostActionEntryTransportRequest<string, string>(request, authority);
        var expectedProof = authority.Proof;
        bool HostProof(HostActionEntryAuthority authority) =>
            authority.Proof == expectedProof &&
            authority.Proof == HostActionEntryAuthorityValidator.ComputeAuthorityHash(authority);

        Assert.True(transport.Validate(now, HostProof).Accepted);
        Assert.False((transport with { Request = request with { Context = context with
        {
            Caller = new RequestPrincipal("attacker", Roles: new HashSet<string>(["administrator"]))
        }}}).Validate(now, HostProof).Accepted);
        Assert.False((transport with { Request = request with { Context = context with
        {
            Features = new ExtensionFeatureSet([new ExtensionFeature("forged", 1, "attacker", 64, CreateElement(new { enabled = true }))])
        }}}).Validate(now, HostProof).Accepted);
        Assert.False((transport with { Request = request with { Context = context with { TraceId = Guid.NewGuid() } } }).Validate(now, HostProof).Accepted);
        Assert.False((transport with { Request = request with { Context = context with { IdempotencyKey = Guid.NewGuid() } } }).Validate(now, HostProof).Accepted);
        Assert.False((transport with { Request = request with { Action = "changed" } }).Validate(now, HostProof).Accepted);
        Assert.False((transport with
        {
            Authority = authority with
            {
                Caller = new RequestPrincipal("attacker", Roles: new HashSet<string>(["administrator"])),
            },
        }).Validate(now, HostProof).Accepted);
        Assert.False((transport with
        {
            Authority = authority with { RequestId = Guid.NewGuid() },
        }).Validate(now, HostProof).Accepted);
        Assert.False((transport with
        {
            Authority = authority with { Proof = "forged-proof" },
        }).Validate(now, HostProof).Accepted);
        var changedSchemaAuthority = authority with
        {
            InputSchemaVersion = authority.InputSchemaVersion + 1,
        };
        changedSchemaAuthority = changedSchemaAuthority with
        {
            Proof = HostActionEntryAuthorityValidator.ComputeAuthorityHash(changedSchemaAuthority),
        };
        Assert.False((transport with { Authority = changedSchemaAuthority }).Validate(
            now,
            authority => authority.Proof == HostActionEntryAuthorityValidator.ComputeAuthorityHash(authority)).Accepted);
    }

    [Fact]
    public void HostActionEntryUsesSidecarSerializationForRecordPayloads()
    {
        var now = DateTimeOffset.UtcNow;
        var descriptor = new ActionDescriptor<EntryRecordAction, string>(
            new SharpClawActionKey("demo.record-entry"),
            1,
            "demo",
            ActionInterceptionCapabilities.Inspect,
            ContainsSensitiveData: false,
            HasIrreversibleEffects: false,
            new ActionRepeatPolicy(ActionRepeatKind.None, 1, TimeSpan.Zero, "demo.record-entry"),
            ContinuationPolicy: null,
            TimeSpan.FromSeconds(5))
        {
            InputSchema = new JsonSchemaReference("demo.record-entry.input", 2, "record-entry-input-schema"),
            ResultSchema = new JsonSchemaReference("demo.record-entry.result", 3, "record-entry-result-schema"),
        };
        var action = new EntryRecordAction("InputValue");
        var caller = new RequestPrincipal("caller-1");
        var features = ExtensionFeatureSet.Empty;
        var traceId = Guid.NewGuid();
        var idempotencyKey = Guid.NewGuid();
        var deadline = now.AddMinutes(1);
        var context = CreateHostActionEntryContext(
            caller, features, traceId, idempotencyKey, deadline, now,
            Lineage(descriptor, action));
        var request = new HostActionEntryRequest<EntryRecordAction, string>(
            descriptor,
            action,
            context);
        var authority = CreateHostActionAuthority(
                descriptor,
                action,
                caller,
                features,
                traceId,
                idempotencyKey,
                deadline,
                now,
                context);
        var transport = new HostActionEntryTransportRequest<EntryRecordAction, string>(request, authority);
        var defaultBytes = JsonSerializer.SerializeToUtf8Bytes(action);
        var transportBytes = SidecarCapabilityTransportCodec.Serialize(action);

        Assert.NotEqual(defaultBytes, transportBytes);
        Assert.Equal(2, transport.Authority.InputSchemaVersion);
        Assert.Equal(3, transport.Authority.ResultSchemaVersion);
        Assert.True(transport.Validate(
            now,
            authority => authority.Proof == HostActionEntryAuthorityValidator.ComputeAuthorityHash(authority)).Accepted);
    }

    private static HostActionEntryAuthority CreateHostActionAuthority<TAction, TResult>(
        ActionDescriptor<TAction, TResult> descriptor,
        TAction action,
        RequestPrincipal caller,
        ExtensionFeatureSet features,
        Guid traceId,
        Guid idempotencyKey,
        DateTimeOffset deadline,
        DateTimeOffset now,
        HostActionEntryRequestContext context)
    {
        var actionBytes = SidecarCapabilityTransportCodec.Serialize(action);
        var authority = new HostActionEntryAuthority(
            "module-a",
            "graph-a",
            Guid.NewGuid(),
            context.RequestId,
            context.CancellationId,
            Guid.NewGuid(),
            "entry-nonce",
            1,
            caller,
            features,
            traceId,
            idempotencyKey,
            descriptor.Key,
            descriptor.Version,
            descriptor.Category,
            typeof(TAction).AssemblyQualifiedName!,
            typeof(TResult).AssemblyQualifiedName!,
            HostActionEntryAuthorityValidator.ComputeDescriptorHash(descriptor),
            descriptor.InputSchema!.ContentHash!,
            descriptor.InputSchema.Version,
            descriptor.ResultSchema!.ContentHash!,
            descriptor.ResultSchema.Version,
            Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(actionBytes)),
            actionBytes.Length,
            deadline,
            now.AddSeconds(-1),
            context.ExpiresAt,
            "");
        var boundAuthority = authority with
        {
            Ingress = context.Ingress,
            InvocationId = context.InvocationId,
            CapabilityId = context.CapabilityId,
            CapabilityHandleHash = HostActionEntryAuthorityValidator.ComputeCapabilityHandleHash(
                context.CapabilityHandle),
        };
        return boundAuthority with
        {
            Proof = HostActionEntryAuthorityValidator.ComputeAuthorityHash(boundAuthority),
        };
    }

    private static HostActionEntryRequestContext CreateHostActionEntryContext(
        RequestPrincipal caller,
        ExtensionFeatureSet features,
        Guid traceId,
        Guid idempotencyKey,
        DateTimeOffset deadline,
        DateTimeOffset now,
        HostActionEntryLineage lineage,
        HostActionEntryIngress ingress = HostActionEntryIngress.Endpoint) =>
        new(
            Guid.NewGuid(),
            "opaque-test-capability",
            ingress,
            Guid.NewGuid(),
            Guid.NewGuid(),
            Guid.NewGuid(),
            caller,
            features,
            traceId,
            idempotencyKey,
            deadline,
            now.AddMinutes(2))
        {
            Lineage = lineage,
        };

    private static HostActionEntryLineage Lineage<TAction, TResult>(
        ActionDescriptor<TAction, TResult> descriptor,
        TAction action)
    {
        var bytes = SidecarCapabilityTransportCodec.Serialize(action);
        return new HostActionEntryLineage(
            descriptor.Key,
            descriptor.Version,
            HostActionEntryAuthorityValidator.ComputeDescriptorHash(descriptor),
            typeof(TAction).AssemblyQualifiedName!,
            descriptor.InputSchema!.Version,
            descriptor.InputSchema.ContentHash!,
            SidecarCapabilityTransportCodec.ComputeSha256(bytes),
            bytes.Length);
    }

    private sealed class RecordingHostActionEntry : IHostActionEntry
    {
        public object? Request { get; private set; }
        public CancellationToken CancellationToken { get; private set; }

        public ValueTask<IActionOutcome<TResult>> InvokeAsync<TAction, TResult>(
            HostActionEntryRequest<TAction, TResult> request,
            CancellationToken cancellationToken = default)
        {
            Request = request;
            CancellationToken = cancellationToken;
            return ValueTask.FromResult<IActionOutcome<TResult>>(
                new RecordedOutcome<TResult>(ActionOutcomeKind.Completed));
        }
    }

    private sealed record EntryRecordAction(string PascalCaseValue);

    private sealed record RecordedOutcome<TResult>(ActionOutcomeKind Kind) : IActionOutcome<TResult>
    {
        public TResult? Result => default;
        public ContinuationToken? Continuation => null;
        public ExecutionError? Error => null;
        public ActionUncertainty? Uncertainty => null;
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
    public void JobsCatalogMatchesTheAccepted46FamilyAuthority()
    {
        var expectedFamilies = new[]
        {
            "jobs.submit",
            "jobs.validate",
            "jobs.identity.create",
            "jobs.queue.persist",
            "jobs.hold.evaluate",
            "jobs.hold.resolve",
            "jobs.dispatch",
            "jobs.start",
            "jobs.handler.invoke",
            "jobs.progress.report",
            "jobs.artifact.seal",
            "jobs.complete",
            "jobs.fail",
            "jobs.cancel",
            "jobs.cancel.request",
            "jobs.cancel.apply",
            "jobs.pause",
            "jobs.stop",
            "jobs.recovery",
            "jobs.recovery.scan",
            "jobs.recovery.classify",
            "jobs.retry",
            "jobs.retry.evaluate",
            "jobs.retry.schedule",
            "jobs.resume",
            "jobs.delete",
            "jobs.read",
            "jobs.list",
            "jobs.logs.read",
            "jobs.audit.read",
            "jobs.artifact.read",
            "jobs.event.deliver",
            "jobs.state.transition",
            "jobs.state.transition.prepare",
            "jobs.state.transition.commit",
            "jobs.state.transition.rollback",
            "jobs.persistence",
            "jobs.persistence.prepare",
            "jobs.persistence.commit",
            "jobs.persistence.rollback",
            "jobs.interruption.check",
            "jobs.external_call",
            "jobs.irreversible_effect",
            "jobs.external_effect.prepare",
            "jobs.external_effect.receipt",
            "jobs.external_effect.uncertain"
        };

        var expectedKeys = expectedFamilies.SelectMany(family => new[]
        {
            family,
            $"{family}.before",
            $"{family}.after"
        }).ToArray();

        Assert.Equal(172, SharpClawActionCatalog.Kernel.Count);
        Assert.Equal(expectedFamilies, SharpClawActionCatalog.JobsFamilies);
        Assert.Equal(expectedKeys, SharpClawActionCatalog.Jobs.Select(key => key.Value));
        Assert.Equal(46, SharpClawActionCatalog.JobsFamilies.Count);
        Assert.Equal(138, SharpClawActionCatalog.Jobs.Count);
        Assert.Equal(310, SharpClawActionCatalog.All.Count);
        Assert.Equal(310, SharpClawActionCatalog.All.Select(key => key.Value).Distinct().Count());

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
            "tool-handler",
            CreateElement(new { value = 2 }),
            new JsonSchemaReference("demo.tool.result", 1, "result-hash"));
        var toolCancelled = new SidecarToolHandlerCancelled(
            Header(3),
            invocationId,
            "tool-handler",
            "cancelled",
            "The caller cancelled the tool.");
        var toolFailed = new SidecarToolHandlerFailed(
            Header(4),
            invocationId,
            "tool-handler",
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
            "lifecycle-handler",
            CreateElement(new { started = true }));
        var lifecycleCancelled = new SidecarLifecycleHandlerCancelled(
            Header(7),
            lifecycleStart.InvocationId,
            SidecarLifecycleCallKind.Start,
            "lifecycle-handler",
            "cancelled",
            "The lifecycle call was cancelled.");
        var lifecycleFailed = new SidecarLifecycleHandlerFailed(
            Header(8),
            lifecycleStart.InvocationId,
            SidecarLifecycleCallKind.Start,
            "lifecycle-handler",
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
                ((SidecarEventListenerDelivery)delivery).ListenerId,
                envelope.Descriptor,
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
    public void SidecarStateRequiresSidecarOutcomeAndHostCompletionAndRejectsDuplicateUse()
    {
        var now = DateTimeOffset.UtcNow;
        var invocationId = Guid.NewGuid();
        var handle = Guid.NewGuid();
        var actionKey = new SharpClawActionKey("demo.action");
        var actionGrant = new ActionCapabilityGrant(
            actionKey,
            1,
            ActionInterceptionCapabilities.Inspect |
            ActionInterceptionCapabilities.ReplaceInput |
            ActionInterceptionCapabilities.Cancel |
            ActionInterceptionCapabilities.ReplaceResult |
            ActionInterceptionCapabilities.Defer |
            ActionInterceptionCapabilities.Repeat |
            ActionInterceptionCapabilities.Wrap);
        var state = new SidecarProtocolState(
            SidecarExchangeKind.ActionHook,
            invocationId,
            handle,
            SidecarProtocolPhase.Invoking,
            LastSequence: 1,
            now.AddMinutes(1),
            NegotiatedProtocolVersion: 1,
            HostLimits: new SidecarPayloadLimits(),
            ActionKey: actionKey,
            ActionGrant: actionGrant,
            ActionVersion: 1,
            HostAuthorization: new SidecarHostAuthorization("module-a", [actionGrant], []));
        var effect = new SidecarEffectRequest(
            Header(2),
            handle,
            SidecarContinuationCommand.ContinueOriginal);
        var accepted = SidecarProtocolStateMachine.Validate(state, effect, now);

        Assert.True(accepted.Accepted);
        var mismatchedCommand = SidecarProtocolStateMachine.Validate(
            accepted.State!,
            new ContinuationAccepted(
                Header(3),
                handle,
                SidecarContinuationCommand.Cancel,
                ActionSafePoint.BeforeTerminal,
                ContinuationState.Pending),
            now);
        Assert.False(mismatchedCommand.Accepted);
        Assert.Equal(SidecarProtocolErrors.ContinuationCommandMismatch, mismatchedCommand.ErrorCode);
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

        var sidecarOutcome = new HookOutcome(
            Header(6),
            handle,
            SidecarHookOutcomeKind.Completed);
        var sidecarOutcomeAccepted = SidecarProtocolStateMachine.Validate(outcome.State, sidecarOutcome, now);
        Assert.True(sidecarOutcomeAccepted.Accepted);
        Assert.Equal(SidecarProtocolPhase.SidecarOutcomeSent, sidecarOutcomeAccepted.State!.Phase);

        var completedWithoutReplacement = SidecarProtocolStateMachine.Validate(
            sidecarOutcomeAccepted.State,
            new HookCompleted(
                Header(7),
                handle,
                ActionOutcomeKind.Completed,
                ActionOutcomeCertainty.Certain),
            now);
        Assert.True(completedWithoutReplacement.Accepted);
        Assert.Equal(SidecarProtocolPhase.Completed, completedWithoutReplacement.State!.Phase);

        var replacementState = new SidecarProtocolState(
            SidecarExchangeKind.ActionHook,
            invocationId,
            handle,
            SidecarProtocolPhase.Invoking,
            LastSequence: 1,
            now.AddMinutes(1),
            NegotiatedProtocolVersion: 1,
            HostLimits: new SidecarPayloadLimits(),
            ActionKey: actionKey,
            ActionGrant: actionGrant,
            ActionVersion: 1,
            HostAuthorization: new SidecarHostAuthorization("module-a", [actionGrant], []));
        var replacementAccepted = SidecarProtocolStateMachine.Validate(
            replacementState,
            effect with { Header = Header(2) },
            now);
        replacementAccepted = SidecarProtocolStateMachine.Validate(
            replacementAccepted.State!,
            effectAccepted with { Header = Header(3) },
            now);
        replacementAccepted = SidecarProtocolStateMachine.Validate(
            replacementAccepted.State!,
            continuation with { Header = Header(4) },
            now);
        replacementAccepted = SidecarProtocolStateMachine.Validate(
            replacementAccepted.State!,
            sidecarOutcome with { Header = Header(5) },
            now);
        replacementAccepted = SidecarProtocolStateMachine.Validate(
            replacementAccepted.State!,
            new SidecarResultReplacement(
                Header(6),
                handle,
                CreateElement(new { value = 4 }),
                "validated replacement"),
            now);
        Assert.True(replacementAccepted.Accepted);
        Assert.Equal(SidecarProtocolPhase.SidecarOutcomeSent, replacementAccepted.State!.Phase);
        Assert.True(replacementAccepted.State.ResultReplacementAccepted);

        var duplicateReplacement = SidecarProtocolStateMachine.Validate(
            replacementAccepted.State,
            new SidecarResultReplacement(
                Header(7),
                handle,
                CreateElement(new { value = 5 }),
                "second replacement"),
            now);
        Assert.False(duplicateReplacement.Accepted);
        Assert.Equal(SidecarProtocolErrors.ContinuationAlreadyUsed, duplicateReplacement.ErrorCode);

        var completed = SidecarProtocolStateMachine.Validate(
            replacementAccepted.State,
            new HookCompleted(
                Header(8),
                handle,
                ActionOutcomeKind.Completed,
                ActionOutcomeCertainty.Certain,
                CreateElement(new { value = 4 })),
            now);
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
            effect with { Header = Header(20) },
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
            property.Name is "Result" or "Uncertainty" or "RequestedEffect");
    }

    [Fact]
    public void SidecarDirectTerminalOutcomesAcceptCompiledTypedAndUntypedAuthorities()
    {
        var now = DateTimeOffset.UtcNow;
        var authorities = new[]
        {
            ("typed", SidecarPayloadMode.Typed, SidecarHookTargetKind.Exact, false, false),
            ("exact", SidecarPayloadMode.Untyped, SidecarHookTargetKind.Exact, false, false),
            ("category", SidecarPayloadMode.Untyped, SidecarHookTargetKind.Category, true, false),
            ("wildcard", SidecarPayloadMode.Untyped, SidecarHookTargetKind.Wildcard, false, true),
        };

        Assert.True(SidecarProtocolStateMachine.CanApply(
            SidecarProtocolPhase.Invoking,
            SidecarProtocolMessageKind.ResultReplacement));
        Assert.True(SidecarProtocolStateMachine.CanApply(
            SidecarProtocolPhase.Invoking,
            SidecarProtocolMessageKind.HookOutcome,
            command: null,
            SidecarHookOutcomeKind.Failed));

        foreach (var authority in authorities)
        {
            var replacementFixture = CreateDirectActionFixture(
                now,
                authority.Item1 + "-replacement",
                authority.Item2,
                authority.Item3,
                authority.Item4,
                authority.Item5);
            var replacementStart = SidecarProtocolStateMachine.Validate(
                replacementFixture.State,
                replacementFixture.Start,
                now);
            Assert.True(replacementStart.Accepted);

            var replacement = new SidecarResultReplacement(
                Header(2),
                replacementFixture.Start.Continuation.HandleId,
                CreateElement(new { authority = authority.Item1 }),
                "Direct result replacement");
            Assert.True(SidecarProtocolStateMachine.CanApply(replacementStart.State!, replacement));
            var replacementResult = SidecarProtocolStateMachine.Validate(
                replacementStart.State!,
                replacement,
                now);
            Assert.True(replacementResult.Accepted);
            Assert.Equal(SidecarProtocolPhase.SidecarOutcomeSent, replacementResult.State!.Phase);
            Assert.True(replacementResult.State.ResultReplacementAccepted);
            Assert.True(replacementResult.State.DirectTerminalOutcomeAccepted);

            var replacementCompleted = SidecarProtocolStateMachine.Validate(
                replacementResult.State,
                new HookCompleted(
                    Header(3),
                    replacementFixture.Start.Continuation.HandleId,
                    ActionOutcomeKind.Completed,
                    ActionOutcomeCertainty.Certain,
                    CreateElement(new { authority = authority.Item1 })),
                now);
            Assert.True(replacementCompleted.Accepted);
            Assert.Equal(SidecarProtocolPhase.Completed, replacementCompleted.State!.Phase);

            var failureFixture = CreateDirectActionFixture(
                now,
                authority.Item1 + "-failure",
                authority.Item2,
                authority.Item3,
                authority.Item4,
                authority.Item5);
            var failureStart = SidecarProtocolStateMachine.Validate(
                failureFixture.State,
                failureFixture.Start,
                now);
            Assert.True(failureStart.Accepted);

            var error = new ExecutionError("direct_failure", "The action hook failed before continuation.");
            var failure = new HookOutcome(
                Header(2),
                failureFixture.Start.Continuation.HandleId,
                SidecarHookOutcomeKind.Failed,
                error);
            Assert.True(SidecarProtocolStateMachine.CanApply(failureStart.State!, failure));
            var failureResult = SidecarProtocolStateMachine.Validate(
                failureStart.State!,
                failure,
                now);
            Assert.True(failureResult.Accepted);
            Assert.Equal(SidecarProtocolPhase.SidecarOutcomeSent, failureResult.State!.Phase);
            Assert.True(failureResult.State.DirectTerminalOutcomeAccepted);

            var failureCompleted = SidecarProtocolStateMachine.Validate(
                failureResult.State,
                new HookCompleted(
                    Header(3),
                    failureFixture.Start.Continuation.HandleId,
                    ActionOutcomeKind.Failed,
                    ActionOutcomeCertainty.Certain,
                    Error: error),
                now);
            Assert.True(failureCompleted.Accepted);
            Assert.Equal(SidecarProtocolPhase.Completed, failureCompleted.State!.Phase);
        }
    }

    [Fact]
    public void SidecarDirectTerminalOutcomesRejectInvalidMessagesAndAuthority()
    {
        var now = DateTimeOffset.UtcNow;
        var fixture = CreateDirectActionFixture(
            now,
            "negative",
            SidecarPayloadMode.Untyped,
            SidecarHookTargetKind.Exact);
        var started = SidecarProtocolStateMachine.Validate(fixture.State, fixture.Start, now);
        Assert.True(started.Accepted);

        foreach (var kind in new[] { SidecarHookOutcomeKind.Completed, SidecarHookOutcomeKind.Cancelled })
        {
            Assert.False(SidecarProtocolStateMachine.CanApply(
                SidecarProtocolPhase.Invoking,
                SidecarProtocolMessageKind.HookOutcome,
                command: null,
                kind));
            var invalid = SidecarProtocolStateMachine.Validate(
                started.State!,
                new HookOutcome(Header(2), fixture.Start.Continuation.HandleId, kind),
                now);
            Assert.False(invalid.Accepted);
            Assert.Equal(SidecarProtocolErrors.InvalidLifecyclePhase, invalid.ErrorCode);
        }

        var malformedFailure = SidecarProtocolStateMachine.Validate(
            started.State!,
            new HookOutcome(
                Header(2),
                fixture.Start.Continuation.HandleId,
                SidecarHookOutcomeKind.Failed),
            now);
        Assert.False(malformedFailure.Accepted);
        Assert.Equal(SidecarProtocolErrors.MalformedMessage, malformedFailure.ErrorCode);

        var malformedReplacement = SidecarProtocolStateMachine.Validate(
            started.State!,
            new SidecarResultReplacement(
                Header(2),
                fixture.Start.Continuation.HandleId,
                CreateElement(new { value = 1 }),
                " "),
            now);
        Assert.False(malformedReplacement.Accepted);
        Assert.Equal(SidecarProtocolErrors.MalformedMessage, malformedReplacement.ErrorCode);

        var unauthorizedReplacementFixture = CreateDirectActionFixture(
            now,
            "unauthorized-replacement",
            SidecarPayloadMode.Typed,
            SidecarHookTargetKind.Exact,
            capabilities: ActionInterceptionCapabilities.Inspect);
        var unauthorizedReplacementStart = SidecarProtocolStateMachine.Validate(
            unauthorizedReplacementFixture.State,
            unauthorizedReplacementFixture.Start,
            now);
        var unauthorizedReplacement = SidecarProtocolStateMachine.Validate(
            unauthorizedReplacementStart.State!,
            new SidecarResultReplacement(
                Header(2),
                unauthorizedReplacementFixture.Start.Continuation.HandleId,
                CreateElement(new { value = 1 }),
                "Unauthorized replacement"),
            now);
        Assert.False(unauthorizedReplacement.Accepted);
        Assert.Equal(SidecarProtocolErrors.UnsupportedCapability, unauthorizedReplacement.ErrorCode);

        var unauthorizedFailureFixture = CreateDirectActionFixture(
            now,
            "unauthorized-failure",
            SidecarPayloadMode.Typed,
            SidecarHookTargetKind.Exact,
            capabilities: ActionInterceptionCapabilities.Observe | ActionInterceptionCapabilities.ReplaceResult);
        var unauthorizedFailureStart = SidecarProtocolStateMachine.Validate(
            unauthorizedFailureFixture.State,
            unauthorizedFailureFixture.Start,
            now);
        var unauthorizedFailure = SidecarProtocolStateMachine.Validate(
            unauthorizedFailureStart.State!,
            new HookOutcome(
                Header(2),
                unauthorizedFailureFixture.Start.Continuation.HandleId,
                SidecarHookOutcomeKind.Failed,
                new ExecutionError("failure", "The action hook failed.")),
            now);
        Assert.False(unauthorizedFailure.Accepted);
        Assert.Equal(SidecarProtocolErrors.UnsupportedCapability, unauthorizedFailure.ErrorCode);

        var forgedState = started.State! with
        {
            HostAuthorization = new SidecarHostAuthorization(
                "module-a",
                [fixture.Grant with { Capabilities = ActionInterceptionCapabilities.Inspect }],
                []),
        };
        var forged = SidecarProtocolStateMachine.Validate(
            forgedState,
            new SidecarResultReplacement(
                Header(2),
                fixture.Start.Continuation.HandleId,
                CreateElement(new { value = 1 }),
                "Forged grant"),
            now);
        Assert.False(forged.Accepted);
        Assert.Equal(SidecarProtocolErrors.UnsupportedCapability, forged.ErrorCode);

        var wrongExchange = SidecarProtocolStateMachine.Validate(
            started.State! with { ExchangeKind = SidecarExchangeKind.ToolHandler },
            new SidecarResultReplacement(
                Header(2),
                fixture.Start.Continuation.HandleId,
                CreateElement(new { value = 1 }),
                "Wrong exchange"),
            now);
        Assert.False(wrongExchange.Accepted);
        Assert.Equal(SidecarProtocolErrors.ExchangeIdentityMismatch, wrongExchange.ErrorCode);

        var wrongHandle = SidecarProtocolStateMachine.Validate(
            started.State!,
            new SidecarResultReplacement(
                Header(2),
                Guid.NewGuid(),
                CreateElement(new { value = 1 }),
                "Wrong handle"),
            now);
        Assert.False(wrongHandle.Accepted);
        Assert.Equal(SidecarProtocolErrors.InvalidContinuationHandle, wrongHandle.ErrorCode);

        var wrongActionVersion = SidecarProtocolStateMachine.Validate(
            started.State! with { ActionVersion = 2 },
            new SidecarResultReplacement(
                Header(2),
                fixture.Start.Continuation.HandleId,
                CreateElement(new { value = 1 }),
                "Wrong action version"),
            now);
        Assert.False(wrongActionVersion.Accepted);
        Assert.Equal(SidecarProtocolErrors.ExchangeIdentityMismatch, wrongActionVersion.ErrorCode);

        var wrongProtocolVersion = SidecarProtocolStateMachine.Validate(
            started.State!,
            new SidecarResultReplacement(
                Header(2) with { ProtocolVersion = 2 },
                fixture.Start.Continuation.HandleId,
                CreateElement(new { value = 1 }),
                "Wrong protocol version"),
            now);
        Assert.False(wrongProtocolVersion.Accepted);
        Assert.Equal(SidecarProtocolErrors.UnsupportedVersion, wrongProtocolVersion.ErrorCode);

        var expired = SidecarProtocolStateMachine.Validate(
            started.State! with { Deadline = now.AddTicks(-1) },
            new SidecarResultReplacement(
                Header(2),
                fixture.Start.Continuation.HandleId,
                CreateElement(new { value = 1 }),
                "Expired exchange"),
            now);
        Assert.False(expired.Accepted);
        Assert.Equal(SidecarProtocolErrors.DeadlineExceeded, expired.ErrorCode);

        var invalidSequence = SidecarProtocolStateMachine.Validate(
            started.State!,
            new SidecarResultReplacement(
                Header(1),
                fixture.Start.Continuation.HandleId,
                CreateElement(new { value = 1 }),
                "Repeated sequence"),
            now);
        Assert.False(invalidSequence.Accepted);
        Assert.Equal(SidecarProtocolErrors.ContinuationAlreadyUsed, invalidSequence.ErrorCode);

        var sizeFixture = CreateDirectActionFixture(
            now,
            "size",
            SidecarPayloadMode.Untyped,
            SidecarHookTargetKind.Exact,
            limits: new SidecarPayloadLimits(
                ActionInputBytes: 4096,
                ActionResultBytes: 128,
                EventPayloadBytes: 4096,
                ProtocolMessageBytes: 4096,
                StreamChunkBytes: 4096));
        var sizeStart = SidecarProtocolStateMachine.Validate(sizeFixture.State, sizeFixture.Start, now);
        Assert.True(sizeStart.Accepted);
        var oversized = SidecarProtocolStateMachine.Validate(
            sizeStart.State!,
            new SidecarResultReplacement(
                new SidecarMessageHeader(
                    1,
                    2,
                    now.AddMinutes(1),
                    new SidecarMessageSizeAuthority(1, 128)),
                sizeFixture.Start.Continuation.HandleId,
                CreateElement(new { value = new string('x', 1024) }),
                "Oversized result"),
            now);
        Assert.False(oversized.Accepted);
        Assert.Equal(SidecarProtocolErrors.ModulePayloadTooLarge, oversized.ErrorCode);

        var directReplacement = new SidecarResultReplacement(
            Header(2),
            fixture.Start.Continuation.HandleId,
            CreateElement(new { value = 1 }),
            "First result");
        var replacementAccepted = SidecarProtocolStateMachine.Validate(started.State!, directReplacement, now);
        Assert.True(replacementAccepted.Accepted);
        var duplicateReplacement = SidecarProtocolStateMachine.Validate(
            replacementAccepted.State!,
            directReplacement with { Header = Header(3) },
            now);
        Assert.False(duplicateReplacement.Accepted);
        Assert.Equal(SidecarProtocolErrors.ContinuationAlreadyUsed, duplicateReplacement.ErrorCode);

        var completed = SidecarProtocolStateMachine.Validate(
            replacementAccepted.State!,
            new HookCompleted(
                Header(3),
                fixture.Start.Continuation.HandleId,
                ActionOutcomeKind.Completed,
                ActionOutcomeCertainty.Certain,
                CreateElement(new { value = 1 })),
            now);
        var late = SidecarProtocolStateMachine.Validate(
            completed.State!,
            directReplacement with { Header = Header(4) },
            now);
        Assert.False(late.Accepted);
        Assert.Equal(SidecarProtocolErrors.LateMessage, late.ErrorCode);

        var failureFixture = CreateDirectActionFixture(
            now,
            "duplicate-failure",
            SidecarPayloadMode.Typed,
            SidecarHookTargetKind.Exact);
        var failureStart = SidecarProtocolStateMachine.Validate(failureFixture.State, failureFixture.Start, now);
        var directFailure = new HookOutcome(
            Header(2),
            failureFixture.Start.Continuation.HandleId,
            SidecarHookOutcomeKind.Failed,
            new ExecutionError("failure", "The action hook failed."));
        var failureAccepted = SidecarProtocolStateMachine.Validate(failureStart.State!, directFailure, now);
        Assert.True(failureAccepted.Accepted);

        var duplicateFailure = SidecarProtocolStateMachine.Validate(
            failureAccepted.State!,
            directFailure with { Header = Header(3) },
            now);
        Assert.False(duplicateFailure.Accepted);
        Assert.Equal(SidecarProtocolErrors.ContinuationAlreadyUsed, duplicateFailure.ErrorCode);

        var replacementAfterFailure = SidecarProtocolStateMachine.Validate(
            failureAccepted.State!,
            new SidecarResultReplacement(
                Header(3),
                failureFixture.Start.Continuation.HandleId,
                CreateElement(new { value = 1 }),
                "Result after failure"),
            now);
        Assert.False(replacementAfterFailure.Accepted);
        Assert.Equal(SidecarProtocolErrors.ContinuationAlreadyUsed, replacementAfterFailure.ErrorCode);

        var crossPhase = SidecarProtocolStateMachine.Validate(
            started.State! with { Phase = SidecarProtocolPhase.EffectRequested },
            directReplacement,
            now);
        Assert.False(crossPhase.Accepted);
        Assert.Equal(SidecarProtocolErrors.InvalidLifecyclePhase, crossPhase.ErrorCode);
    }

    [Fact]
    public void SidecarDirectTerminalOutcomesPreserveIdentitySchemaAndSecurityAuthority()
    {
        var now = DateTimeOffset.UtcNow;
        var exact = CreateDirectActionFixture(
            now,
            "identity",
            SidecarPayloadMode.Untyped,
            SidecarHookTargetKind.Exact);

        AssertIdentityFailure(exact.Start with { InvocationId = Guid.NewGuid() });
        AssertIdentityFailure(exact.Start with { TraceId = Guid.NewGuid() });
        AssertIdentityFailure(exact.Start with { HookId = "other-hook" });
        AssertIdentityFailure(exact.Start with
        {
            Continuation = exact.Start.Continuation with { HookId = "other-hook" },
        });
        AssertIdentityFailure(exact.Start with
        {
            UntypedDescriptor = exact.Descriptor! with
            {
                ResultSchema = new JsonSchemaReference("other.result", 1, "other-hash"),
            },
        });

        var wrongProtocolDescriptor = exact.Descriptor! with
        {
            ProtocolVersionRange = ContractVersionRange.Exact(2),
        };
        var wrongProtocol = SidecarProtocolStateMachine.Validate(
            exact.State with { ActionDescriptor = wrongProtocolDescriptor },
            exact.Start with { UntypedDescriptor = wrongProtocolDescriptor },
            now);
        Assert.False(wrongProtocol.Accepted);
        Assert.Equal(SidecarProtocolErrors.UnsupportedVersion, wrongProtocol.ErrorCode);

        var category = CreateDirectActionFixture(
            now,
            "category-security",
            SidecarPayloadMode.Untyped,
            SidecarHookTargetKind.Category,
            acceptsUnknownSchemas: true);
        var categoryStart = SidecarProtocolStateMachine.Validate(category.State, category.Start, now);
        Assert.True(categoryStart.Accepted);
        var changedCategoryGrant = category.Grant with { AcceptUnknownSchemas = false };
        var changedCategoryState = categoryStart.State! with
        {
            ActionGrant = changedCategoryGrant,
            HostAuthorization = new SidecarHostAuthorization("module-a", [changedCategoryGrant], []),
        };
        var categoryFailure = SidecarProtocolStateMachine.Validate(
            changedCategoryState,
            new SidecarResultReplacement(
                Header(2),
                category.Start.Continuation.HandleId,
                CreateElement(new { value = 1 }),
                "Changed category authority"),
            now);
        Assert.False(categoryFailure.Accepted);
        Assert.Equal(SidecarProtocolErrors.ForgedApproval, categoryFailure.ErrorCode);

        var wildcard = CreateDirectActionFixture(
            now,
            "wildcard-security",
            SidecarPayloadMode.Untyped,
            SidecarHookTargetKind.Wildcard,
            containsSensitiveData: true);
        var wildcardStart = SidecarProtocolStateMachine.Validate(wildcard.State, wildcard.Start, now);
        Assert.True(wildcardStart.Accepted);
        var changedWildcardGrant = wildcard.Grant with { SensitiveApproved = false };
        var changedWildcardState = wildcardStart.State! with
        {
            ActionGrant = changedWildcardGrant,
            HostAuthorization = new SidecarHostAuthorization("module-a", [changedWildcardGrant], []),
        };
        var wildcardFailure = SidecarProtocolStateMachine.Validate(
            changedWildcardState,
            new HookOutcome(
                Header(2),
                wildcard.Start.Continuation.HandleId,
                SidecarHookOutcomeKind.Failed,
                new ExecutionError("failure", "The action hook failed.")),
            now);
        Assert.False(wildcardFailure.Accepted);
        Assert.Equal(SidecarProtocolErrors.ForgedApproval, wildcardFailure.ErrorCode);

        void AssertIdentityFailure(HookInvokeStart candidate)
        {
            var result = SidecarProtocolStateMachine.Validate(exact.State, candidate, now);
            Assert.False(result.Accepted);
            Assert.Equal(SidecarProtocolErrors.ExchangeIdentityMismatch, result.ErrorCode);
        }
    }

    [Fact]
    public void SidecarStateRejectsCrossExchangeIdentitiesAndPrematureAcknowledgements()
    {
        var now = DateTimeOffset.UtcNow;
        var limits = new SidecarPayloadLimits();
        var startInvocationId = Guid.NewGuid();
        var startHandle = new ContinuationHandle(
            Guid.NewGuid(),
            startInvocationId,
            "hook-a",
            now.AddMinutes(1),
            Sequence: 1);
        var startState = new SidecarProtocolState(
            SidecarExchangeKind.ActionHook,
            Guid.Empty,
            Guid.Empty,
            SidecarProtocolPhase.Negotiated,
            LastSequence: 0,
            now.AddMinutes(1),
            NegotiatedProtocolVersion: 1,
            HostLimits: limits,
            HostAuthorization: new SidecarHostAuthorization(
                "module-a",
                [new ActionCapabilityGrant(
                    new SharpClawActionKey("demo.action"),
                    1,
                    ActionInterceptionCapabilities.Inspect)],
                []));
        var started = SidecarProtocolStateMachine.Validate(
            startState,
            new HookInvokeStart(
                Header(1),
                startInvocationId,
                null,
                Guid.NewGuid(),
                "hook-a",
                new SharpClawActionKey("demo.action"),
                1,
                SidecarPayloadMode.Untyped,
                CreateElement(new { value = 1 }),
                null,
                new ActionCapabilityGrant(
                    new SharpClawActionKey("demo.action"),
                    1,
                    ActionInterceptionCapabilities.Inspect),
                new RequestPrincipal("user-1"),
                ExtensionFeatureSet.Empty,
                startHandle),
            now);
        Assert.True(started.Accepted);
        Assert.Equal(startHandle.HandleId, started.State!.ContinuationHandleId);
        Assert.Equal(startInvocationId, started.State.InvocationId);

        var actionHandle = Guid.NewGuid();
        var actionState = new SidecarProtocolState(
            SidecarExchangeKind.ActionHook,
            Guid.NewGuid(),
            actionHandle,
            SidecarProtocolPhase.SidecarOutcomeSent,
            LastSequence: 1,
            now.AddMinutes(1),
            NegotiatedProtocolVersion: 1,
            HostLimits: limits);
        var wrongCompletion = SidecarProtocolStateMachine.Validate(
            actionState,
            new HookCompleted(
                Header(2),
                Guid.NewGuid(),
                ActionOutcomeKind.Completed,
                ActionOutcomeCertainty.Certain),
            now);
        Assert.False(wrongCompletion.Accepted);
        Assert.Equal(SidecarProtocolErrors.InvalidContinuationHandle, wrongCompletion.ErrorCode);

        var toolInvocation = Guid.NewGuid();
        var toolState = new SidecarProtocolState(
            SidecarExchangeKind.ToolHandler,
            Guid.Empty,
            Guid.Empty,
            SidecarProtocolPhase.Negotiated,
            LastSequence: 0,
            now.AddMinutes(1),
            NegotiatedProtocolVersion: 1,
            HostLimits: limits);
        var toolStart = new SidecarToolHandlerInvokeStart(
            Header(1),
            toolInvocation,
            "demo.tool",
            "handler-a",
            CreateElement(new { value = 1 }),
            new JsonSchemaReference("demo.input", 1, "input-hash"),
            new RequestPrincipal("user-1"));
        var toolStarted = SidecarProtocolStateMachine.Validate(toolState, toolStart, now);
        Assert.True(toolStarted.Accepted);
        var wrongToolResult = SidecarProtocolStateMachine.Validate(
            toolStarted.State!,
            new SidecarToolHandlerResult(
                Header(2),
                toolInvocation,
                "handler-b",
                CreateElement(new { value = 2 }),
                new JsonSchemaReference("demo.result", 1, "result-hash")),
            now);
        Assert.False(wrongToolResult.Accepted);
        Assert.Equal(SidecarProtocolErrors.ExchangeIdentityMismatch, wrongToolResult.ErrorCode);

        var lifecycleState = new SidecarProtocolState(
            SidecarExchangeKind.LifecycleHandler,
            Guid.Empty,
            Guid.Empty,
            SidecarProtocolPhase.Negotiated,
            LastSequence: 0,
            now.AddMinutes(1),
            NegotiatedProtocolVersion: 1,
            HostLimits: limits);
        var lifecycleStart = new SidecarLifecycleHandlerInvokeStart(
            Header(1),
            Guid.NewGuid(),
            SidecarLifecycleCallKind.Start,
            "handler-a",
            null);
        var lifecycleStarted = SidecarProtocolStateMachine.Validate(lifecycleState, lifecycleStart, now);
        Assert.True(lifecycleStarted.Accepted);
        var wrongLifecycleResult = SidecarProtocolStateMachine.Validate(
            lifecycleStarted.State!,
            new SidecarLifecycleHandlerResult(
                Header(2),
                lifecycleStart.InvocationId,
                SidecarLifecycleCallKind.Stop,
                "handler-a",
                null),
            now);
        Assert.False(wrongLifecycleResult.Accepted);
        Assert.Equal(SidecarProtocolErrors.ExchangeIdentityMismatch, wrongLifecycleResult.ErrorCode);

        var envelope = new UntypedEventEnvelope(
            new UntypedEventDescriptor(
                new SharpClawEventKey("demo.event"),
                1,
                "demo",
                EventInterceptionCapabilities.Inspect,
                new JsonSchemaReference("demo.event", 1, "event-hash"),
                ContainsSensitiveData: false),
            Guid.NewGuid(),
            null,
            Guid.NewGuid(),
            now,
            "demo.module",
            CreateElement(new { value = 1 }));
        var listenerState = new SidecarProtocolState(
            SidecarExchangeKind.EventListener,
            Guid.Empty,
            Guid.Empty,
            SidecarProtocolPhase.Negotiated,
            LastSequence: 0,
            now.AddMinutes(1),
            NegotiatedProtocolVersion: 1,
            HostLimits: limits,
            EventDescriptor: envelope.Descriptor,
            EventKey: envelope.Descriptor.Key,
            EventVersion: envelope.Descriptor.Version);
        var deliveryId = Guid.NewGuid();
        var earlyAcknowledgement = SidecarProtocolStateMachine.Validate(
            listenerState,
            new SidecarEventListenerAcknowledgement(
                Header(1),
                deliveryId,
                "listener-a",
                envelope.Descriptor,
                EventDelivery.Inline,
                Accepted: true),
            now);
        Assert.False(earlyAcknowledgement.Accepted);
        Assert.Equal(SidecarProtocolErrors.DeliveryNotPending, earlyAcknowledgement.ErrorCode);

        var delivery = new SidecarEventListenerDelivery(
            Header(2),
            deliveryId,
            "listener-a",
            envelope,
            EventDelivery.Inline,
            RequiresAcknowledgement: true);
        var delivered = SidecarProtocolStateMachine.Validate(listenerState, delivery, now);
        Assert.True(delivered.Accepted);
        var wrongDescriptor = SidecarProtocolStateMachine.Validate(
            delivered.State!,
            new SidecarEventListenerAcknowledgement(
                Header(3),
                deliveryId,
                "listener-a",
                envelope.Descriptor with
                {
                    Version = 2,
                    PayloadSchema = new JsonSchemaReference("other.event", 1, "other-hash"),
                },
                EventDelivery.Inline,
                Accepted: true),
            now);
        Assert.False(wrongDescriptor.Accepted);
        Assert.Equal(SidecarProtocolErrors.DeliveryNotPending, wrongDescriptor.ErrorCode);
        var wrongAcknowledgement = SidecarProtocolStateMachine.Validate(
            delivered.State!,
            new SidecarEventListenerAcknowledgement(
                Header(3),
                deliveryId,
                "listener-b",
                envelope.Descriptor,
                EventDelivery.Inline,
                Accepted: true),
            now);
        Assert.False(wrongAcknowledgement.Accepted);
        Assert.Equal(SidecarProtocolErrors.DeliveryNotPending, wrongAcknowledgement.ErrorCode);

        var acknowledged = SidecarProtocolStateMachine.Validate(
            delivered.State!,
            new SidecarEventListenerAcknowledgement(
                Header(4),
                deliveryId,
                "listener-a",
                envelope.Descriptor,
                EventDelivery.Inline,
                Accepted: true),
            now);
        Assert.True(acknowledged.Accepted);
        Assert.False(acknowledged.State!.DeliveryAcknowledgementPending);

        var streamState = new SidecarProtocolState(
            SidecarExchangeKind.Stream,
            Guid.Empty,
            Guid.Empty,
            SidecarProtocolPhase.Invoking,
            LastSequence: 0,
            now.AddMinutes(1),
            NegotiatedProtocolVersion: 1,
            HostLimits: limits,
            StreamId: Guid.NewGuid());
        var wrongStream = SidecarProtocolStateMachine.Validate(
            streamState,
            new SidecarStreamChunk(
                Header(1),
                Guid.NewGuid(),
                1,
                CreateElement(new { value = 1 }),
                IsFinal: true),
            now);
        Assert.False(wrongStream.Accepted);
        Assert.Equal(SidecarProtocolErrors.ExchangeIdentityMismatch, wrongStream.ErrorCode);
    }

    [Fact]
    public void SidecarStateUsesNegotiatedVersionAndHostPayloadLimit()
    {
        var now = DateTimeOffset.UtcNow;
        var state = new SidecarProtocolState(
            SidecarExchangeKind.ActionHook,
            Guid.NewGuid(),
            Guid.NewGuid(),
            SidecarProtocolPhase.Invoking,
            LastSequence: 1,
            now.AddMinutes(1),
            NegotiatedProtocolVersion: 1,
            HostLimits: new SidecarPayloadLimits(ProtocolMessageBytes: 1024));
        var effect = new SidecarEffectRequest(
            Header(2) with { ProtocolVersion = 2 },
            state.ContinuationHandleId,
            SidecarContinuationCommand.ContinueOriginal);
        var wrongVersion = SidecarProtocolStateMachine.Validate(state, effect, now);
        Assert.False(wrongVersion.Accepted);
        Assert.Equal(SidecarProtocolErrors.UnsupportedVersion, wrongVersion.ErrorCode);

        var forgedMaximum = new SidecarEffectRequest(
            Header(2) with
            {
                Size = new SidecarMessageSizeAuthority(128, int.MaxValue),
            },
            state.ContinuationHandleId,
            SidecarContinuationCommand.ContinueOriginal);
        var oversized = SidecarProtocolStateMachine.Validate(state, forgedMaximum, now);
        Assert.False(oversized.Accepted);
        Assert.Equal(SidecarProtocolErrors.ModulePayloadTooLarge, oversized.ErrorCode);
    }

    [Fact]
    public void SidecarDiscoveryValidatesEveryWildcardDescriptorWithHostApproval()
    {
        var inputSchema = new JsonSchemaReference("demo.input", 1, "input-hash");
        var resultSchema = new JsonSchemaReference("demo.result", 1, "result-hash");
        var host = new SidecarHostDescriptorCatalog(
            [
                new SidecarHostActionDescriptor(
                    new SharpClawActionKey("demo.one"),
                    1,
                    "demo",
                    inputSchema,
                    resultSchema,
                    ActionInterceptionCapabilities.Inspect,
                    ContainsSensitiveData: false,
                    ContractVersionRange.Exact(1)),
                new SidecarHostActionDescriptor(
                    new SharpClawActionKey("demo.two"),
                    1,
                    "demo",
                    inputSchema,
                    new JsonSchemaReference("other.result", 1, "other-hash"),
                    ActionInterceptionCapabilities.Inspect,
                    ContainsSensitiveData: false,
                    ContractVersionRange.Exact(1)),
            ],
            []);
        var discovery = new SidecarDiscoveryEnvelope(
            Header(),
            "demo.module",
            "contract-hash",
            new SidecarProtocolOffer(1, 1, [SidecarPayloadMode.Untyped], new SidecarPayloadLimits()),
            [new SidecarActionSubscription(
                SidecarHookTargetKind.Wildcard,
                null,
                null,
                ContractVersionRange.Exact(1),
                inputSchema,
                resultSchema,
                ActionInterceptionCapabilities.Inspect,
                 SidecarPayloadMode.Untyped,
                 new HookOrdering("demo"),
                 AcceptUnknownNonSensitiveSchemas: true)],
            [],
            [],
            [],
            [],
            [],
            []);

        var heterogeneousAccepted = SidecarDiscoveryValidator.Validate(discovery, host);
        Assert.True(heterogeneousAccepted.Accepted, $"{heterogeneousAccepted.ErrorCode}: {heterogeneousAccepted.ErrorMessage}");

        var futureHost = new SidecarHostDescriptorCatalog(
            [
                .. host.Actions,
                new SidecarHostActionDescriptor(
                    new SharpClawActionKey("demo.future"),
                    1,
                    "demo",
                    new JsonSchemaReference("future.input", 1, "future-input-hash"),
                    new JsonSchemaReference("future.result", 1, "future-result-hash"),
                    ActionInterceptionCapabilities.Inspect,
                    ContainsSensitiveData: false,
                    ContractVersionRange.Exact(1)),
            ],
            []);
        Assert.True(SidecarDiscoveryValidator.Validate(discovery, futureHost).Accepted);

        var disabled = discovery with
        {
            Actions = [discovery.Actions[0] with { AcceptUnknownNonSensitiveSchemas = false }],
        };
        var schemaMismatch = SidecarDiscoveryValidator.Validate(disabled, host);
        Assert.False(schemaMismatch.Accepted);
        Assert.Equal(SidecarProtocolErrors.SchemaMismatch, schemaMismatch.ErrorCode);

        var sensitiveHost = new SidecarHostDescriptorCatalog(
            [new SidecarHostActionDescriptor(
                new SharpClawActionKey("demo.sensitive"),
                1,
                "demo",
                inputSchema,
                resultSchema,
                ActionInterceptionCapabilities.Inspect,
                ContainsSensitiveData: true,
                ContractVersionRange.Exact(1))],
            []);
        var sensitiveRejected = SidecarDiscoveryValidator.Validate(discovery, sensitiveHost);
        Assert.False(sensitiveRejected.Accepted);
        Assert.Equal(SidecarProtocolErrors.ForgedApproval, sensitiveRejected.ErrorCode);

        var approved = new SidecarHostDescriptorCatalog(
            sensitiveHost.Actions,
            [],
            sensitiveWildcardApproval: new SensitiveWildcardApproval(
                "demo.module",
                new Dictionary<string, int> { ["demo.sensitive"] = 1 },
                new Dictionary<string, int>()));
        Assert.True(SidecarDiscoveryValidator.Validate(discovery, approved).Accepted);
    }

    [Fact]
    public void SidecarCategorySchemasRequireUnknownSchemaApprovalAndSensitiveApproval()
    {
        var payloadSchema = new JsonSchemaReference("demo.event", 1, "event-hash");
        var host = new SidecarHostDescriptorCatalog(
            [],
            [
                new SidecarHostEventDescriptor(
                    new SharpClawEventKey("demo.one"),
                    1,
                    "demo",
                    payloadSchema,
                    EventInterceptionCapabilities.Inspect,
                    ContainsSensitiveData: false,
                    ContractVersionRange.Exact(1)),
                new SidecarHostEventDescriptor(
                    new SharpClawEventKey("demo.two"),
                    1,
                    "demo",
                    new JsonSchemaReference("other.event", 1, "other-event-hash"),
                    EventInterceptionCapabilities.Inspect,
                    ContainsSensitiveData: false,
                    ContractVersionRange.Exact(1)),
            ]);
        var subscription = new SidecarEventSubscription(
            SidecarHookTargetKind.Category,
            null,
            "demo",
            ContractVersionRange.Exact(1),
            payloadSchema,
            EventInterceptionCapabilities.Inspect,
            EventDelivery.Inline,
            SidecarPayloadMode.Untyped,
            new HookOrdering("demo"),
            AcceptUnknownNonSensitiveSchemas: true);
        var discovery = new SidecarDiscoveryEnvelope(
            Header(),
            "demo.module",
            "contract-hash",
            new SidecarProtocolOffer(1, 1, [SidecarPayloadMode.Untyped], new SidecarPayloadLimits()),
            [],
            [subscription],
            [],
            [],
            [],
            [],
            []);

        Assert.True(SidecarDiscoveryValidator.Validate(discovery, host).Accepted);

        var disabled = discovery with
        {
            Events = [subscription with { AcceptUnknownNonSensitiveSchemas = false }],
        };
        var disabledResult = SidecarDiscoveryValidator.Validate(disabled, host);
        Assert.False(disabledResult.Accepted);
        Assert.Equal(SidecarProtocolErrors.SchemaMismatch, disabledResult.ErrorCode);

        var sensitive = new SidecarHostDescriptorCatalog(
            [],
            [host.Events[0] with { ContainsSensitiveData = true }]);
        var sensitiveResult = SidecarDiscoveryValidator.Validate(discovery, sensitive);
        Assert.False(sensitiveResult.Accepted);
        Assert.Equal(SidecarProtocolErrors.ForgedApproval, sensitiveResult.ErrorCode);
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
            SidecarProtocolPhase.SidecarOutcomeSent,
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
        var eventEnvelope = new UntypedEventEnvelope(
            new UntypedEventDescriptor(
                new SharpClawEventKey("jobs.completed"),
                1,
                "jobs",
                EventInterceptionCapabilities.Inspect,
                new JsonSchemaReference("jobs.completed", 1, "event-hash"),
                ContainsSensitiveData: false),
            Guid.NewGuid(),
            Guid.NewGuid(),
            Guid.NewGuid(),
            DateTimeOffset.UtcNow,
            "module-a",
            JsonSerializer.SerializeToElement(new { id = "job-1" }));
        var request = new ModuleStorageMutationAndOutboxRequest(
            commit,
            [new ModuleStorageMutation(
                ModuleStorageOperations.Upsert,
                "job-1",
                JsonSerializer.SerializeToElement(new { status = "complete" }),
                ExpectedRevision: 7)],
            [new ModuleStorageOutboxMessage(
                eventEnvelope,
                EventDelivery.Durable)],
            authority);

        var json = JsonSerializer.Serialize(request, JsonOptions);
        var roundTrip = JsonSerializer.Deserialize<ModuleStorageMutationAndOutboxRequest>(json, JsonOptions)!;

        Assert.Equal(commit.OperationId, roundTrip.Commit.OperationId);
        Assert.Equal("module-a", roundTrip.Authority!.OwnerId);
        Assert.Equal(3, roundTrip.Authority.Generation);
        Assert.Equal(7, roundTrip.Mutations[0].ExpectedRevision);
        Assert.Equal("idempotency-1", roundTrip.Commit.IdempotencyKey);
        Assert.Equal("jobs.completed", roundTrip.Outbox[0].Event.Descriptor.Key.Value);
        Assert.Equal("jobs", roundTrip.Outbox[0].Event.Descriptor.Category);
        Assert.Equal(EventDelivery.Durable, roundTrip.Outbox[0].Delivery);
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
        var payload = new ModuleStorageClaimRequest(
            "module-a",
            [],
            null,
            1,
            new { status = "running" },
            ExpectedRevision: 12,
            Authority: authority,
            Indexes: null);
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
        var getStore = new ModuleDocumentStore<string>(missingGetKey, "module-a", "documents", "module-a");
        var getFailure = await Assert.ThrowsAsync<ModuleStorageContractException>(() =>
            getStore.GetRecordAsync("job-1"));
        Assert.Equal(ModuleStorageErrors.MissingRecordKey, getFailure.Failure.Code);

        var missingListRevision = new StubStorageGateway(_ =>
            JsonSerializer.SerializeToElement(new
            {
                records = new[] { new { key = "job-1", value = "value" } },
            }));
        var listStore = new ModuleDocumentStore<string>(missingListRevision, "module-a", "documents", "module-a");
        var listFailure = await Assert.ThrowsAsync<ModuleStorageContractException>(() =>
            listStore.ListAsync());
        Assert.Equal(ModuleStorageErrors.MissingRevision, listFailure.Failure.Code);

        var negativeQueryRevision = new StubStorageGateway(_ =>
            JsonSerializer.SerializeToElement(new
            {
                records = new[] { new { key = "job-1", value = "value", revision = -1 } },
            }));
        var queryStore = new ModuleDocumentStore<string>(negativeQueryRevision, "module-a", "documents", "module-a");
        var queryFailure = await Assert.ThrowsAsync<ModuleStorageContractException>(() =>
            queryStore.Query().ToRecordsAsync());
        Assert.Equal(ModuleStorageErrors.InvalidRevision, queryFailure.Failure.Code);

        var missingClaimAuthority = new StubStorageGateway(_ =>
            JsonSerializer.SerializeToElement(new
            {
                records = Array.Empty<object>(),
            }));
        var claimStore = new ModuleDocumentStore<string>(missingClaimAuthority, "module-a", "documents", "module-a");
        var claimFailure = await Assert.ThrowsAsync<ModuleStorageContractException>(() =>
            claimStore.Claim()
                .Patch(new { status = "claimed" })
                .ToRecordsAsync());
        Assert.Equal(ModuleStorageErrors.InvalidClaimAuthority, claimFailure.Failure.Code);
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
    public void StorageClaimValidationRejectsInvalidAndConflictingAuthority()
    {
        var now = DateTimeOffset.UtcNow;
        var request = new ModuleStorageClaimRequest(
            "module-a",
            [],
            Patch: new { status = "claimed" });
        var authority = new ModuleStorageClaimAuthority(
            "module-a",
            Guid.NewGuid(),
            now.AddMinutes(1),
            Generation: 2,
            Revision: 7);
        var record = new ModuleStorageClaimRecord<string>("job-1", "claimed", 7, authority);
        var result = new ModuleStorageClaimResult<string>([record], authority);

        Assert.Same(result, ModuleStorageClaimValidation.Validate(request, result, now));

        var emptyOwner = result with
        {
            Authority = authority with { OwnerId = "" },
        };
        var emptyOwnerFailure = Assert.Throws<ModuleStorageContractException>(() =>
            ModuleStorageClaimValidation.Validate(request, emptyOwner, now));
        Assert.Equal(ModuleStorageErrors.InvalidClaimAuthority, emptyOwnerFailure.Failure.Code);

        var emptyToken = result with
        {
            Authority = authority with { HostToken = Guid.Empty },
        };
        var emptyTokenFailure = Assert.Throws<ModuleStorageContractException>(() =>
            ModuleStorageClaimValidation.Validate(request, emptyToken, now));
        Assert.Equal(ModuleStorageErrors.InvalidClaimAuthority, emptyTokenFailure.Failure.Code);

        var expired = result with
        {
            Authority = authority with { LeaseExpiresAt = now.AddSeconds(-1) },
        };
        var expiredFailure = Assert.Throws<ModuleStorageContractException>(() =>
            ModuleStorageClaimValidation.Validate(request, expired, now));
        Assert.Equal(ModuleStorageErrors.InvalidClaimAuthority, expiredFailure.Failure.Code);

        var wrongOwner = result with
        {
            Authority = authority with { OwnerId = "module-b" },
        };
        var wrongOwnerFailure = Assert.Throws<ModuleStorageContractException>(() =>
            ModuleStorageClaimValidation.Validate(request, wrongOwner, now));
        Assert.Equal(ModuleStorageErrors.ClaimOwnerMismatch, wrongOwnerFailure.Failure.Code);

        var wrongRecordAuthority = result with
        {
            Records = [record with { Authority = authority with { Generation = 3 } }],
        };
        var wrongRecordAuthorityFailure = Assert.Throws<ModuleStorageContractException>(() =>
            ModuleStorageClaimValidation.Validate(request, wrongRecordAuthority, now));
        Assert.Equal(ModuleStorageErrors.ClaimAuthorityMismatch, wrongRecordAuthorityFailure.Failure.Code);

        var independentRecordRevision = result with
        {
            Records = [record with { Revision = 8 }],
        };
        Assert.Same(independentRecordRevision, ModuleStorageClaimValidation.Validate(request, independentRecordRevision, now));

        var staleFence = result with
        {
            Records = [record with { Authority = authority with { HostToken = Guid.NewGuid() } }],
        };
        var staleFenceFailure = Assert.Throws<ModuleStorageContractException>(() =>
            ModuleStorageClaimValidation.Validate(request, staleFence, now));
        Assert.Equal(ModuleStorageErrors.ClaimAuthorityMismatch, staleFenceFailure.Failure.Code);
    }

    [Fact]
    public void StorageClaimsAllowIndependentRecordRevisionsUnderOneBatchFence()
    {
        var now = DateTimeOffset.UtcNow;
        var authority = new ModuleStorageClaimAuthority(
            "module-a",
            Guid.NewGuid(),
            now.AddMinutes(1),
            Generation: 4,
            Revision: 20);
        var request = new ModuleStorageClaimRequest("module-a", []);
        var result = new ModuleStorageClaimResult<string>(
            [
                new ModuleStorageClaimRecord<string>("job-1", "one", 7, authority),
                new ModuleStorageClaimRecord<string>("job-2", "two", 13, authority),
            ],
            authority);

        Assert.Same(result, ModuleStorageClaimValidation.Validate(request, result, now));

        var wrongRecordFence = result with
        {
            Records = [result.Records[0] with { Authority = authority with { Generation = 5 } }, result.Records[1]],
        };
        var wrongRecordFailure = Assert.Throws<ModuleStorageContractException>(() =>
            ModuleStorageClaimValidation.Validate(request, wrongRecordFence, now));
        Assert.Equal(ModuleStorageErrors.ClaimAuthorityMismatch, wrongRecordFailure.Failure.Code);

        var wrongBatchRevision = result with
        {
            Records = [result.Records[0] with { Authority = authority with { Revision = 19 } }, result.Records[1]],
        };
        var wrongBatchRevisionFailure = Assert.Throws<ModuleStorageContractException>(() =>
            ModuleStorageClaimValidation.Validate(request, wrongBatchRevision, now));
        Assert.Equal(ModuleStorageErrors.ClaimAuthorityMismatch, wrongBatchRevisionFailure.Failure.Code);

        var staleBatchFence = result with
        {
            Authority = authority with { Generation = 3 },
        };
        var staleBatchFailure = Assert.Throws<ModuleStorageContractException>(() =>
            ModuleStorageClaimValidation.Validate(request, staleBatchFence, now));
        Assert.Equal(ModuleStorageErrors.ClaimAuthorityMismatch, staleBatchFailure.Failure.Code);
    }

    [Fact]
    public async Task StorageAtomicCommitRetryPreservesOneIdentityAndRejectsMismatch()
    {
        var commit = new ModuleStorageCommitIdentity(Guid.NewGuid(), "retry-1");
        var eventEnvelope = new UntypedEventEnvelope(
            new UntypedEventDescriptor(
                new SharpClawEventKey("jobs.completed"),
                1,
                "jobs",
                EventInterceptionCapabilities.Inspect,
                new JsonSchemaReference("jobs.completed", 1, "event-hash"),
                ContainsSensitiveData: false),
            Guid.NewGuid(),
            Guid.NewGuid(),
            Guid.NewGuid(),
            DateTimeOffset.UtcNow,
            "module-a",
            CreateElement(new { id = "job-1" }));
        var request = new ModuleStorageMutationAndOutboxRequest(
            commit,
            [new ModuleStorageMutation(
                ModuleStorageOperations.Upsert,
                "job-1",
                CreateElement(new { status = "complete" }),
                ExpectedRevision: 7)],
            [new ModuleStorageOutboxMessage(eventEnvelope, EventDelivery.Durable)]);
        var gateway = new StatefulCommitGateway();

        await Assert.ThrowsAsync<TimeoutException>(() =>
            gateway.CommitMutationAndOutboxAsync("module-a", "documents", request));

        var retry = await gateway.CommitMutationAndOutboxAsync("module-a", "documents", request);
        var validated = ModuleStorageCommitValidation.Validate(request, retry);
        Assert.True(validated.AlreadyCommitted);
        Assert.Equal(commit, validated.Commit);
        Assert.Single(gateway.CommittedEventIds);

        var mismatched = retry with
        {
            Commit = new ModuleStorageCommitIdentity(Guid.NewGuid(), "other"),
        };
        var mismatchFailure = Assert.Throws<ModuleStorageContractException>(() =>
            ModuleStorageCommitValidation.Validate(request, mismatched));
        Assert.Equal(ModuleStorageErrors.CommitIdentityConflict, mismatchFailure.Failure.Code);

        await Assert.ThrowsAsync<ModuleStorageContractException>(() =>
            gateway.CommitMutationAndOutboxAsync(
                "module-a",
                "documents",
                request with
                {
                    Mutations = [request.Mutations[0] with { ExpectedRevision = 8 }],
                }));
    }

    [Fact]
    public void StorageAtomicCommitValidationRejectsIncompleteTerminalEvidence()
    {
        var commit = new ModuleStorageCommitIdentity(Guid.NewGuid(), "atomic-validation");
        var firstEvent = CreateStorageEvent("job-1");
        var secondEvent = CreateStorageEvent("job-2");
        var request = new ModuleStorageMutationAndOutboxRequest(
            commit,
            [
                new ModuleStorageMutation(ModuleStorageOperations.Upsert, "job-1", CreateElement(new { value = 1 }), ExpectedRevision: 1),
                new ModuleStorageMutation(ModuleStorageOperations.Upsert, "job-2", CreateElement(new { value = 2 }), ExpectedRevision: 2),
            ],
            [
                new ModuleStorageOutboxMessage(firstEvent, EventDelivery.Durable),
                new ModuleStorageOutboxMessage(secondEvent, EventDelivery.Durable),
            ]);
        var valid = new ModuleStorageMutationAndOutboxResult(
            commit,
            [new ModuleStorageRevision("job-1", 2), new ModuleStorageRevision("job-2", 3)],
            ["outbox-1", "outbox-2"],
            CommitRevision: 3);

        Assert.Same(valid, ModuleStorageCommitValidation.Validate(request, valid));
        AssertFailure(valid with { OutboxMessageIds = ["", "outbox-2"] }, ModuleStorageErrors.InvalidOutboxIdentity);
        AssertFailure(valid with { OutboxMessageIds = ["same", "same"] }, ModuleStorageErrors.InvalidOutboxIdentity);
        AssertFailure(valid with { Revisions = [new ModuleStorageRevision("job-1", 2)] }, ModuleStorageErrors.MissingMutationRevision);
        AssertFailure(
            valid with { Revisions = [new ModuleStorageRevision("job-1", 2), new ModuleStorageRevision("job-1", 3)] },
            ModuleStorageErrors.DuplicateMutationRevision);
        AssertFailure(
            valid with { Revisions = [new ModuleStorageRevision("job-1", -1), new ModuleStorageRevision("job-2", 3)] },
            ModuleStorageErrors.InvalidRevision);
        AssertFailure(valid with { CommitRevision = -1 }, ModuleStorageErrors.InvalidCommitRevision);
        AssertFailure(
            valid with { Revisions = [new ModuleStorageRevision("job-1", 2), new ModuleStorageRevision("other", 3)] },
            ModuleStorageErrors.MutationRevisionMismatch);

        void AssertFailure(ModuleStorageMutationAndOutboxResult candidate, string code)
        {
            var failure = Assert.Throws<ModuleStorageContractException>(() =>
                ModuleStorageCommitValidation.Validate(request, candidate));
            Assert.Equal(code, failure.Failure.Code);
        }
    }

    [Fact]
    public void SidecarEventOutcomeRequiresExactDescriptorAndGrantedEffect()
    {
        var now = DateTimeOffset.UtcNow;
        var descriptor = new UntypedEventDescriptor(
            new SharpClawEventKey("demo.event"),
            2,
            "demo",
            EventInterceptionCapabilities.Inspect,
            new JsonSchemaReference("demo.event", 2, "event-hash"),
            ContainsSensitiveData: false);
        var envelope = new UntypedEventEnvelope(
            descriptor,
            Guid.NewGuid(),
            null,
            Guid.NewGuid(),
            now,
            "module-a",
            CreateElement(new { value = 1 }));
        var grant = new EventCapabilityGrant(
            descriptor.Key,
            descriptor.Version,
            EventInterceptionCapabilities.Inspect);
        var handle = new ContinuationHandle(Guid.NewGuid(), Guid.NewGuid(), "event-hook", now.AddMinutes(1), 1);
        var state = new SidecarProtocolState(
            SidecarExchangeKind.EventIntercept,
            Guid.Empty,
            Guid.Empty,
            SidecarProtocolPhase.Negotiated,
            LastSequence: 0,
            now.AddMinutes(1),
            NegotiatedProtocolVersion: 1,
            HostLimits: new SidecarPayloadLimits(),
            EventDescriptor: descriptor,
            EventGrant: grant,
            EventKey: descriptor.Key,
            EventVersion: descriptor.Version,
            HostAuthorization: new SidecarHostAuthorization("module-a", [], [grant]));
        var start = new EventInterceptStart(
            Header(1),
            "event-hook",
            envelope,
            grant,
            handle);
        var started = SidecarProtocolStateMachine.Validate(state, start, now);
        Assert.True(started.Accepted);

        var continued = new EventInterceptOutcome(
            Header(2),
            handle.HandleId,
            descriptor.Key,
            descriptor.Version,
            descriptor.PayloadSchema,
            EventInterceptionKind.Continued);
        var completed = SidecarProtocolStateMachine.Validate(started.State!, continued, now);
        Assert.True(completed.Accepted);
        Assert.Equal(SidecarProtocolPhase.Completed, completed.State!.Phase);

        var changedSchema = continued with
        {
            Header = Header(2),
            EventSchema = new JsonSchemaReference("other.event", 1, "other-hash"),
        };
        var schemaFailure = SidecarProtocolStateMachine.Validate(started.State!, changedSchema, now);
        Assert.False(schemaFailure.Accepted);
        Assert.Equal(SidecarProtocolErrors.ExchangeIdentityMismatch, schemaFailure.ErrorCode);

        var inspectOnlyState = started.State! with
        {
            Phase = SidecarProtocolPhase.Invoking,
            LastSequence = 1,
        };
        var replacement = continued with
        {
            Header = Header(2),
            Kind = EventInterceptionKind.Replaced,
        };
        var capabilityFailure = SidecarProtocolStateMachine.Validate(inspectOnlyState, replacement, now);
        Assert.False(capabilityFailure.Accepted);
        Assert.Equal(SidecarProtocolErrors.UnsupportedCapability, capabilityFailure.ErrorCode);
    }

    [Fact]
    public void SidecarInspectOnlyGrantRejectsUnauthorizedActionEffects()
    {
        var now = DateTimeOffset.UtcNow;
        var actionKey = new SharpClawActionKey("demo.action");
        var state = new SidecarProtocolState(
            SidecarExchangeKind.ActionHook,
            Guid.NewGuid(),
            Guid.NewGuid(),
            SidecarProtocolPhase.Invoking,
            LastSequence: 1,
            now.AddMinutes(1),
            NegotiatedProtocolVersion: 1,
            HostLimits: new SidecarPayloadLimits(),
            ActionKey: actionKey,
            ActionVersion: 1,
            ActionGrant: new ActionCapabilityGrant(actionKey, 1, ActionInterceptionCapabilities.Inspect),
            HostAuthorization: new SidecarHostAuthorization(
                "module-a",
                [new ActionCapabilityGrant(actionKey, 1, ActionInterceptionCapabilities.Inspect)],
                []));

        foreach (var command in new[]
        {
            SidecarContinuationCommand.ContinueReplacement,
            SidecarContinuationCommand.Cancel,
            SidecarContinuationCommand.Defer,
            SidecarContinuationCommand.Repeat,
        })
        {
            Assert.False(SidecarProtocolStateMachine.CanApply(
                state,
                new SidecarEffectRequest(Header(2), state.ContinuationHandleId, command)));
            var rejected = SidecarProtocolStateMachine.Validate(
                state,
                new SidecarEffectRequest(Header(2), state.ContinuationHandleId, command),
                now);
            Assert.False(rejected.Accepted);
            Assert.Equal(SidecarProtocolErrors.UnsupportedCapability, rejected.ErrorCode);
        }

        var replacement = SidecarProtocolStateMachine.Validate(
            state with { Phase = SidecarProtocolPhase.SidecarOutcomeSent },
            new SidecarResultReplacement(
                Header(2),
                state.ContinuationHandleId,
                CreateElement(new { value = 1 }),
                "unauthorized"),
            now);
        Assert.False(replacement.Accepted);
        Assert.Equal(SidecarProtocolErrors.UnsupportedCapability, replacement.ErrorCode);
    }

    [Fact]
    public void SidecarMeasuresEachMessageAgainstItsSpecificHostPayloadLimit()
    {
        var now = DateTimeOffset.UtcNow;
        var limits = new SidecarPayloadLimits(
            ActionInputBytes: 64,
            ActionResultBytes: 64,
            EventPayloadBytes: 64,
            ProtocolMessageBytes: 4096,
            StreamChunkBytes: 64);
        var actionKey = new SharpClawActionKey("demo.action");
        var actionGrant = new ActionCapabilityGrant(
            actionKey,
            1,
            ActionInterceptionCapabilities.Inspect |
            ActionInterceptionCapabilities.ReplaceInput |
            ActionInterceptionCapabilities.Wrap |
            ActionInterceptionCapabilities.ReplaceResult);
        var actionDescriptor = new UntypedActionDescriptor(
            actionKey,
            1,
            "demo",
            actionGrant.Capabilities,
            new JsonSchemaReference("demo.input", 1, "input-hash"),
            new JsonSchemaReference("demo.result", 1, "result-hash"),
            ContainsSensitiveData: false);
        var authorization = new SidecarHostAuthorization("module-a", [actionGrant], []);
        var invocationId = Guid.NewGuid();
        var handle = new ContinuationHandle(Guid.NewGuid(), invocationId, "hook-a", now.AddMinutes(1), 1);
        var smallHeader = Header(1) with
        {
            Size = new SidecarMessageSizeAuthority(1, 64),
        };
        var large = CreateElement(new { value = new string('x', 512) });
        var startState = new SidecarProtocolState(
            SidecarExchangeKind.ActionHook,
            Guid.Empty,
            Guid.Empty,
            SidecarProtocolPhase.Negotiated,
            LastSequence: 0,
            now.AddMinutes(1),
            NegotiatedProtocolVersion: 1,
            HostLimits: limits,
            HostAuthorization: authorization);
        var actionInput = SidecarProtocolStateMachine.Validate(
            startState,
            new HookInvokeStart(
                smallHeader,
                invocationId,
                null,
                Guid.NewGuid(),
                "hook-a",
                actionKey,
                1,
                SidecarPayloadMode.Untyped,
                large,
                actionDescriptor,
                actionGrant,
                new RequestPrincipal("user-1"),
                ExtensionFeatureSet.Empty,
                handle),
            now);
        Assert.False(actionInput.Accepted);
        Assert.Equal(SidecarProtocolErrors.ModulePayloadTooLarge, actionInput.ErrorCode);

        var invokingState = new SidecarProtocolState(
            SidecarExchangeKind.ActionHook,
            invocationId,
            handle.HandleId,
            SidecarProtocolPhase.Invoking,
            LastSequence: 1,
            now.AddMinutes(1),
            NegotiatedProtocolVersion: 1,
            HostLimits: limits,
            ActionKey: actionKey,
            ActionGrant: actionGrant,
            ActionVersion: 1,
            ActionDescriptor: actionDescriptor,
            HostAuthorization: authorization);
        var replacementInput = SidecarProtocolStateMachine.Validate(
            invokingState,
            new SidecarEffectRequest(
                smallHeader with { Sequence = 2 },
                handle.HandleId,
                SidecarContinuationCommand.ContinueReplacement,
                large),
            now);
        Assert.False(replacementInput.Accepted);
        Assert.Equal(SidecarProtocolErrors.ModulePayloadTooLarge, replacementInput.ErrorCode);

        var actionResult = SidecarProtocolStateMachine.Validate(
            invokingState with { Phase = SidecarProtocolPhase.SidecarOutcomeSent },
            new SidecarResultReplacement(
                smallHeader with { Sequence = 2 },
                handle.HandleId,
                large,
                "large result"),
            now);
        Assert.False(actionResult.Accepted);
        Assert.Equal(SidecarProtocolErrors.ModulePayloadTooLarge, actionResult.ErrorCode);

        var eventKey = new SharpClawEventKey("demo.event");
        var eventDescriptor = new UntypedEventDescriptor(
            eventKey,
            1,
            "demo",
            EventInterceptionCapabilities.Inspect,
            new JsonSchemaReference("demo.event", 1, "event-hash"),
            ContainsSensitiveData: false);
        var eventGrant = new EventCapabilityGrant(eventKey, 1, EventInterceptionCapabilities.Inspect);
        var eventState = new SidecarProtocolState(
            SidecarExchangeKind.EventIntercept,
            Guid.Empty,
            Guid.Empty,
            SidecarProtocolPhase.Negotiated,
            LastSequence: 0,
            now.AddMinutes(1),
            NegotiatedProtocolVersion: 1,
            HostLimits: limits,
            EventDescriptor: eventDescriptor,
            EventGrant: eventGrant,
            HostAuthorization: new SidecarHostAuthorization("module-a", [], [eventGrant]));
        var eventEnvelope = new UntypedEventEnvelope(
            eventDescriptor,
            Guid.NewGuid(),
            null,
            Guid.NewGuid(),
            now,
            "module-a",
            large);
        var eventPayload = SidecarProtocolStateMachine.Validate(
            eventState,
            new EventInterceptStart(
                smallHeader with { Sequence = 1 },
                "event-hook",
                eventEnvelope,
                eventGrant,
                new ContinuationHandle(Guid.NewGuid(), Guid.NewGuid(), "event-hook", now.AddMinutes(1), 1)),
            now);
        Assert.False(eventPayload.Accepted);
        Assert.Equal(SidecarProtocolErrors.ModulePayloadTooLarge, eventPayload.ErrorCode);

        var streamId = Guid.NewGuid();
        var streamPayload = SidecarProtocolStateMachine.Validate(
            new SidecarProtocolState(
                SidecarExchangeKind.Stream,
                Guid.Empty,
                Guid.Empty,
                SidecarProtocolPhase.Invoking,
                LastSequence: 0,
                now.AddMinutes(1),
                NegotiatedProtocolVersion: 1,
                HostLimits: limits,
                StreamId: streamId),
            new SidecarStreamChunk(
                smallHeader with { Sequence = 1 },
                streamId,
                1,
                large,
                IsFinal: false),
            now);
        Assert.False(streamPayload.Accepted);
        Assert.Equal(SidecarProtocolErrors.ModulePayloadTooLarge, streamPayload.ErrorCode);
    }

    [Fact]
    public void SidecarContinuationRequiresWrapAndValidCommandShapes()
    {
        var now = DateTimeOffset.UtcNow;
        var key = new SharpClawActionKey("demo.action");

        static SidecarProtocolState State(
            DateTimeOffset now,
            SharpClawActionKey key,
            ActionCapabilityGrant grant) =>
            new(
                SidecarExchangeKind.ActionHook,
                Guid.NewGuid(),
                Guid.NewGuid(),
                SidecarProtocolPhase.Invoking,
                LastSequence: 1,
                now.AddMinutes(1),
                NegotiatedProtocolVersion: 1,
                HostLimits: new SidecarPayloadLimits(),
                ActionKey: key,
                ActionVersion: grant.ActionVersion,
                ActionGrant: grant,
                HostAuthorization: new SidecarHostAuthorization("module-a", [grant], []));

        var inspectOnly = new ActionCapabilityGrant(key, 1, ActionInterceptionCapabilities.Inspect);
        Assert.False(SidecarProtocolStateMachine.CanApply(
            State(now, key, inspectOnly),
            new SidecarEffectRequest(Header(2), Guid.Empty, SidecarContinuationCommand.ContinueOriginal)));

        var observeOnly = new ActionCapabilityGrant(key, 1, ActionInterceptionCapabilities.Observe);
        Assert.False(SidecarProtocolStateMachine.CanApply(
            State(now, key, observeOnly),
            new SidecarEffectRequest(Header(2), Guid.Empty, SidecarContinuationCommand.ContinueOriginal)));

        var wrapping = new ActionCapabilityGrant(
            key,
            1,
            ActionInterceptionCapabilities.Inspect | ActionInterceptionCapabilities.Wrap);
        var wrappingState = State(now, key, wrapping);
        Assert.True(SidecarProtocolStateMachine.CanApply(
            wrappingState,
            new SidecarEffectRequest(Header(2), wrappingState.ContinuationHandleId, SidecarContinuationCommand.ContinueOriginal)));

        var wrappingReplacement = wrapping with
        {
            Capabilities = wrapping.Capabilities | ActionInterceptionCapabilities.ReplaceInput,
        };
        var replacementState = State(now, key, wrappingReplacement);
        Assert.True(SidecarProtocolStateMachine.CanApply(
            replacementState,
            new SidecarEffectRequest(
                Header(2),
                replacementState.ContinuationHandleId,
                SidecarContinuationCommand.ContinueReplacement,
                CreateElement(new { value = 2 }),
                Reason: "replace input")));

        var malformedReplacement = SidecarProtocolStateMachine.Validate(
            replacementState,
            new SidecarEffectRequest(
                Header(2),
                replacementState.ContinuationHandleId,
                SidecarContinuationCommand.ContinueReplacement),
            now);
        Assert.False(malformedReplacement.Accepted);
        Assert.Equal(SidecarProtocolErrors.MalformedMessage, malformedReplacement.ErrorCode);

        var malformedOriginal = SidecarProtocolStateMachine.Validate(
            wrappingState,
            new SidecarEffectRequest(
                Header(2),
                wrappingState.ContinuationHandleId,
                SidecarContinuationCommand.ContinueOriginal,
                CreateElement(new { value = 2 })),
            now);
        Assert.False(malformedOriginal.Accepted);
        Assert.Equal(SidecarProtocolErrors.MalformedMessage, malformedOriginal.ErrorCode);
    }

    [Fact]
    public void SidecarRuntimeGrantsMatchCompiledAuthorizationAndSchemaSecurity()
    {
        var now = DateTimeOffset.UtcNow;
        var actionKey = new SharpClawActionKey("demo.action");
        var actionCapabilities = ActionInterceptionCapabilities.Inspect | ActionInterceptionCapabilities.Wrap;

        static UntypedActionDescriptor ActionDescriptor(
            SharpClawActionKey key,
            bool sensitive,
            bool acceptsUnknown) =>
            new(
                key,
                1,
                "demo",
                ActionInterceptionCapabilities.Inspect | ActionInterceptionCapabilities.Wrap,
                new JsonSchemaReference("demo.input", 1, "input-hash"),
                new JsonSchemaReference("demo.result", 1, "result-hash"),
                sensitive)
            {
                AcceptsUnknownNonSensitiveSchemas = acceptsUnknown,
            };

        static SidecarProtocolState ActionState(
            DateTimeOffset now,
            ActionCapabilityGrant grant) =>
            new(
                SidecarExchangeKind.ActionHook,
                Guid.Empty,
                Guid.Empty,
                SidecarProtocolPhase.Negotiated,
                LastSequence: 0,
                now.AddMinutes(1),
                NegotiatedProtocolVersion: 1,
                HostLimits: new SidecarPayloadLimits(),
                HostAuthorization: new SidecarHostAuthorization("module-a", [grant], []));

        HookInvokeStart ActionStart(
            UntypedActionDescriptor descriptor,
            ActionCapabilityGrant grant,
            long sequence = 1)
        {
            var invocationId = Guid.NewGuid();
            return new(
                Header(sequence),
                invocationId,
                null,
                Guid.NewGuid(),
                "action-hook",
                actionKey,
                1,
                SidecarPayloadMode.Untyped,
                CreateElement(new { value = 1 }),
                descriptor,
                grant,
                new RequestPrincipal("user-1"),
                ExtensionFeatureSet.Empty,
                new ContinuationHandle(Guid.NewGuid(), invocationId, "action-hook", now.AddMinutes(1), sequence));
        }

        var exactSensitiveDescriptor = ActionDescriptor(actionKey, sensitive: true, acceptsUnknown: false);
        var exactSensitiveGrant = new ActionCapabilityGrant(
            actionKey,
            1,
            actionCapabilities,
            SensitiveApproved: true);
        var exactStart = ActionStart(exactSensitiveDescriptor, exactSensitiveGrant);
        var exactResult = SidecarProtocolStateMachine.Validate(ActionState(now, exactSensitiveGrant), exactStart, now);
        Assert.True(exactResult.Accepted);

        var changedAuthorization = SidecarProtocolStateMachine.Validate(
            ActionState(now, exactSensitiveGrant),
            exactStart with
            {
                Header = Header(1),
                Grant = exactSensitiveGrant with { SensitiveApproved = false },
            },
            now);
        Assert.False(changedAuthorization.Accepted);
        Assert.Equal(SidecarProtocolErrors.UnsupportedCapability, changedAuthorization.ErrorCode);

        var broadSensitiveDescriptor = ActionDescriptor(actionKey, sensitive: true, acceptsUnknown: true);
        var broadSensitiveGrant = exactSensitiveGrant with { AcceptUnknownSchemas = true };
        var broadSensitive = SidecarProtocolStateMachine.Validate(
            ActionState(now, broadSensitiveGrant),
            ActionStart(broadSensitiveDescriptor, broadSensitiveGrant),
            now);
        Assert.False(broadSensitive.Accepted);
        Assert.Equal(SidecarProtocolErrors.ForgedApproval, broadSensitive.ErrorCode);

        var futureDescriptor = ActionDescriptor(actionKey, sensitive: false, acceptsUnknown: true);
        var futureGrant = new ActionCapabilityGrant(actionKey, 1, actionCapabilities, AcceptUnknownSchemas: true);
        var future = SidecarProtocolStateMachine.Validate(
            ActionState(now, futureGrant),
            ActionStart(futureDescriptor, futureGrant),
            now);
        Assert.True(future.Accepted);

        var disabledFutureGrant = futureGrant with { AcceptUnknownSchemas = false };
        var disabledFuture = SidecarProtocolStateMachine.Validate(
            ActionState(now, disabledFutureGrant),
            ActionStart(futureDescriptor, disabledFutureGrant),
            now);
        Assert.False(disabledFuture.Accepted);
        Assert.Equal(SidecarProtocolErrors.ForgedApproval, disabledFuture.ErrorCode);

        var eventKey = new SharpClawEventKey("demo.event");
        var eventCapabilities = EventInterceptionCapabilities.Inspect;

        static UntypedEventDescriptor EventDescriptor(
            SharpClawEventKey key,
            bool sensitive,
            bool acceptsUnknown) =>
            new(
                key,
                1,
                "demo",
                EventInterceptionCapabilities.Inspect,
                new JsonSchemaReference("demo.event", 1, "event-hash"),
                sensitive)
            {
                AcceptsUnknownNonSensitiveSchemas = acceptsUnknown,
            };

        EventInterceptStart EventStart(
            UntypedEventDescriptor descriptor,
            EventCapabilityGrant grant,
            long sequence = 1)
        {
            var envelope = new UntypedEventEnvelope(
                descriptor,
                Guid.NewGuid(),
                null,
                Guid.NewGuid(),
                now,
                "module-a",
                CreateElement(new { value = 1 }));
            return new(
                Header(sequence),
                "event-hook",
                envelope,
                grant,
                new ContinuationHandle(Guid.NewGuid(), Guid.NewGuid(), "event-hook", now.AddMinutes(1), sequence));
        }

        SidecarProtocolState EventState(
            EventCapabilityGrant grant) =>
            new(
                SidecarExchangeKind.EventIntercept,
                Guid.Empty,
                Guid.Empty,
                SidecarProtocolPhase.Negotiated,
                LastSequence: 0,
                now.AddMinutes(1),
                NegotiatedProtocolVersion: 1,
                HostLimits: new SidecarPayloadLimits(),
                HostAuthorization: new SidecarHostAuthorization("module-a", [], [grant]));

        var exactEventDescriptor = EventDescriptor(eventKey, sensitive: true, acceptsUnknown: false);
        var exactEventGrant = new EventCapabilityGrant(eventKey, 1, eventCapabilities, SensitiveApproved: true);
        Assert.True(SidecarProtocolStateMachine.Validate(
            EventState(exactEventGrant),
            EventStart(exactEventDescriptor, exactEventGrant),
            now).Accepted);

        var forgedEvent = exactEventGrant with { SensitiveApproved = false };
        var forgedEventResult = SidecarProtocolStateMachine.Validate(
            EventState(forgedEvent),
            EventStart(exactEventDescriptor, forgedEvent),
            now);
        Assert.False(forgedEventResult.Accepted);
        Assert.Equal(SidecarProtocolErrors.ForgedApproval, forgedEventResult.ErrorCode);

        var broadEventDescriptor = EventDescriptor(eventKey, sensitive: true, acceptsUnknown: true);
        var broadEventGrant = exactEventGrant with { AcceptUnknownSchemas = true };
        var broadEvent = SidecarProtocolStateMachine.Validate(
            EventState(broadEventGrant),
            EventStart(broadEventDescriptor, broadEventGrant),
            now);
        Assert.False(broadEvent.Accepted);
        Assert.Equal(SidecarProtocolErrors.ForgedApproval, broadEvent.ErrorCode);

        var futureEventDescriptor = EventDescriptor(eventKey, sensitive: false, acceptsUnknown: true);
        var futureEventGrant = new EventCapabilityGrant(eventKey, 1, eventCapabilities, AcceptUnknownSchemas: true);
        Assert.True(SidecarProtocolStateMachine.Validate(
            EventState(futureEventGrant),
            EventStart(futureEventDescriptor, futureEventGrant),
            now).Accepted);

        var disabledFutureEventGrant = futureEventGrant with { AcceptUnknownSchemas = false };
        var disabledFutureEvent = SidecarProtocolStateMachine.Validate(
            EventState(disabledFutureEventGrant),
            EventStart(futureEventDescriptor, disabledFutureEventGrant),
            now);
        Assert.False(disabledFutureEvent.Accepted);
        Assert.Equal(SidecarProtocolErrors.ForgedApproval, disabledFutureEvent.ErrorCode);
    }

    [Fact]
    public void SidecarEventOutcomesRejectContradictoryPayloadAndErrorShapes()
    {
        var now = DateTimeOffset.UtcNow;
        var descriptor = new UntypedEventDescriptor(
            new SharpClawEventKey("demo.event"),
            1,
            "demo",
            EventInterceptionCapabilities.Inspect | EventInterceptionCapabilities.Replace,
            new JsonSchemaReference("demo.event", 1, "event-hash"),
            ContainsSensitiveData: false);
        var grant = new EventCapabilityGrant(
            descriptor.Key,
            descriptor.Version,
            descriptor.Capabilities);
        var state = new SidecarProtocolState(
            SidecarExchangeKind.EventIntercept,
            Guid.NewGuid(),
            Guid.NewGuid(),
            SidecarProtocolPhase.Invoking,
            LastSequence: 1,
            now.AddMinutes(1),
            NegotiatedProtocolVersion: 1,
            HostLimits: new SidecarPayloadLimits(),
            EventDescriptor: descriptor,
            EventGrant: grant,
            EventKey: descriptor.Key,
            EventVersion: descriptor.Version,
            HostAuthorization: new SidecarHostAuthorization("module-a", [], [grant]));

        var continuedWithPayload = SidecarProtocolStateMachine.Validate(
            state,
            new EventInterceptOutcome(
                Header(2),
                state.ContinuationHandleId,
                descriptor.Key,
                descriptor.Version,
                descriptor.PayloadSchema,
                EventInterceptionKind.Continued,
                Payload: CreateElement(new { invalid = true })),
            now);
        Assert.False(continuedWithPayload.Accepted);
        Assert.Equal(SidecarProtocolErrors.MalformedMessage, continuedWithPayload.ErrorCode);

        var replacedWithoutPayload = SidecarProtocolStateMachine.Validate(
            state,
            new EventInterceptOutcome(
                Header(2),
                state.ContinuationHandleId,
                descriptor.Key,
                descriptor.Version,
                descriptor.PayloadSchema,
                EventInterceptionKind.Replaced),
            now);
        Assert.False(replacedWithoutPayload.Accepted);
        Assert.Equal(SidecarProtocolErrors.MalformedMessage, replacedWithoutPayload.ErrorCode);

        var failedWithoutError = SidecarProtocolStateMachine.Validate(
            state,
            new EventInterceptOutcome(
                Header(2),
                state.ContinuationHandleId,
                descriptor.Key,
                descriptor.Version,
                descriptor.PayloadSchema,
                EventInterceptionKind.Failed),
            now);
        Assert.False(failedWithoutError.Accepted);
        Assert.Equal(SidecarProtocolErrors.MalformedMessage, failedWithoutError.ErrorCode);
    }

    [Fact]
    public void StorageAtomicCommitRejectsIncompleteImmutableEventIdentity()
    {
        var commit = new ModuleStorageCommitIdentity(Guid.NewGuid(), "event-identity");
        var eventEnvelope = CreateStorageEvent("job-1");
        var request = new ModuleStorageMutationAndOutboxRequest(
            commit,
            [new ModuleStorageMutation(ModuleStorageOperations.Upsert, "job-1", CreateElement(new { value = 1 }))],
            [new ModuleStorageOutboxMessage(eventEnvelope, EventDelivery.Durable)]);
        var valid = new ModuleStorageMutationAndOutboxResult(
            commit,
            [new ModuleStorageRevision("job-1", 1)],
            ["outbox-1"],
            CommitRevision: 1);

        foreach (var candidate in new[]
        {
            eventEnvelope with { EventId = Guid.Empty },
            eventEnvelope with { TraceId = Guid.Empty },
            eventEnvelope with { OwnerModuleId = "" },
            eventEnvelope with { Payload = default },
            eventEnvelope with
            {
                Descriptor = eventEnvelope.Descriptor with
                {
                    PayloadSchema = eventEnvelope.Descriptor.PayloadSchema with { ContentHash = null },
                },
            },
        })
        {
            var failure = Assert.Throws<ModuleStorageContractException>(() =>
                ModuleStorageCommitValidation.Validate(
                    request with
                    {
                        Outbox = [new ModuleStorageOutboxMessage(candidate, EventDelivery.Durable)],
                    },
                    valid));
            Assert.Equal(ModuleStorageErrors.InvalidEventIdentity, failure.Failure.Code);
        }
    }

    [Fact]
    public void RetiredLookupCliTypesAreAbsent_and_canonical_jobs_types_are_present()
    {
        var names = typeof(ISharpClawModule).Assembly
            .GetTypes()
            .Select(type => type.FullName ?? type.Name)
            .ToArray();

        Assert.DoesNotContain(names, name => name.EndsWith("ModuleCliCommand", StringComparison.Ordinal));
        Assert.DoesNotContain(names, name => name.EndsWith("ModuleCliScope", StringComparison.Ordinal));
        Assert.DoesNotContain(names, name => name.EndsWith("JobsContracts", StringComparison.Ordinal));
        Assert.DoesNotContain(names, name => name.EndsWith("JobHandlerResult", StringComparison.Ordinal));
        Assert.Contains("SharpClaw.Contracts.Modules.JobDocument", names);
        Assert.DoesNotContain(typeof(IModuleLifecycleManager).GetMethods(), method =>
            method.Name is "FindToolByName" or "IsToolPrefixRegistered");
        Assert.Contains(typeof(ICliContributionBuilder).GetMethods(), method =>
            method.GetParameters().Any(parameter => parameter.ParameterType == typeof(ModuleCliCommandDescriptor)));
    }

    [Fact]
    public void Jobs_contracts_preserve_typed_checkpoint_authority()
    {
        var invocationId = Guid.NewGuid();
        var checkpoint = new JobCheckpoint<int>(
            Guid.NewGuid(),
            Guid.NewGuid(),
            invocationId,
            Guid.NewGuid(),
            JobStatus.Queued,
            JobStatus.Running,
            JobSafePoint.BeforeTerminal,
            7,
            11);

        Assert.Equal(invocationId, checkpoint.InvocationId);
        Assert.Equal(JobStatus.Queued, checkpoint.CurrentStatus);
        Assert.Equal(JobSafePoint.BeforeTerminal, checkpoint.SafePoint);
        Assert.Equal(7, checkpoint.Value);

        var input = new JobActionInput<int>(7);
        var result = new JobActionResult<string>("complete");
        Assert.Equal(7, input.Value);
        Assert.Equal("complete", result.Value);

        var key = new SharpClawActionKey("jobs.sample");
        var repeat = new ActionRepeatPolicy(ActionRepeatKind.None, 1, TimeSpan.Zero, "jobs.sample");
        var before = new ActionDescriptor<JobCheckpoint<int>, JobCheckpoint<int>>(
            key,
            1,
            "jobs",
            ActionInterceptionCapabilities.Inspect | ActionInterceptionCapabilities.Wrap,
            true,
            false,
            repeat,
            null,
            TimeSpan.FromSeconds(1));
        var action = new ActionDescriptor<int, string>(
            key,
            1,
            "jobs",
            ActionInterceptionCapabilities.Inspect | ActionInterceptionCapabilities.Wrap,
            true,
            false,
            repeat,
            null,
            TimeSpan.FromSeconds(1));
        var after = new ActionDescriptor<JobCheckpoint<string>, JobCheckpoint<string>>(
            key,
            1,
            "jobs",
            ActionInterceptionCapabilities.Inspect | ActionInterceptionCapabilities.Wrap,
            true,
            false,
            repeat,
            null,
            TimeSpan.FromSeconds(1));
        var contract = new JobActionContract<int, string>(before, action, after);

        Assert.Same(before, contract.Before);
        Assert.Same(action, contract.Action);
        Assert.Same(after, contract.After);
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
            CreateHostActionEntryContext(
                new RequestPrincipal("user-1"),
                ExtensionFeatureSet.Empty,
                Guid.NewGuid(),
                 Guid.NewGuid(),
                 DateTimeOffset.UtcNow.AddMinutes(1),
                 DateTimeOffset.UtcNow,
                 new HostActionEntryLineage(
                     new SharpClawActionKey("tool.entry"),
                     1,
                     "tool-descriptor",
                     typeof(JsonElement).AssemblyQualifiedName!,
                     1,
                     "tool-schema",
                     "tool-payload",
                     1),
                 HostActionEntryIngress.Tool));
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

    private static UntypedEventEnvelope CreateStorageEvent(string key) =>
        new(
            new UntypedEventDescriptor(
                new SharpClawEventKey("storage.changed"),
                1,
                "storage",
                EventInterceptionCapabilities.Inspect,
                new JsonSchemaReference("storage.changed", 1, "storage-event-hash"),
                ContainsSensitiveData: false),
            Guid.NewGuid(),
            null,
            Guid.NewGuid(),
            DateTimeOffset.UtcNow,
            "module-a",
            CreateElement(new { key }));

    private static SidecarMessageHeader Header(long sequence = 1) =>
        new(1, sequence, DateTimeOffset.UtcNow.AddMinutes(1), new SidecarMessageSizeAuthority(128, 1024));

    private static DirectActionFixture CreateDirectActionFixture(
        DateTimeOffset now,
        string authorityName,
        SidecarPayloadMode payloadMode,
        SidecarHookTargetKind targetKind,
        bool acceptsUnknownSchemas = false,
        bool containsSensitiveData = false,
        ActionInterceptionCapabilities capabilities =
            ActionInterceptionCapabilities.Inspect | ActionInterceptionCapabilities.ReplaceResult,
        SidecarPayloadLimits? limits = null)
    {
        var actionKey = new SharpClawActionKey($"direct.{authorityName}");
        var category = targetKind == SidecarHookTargetKind.Category
            ? "direct.category"
            : "direct";
        var grant = new ActionCapabilityGrant(
            actionKey,
            1,
            capabilities,
            SensitiveApproved: containsSensitiveData,
            AcceptUnknownSchemas: acceptsUnknownSchemas);
        var descriptor = payloadMode == SidecarPayloadMode.Untyped
            ? new UntypedActionDescriptor(
                actionKey,
                1,
                category,
                capabilities,
                new JsonSchemaReference($"direct.{authorityName}.input", 1, "input-hash"),
                new JsonSchemaReference($"direct.{authorityName}.result", 1, "result-hash"),
                containsSensitiveData)
            {
                AcceptsUnknownNonSensitiveSchemas = acceptsUnknownSchemas,
                ProtocolVersionRange = ContractVersionRange.Exact(1),
            }
            : null;
        var invocationId = Guid.NewGuid();
        var traceId = Guid.NewGuid();
        var hookId = $"hook-{authorityName}";
        var continuation = new ContinuationHandle(
            Guid.NewGuid(),
            invocationId,
            hookId,
            now.AddMinutes(1),
            Sequence: 1);
        var wildcardApproval = targetKind == SidecarHookTargetKind.Wildcard && containsSensitiveData
            ? new SensitiveWildcardApproval(
                "module-a",
                new Dictionary<string, int>(StringComparer.Ordinal) { [actionKey.Value] = 1 },
                new Dictionary<string, int>(StringComparer.Ordinal))
            : null;
        var authorization = new SidecarHostAuthorization(
            "module-a",
            [grant],
            [],
            wildcardApproval);
        var state = new SidecarProtocolState(
            SidecarExchangeKind.ActionHook,
            invocationId,
            continuation.HandleId,
            SidecarProtocolPhase.Negotiated,
            LastSequence: 0,
            now.AddMinutes(1),
            NegotiatedProtocolVersion: 1,
            HostLimits: limits ?? new SidecarPayloadLimits(),
            ActionKey: actionKey,
            HookId: hookId,
            TraceId: traceId,
            ActionDescriptor: descriptor,
            ActionGrant: grant,
            ActionVersion: 1,
            HostAuthorization: authorization);
        var start = new HookInvokeStart(
            Header(1),
            invocationId,
            null,
            traceId,
            hookId,
            actionKey,
            1,
            payloadMode,
            CreateElement(new { value = 1 }),
            descriptor,
            grant,
            new RequestPrincipal("user-1"),
            ExtensionFeatureSet.Empty,
            continuation);

        return new DirectActionFixture(targetKind, state, start, grant, descriptor);
    }

    private sealed class StatefulCommitGateway : IModuleStorageGateway
    {
        private ModuleStorageMutationAndOutboxRequest? _committedRequest;
        private ModuleStorageMutationAndOutboxResult? _committedResult;

        public HashSet<Guid> CommittedEventIds { get; } = [];

        public IReadOnlyList<ModuleStorageContractDescriptor> ListContracts() => [];

        public Task<JsonElement> InvokeAsync(
            string moduleId,
            string storageName,
            string operation,
            JsonElement parameters,
            CancellationToken ct = default) =>
            throw new NotSupportedException();

        public Task<ModuleStorageMutationAndOutboxResult> CommitMutationAndOutboxAsync(
            string moduleId,
            string storageName,
            ModuleStorageMutationAndOutboxRequest request,
            CancellationToken ct = default)
        {
            if (_committedResult is not null)
            {
                if (_committedRequest!.Commit != request.Commit)
                    throw new ModuleStorageContractException(new ModuleStorageContractFailure(
                        ModuleStorageErrors.CommitIdentityConflict,
                        "The retry uses a different commit identity."));

                if (!SameExpectedRevisions(_committedRequest, request))
                    throw new ModuleStorageContractException(new ModuleStorageContractFailure(
                        ModuleStorageErrors.RevisionConflict,
                        "The retry uses a stale expected revision."));

                return Task.FromResult(_committedResult with { AlreadyCommitted = true });
            }

            _committedRequest = request;
            foreach (var item in request.Outbox)
                CommittedEventIds.Add(item.Event.EventId);

            _committedResult = new ModuleStorageMutationAndOutboxResult(
                request.Commit,
                request.Mutations
                    .Select(item => new ModuleStorageRevision(item.Key, (item.ExpectedRevision ?? 0) + 1))
                    .ToArray(),
                request.Outbox
                    .Select((_, index) => $"outbox-{index}")
                    .ToArray(),
                CommitRevision: request.Mutations.Select(item => item.ExpectedRevision ?? 0).DefaultIfEmpty().Max() + 1);

            throw new TimeoutException("The response was lost after the atomic commit.");
        }

        public Task<ModuleStorageClaimResult<T>> ClaimAsync<T>(
            string moduleId,
            string storageName,
            ModuleStorageClaimRequest request,
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

        private static bool SameExpectedRevisions(
            ModuleStorageMutationAndOutboxRequest left,
            ModuleStorageMutationAndOutboxRequest right) =>
            left.Mutations.Count == right.Mutations.Count &&
            left.Mutations.Zip(right.Mutations).All(pair =>
                string.Equals(pair.First.Key, pair.Second.Key, StringComparison.Ordinal) &&
                pair.First.ExpectedRevision == pair.Second.ExpectedRevision);
    }

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
            ModuleStorageClaimRequest request,
            CancellationToken ct = default)
        {
            var response = responseFactory(ModuleStorageOperations.Claim);
            var result = response.Deserialize<ModuleStorageClaimResult<T>>(
                new JsonSerializerOptions(JsonSerializerDefaults.Web));
            return Task.FromResult(result!);
        }

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

    private sealed record DirectActionFixture(
        SidecarHookTargetKind TargetKind,
        SidecarProtocolState State,
        HookInvokeStart Start,
        ActionCapabilityGrant Grant,
        UntypedActionDescriptor? Descriptor);
}
