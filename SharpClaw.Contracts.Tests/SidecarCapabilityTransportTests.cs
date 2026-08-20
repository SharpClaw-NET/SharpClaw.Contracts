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
        Assert.Equal(
            SidecarCapabilityTransportCodec.ComputeSha256(first),
            SidecarCapabilityTransportCodec.ComputeSha256(
                SidecarCapabilityTransportCodec.Serialize(roundTrip)));
        Assert.Equal(first, SidecarCapabilityTransportCodec.Serialize(roundTrip));

        var json = Encoding.UTF8.GetString(first);
        var withUnknown = Encoding.UTF8.GetBytes(json[..^1] + ",\"unexpected\":true}");
        Assert.Throws<JsonException>(() =>
            SidecarCapabilityTransportCodec.Deserialize<SidecarCapabilitySessionBinding>(withUnknown));
    }

    [Fact]
    public void Role_bearing_binding_round_trips_with_an_ordinal_canonical_fingerprint()
    {
        var roles = new HashSet<string>(StringComparer.Ordinal) { "writer", "reader" };
        var fixture = CreateFixture();
        var context = new HostActionEntryRequestContext(
            Guid.NewGuid(),
            "opaque-capability",
            HostActionEntryIngress.Cli,
            Guid.NewGuid(),
            fixture.Binding.RequestId,
            fixture.Binding.CancellationId,
            new RequestPrincipal("role-user", Roles: roles),
            ExtensionFeatureSet.Empty,
            Guid.NewGuid(),
            Guid.NewGuid(),
            fixture.Now.AddMinutes(1),
            fixture.Binding.ExpiresAt);
        var encoded = SidecarCapabilityTransportCodec.Serialize(context);
        var roundTrip = SidecarCapabilityTransportCodec.Deserialize<HostActionEntryRequestContext>(encoded);
        var reversed = SidecarCapabilityTransportCodec.Serialize(
            context with
            {
                Caller = context.Caller with
                {
                    Roles = new HashSet<string>(["reader", "writer"], StringComparer.Ordinal),
                },
            });

        Assert.NotNull(roundTrip.Caller.Roles);
        Assert.True(roundTrip.Caller.Roles.SetEquals(roles));
        Assert.Equal(encoded, SidecarCapabilityTransportCodec.Serialize(roundTrip));
        Assert.Equal(
            SidecarCapabilityTransportCodec.ComputeSha256(encoded),
            SidecarCapabilityTransportCodec.ComputeSha256(reversed));

        var nullRoles = SidecarCapabilityTransportCodec.Deserialize<RequestPrincipal>(
            SidecarCapabilityTransportCodec.Serialize(new RequestPrincipal("null-roles")));
        Assert.Null(nullRoles.Roles);

        var duplicateRoles = Encoding.UTF8.GetBytes(
            "{\"subjectId\":\"role-user\",\"displayName\":null,\"roles\":[\"reader\",\"reader\"],\"isAuthenticated\":true}");
        Assert.Throws<JsonException>(() =>
            SidecarCapabilityTransportCodec.Deserialize<RequestPrincipal>(duplicateRoles));
    }

    [Fact]
    public void Role_bearing_host_entry_requires_the_complete_caller_role_set()
    {
        var caller = new RequestPrincipal(
            "role-user",
            Roles: new HashSet<string>(["reader", "writer"], StringComparer.Ordinal));
        var fixture = CreateFixture();
        var descriptor = new ActionDescriptor<string, string>(
            new SharpClawActionKey("roles.action"),
            1,
            "roles",
            ActionInterceptionCapabilities.Inspect,
            ContainsSensitiveData: false,
            HasIrreversibleEffects: false,
            new ActionRepeatPolicy(ActionRepeatKind.None, 1, TimeSpan.Zero, "roles.action"),
            ContinuationPolicy: null,
            TimeSpan.FromSeconds(5))
        {
            InputSchema = new JsonSchemaReference("roles.input", 1, "roles-input"),
            ResultSchema = new JsonSchemaReference("roles.result", 1, "roles-result"),
        };
        var context = IssueContext(
            fixture,
            caller,
            HostActionEntryIngress.Cli,
            lineage: Lineage(descriptor, "input"));
        var call = fixture.Call with
        {
            Capability = SidecarCapabilityKind.Action,
            CallId = Guid.NewGuid(),
            ReplayNonce = "roles-entry",
        };
        var payload = Payload(typeof(string).AssemblyQualifiedName!, "input");
        ActivateContext(fixture, context);
        Assert.True(fixture.Session.BeginCall(
            call,
            SidecarCapabilityKind.Action,
            payload,
            payload.ByteLength,
            fixture.Now,
            context).Accepted);

        var request = new HostActionEntryRequest<string, string>(
            descriptor,
            "input",
            context);
        var issued = fixture.Session.IssueHostActionEntry(
            request,
            call.CallId,
            fixture.Now,
            authority => HostActionEntryAuthorityValidator.ComputeAuthorityHash(authority),
            out var transport);

        Assert.True(issued.Accepted);
        Assert.NotNull(transport);
        Assert.True(fixture.Session.ValidateHostActionEntry(
            transport!,
            fixture.Now,
            authority => authority.Proof == HostActionEntryAuthorityValidator.ComputeAuthorityHash(authority)).Accepted);

        var comparerSpoofedRequest = request with
        {
            Context = context with
            {
                Caller = caller with
                {
                    Roles = new HashSet<string>(["READER", "WRITER"], StringComparer.OrdinalIgnoreCase),
                },
            },
        };
        var comparerSpoofedIssue = fixture.Session.IssueHostActionEntry(
            comparerSpoofedRequest,
            call.CallId,
            fixture.Now,
            authority => HostActionEntryAuthorityValidator.ComputeAuthorityHash(authority),
            out var comparerSpoofedTransport);
        Assert.Equal(SidecarCapabilityErrors.SpoofedIdentity, comparerSpoofedIssue.Code);
        Assert.Null(comparerSpoofedTransport);

        var comparerSpoofedAuthority = transport!.Authority with
        {
            Caller = transport.Authority.Caller with
            {
                Roles = new HashSet<string>(["READER", "WRITER"], StringComparer.OrdinalIgnoreCase),
            },
        };
        comparerSpoofedAuthority = comparerSpoofedAuthority with
        {
            Proof = HostActionEntryAuthorityValidator.ComputeAuthorityHash(comparerSpoofedAuthority),
        };
        Assert.Equal(
            "host_action_spoofed_authority",
            fixture.Session.ValidateHostActionEntry(
                transport with { Authority = comparerSpoofedAuthority },
                fixture.Now,
                authority => authority.Proof == HostActionEntryAuthorityValidator.ComputeAuthorityHash(authority)).Code);

        foreach (var changedCaller in new[]
        {
            caller with { Roles = new HashSet<string>(["reader"], StringComparer.Ordinal) },
            caller with { Roles = new HashSet<string>(["reader", "writer", "admin"], StringComparer.Ordinal) },
            caller with { Roles = new HashSet<string>(["reader", "auditor"], StringComparer.Ordinal) },
        })
        {
            Assert.False(fixture.Session.ValidateHostActionEntry(
                transport! with { Request = request with { Context = context with { Caller = changedCaller } } },
                fixture.Now,
                authority => authority.Proof == HostActionEntryAuthorityValidator.ComputeAuthorityHash(authority)).Accepted);
        }
    }

    [Fact]
    public void Tool_handler_start_round_trips_and_binds_the_host_entry_context()
    {
        var fixture = CreateFixture();
        var context = IssueContext(
            fixture,
            new RequestPrincipal("tool-user", Roles: new HashSet<string>(["reader"], StringComparer.Ordinal)),
            HostActionEntryIngress.Tool,
            lineage: new HostActionEntryLineage(
                new SharpClawActionKey("tool.entry"),
                1,
                "tool-descriptor",
                typeof(JsonElement).AssemblyQualifiedName!,
                1,
                "action-input-schema",
                null,
                null));
        var limits = new SidecarPayloadLimits(1_048_576, 1_048_576, 1_048_576, 2_097_152, 512);
        var header = new SidecarMessageHeader(
            1,
            1,
            context.Deadline,
            new SidecarMessageSizeAuthority(1024, limits.ActionInputBytes));
        var start = new SidecarToolHandlerInvokeStart(
            header,
            context.InvocationId,
            "clock_now",
            "clock-handler",
            JsonSerializer.SerializeToElement(new { value = 1 }),
            new JsonSchemaReference("clock.input", 1, "tool-input-schema"),
            context.Caller,
            context);

        var encoded = SidecarCapabilityTransportCodec.Serialize(start);
        var roundTrip = SidecarCapabilityTransportCodec.Deserialize<SidecarToolHandlerInvokeStart>(encoded);

        Assert.Equal(encoded, SidecarCapabilityTransportCodec.Serialize(roundTrip));
        Assert.True(roundTrip.IsWellFormed(fixture.Now));
        Assert.Equal(context.CapabilityId, roundTrip.HostActionContext.CapabilityId);
        Assert.Equal(context.CancellationId, roundTrip.HostActionContext.CancellationId);

        var state = new SidecarProtocolState(
            SidecarExchangeKind.ToolHandler,
            Guid.Empty,
            Guid.Empty,
            SidecarProtocolPhase.Negotiated,
            0,
            context.Deadline,
            1,
            limits);
        var accepted = SidecarProtocolStateMachine.Validate(state, roundTrip, fixture.Now);
        Assert.True(accepted.Accepted, accepted.ErrorMessage);

        var missingContext = roundTrip with { HostActionContext = null! };
        Assert.False(missingContext.IsWellFormed(fixture.Now));
        var malformedInput = roundTrip with { Input = default };
        Assert.False(malformedInput.IsWellFormed(fixture.Now));
        var changedSchema = roundTrip with
        {
            InputSchema = roundTrip.InputSchema with { Version = 0 },
        };
        Assert.False(changedSchema.IsWellFormed(fixture.Now));
        var wrongInvocation = roundTrip with
        {
            InvocationId = Guid.NewGuid(),
        };
        Assert.False(wrongInvocation.IsWellFormed(fixture.Now));
        var wrongTool = roundTrip with
        {
            ToolName = "other-tool",
        };
        Assert.False(wrongTool.IsWellFormed(fixture.Now));
        var wrongCaller = roundTrip with
        {
            Caller = new RequestPrincipal("other-user"),
        };
        Assert.False(wrongCaller.IsWellFormed(fixture.Now));
        var wrongIngress = roundTrip with
        {
            HostActionContext = roundTrip.HostActionContext with
            {
                Ingress = HostActionEntryIngress.Cli,
            },
        };
        Assert.False(wrongIngress.IsWellFormed(fixture.Now));
        var wrongContribution = roundTrip with
        {
            HostActionContext = roundTrip.HostActionContext with
            {
                Contribution = roundTrip.HostActionContext.Contribution! with
                {
                    IngressBinding = new HostActionEntryIngressBinding(
                        HostActionEntryIngress.Tool,
                        "other-tool"),
                },
            },
        };
        Assert.False(wrongContribution.IsWellFormed(fixture.Now));

        var changedDescriptor = roundTrip.HostActionContext with
        {
            Contribution = roundTrip.HostActionContext.Contribution! with
            {
                Lineage = roundTrip.HostActionContext.Contribution.Lineage with
                {
                    ActionKey = new SharpClawActionKey("other.action"),
                },
            },
        };
        var changedDescriptorResult = SidecarProtocolStateMachine.Validate(
            accepted.State! with
            {
                Phase = SidecarProtocolPhase.Negotiated,
                LastSequence = 0,
                InvocationId = Guid.Empty,
                HandlerId = null,
                ToolName = null,
            },
            roundTrip with { HostActionContext = changedDescriptor },
            fixture.Now);
        Assert.False(changedDescriptorResult.Accepted);
        Assert.Equal(SidecarProtocolErrors.ExchangeIdentityMismatch, changedDescriptorResult.ErrorCode);

        var changedContextResult = SidecarProtocolStateMachine.Validate(
            accepted.State! with
            {
                Phase = SidecarProtocolPhase.Negotiated,
                LastSequence = 0,
                InvocationId = Guid.Empty,
                HandlerId = null,
                ToolName = null,
            },
            roundTrip with
            {
                Header = header with { Sequence = 1 },
                HostActionContext = roundTrip.HostActionContext with { TraceId = Guid.NewGuid() },
            },
            fixture.Now);
        Assert.False(changedContextResult.Accepted);
        Assert.Equal(SidecarProtocolErrors.ExchangeIdentityMismatch, changedContextResult.ErrorCode);

        var replay = SidecarProtocolStateMachine.Validate(
            accepted.State! with
            {
                Phase = SidecarProtocolPhase.Negotiated,
                LastSequence = 1,
                InvocationId = Guid.Empty,
                HandlerId = null,
                ToolName = null,
            },
            roundTrip,
            fixture.Now);
        Assert.False(replay.Accepted);
        Assert.Equal(SidecarProtocolErrors.InvalidSequence, replay.ErrorCode);

        var expired = roundTrip.HostActionContext with
        {
            Deadline = fixture.Now.AddSeconds(-1),
            ExpiresAt = fixture.Now,
        };
        var expiredResult = SidecarProtocolStateMachine.Validate(
            state,
            roundTrip with
            {
                Header = header with { Deadline = expired.Deadline },
                HostActionContext = expired,
            },
            fixture.Now);
        Assert.False(expiredResult.Accepted);
        Assert.Equal(SidecarProtocolErrors.DeadlineExceeded, expiredResult.ErrorCode);
    }

    [Fact]
    public void Tool_start_keeps_raw_tool_schema_separate_from_action_lineage()
    {
        var fixture = CreateFixture();
        var descriptor = new ActionDescriptor<string, string>(
            new SharpClawActionKey("agents.api.dispatch"),
            1,
            "agents",
            ActionInterceptionCapabilities.Inspect,
            ContainsSensitiveData: false,
            HasIrreversibleEffects: false,
            new ActionRepeatPolicy(ActionRepeatKind.None, 1, TimeSpan.Zero, "agents.api.dispatch"),
            ContinuationPolicy: null,
            TimeSpan.FromSeconds(5))
        {
            InputSchema = new JsonSchemaReference("agents.action.input", 1, "action-input-schema"),
            ResultSchema = new JsonSchemaReference("agents.action.result", 1, "action-result-schema"),
        };
        var context = IssueContext(
            fixture,
            new RequestPrincipal("tool-user"),
            HostActionEntryIngress.Tool,
            actionDeadline: fixture.Call.Deadline,
            lineage: Lineage(descriptor, "input"));
        var call = fixture.Call with
        {
            Capability = SidecarCapabilityKind.Action,
            CallId = Guid.NewGuid(),
            ReplayNonce = "tool-action-call",
        };
        var start = new SidecarToolHandlerInvokeStart(
            new SidecarMessageHeader(
                1,
                1,
                context.Deadline,
                new SidecarMessageSizeAuthority(1024, 1_048_576)),
            context.InvocationId,
            "clock_now",
            "clock-handler",
            JsonSerializer.SerializeToElement(new { timezone = "UTC" }),
            new JsonSchemaReference("clock.tool.input", 1, "tool-input-schema"),
            context.Caller,
            context);

        Assert.True(start.IsWellFormed(fixture.Now));

        var actionPayload = Payload(typeof(string).AssemblyQualifiedName!, "input");
        ActivateContext(fixture, context);
        Assert.True(fixture.Session.BeginCall(
            call,
            SidecarCapabilityKind.Action,
            actionPayload,
            actionPayload.ByteLength,
            fixture.Now,
            context).Accepted);

        var issued = fixture.Session.IssueHostActionEntry(
            new HostActionEntryRequest<string, string>(descriptor, "input", context),
            call.CallId,
            fixture.Now,
            authority => HostActionEntryAuthorityValidator.ComputeAuthorityHash(authority),
            out var transport);

        Assert.True(issued.Accepted, issued.Message);
        Assert.NotNull(transport);
        Assert.Equal("tool-input-schema", start.InputSchema.ContentHash);
        Assert.Equal("action-input-schema", context.Contribution!.Lineage.InputSchemaHash);
        Assert.Equal(actionPayload.ContentHash, transport!.Authority.ActionContentHash);
    }

    [Fact]
    public void All_ingress_carriers_round_trip_the_issued_context()
    {
        var fixture = CreateFixture();
        var endpointContext = IssueContext(
            fixture,
            new RequestPrincipal("endpoint"),
            HostActionEntryIngress.Endpoint);
        var cliContext = IssueContext(
            fixture,
            new RequestPrincipal("cli"),
            HostActionEntryIngress.Cli);
        var toolContext = IssueContext(
            fixture,
            new RequestPrincipal("tool"),
            HostActionEntryIngress.Tool);
        var crossModuleContext = IssueContext(
            fixture,
            new RequestPrincipal("cross-module"),
            HostActionEntryIngress.CrossModule);

        var endpoint = new HostEndpointInvocation(
            endpointContext.InvocationId,
            "/demo",
            endpointContext);
        var crossModule = new CrossModuleActionInvocation(
            crossModuleContext.InvocationId,
            "source.module",
            "target.module",
            crossModuleContext);
        var cli = new ModuleCliInvocation(
            cliContext.InvocationId,
            "demo",
            [],
            cliContext);
        var tool = new ToolInvocation(
            toolContext.InvocationId,
            null,
            "tool-call",
            "demo",
            JsonDocument.Parse("{}").RootElement.Clone(),
            toolContext);

        var endpointRoundTrip = SidecarCapabilityTransportCodec.Deserialize<HostEndpointInvocation>(
            SidecarCapabilityTransportCodec.Serialize(endpoint));
        var crossModuleRoundTrip = SidecarCapabilityTransportCodec.Deserialize<CrossModuleActionInvocation>(
            SidecarCapabilityTransportCodec.Serialize(crossModule));
        var cliRoundTrip = SidecarCapabilityTransportCodec.Deserialize<ModuleCliInvocation>(
            SidecarCapabilityTransportCodec.Serialize(cli));
        var toolRoundTrip = SidecarCapabilityTransportCodec.Deserialize<ToolInvocation>(
            SidecarCapabilityTransportCodec.Serialize(tool));

        Assert.True(endpointRoundTrip.IsWellFormed(fixture.Now));
        Assert.True(crossModuleRoundTrip.IsWellFormed(fixture.Now));
        Assert.Equal(HostActionEntryIngress.Cli, cliRoundTrip.HostActionContext.Ingress);
        Assert.Equal(HostActionEntryIngress.Tool, toolRoundTrip.HostActionContext.Ingress);
        Assert.Equal(endpointContext.CapabilityId, endpointRoundTrip.HostActionContext.CapabilityId);
        Assert.Equal(crossModuleContext.CapabilityId, crossModuleRoundTrip.HostActionContext.CapabilityId);
        Assert.False(endpointContext.Contribution!.Lineage.IsPayloadBound);
        Assert.False(cliContext.Contribution!.Lineage.IsPayloadBound);
        Assert.False(toolContext.Contribution!.Lineage.IsPayloadBound);
        Assert.False(crossModuleContext.Contribution!.Lineage.IsPayloadBound);
    }

    [Fact]
    public void Ingress_carriers_reject_changed_host_bound_identity()
    {
        var fixture = CreateFixture();
        var endpointContext = IssueContext(
            fixture,
            new RequestPrincipal("endpoint"),
            HostActionEntryIngress.Endpoint);
        var cliContext = IssueContext(
            fixture,
            new RequestPrincipal("cli"),
            HostActionEntryIngress.Cli);
        var toolContext = IssueContext(
            fixture,
            new RequestPrincipal("tool"),
            HostActionEntryIngress.Tool);
        var crossModuleContext = IssueContext(
            fixture,
            new RequestPrincipal("cross-module"),
            HostActionEntryIngress.CrossModule);

        Assert.False(new HostEndpointInvocation(
            endpointContext.InvocationId,
            "/other",
            endpointContext).IsWellFormed(fixture.Now));
        Assert.False(new ModuleCliInvocation(
            cliContext.InvocationId,
            "other",
            [],
            cliContext).IsWellFormed(fixture.Now));
        Assert.False(new ToolInvocation(
            toolContext.InvocationId,
            null,
            "tool-call",
            "other.tool",
            JsonDocument.Parse("{}").RootElement.Clone(),
            toolContext).IsWellFormed(fixture.Now));
        Assert.False(new CrossModuleActionInvocation(
            crossModuleContext.InvocationId,
            "other.source",
            "target.module",
            crossModuleContext).IsWellFormed(fixture.Now));
    }

    [Fact]
    public void Carrier_completion_revokes_cli_and_tool_contexts_and_rejects_replay()
    {
        var fixture = CreateFixture();
        var cliContext = IssueContext(
            fixture,
            new RequestPrincipal("cli"),
            HostActionEntryIngress.Cli);
        var cliAuthority = ActivateContext(fixture, cliContext);

        Assert.Equal(1, fixture.Session.ActiveHostActionEntryCarrierCount);
        Assert.True(fixture.Session.CompleteHostActionEntryCarrier(
            cliAuthority,
            HostActionEntryCarrierCompletionKind.Succeeded,
            fixture.Now).Accepted);
        Assert.Equal(0, fixture.Session.IssuedHostActionEntryContextCount);
        Assert.Equal(
            SidecarCapabilityErrors.Replay,
            fixture.Session.CompleteHostActionEntryCarrier(
                cliAuthority,
                HostActionEntryCarrierCompletionKind.Succeeded,
                fixture.Now).Code);

        var delayed = fixture.Session.BeginCall(
            fixture.Call with
            {
                Capability = SidecarCapabilityKind.Action,
                CallId = Guid.NewGuid(),
                ReplayNonce = "completed-carrier",
            },
            SidecarCapabilityKind.Action,
            Payload("entry.input", "delayed"),
            32,
            fixture.Now,
            cliContext);
        Assert.Equal(SidecarCapabilityErrors.SpoofedIdentity, delayed.Code);

        var toolContext = IssueContext(
            fixture,
            new RequestPrincipal("tool"),
            HostActionEntryIngress.Tool);
        var toolAuthority = ActivateContext(fixture, toolContext);
        Assert.True(fixture.Session.CompleteHostActionEntryCarrier(
            toolAuthority,
            HostActionEntryCarrierCompletionKind.Failed,
            fixture.Now).Accepted);
        Assert.Equal(0, fixture.Session.ActiveHostActionEntryCarrierCount);

        var cancelledContext = IssueContext(
            fixture,
            new RequestPrincipal("cancelled"),
            HostActionEntryIngress.Cli);
        var cancelledAuthority = ActivateContext(fixture, cancelledContext);
        Assert.True(fixture.Session.CompleteHostActionEntryCarrier(
            cancelledAuthority,
            HostActionEntryCarrierCompletionKind.Cancelled,
            fixture.Now).Accepted);
        Assert.Equal(0, fixture.Session.IssuedHostActionEntryContextCount);
    }

    [Fact]
    public void Carrier_completion_waits_for_the_active_host_entry_call()
    {
        var fixture = CreateFixture();
        var context = IssueContext(
            fixture,
            new RequestPrincipal("entry-user"),
            HostActionEntryIngress.Cli);
        var authority = ActivateContext(fixture, context);
        var call = fixture.Call with
        {
            Capability = SidecarCapabilityKind.Action,
            CallId = Guid.NewGuid(),
            ReplayNonce = "active-entry",
        };
        var payload = Payload(typeof(string).AssemblyQualifiedName!, "input");
        Assert.True(fixture.Session.BeginCall(
            call,
            SidecarCapabilityKind.Action,
            payload,
            payload.ByteLength,
            fixture.Now,
            context).Accepted);

        Assert.Equal(
            SidecarCapabilityErrors.InvalidBinding,
            fixture.Session.CompleteHostActionEntryCarrier(
                authority,
                HostActionEntryCarrierCompletionKind.Succeeded,
                fixture.Now).Code);
        Assert.True(fixture.Session.CompleteCall(call.CallId, 0).Accepted);
        Assert.True(fixture.Session.CompleteHostActionEntryCarrier(
            authority,
            HostActionEntryCarrierCompletionKind.Succeeded,
            fixture.Now).Accepted);
    }

    [Fact]
    public void Distinct_cli_and_tool_carriers_remain_isolated()
    {
        var fixture = CreateFixture();
        var cliContext = IssueContext(
            fixture,
            new RequestPrincipal("cli"),
            HostActionEntryIngress.Cli);
        var toolContext = IssueContext(
            fixture,
            new RequestPrincipal("tool"),
            HostActionEntryIngress.Tool);
        var cliAuthority = ActivateContext(fixture, cliContext);
        var toolAuthority = ActivateContext(fixture, toolContext);

        Assert.NotEqual(cliAuthority.CapabilityId, toolAuthority.CapabilityId);
        Assert.NotEqual(cliAuthority.Carrier.InvocationId, toolAuthority.Carrier.InvocationId);
        Assert.Equal(2, fixture.Session.ActiveHostActionEntryCarrierCount);

        Assert.True(fixture.Session.CompleteHostActionEntryCarrier(
            cliAuthority,
            HostActionEntryCarrierCompletionKind.Succeeded,
            fixture.Now).Accepted);
        Assert.True(fixture.Session.TryGetActiveHostActionEntryCarrier(
            toolAuthority.CapabilityId,
            out var activeTool));
        Assert.Equal(toolAuthority, activeTool);
        Assert.True(fixture.Session.CompleteHostActionEntryCarrier(
            toolAuthority,
            HostActionEntryCarrierCompletionKind.Cancelled,
            fixture.Now).Accepted);
    }

    [Fact]
    public void Active_carrier_authority_survives_binding_rotation()
    {
        var fixture = CreateFixture();
        var context = IssueContext(
            fixture,
            new RequestPrincipal("rotating"),
            HostActionEntryIngress.Tool);
        var authority = ActivateContext(fixture, context);
        var rotatedExpiry = fixture.Binding.ExpiresAt.AddMinutes(1);
        var rotated = fixture.Binding with
        {
            SessionId = Guid.NewGuid(),
            RequestId = Guid.NewGuid(),
            CancellationId = Guid.NewGuid(),
            ExpiresAt = rotatedExpiry,
            Grant = fixture.Binding.Grant with { ExpiresAt = rotatedExpiry },
            Authentication = fixture.Binding.Authentication with
            {
                Nonce = "rotation-nonce",
                ExpiresAt = rotatedExpiry,
                BindingHash = string.Empty,
            },
        };
        rotated = rotated with
        {
            Authentication = rotated.Authentication with
            {
                BindingHash = SidecarCapabilitySessionValidator.ComputeBindingHash(rotated),
            },
        };
        fixture.BindingHashes.Add(rotated.Authentication.BindingHash);

        Assert.True(fixture.Session.RotateBinding(rotated, fixture.Now).Accepted);
        Assert.Equal(2L, fixture.Session.BindingGeneration);
        Assert.True(fixture.Session.TryGetActiveHostActionEntryCarrier(
            authority.CapabilityId,
            out var active));
        Assert.Equal(authority, active);
        Assert.True(fixture.Session.CompleteHostActionEntryCarrier(
            authority,
            HostActionEntryCarrierCompletionKind.Succeeded,
            fixture.Now).Accepted);
    }

    [Fact]
    public void Rebind_advances_request_identity_resets_call_budget_and_preserves_active_carrier()
    {
        var fixture = CreateFixture(maxCalls: 1);
        var context = IssueContext(
            fixture,
            new RequestPrincipal("rebind-user"),
            HostActionEntryIngress.Cli);
        var authority = ActivateContext(fixture, context);
        var firstPayload = Payload("storage.request", new { value = 1 });
        Assert.True(fixture.Session.BeginCall(
            fixture.Call,
            SidecarCapabilityKind.Storage,
            firstPayload,
            firstPayload.ByteLength,
            fixture.Now).Accepted);

        var rotatedExpiry = fixture.Binding.ExpiresAt.AddMinutes(1);
        var rotated = fixture.Binding with
        {
            SessionId = Guid.NewGuid(),
            RequestId = Guid.NewGuid(),
            CancellationId = Guid.NewGuid(),
            ExpiresAt = rotatedExpiry,
            Grant = fixture.Binding.Grant with { ExpiresAt = rotatedExpiry },
            Authentication = fixture.Binding.Authentication with
            {
                Nonce = "rebind-nonce",
                ExpiresAt = rotatedExpiry,
                BindingHash = string.Empty,
            },
        };
        rotated = rotated with
        {
            Authentication = rotated.Authentication with
            {
                BindingHash = SidecarCapabilitySessionValidator.ComputeBindingHash(rotated),
            },
        };
        fixture.BindingHashes.Add(rotated.Authentication.BindingHash);

        Assert.Equal(
            SidecarCapabilityErrors.InvalidBinding,
            fixture.Session.RotateBinding(rotated, fixture.Now).Code);
        Assert.True(fixture.Session.CompleteCall(fixture.Call.CallId, 0).Accepted);
        Assert.True(fixture.Session.RotateBinding(rotated, fixture.Now).Accepted);
        Assert.Equal(rotated.SessionId, fixture.Session.Binding.SessionId);
        Assert.Equal(2L, fixture.Session.BindingGeneration);

        var nextCall = fixture.Call with
        {
            SessionId = rotated.SessionId,
            RequestId = rotated.RequestId,
            CancellationId = rotated.CancellationId,
            CallId = Guid.NewGuid(),
            ReplayNonce = "rebind-call",
            Sequence = 1,
            Capability = SidecarCapabilityKind.Action,
        };
        var nextPayload = Payload(typeof(string).AssemblyQualifiedName!, "after-rebind");
        Assert.True(fixture.Session.BeginCall(
            nextCall,
            SidecarCapabilityKind.Action,
            nextPayload,
            nextPayload.ByteLength,
            fixture.Now,
            context).Accepted);
        Assert.True(fixture.Session.CompleteCall(nextCall.CallId, 0).Accepted);
        Assert.True(fixture.Session.CompleteHostActionEntryCarrier(
            authority,
            HostActionEntryCarrierCompletionKind.Succeeded,
            fixture.Now).Accepted);
    }

    [Fact]
    public void Pending_context_blocks_rebind_and_remains_activatable()
    {
        var fixture = CreateFixture();
        var context = IssueContext(
            fixture,
            new RequestPrincipal("pending-rebind"),
            HostActionEntryIngress.Cli);
        var rotated = CreateRotatedBinding(fixture, "pending-rebind-nonce");
        fixture.BindingHashes.Add(rotated.Authentication.BindingHash);

        var result = fixture.Session.RotateBinding(rotated, fixture.Now);

        Assert.Equal(SidecarCapabilityErrors.InvalidBinding, result.Code);
        Assert.Equal(fixture.Binding.RequestId, fixture.Session.Binding.RequestId);
        Assert.Equal(1, fixture.Session.IssuedHostActionEntryContextCount);
        var authority = ActivateContext(fixture, context);
        Assert.True(fixture.Session.CompleteHostActionEntryCarrier(
            authority,
            HostActionEntryCarrierCompletionKind.Succeeded,
            fixture.Now).Accepted);
    }

    [Fact]
    public void Rebind_rejects_null_nested_authority_records_without_changing_binding()
    {
        var fixture = CreateFixture();
        var original = fixture.Session.Binding;
        var malformed = new[]
        {
            original with { Grant = null! },
            original with { PayloadLimits = null! },
            original with { ConcurrencyLimits = null! },
        };

        foreach (var replacement in malformed)
        {
            var result = fixture.Session.RotateBinding(replacement, fixture.Now);
            Assert.Equal(SidecarCapabilityErrors.InvalidBinding, result.Code);
            Assert.Equal(original, fixture.Session.Binding);
        }
    }

    [Fact]
    public void Rebind_rejects_action_result_limit_reduction_for_an_active_carrier()
    {
        var fixture = CreateFixture();
        var context = IssueContext(
            fixture,
            new RequestPrincipal("result-limit"),
            HostActionEntryIngress.Tool);
        _ = ActivateContext(fixture, context);
        var rotated = CreateRotatedBinding(
            fixture,
            "result-limit-nonce",
            fixture.Binding.PayloadLimits.ActionResultBytes - 1);
        fixture.BindingHashes.Add(rotated.Authentication.BindingHash);

        var result = fixture.Session.RotateBinding(rotated, fixture.Now);

        Assert.Equal(SidecarCapabilityErrors.InvalidBinding, result.Code);
        Assert.Equal(fixture.Binding.ExpiresAt, fixture.Session.Binding.ExpiresAt);
        Assert.Equal(
            fixture.Binding.PayloadLimits.ActionResultBytes,
            fixture.Session.Binding.PayloadLimits.ActionResultBytes);
    }

    [Fact]
    public void One_carrier_cannot_start_a_second_host_entry_call()
    {
        var fixture = CreateFixture();
        var context = IssueContext(
            fixture,
            new RequestPrincipal("single-use"),
            HostActionEntryIngress.Tool);
        var authority = ActivateContext(fixture, context);
        var first = fixture.Call with
        {
            Capability = SidecarCapabilityKind.Action,
            CallId = Guid.NewGuid(),
            ReplayNonce = "single-use-first",
        };
        var payload = Payload(typeof(string).AssemblyQualifiedName!, "first");
        Assert.True(fixture.Session.BeginCall(
            first,
            SidecarCapabilityKind.Action,
            payload,
            payload.ByteLength,
            fixture.Now,
            context).Accepted);
        Assert.True(fixture.Session.CompleteCall(first.CallId, 0).Accepted);

        var second = first with
        {
            CallId = Guid.NewGuid(),
            ReplayNonce = "single-use-second",
            Sequence = 2,
        };
        Assert.Equal(
            SidecarCapabilityErrors.Replay,
            fixture.Session.BeginCall(
                second,
                SidecarCapabilityKind.Action,
                payload,
                payload.ByteLength,
                fixture.Now,
                context).Code);
        Assert.True(fixture.Session.CompleteHostActionEntryCarrier(
            authority,
            HostActionEntryCarrierCompletionKind.Failed,
            fixture.Now).Accepted);
    }

    [Fact]
    public void Carrier_replay_tombstones_expire_after_their_required_lifetime()
    {
        var fixture = CreateFixture();
        var context = IssueContext(
            fixture,
            new RequestPrincipal("tombstone"),
            HostActionEntryIngress.Cli);
        var authority = ActivateContext(fixture, context);
        Assert.True(fixture.Session.CompleteHostActionEntryCarrier(
            authority,
            HostActionEntryCarrierCompletionKind.Succeeded,
            fixture.Now).Accepted);
        Assert.Equal(1, fixture.Session.CompletedHostActionEntryTombstoneCount);

        Assert.Equal(
            0,
            fixture.Session.SweepExpiredHostActionEntryCarriers(
                authority.ExpiresAt.AddSeconds(1)));
        Assert.Equal(0, fixture.Session.CompletedHostActionEntryTombstoneCount);
    }

    [Fact]
    public void Expired_carriers_are_swept_without_disconnect_and_cannot_replay()
    {
        var fixture = CreateFixture();
        var context = IssueContext(
            fixture,
            new RequestPrincipal("expired"),
            HostActionEntryIngress.Cli);
        var authority = ActivateContext(fixture, context);
        var afterExpiry = context.ExpiresAt.AddSeconds(1);

        Assert.Equal(1, fixture.Session.SweepExpiredHostActionEntryCarriers(afterExpiry));
        Assert.Equal(0, fixture.Session.IssuedHostActionEntryContextCount);
        Assert.Equal(0, fixture.Session.ActiveHostActionEntryCarrierCount);
        Assert.False(fixture.Session.TryGetActiveHostActionEntryCarrier(
            authority.CapabilityId,
            out _));
        Assert.Equal(
            SidecarCapabilityErrors.Replay,
            fixture.Session.CompleteHostActionEntryCarrier(
                authority,
                HostActionEntryCarrierCompletionKind.Succeeded,
                afterExpiry).Code);
        Assert.True(fixture.Session.BeginCall(
            fixture.Call with
            {
                Capability = SidecarCapabilityKind.Action,
                CallId = Guid.NewGuid(),
                ReplayNonce = "expired-carrier",
            },
            SidecarCapabilityKind.Action,
            Payload("entry.input", "expired"),
            32,
            afterExpiry,
            context).Code is SidecarCapabilityErrors.SpoofedIdentity or SidecarCapabilityErrors.Expired);
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
        Assert.Equal(
            SidecarCapabilityErrors.InvalidBinding,
            fixture.Session.RecordTerminal(
                fixture.Call.CallId,
                Guid.NewGuid(),
                new SidecarTerminalReceipt(
                    "storage-receipt",
                    new SharpClawActionKey("storage"),
                    1,
                    fixture.Call.CallId,
                    1,
                    "storage-scope",
                    "storage-hash")).Code);
        Assert.True(fixture.Session.CompleteCall(fixture.Call.CallId, 0).Accepted);

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
    public async Task Entry_contexts_are_distinct_single_use_and_bound_to_ingress_lifetime()
    {
        var fixture = CreateFixture();
        var contexts = await Task.WhenAll(
            Enum.GetValues<HostActionEntryIngress>().Select(ingress =>
                Task.Run(() => IssueContext(
                    fixture,
                    new RequestPrincipal($"caller-{ingress}"),
                    ingress))));

        Assert.Equal(contexts.Length, contexts.Select(context => context.CapabilityId).Distinct().Count());
        Assert.Equal(contexts.Length, contexts.Select(context => context.InvocationId).Distinct().Count());
        Assert.Equal(contexts.Length, contexts.Select(context => context.TraceId).Distinct().Count());
        Assert.Equal(contexts.Length, contexts.Select(context => context.IdempotencyKey).Distinct().Count());

        var firstCall = fixture.Call with
        {
            Capability = SidecarCapabilityKind.Action,
            CallId = Guid.NewGuid(),
            ReplayNonce = "entry-context-1",
            Sequence = 1,
        };
        var firstPayload = Payload(typeof(string).AssemblyQualifiedName!, "first");
        ActivateContext(fixture, contexts[0]);
        Assert.True(fixture.Session.BeginCall(
            firstCall,
            SidecarCapabilityKind.Action,
            firstPayload,
            firstPayload.ByteLength,
            fixture.Now,
            contexts[0]).Accepted);

        var wrongOwner = fixture.Session.BeginCall(
            firstCall with
            {
                CallId = Guid.NewGuid(),
                ReplayNonce = "entry-context-wrong-owner",
                Sequence = 2,
                ModuleId = "module-spoof",
            },
            SidecarCapabilityKind.Action,
            firstPayload,
            firstPayload.ByteLength,
            fixture.Now,
            contexts[1]);
        Assert.Equal(SidecarCapabilityErrors.SpoofedIdentity, wrongOwner.Code);

        var wrongGraph = fixture.Session.BeginCall(
            firstCall with
            {
                CallId = Guid.NewGuid(),
                ReplayNonce = "entry-context-wrong-graph",
                Sequence = 2,
                GraphId = "graph-spoof",
            },
            SidecarCapabilityKind.Action,
            firstPayload,
            firstPayload.ByteLength,
            fixture.Now,
            contexts[1]);
        Assert.Equal(SidecarCapabilityErrors.SpoofedIdentity, wrongGraph.Code);

        var replay = fixture.Session.BeginCall(
            firstCall with { ReplayNonce = "entry-context-replay", Sequence = 2 },
            SidecarCapabilityKind.Action,
            firstPayload,
            firstPayload.ByteLength,
            fixture.Now,
            contexts[0]);
        Assert.Equal(SidecarCapabilityErrors.Replay, replay.Code);

        var wrongIngress = contexts[1] with { Ingress = HostActionEntryIngress.Tool };
        var wrongIngressResult = fixture.Session.BeginCall(
            fixture.Call with
            {
                Capability = SidecarCapabilityKind.Action,
                CallId = Guid.NewGuid(),
                ReplayNonce = "entry-context-wrong-ingress",
                Sequence = 2,
            },
            SidecarCapabilityKind.Action,
            firstPayload,
            firstPayload.ByteLength,
            fixture.Now,
            wrongIngress);
        Assert.Equal(SidecarCapabilityErrors.SpoofedIdentity, wrongIngressResult.Code);

        var expired = contexts[2] with
        {
            Deadline = fixture.Now.AddSeconds(-1),
            ExpiresAt = fixture.Now.AddSeconds(-1),
        };
        var expiredResult = fixture.Session.BeginCall(
            fixture.Call with
            {
                Capability = SidecarCapabilityKind.Action,
                CallId = Guid.NewGuid(),
                ReplayNonce = "entry-context-expired",
                Sequence = 2,
            },
            SidecarCapabilityKind.Action,
            firstPayload,
            firstPayload.ByteLength,
            fixture.Now,
            expired);
        Assert.False(expiredResult.Accepted);

        fixture.Session.Disconnect();
        var disconnected = fixture.Session.BeginCall(
            fixture.Call with
            {
                Capability = SidecarCapabilityKind.Action,
                CallId = Guid.NewGuid(),
                ReplayNonce = "entry-context-disconnected",
                Sequence = 2,
            },
            SidecarCapabilityKind.Action,
            firstPayload,
            firstPayload.ByteLength,
            fixture.Now,
            contexts[3]);
        Assert.Equal(SidecarCapabilityErrors.Disconnected, disconnected.Code);
    }

    [Fact]
    public void Session_accepts_zero_or_one_terminal_for_action_completion()
    {
        var fixture = CreateFixture();
        var actionCall = fixture.Call with { Capability = SidecarCapabilityKind.Action };
        var action = Payload("sample.input", new { value = 1 });
        Assert.True(fixture.Session.BeginCall(actionCall, SidecarCapabilityKind.Action, action, action.ByteLength, fixture.Now).Accepted);
        Assert.True(fixture.Session.CompleteCall(actionCall.CallId, 0).Accepted);

        var terminalCall = actionCall with { CallId = Guid.NewGuid(), ReplayNonce = "terminal-nonce", Sequence = 2 };
        Assert.True(fixture.Session.BeginCall(terminalCall, SidecarCapabilityKind.Action, action, action.ByteLength, fixture.Now).Accepted);
        Assert.Equal(
            SidecarCapabilityErrors.TerminalAlreadyCalled,
            fixture.Session.CompleteCall(terminalCall.CallId, 1).Code);
        var authorityId = Guid.NewGuid();
        var terminalReceipt = new SidecarTerminalReceipt(
            "terminal-receipt",
            new SharpClawActionKey("sample.action"),
            1,
            terminalCall.CallId,
            1,
            "terminal-scope",
            "terminal-hash");
        Assert.True(fixture.Session.RecordTerminal(terminalCall.CallId, authorityId, terminalReceipt).Accepted);
        Assert.Equal(
            SidecarCapabilityErrors.TerminalAlreadyCalled,
            fixture.Session.RecordTerminal(terminalCall.CallId, authorityId, terminalReceipt).Code);
        Assert.True(fixture.Session.CompleteCall(terminalCall.CallId, 1).Accepted);
    }

    [Fact]
    public void Session_binds_host_action_entry_to_authenticated_call_and_payload()
    {
        var caller = new RequestPrincipal("user-1", Roles: new HashSet<string>(["reader"]));
        var traceId = Guid.NewGuid();
        var idempotencyKey = Guid.NewGuid();
        var fixture = CreateFixture();
        var now = fixture.Now;
        var descriptor = new ActionDescriptor<string, string>(
            new SharpClawActionKey("sample.action"),
            1,
            "sample",
            ActionInterceptionCapabilities.Inspect,
            ContainsSensitiveData: false,
            HasIrreversibleEffects: false,
            new ActionRepeatPolicy(ActionRepeatKind.None, 1, TimeSpan.Zero, "sample.action"),
            ContinuationPolicy: null,
            TimeSpan.FromSeconds(5))
        {
            InputSchema = new JsonSchemaReference("sample.action.input", 1, "sample-input-schema"),
            ResultSchema = new JsonSchemaReference("sample.action.result", 1, "sample-result-schema"),
        };
        var context = IssueContext(
            fixture,
            caller,
            HostActionEntryIngress.Endpoint,
            traceId,
            idempotencyKey,
            actionDeadline: fixture.Call.Deadline,
            lineage: Lineage(descriptor, "input"));
        var payload = Payload(typeof(string).AssemblyQualifiedName!, "input");
        var actionCall = fixture.Call with
        {
            Capability = SidecarCapabilityKind.Action,
            CallId = Guid.NewGuid(),
            ReplayNonce = "entry-nonce",
            Sequence = 1,
        };
        ActivateContext(fixture, context);
        Assert.True(fixture.Session.BeginCall(
            actionCall,
            SidecarCapabilityKind.Action,
            payload,
            payload.ByteLength,
            now,
            context).Accepted);

        var deadline = actionCall.Deadline;
        var authority = new HostActionEntryAuthority(
            fixture.Binding.ModuleId,
            fixture.Binding.GraphId,
            fixture.Binding.SessionId,
            fixture.Binding.RequestId,
            fixture.Binding.CancellationId,
            actionCall.CallId,
            actionCall.ReplayNonce,
            actionCall.Sequence,
            caller,
            ExtensionFeatureSet.Empty,
            traceId,
            idempotencyKey,
            descriptor.Key,
            descriptor.Version,
            descriptor.Category,
            typeof(string).AssemblyQualifiedName!,
            typeof(string).AssemblyQualifiedName!,
            HostActionEntryAuthorityValidator.ComputeDescriptorHash(descriptor),
            descriptor.InputSchema.ContentHash!,
            descriptor.InputSchema.Version,
            descriptor.ResultSchema.ContentHash!,
            descriptor.ResultSchema.Version,
            payload.ContentHash,
            payload.ByteLength,
            deadline,
            now.AddSeconds(-1),
            fixture.Binding.ExpiresAt,
            "")
        {
            Ingress = context.Ingress,
            InvocationId = context.InvocationId,
            CapabilityId = context.CapabilityId,
            CapabilityHandleHash = HostActionEntryAuthorityValidator.ComputeCapabilityHandleHash(
                context.CapabilityHandle),
        };
        authority = authority with
        {
            Proof = HostActionEntryAuthorityValidator.ComputeAuthorityHash(authority),
        };
        var request = new HostActionEntryRequest<string, string>(
            descriptor,
            "input",
            context);
        var transport = new HostActionEntryTransportRequest<string, string>(request, authority);

        Assert.True(fixture.Session.ValidateHostActionEntry(
            transport,
            now,
            candidate => candidate.Proof == HostActionEntryAuthorityValidator.ComputeAuthorityHash(candidate)).Accepted);
        var changedCallAuthority = authority with { ReplayNonce = "wrong-nonce" };
        changedCallAuthority = changedCallAuthority with
        {
            Proof = HostActionEntryAuthorityValidator.ComputeAuthorityHash(changedCallAuthority),
        };
        Assert.Equal(
            SidecarCapabilityErrors.SpoofedIdentity,
            fixture.Session.ValidateHostActionEntry(
                transport with { Authority = changedCallAuthority },
                now,
                candidate => candidate.Proof == HostActionEntryAuthorityValidator.ComputeAuthorityHash(candidate)).Code);
        Assert.False(fixture.Session.ValidateHostActionEntry(
                transport with
                {
                    Request = request with
                    {
                        Context = request.Context with
                        {
                            Caller = new RequestPrincipal("attacker"),
                        },
                    },
                },
            now,
            candidate => candidate.Proof == HostActionEntryAuthorityValidator.ComputeAuthorityHash(candidate)).Accepted);

        var otherDescriptor = descriptor with
        {
            Key = new SharpClawActionKey("other.action"),
        };
        var otherRequest = request with { Descriptor = otherDescriptor };
        Assert.Equal(
            SidecarCapabilityErrors.SpoofedIdentity,
            fixture.Session.IssueHostActionEntry(
                otherRequest,
                actionCall.CallId,
                now,
                authorityCandidate => HostActionEntryAuthorityValidator.ComputeAuthorityHash(authorityCandidate),
                out _).Code);

        var changedPayloadRequest = request with { Action = "changed" };
        Assert.Equal(
            SidecarCapabilityErrors.SpoofedIdentity,
            fixture.Session.IssueHostActionEntry(
                changedPayloadRequest,
                actionCall.CallId,
                now,
                authorityCandidate => HostActionEntryAuthorityValidator.ComputeAuthorityHash(authorityCandidate),
                out _).Code);

        Assert.True(fixture.Session.CompleteCall(actionCall.CallId, 0).Accepted);
        Assert.Equal(
            SidecarCapabilityErrors.SpoofedIdentity,
            fixture.Session.ValidateHostActionEntry(
                transport,
                now,
                candidate => candidate.Proof == HostActionEntryAuthorityValidator.ComputeAuthorityHash(candidate)).Code);
    }

    [Fact]
    public async Task Module_host_entry_request_uses_session_issued_authority_without_module_proof_access()
    {
        var now = new DateTimeOffset(2026, 8, 14, 12, 0, 0, TimeSpan.Zero);
        var caller = new RequestPrincipal("endpoint-user", Roles: new HashSet<string>(["reader"]));
        var fixture = CreateFixture();
        var descriptor = new ActionDescriptor<string, string>(
            new SharpClawActionKey("sample.nested"),
            1,
            "sample",
            ActionInterceptionCapabilities.Inspect,
            ContainsSensitiveData: false,
            HasIrreversibleEffects: false,
            new ActionRepeatPolicy(ActionRepeatKind.None, 1, TimeSpan.Zero, "sample.nested"),
            ContinuationPolicy: null,
            TimeSpan.FromSeconds(5))
        {
            InputSchema = new JsonSchemaReference("sample.nested.input", 1, "sample-nested-input"),
            ResultSchema = new JsonSchemaReference("sample.nested.result", 1, "sample-nested-result"),
        };
        var context = IssueContext(
            fixture,
            caller,
            HostActionEntryIngress.Endpoint,
            lineage: Lineage(descriptor, "input"));
        var call = fixture.Call with
        {
            Capability = SidecarCapabilityKind.Action,
            CallId = Guid.NewGuid(),
            ReplayNonce = "nested-entry-nonce",
            Sequence = 1,
        };
        var payload = Payload(typeof(string).AssemblyQualifiedName!, "input");
        ActivateContext(fixture, context);
        Assert.True(fixture.Session.BeginCall(
            call,
            SidecarCapabilityKind.Action,
            payload,
            payload.ByteLength,
            now,
            context).Accepted);

        var request = new HostActionEntryRequest<string, string>(
            descriptor,
            "input",
            context);
        var proxy = new SessionHostActionEntryProxy(fixture.Session, call.CallId, now);

        var outcome = await proxy.InvokeAsync(request);

        Assert.Equal(ActionOutcomeKind.Completed, outcome.Kind);
        Assert.True(proxy.AuthorityIssued);
        Assert.True(proxy.TransportValidated);
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
        var resultPayload = Payload("storage.result", new { revision = 4 });
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
        Assert.Equal(
            SidecarCapabilityErrors.InvalidResponse,
            SidecarCapabilityTransportValidation.ValidateStorageResponse(
                request,
                response with { ResultPayload = resultPayload with { TypeIdentity = "storage.other" } },
                fixture.Binding).Code);
        Assert.Equal(
            SidecarCapabilityErrors.InvalidResponse,
            SidecarCapabilityTransportValidation.ValidateStorageResponse(
                request,
                response with { ResultPayload = resultPayload with { SchemaVersion = 2 } },
                fixture.Binding).Code);
    }

    [Fact]
    public void Action_transport_validates_request_response_and_replacement_terminal_exchange()
    {
        var fixture = CreateFixture();
        var key = new SharpClawActionKey("sample.action");
        var snapshot = new ActionPipelineSnapshot("graph-hash", [new ActionCapabilityGrant(key, 1, ActionInterceptionCapabilities.Inspect)]);
        var descriptor = new SidecarActionDescriptorIdentity(
            key, 1, "sample", "sample.input", "input-schema-hash", 1, "sample.result", "result-schema-hash", 1, "descriptor-hash");
        var receipt = new SidecarTerminalReceipt("receipt-1", key, 1, fixture.Call.CallId, 1, "sample.scope", "receipt-hash");
        var replacement = Payload("sample.input", new { value = 2 });
        var replacementResult = Payload("sample.result", new { value = 2 });
        var request = new SidecarActionCapabilityRequest(
            fixture.Call with { Capability = SidecarCapabilityKind.Action },
            SidecarActionInvocationKind.RunRequired,
            descriptor,
            Payload("sample.input", new { value = 1 }),
            snapshot,
            new SidecarCancellationIdentity(fixture.Call.CancellationId, "cancel-authority-hash", fixture.Call.Deadline),
            new SidecarTerminalContinuationRequest(Guid.NewGuid(), true, replacementResult, receipt, fixture.Call.Deadline),
            fixture.Call.Deadline);
        var outcomePayload = Payload("sample.result", new { value = 3 });
        var outcome = new SidecarActionOutcomeEnvelope(
            ActionOutcomeKind.Completed,
            outcomePayload,
            null,
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
        var actionCall = fixture.Call with { Capability = SidecarCapabilityKind.Action };
        Assert.True(fixture.Session.BeginCall(actionCall, SidecarCapabilityKind.Action, request.Action, request.Action.ByteLength, fixture.Now).Accepted);
        Assert.True(fixture.Session.RecordTerminal(actionCall.CallId, Guid.NewGuid(), receipt).Accepted);
        Assert.True(SidecarCapabilityTransportValidation.ValidateActionResponse(request, response, fixture.Binding, fixture.Session).Accepted);
        Assert.Equal(
            SidecarCapabilityErrors.InvalidResponse,
            SidecarCapabilityTransportValidation.ValidateActionResponse(
                request,
                response with { Outcome = outcome with { Receipt = receipt with { Attempt = 2 } } },
                fixture.Binding,
                fixture.Session).Code);
        Assert.Equal(
            SidecarCapabilityErrors.InvalidResponse,
            SidecarCapabilityTransportValidation.ValidateActionResponse(
                request,
                response with
                {
                    Continuation = continuationResponse with
                    {
                        Outcome = outcome with { Receipt = receipt with { ContentHash = "nested-forged" } },
                    },
                },
                fixture.Binding,
                fixture.Session).Code);
        Assert.Equal(
            SidecarCapabilityErrors.InvalidResponse,
            SidecarCapabilityTransportValidation.ValidateActionResponse(
                request,
                response with
                {
                    Continuation = continuationResponse with
                    {
                        Outcome = outcome with { Result = outcomePayload with { SchemaVersion = 2 } },
                    },
                },
                fixture.Binding,
                fixture.Session).Code);

        var terminalCaller = new RequestPrincipal("terminal-caller", Roles: new HashSet<string>(["reader"]));
        var terminalFeatures = new ExtensionFeatureSet([]);
        var terminalContext = new SidecarActionTerminalExecutionContext(
            request.Call,
            request.Invocation,
            descriptor,
            replacement,
            snapshot,
            Guid.NewGuid(),
            null,
            0,
            1,
            terminalCaller,
            terminalFeatures,
            Guid.NewGuid(),
            Guid.NewGuid(),
            request.Cancellation,
            receipt,
            request.Deadline);
        var terminalAuthority = new SidecarHostTerminalAuthority(
            Guid.NewGuid(),
            fixture.Binding.SessionId,
            fixture.Binding.RequestId,
            fixture.Binding.CancellationId,
            request.Call.CallId,
            fixture.Binding.ModuleId,
            fixture.Binding.GraphId,
            request.Invocation,
            descriptor.Key,
            descriptor.Version,
            descriptor.DescriptorHash,
            replacement.TypeIdentity,
            replacement.SchemaVersion,
            replacement.ContentHash,
            replacement.ByteLength,
            receipt.ReceiptId,
            receipt.ActionKey,
            receipt.ActionVersion,
            receipt.CallId,
            receipt.Attempt,
            receipt.IdempotencyScope,
            receipt.ContentHash,
            request.Deadline,
            fixture.Now.AddMinutes(-1),
            request.Deadline,
            "host-proof")
        {
            SnapshotContentHash = SidecarCapabilityTransportCodec.ComputeSha256(
                SidecarCapabilityTransportCodec.Serialize(snapshot)),
            Caller = terminalCaller,
            Features = terminalFeatures,
            TraceId = terminalContext.TraceId,
            IdempotencyKey = terminalContext.IdempotencyKey,
            InvocationId = terminalContext.InvocationId,
            ParentInvocationId = terminalContext.ParentInvocationId,
            Depth = terminalContext.Depth,
            Attempt = terminalContext.Attempt,
        };
        terminalAuthority = terminalAuthority with
        {
            CanonicalBindingHash = SidecarCapabilityTransportValidation.ComputeTerminalAuthorityBindingHash(terminalAuthority),
        };
        var terminalRequest = new SidecarActionTerminalTransportRequest(
            request.Call,
            request.Invocation,
            descriptor,
            replacement,
            terminalAuthority,
            receipt,
            request.Cancellation,
            request.Deadline)
        {
            Context = terminalContext,
        };
        var terminalResponse = new SidecarActionTerminalTransportResponse(
            resultIdentity,
            new SidecarTerminalExecutionResult(outcomePayload, null, true),
            receipt,
            fixture.SafeFailure)
        {
            TerminalId = terminalRequest.TerminalId,
        };
        Assert.True(SidecarCapabilityTransportValidation.ValidateActionTerminalRequest(
            request,
            terminalRequest,
            fixture.Binding,
            fixture.Now,
            (authority, bindingHash) => authority.Proof == "host-proof" &&
                bindingHash == SidecarCapabilityTransportValidation.ComputeTerminalAuthorityBindingHash(authority)).Accepted);
        Assert.True(SidecarCapabilityTransportValidation.ValidateActionTerminalResponse(terminalRequest, terminalResponse, fixture.Binding).Accepted);
        Assert.True(SidecarCapabilityTransportValidation.ValidateActionTerminalResponse(
            terminalRequest,
            terminalResponse with
            {
                ResultIdentity = null,
                Execution = new SidecarTerminalExecutionResult(null, fixture.SafeFailure, true),
            },
            fixture.Binding).Accepted);
        Assert.Equal(
            SidecarCapabilityErrors.SpoofedIdentity,
            SidecarCapabilityTransportValidation.ValidateActionTerminalRequest(
                request,
                terminalRequest with
                {
                    Descriptor = descriptor with { Key = new SharpClawActionKey("other.action") },
                    Receipt = receipt with { ActionKey = new SharpClawActionKey("other.action") },
                },
                fixture.Binding,
                fixture.Now,
                (_, _) => true).Code);

        Assert.Equal(
            SidecarCapabilityErrors.InvalidPayload,
            SidecarCapabilityTransportValidation.ValidateActionRequest(
                request with
                {
                    Continuation = request.Continuation with { ReplacementResult = replacement },
                },
                fixture.Binding,
                fixture.Now).Code);

        Assert.Equal(
            SidecarCapabilityErrors.InvalidResponse,
            SidecarCapabilityTransportValidation.ValidateActionTerminalResponse(
                terminalRequest,
                terminalResponse with
                {
                    ResultIdentity = null,
                    Execution = new SidecarTerminalExecutionResult(null, null, true),
                },
                fixture.Binding).Code);
        Assert.Equal(
            SidecarCapabilityErrors.SpoofedIdentity,
            SidecarCapabilityTransportValidation.ValidateActionTerminalRequest(
                request,
                terminalRequest with { Receipt = receipt with { ReceiptId = "forged-receipt" } },
                fixture.Binding,
                fixture.Now,
                (_, _) => true).Code);

        Assert.Equal(
            SidecarCapabilityErrors.SpoofedIdentity,
            SidecarCapabilityTransportValidation.ValidateActionTerminalRequest(
                request,
                terminalRequest with { EffectiveAction = replacement with { TypeIdentity = "other.input" } },
                fixture.Binding,
                fixture.Now,
                (_, _) => true).Code);
        Assert.Equal(
            SidecarCapabilityErrors.SpoofedIdentity,
            SidecarCapabilityTransportValidation.ValidateActionTerminalRequest(
                request,
                terminalRequest with { EffectiveAction = replacement with { SchemaVersion = 2 } },
                fixture.Binding,
                fixture.Now,
                (_, _) => true).Code);
        Assert.Equal(
            SidecarCapabilityErrors.SpoofedIdentity,
            SidecarCapabilityTransportValidation.ValidateActionTerminalRequest(
                request,
                terminalRequest with { Receipt = receipt with { Attempt = 2 } },
                fixture.Binding,
                fixture.Now,
                (_, _) => true).Code);
        Assert.Equal(
            SidecarCapabilityErrors.SpoofedIdentity,
            SidecarCapabilityTransportValidation.ValidateActionTerminalRequest(
                request,
                terminalRequest with { Receipt = receipt with { IdempotencyScope = "other.scope" } },
                fixture.Binding,
                fixture.Now,
                (_, _) => true).Code);
        Assert.Equal(
            SidecarCapabilityErrors.SpoofedIdentity,
            SidecarCapabilityTransportValidation.ValidateActionTerminalRequest(
                request,
                terminalRequest with { Receipt = receipt with { ContentHash = "other-receipt-hash" } },
                fixture.Binding,
                fixture.Now,
                (_, _) => true).Code);

        Assert.Equal(
            SidecarCapabilityErrors.InvalidPayload,
            SidecarCapabilityTransportValidation.ValidateActionRequest(
                request with { Action = request.Action with { SchemaVersion = 2 } },
                fixture.Binding,
                fixture.Now).Code);
        Assert.Equal(
            SidecarCapabilityErrors.InvalidPayload,
            SidecarCapabilityTransportValidation.ValidateActionRequest(
                request with
                {
                    Continuation = request.Continuation with
                    {
                        ReplacementResult = replacementResult with { SchemaVersion = 2 },
                    },
                },
                fixture.Binding,
                fixture.Now).Code);
        Assert.Equal(
            SidecarCapabilityErrors.InvalidResponse,
            SidecarCapabilityTransportValidation.ValidateActionResponse(
                request,
                response with
                {
                    Outcome = outcome with { Result = outcomePayload with { SchemaVersion = 2 } },
                },
                fixture.Binding,
                fixture.Session).Code);
        Assert.Equal(
            SidecarCapabilityErrors.InvalidResponse,
            SidecarCapabilityTransportValidation.ValidateActionTerminalResponse(
                terminalRequest,
                terminalResponse with
                {
                    Execution = new SidecarTerminalExecutionResult(
                        outcomePayload with { SchemaVersion = 2 },
                        null,
                        true),
                },
                fixture.Binding).Code);
        var wrongTerminalResult = Payload("wrong.result", new { value = 5 });
        Assert.Equal(
            SidecarCapabilityErrors.InvalidResponse,
            SidecarCapabilityTransportValidation.ValidateActionTerminalResponse(
                terminalRequest,
                terminalResponse with
                {
                    ResultIdentity = resultIdentity with
                    {
                        ResultTypeIdentity = "wrong.result",
                        ContentHash = wrongTerminalResult.ContentHash,
                    },
                    Execution = new SidecarTerminalExecutionResult(wrongTerminalResult, null, true),
                },
                fixture.Binding).Code);
        Assert.Equal(
            SidecarCapabilityErrors.InvalidResponse,
            SidecarCapabilityTransportValidation.ValidateActionTerminalResponse(
                terminalRequest,
                terminalResponse with
                {
                    ResultIdentity = resultIdentity,
                    Execution = new SidecarTerminalExecutionResult(null, fixture.SafeFailure, true),
                },
                fixture.Binding).Code);

        Assert.Equal(
            SidecarCapabilityErrors.TerminalAlreadyCalled,
            fixture.Session.RecordTerminal(actionCall.CallId, terminalRequest.Authority.AuthorityId, receipt).Code);
        Assert.Equal(
            SidecarCapabilityErrors.TerminalAlreadyCalled,
            fixture.Session.RecordTerminal(actionCall.CallId, terminalRequest.Authority.AuthorityId, receipt).Code);
        Assert.True(fixture.Session.CompleteCall(actionCall.CallId, 1).Accepted);
        Assert.Equal("sample.input", terminalRequest.EffectiveAction.TypeIdentity);
        Assert.NotEqual(request.Action.Value.GetProperty("value").GetInt32(), terminalRequest.EffectiveAction.Value.GetProperty("value").GetInt32());

        var zeroRequest = request with { Continuation = null };
        var zeroOutcome = outcome with { Receipt = null, TerminalCallCount = 0 };
        Assert.True(SidecarCapabilityTransportValidation.ValidateActionResponse(
            zeroRequest,
            response with { ResultIdentity = resultIdentity, Outcome = zeroOutcome, Continuation = null },
            fixture.Binding,
            fixture.Session).Accepted);
        Assert.True(SidecarCapabilityTransportValidation.ValidateActionResponse(
            zeroRequest,
            response with
            {
                ResultIdentity = null,
                Outcome = zeroOutcome with
                {
                    Kind = ActionOutcomeKind.Cancelled,
                    Result = null,
                    Error = new ExecutionError("cancelled", "Cancelled."),
                },
                Continuation = null,
            },
            fixture.Binding,
            fixture.Session).Accepted);
        Assert.True(SidecarCapabilityTransportValidation.ValidateActionResponse(
            zeroRequest,
            response with
            {
                ResultIdentity = null,
                Outcome = zeroOutcome with
                {
                    Kind = ActionOutcomeKind.Deferred,
                    Result = null,
                    Continuation = new ContinuationToken(Guid.NewGuid(), "defer-secret"),
                    Error = null,
                },
                Continuation = null,
            },
            fixture.Binding,
            fixture.Session).Accepted);
        Assert.True(SidecarCapabilityTransportValidation.ValidateActionResponse(
            zeroRequest,
            response with
            {
                ResultIdentity = null,
                Outcome = zeroOutcome with
                {
                    Kind = ActionOutcomeKind.Failed,
                    Result = null,
                    Error = new ExecutionError("failed", "Failed."),
                },
                Continuation = null,
            },
            fixture.Binding,
            fixture.Session).Accepted);
        Assert.True(SidecarCapabilityTransportValidation.ValidateActionResponse(
            zeroRequest,
            response with
            {
                ResultIdentity = null,
                Outcome = zeroOutcome with
                {
                    Kind = ActionOutcomeKind.Uncertain,
                    Result = null,
                    Error = null,
                    Uncertainty = new ActionUncertainty(
                        "uncertain",
                        "Uncertain.",
                        ActionExecutionStage.BeforeContinuation,
                        null,
                        new ActionRecoveryReference(Guid.NewGuid(), key, 1, Guid.NewGuid()),
                        fixture.Now),
                },
                Continuation = null,
            },
            fixture.Binding,
            fixture.Session).Accepted);

        var nestedInvalid = response with
        {
            Continuation = response.Continuation! with
            {
                Outcome = response.Outcome with { Result = Payload("wrong.result", new { value = 4 }) },
            },
        };
        Assert.Equal(
            SidecarCapabilityErrors.InvalidResponse,
            SidecarCapabilityTransportValidation.ValidateActionResponse(request, nestedInvalid, fixture.Binding, fixture.Session).Code);
    }

    [Fact]
    public void Action_response_rejects_wrong_call_descriptor_result_and_safe_failure_bindings()
    {
        var fixture = CreateFixture();
        var key = new SharpClawActionKey("sample.action");
        var descriptor = new SidecarActionDescriptorIdentity(key, 1, "sample", "sample.input", "input", 1, "sample.result", "result", 1, "descriptor");
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
            SidecarCapabilityTransportValidation.ValidateActionResponse(request, response, fixture.Binding, fixture.Session).Code);
        Assert.Equal(
            SidecarCapabilityErrors.InvalidResponse,
            SidecarCapabilityTransportValidation.ValidateActionResponse(
                request,
                response with { ResultIdentity = response.ResultIdentity! with { CallId = fixture.Call.CallId, ActionKey = new SharpClawActionKey("other.action") } },
                fixture.Binding,
                fixture.Session).Code);

        var tamperedResult = response with
        {
            ResultIdentity = response.ResultIdentity! with { CallId = fixture.Call.CallId, ContentHash = "forged" },
            Outcome = response.Outcome with
            {
                Result = response.Outcome.Result! with { ContentHash = "forged" },
            },
        };
        Assert.Equal(
            SidecarCapabilityErrors.InvalidResponse,
            SidecarCapabilityTransportValidation.ValidateActionResponse(request, tamperedResult, fixture.Binding, fixture.Session).Code);
    }

    [Fact]
    public void Action_response_uses_recorded_duplex_receipt_when_request_has_no_receipt()
    {
        var fixture = CreateFixture();
        var key = new SharpClawActionKey("duplex.action");
        var descriptor = new SidecarActionDescriptorIdentity(
            key,
            1,
            "duplex",
            "duplex.input",
            "input-schema",
            1,
            "duplex.result",
            "result-schema",
            1,
            "duplex-descriptor");
        var call = fixture.Call with { Capability = SidecarCapabilityKind.Action };
        var action = Payload("duplex.input", new { value = 1 });
        var request = new SidecarActionCapabilityRequest(
            call,
            SidecarActionInvocationKind.Run,
            descriptor,
            action,
            new ActionPipelineSnapshot("duplex-graph", []),
            new SidecarCancellationIdentity(call.CancellationId, "duplex-cancel", call.Deadline),
            null,
            call.Deadline);
        var result = Payload("duplex.result", new { value = 2 });
        var receipt = new SidecarTerminalReceipt(
            "duplex-receipt",
            key,
            1,
            call.CallId,
            1,
            "duplex-scope",
            "duplex-receipt-hash");
        var outcome = new SidecarActionOutcomeEnvelope(
            ActionOutcomeKind.Completed,
            result,
            null,
            null,
            null,
            receipt,
            fixture.SafeFailure,
            1);
        var response = new SidecarActionCapabilityResponse(
            new SidecarActionResultIdentity(Guid.NewGuid(), call.CallId, key, 1, "duplex.result", result.ContentHash),
            outcome,
            null,
            fixture.SafeFailure,
            true);

        Assert.Equal(
            SidecarCapabilityErrors.InvalidResponse,
            SidecarCapabilityTransportValidation.ValidateActionResponse(
                request,
                response,
                fixture.Binding,
                fixture.Session).Code);
        Assert.True(fixture.Session.BeginCall(call, SidecarCapabilityKind.Action, action, action.ByteLength, fixture.Now).Accepted);
        Assert.True(fixture.Session.RecordTerminal(call.CallId, Guid.NewGuid(), receipt).Accepted);
        Assert.True(SidecarCapabilityTransportValidation.ValidateActionResponse(request, response, fixture.Binding, fixture.Session).Accepted);
        Assert.Equal(
            SidecarCapabilityErrors.InvalidResponse,
            SidecarCapabilityTransportValidation.ValidateActionResponse(
                request,
                response with { Outcome = outcome with { Receipt = receipt with { IdempotencyScope = "forged-scope" } } },
                fixture.Binding,
                fixture.Session).Code);
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

    [Fact]
    public async Task Host_entry_uses_existing_action_exchange_without_module_snapshot()
    {
        var fixture = CreateFixture();
        var call = fixture.Call with { Capability = SidecarCapabilityKind.Action };
        var key = new SharpClawActionKey("host.entry");
        var descriptor = new SidecarActionDescriptorIdentity(
            key,
            1,
            "host",
            typeof(string).AssemblyQualifiedName!,
            "host-input",
            1,
            typeof(string).AssemblyQualifiedName!,
            "host-result",
            1,
            "host-descriptor");
        var context = IssueContext(
            fixture,
            new RequestPrincipal("host-user"),
            HostActionEntryIngress.Endpoint,
            actionDeadline: call.Deadline,
            lineage: new HostActionEntryLineage(
                key,
                descriptor.Version,
                descriptor.DescriptorHash,
                descriptor.InputTypeIdentity,
                descriptor.InputSchemaVersion,
                descriptor.InputSchemaHash,
                Payload(typeof(string).AssemblyQualifiedName!, "input").ContentHash,
                Payload(typeof(string).AssemblyQualifiedName!, "input").ByteLength));
        var request = SidecarActionCapabilityRequest.HostEntry(
            call,
            descriptor,
            Payload(typeof(string).AssemblyQualifiedName!, "input"),
            new SidecarCancellationIdentity(call.CancellationId, "host-cancel", call.Deadline),
            call.Deadline,
            context,
            new SidecarActionTerminalRegistration(
                Guid.NewGuid(),
                descriptor.InputTypeIdentity,
                descriptor.InputSchemaVersion,
                descriptor.ResultTypeIdentity,
                descriptor.ResultSchemaVersion,
                descriptor.DescriptorHash));
        var transport = new RecordingSidecarTransport(fixture.SafeFailure);

        var response = await transport.InvokeActionAsync(request);

        Assert.Equal(1, transport.ActionCalls);
        Assert.Equal(SidecarActionInvocationKind.HostEntry, transport.Request!.Invocation);
        Assert.Null(transport.Request.Snapshot);
        Assert.Equal(
            SidecarCapabilityErrors.InvalidPayload,
            SidecarCapabilityTransportValidation.ValidateActionRequest(
                transport.Request with { Snapshot = new ActionPipelineSnapshot("module-graph", []) },
                fixture.Binding,
                fixture.Now).Code);
        Assert.True(SidecarCapabilityTransportValidation.ValidateActionRequest(
            transport.Request,
            fixture.Binding,
            fixture.Now).Accepted);
        Assert.False(response.Completed);
    }

    [Fact]
    public async Task Host_action_entry_proxy_sends_typed_request_through_existing_transport()
    {
        var fixture = CreateFixture();
        var call = fixture.Call with
        {
            Capability = SidecarCapabilityKind.Action,
            CallId = Guid.NewGuid(),
            ReplayNonce = "proxy-host-entry",
        };
        var descriptor = new ActionDescriptor<string, string>(
            new SharpClawActionKey("proxy.host.entry"),
            1,
            "proxy",
            ActionInterceptionCapabilities.Inspect,
            ContainsSensitiveData: false,
            HasIrreversibleEffects: false,
            new ActionRepeatPolicy(ActionRepeatKind.None, 1, TimeSpan.Zero, "proxy.host.entry"),
            ContinuationPolicy: null,
            TimeSpan.FromSeconds(5))
        {
            InputSchema = new JsonSchemaReference("proxy.host.input", 1, "proxy-host-input"),
            ResultSchema = new JsonSchemaReference("proxy.host.result", 1, "proxy-host-result"),
        };
        var context = IssueContext(
            fixture,
            new RequestPrincipal("module-user"),
            HostActionEntryIngress.Endpoint,
            actionDeadline: call.Deadline,
            lineage: Lineage(descriptor, "input"));
        var moduleRequest = new HostActionEntryRequest<string, string>(
            descriptor,
            "input",
            context);
        var transport = new RecordingSidecarTransport(fixture.SafeFailure);
        var proxy = new TransportHostActionEntryProxy(transport, call);

        var outcome = await proxy.InvokeAsync(
            moduleRequest,
            new RecordingHostActionEntryTerminal<string, string>());

        Assert.Equal(ActionOutcomeKind.Cancelled, outcome.Kind);
        Assert.Equal(1, transport.ActionCalls);
        Assert.Equal(SidecarActionInvocationKind.HostEntry, transport.Request!.Invocation);
        Assert.Null(transport.Request.Snapshot);
    }

    [Fact]
    public void Host_entry_accepts_each_ingress_with_one_descriptor_bound_terminal()
    {
        var fixture = CreateFixture(maxCalls: 8);
        var ingresses = Enum.GetValues<HostActionEntryIngress>();

        for (var index = 0; index < ingresses.Length; index++)
        {
            var ingress = ingresses[index];
            var call = fixture.Call with
            {
                Capability = SidecarCapabilityKind.Action,
                CallId = Guid.NewGuid(),
                ReplayNonce = $"ingress-terminal-{index}",
                Sequence = index + 1,
            };
            var key = new SharpClawActionKey($"module.{ingress.ToString().ToLowerInvariant()}");
            var descriptor = new SidecarActionDescriptorIdentity(
                key,
                1,
                "module",
                typeof(string).AssemblyQualifiedName!,
                $"{key.Value}.input",
                1,
                typeof(string).AssemblyQualifiedName!,
                $"{key.Value}.result",
                1,
                $"{key.Value}.descriptor");
            var action = Payload(descriptor.InputTypeIdentity, $"input-{index}");
            var context = IssueContext(
                fixture,
                new RequestPrincipal($"caller-{index}"),
                ingress,
                actionDeadline: call.Deadline,
                lineage: new HostActionEntryLineage(
                    descriptor.Key,
                    descriptor.Version,
                    descriptor.DescriptorHash,
                    descriptor.InputTypeIdentity,
                    descriptor.InputSchemaVersion,
                    descriptor.InputSchemaHash,
                    null,
                    null));
            var request = SidecarActionCapabilityRequest.HostEntry(
                call,
                descriptor,
                action,
                new SidecarCancellationIdentity(call.CancellationId, $"cancel-{index}", call.Deadline),
                call.Deadline,
                context,
                new SidecarActionTerminalRegistration(
                    Guid.NewGuid(),
                    descriptor.InputTypeIdentity,
                    descriptor.InputSchemaVersion,
                    descriptor.ResultTypeIdentity,
                    descriptor.ResultSchemaVersion,
                    descriptor.DescriptorHash));

            Assert.True(SidecarCapabilityTransportValidation.ValidateActionRequest(
                request,
                fixture.Binding,
                fixture.Now).Accepted);
            var authority = ActivateContext(fixture, context);
            Assert.True(fixture.Session.BeginCall(
                call,
                SidecarCapabilityKind.Action,
                action,
                action.ByteLength,
                fixture.Now,
                context).Accepted);
            Assert.True(fixture.Session.CompleteCall(call.CallId, 0).Accepted);
            Assert.True(fixture.Session.CompleteHostActionEntryCarrier(
                authority,
                HostActionEntryCarrierCompletionKind.Succeeded,
                fixture.Now).Accepted);
        }
    }

    [Fact]
    public void Host_entry_terminal_rejects_missing_and_changed_authority()
    {
        var fixture = CreateFixture();
        var call = fixture.Call with
        {
            Capability = SidecarCapabilityKind.Action,
            CallId = Guid.NewGuid(),
            ReplayNonce = "terminal-authority",
        };
        var descriptor = new SidecarActionDescriptorIdentity(
            new SharpClawActionKey("module.terminal"),
            1,
            "module",
            typeof(string).AssemblyQualifiedName!,
            "terminal.input",
            1,
            typeof(string).AssemblyQualifiedName!,
            "terminal.result",
            1,
            "terminal.descriptor");
        var action = Payload(descriptor.InputTypeIdentity, "original");
        var context = IssueContext(
            fixture,
            new RequestPrincipal("terminal-caller", Roles: new HashSet<string>(["reader"])),
            HostActionEntryIngress.Tool,
            actionDeadline: call.Deadline,
            lineage: new HostActionEntryLineage(
                descriptor.Key,
                descriptor.Version,
                descriptor.DescriptorHash,
                descriptor.InputTypeIdentity,
                descriptor.InputSchemaVersion,
                descriptor.InputSchemaHash,
                null,
                null));
        var request = SidecarCapabilityTransportValidationRequest(
            call,
            descriptor,
            action,
            context);

        Assert.Equal(
            SidecarCapabilityErrors.InvalidPayload,
            SidecarCapabilityTransportValidation.ValidateActionRequest(
                request with { Terminal = null },
                fixture.Binding,
                fixture.Now).Code);

        var terminalRequest = CreateTerminalRequest(
            fixture,
            request,
            new ActionPipelineSnapshot("host-graph", []));
        Assert.True(SidecarCapabilityTransportValidation.ValidateActionTerminalRequest(
            request,
            terminalRequest,
            fixture.Binding,
            fixture.Now,
            (authority, bindingHash) => authority.Proof == "host-proof" &&
                bindingHash == SidecarCapabilityTransportValidation.ComputeTerminalAuthorityBindingHash(authority)).Accepted);
        var carrierAuthority = ActivateContext(fixture, context);
        Assert.True(fixture.Session.BeginCall(
            request.Call,
            SidecarCapabilityKind.Action,
            request.Action,
            request.Action.ByteLength,
            fixture.Now,
            context).Accepted);
        Assert.True(fixture.Session.RecordTerminal(
            request.Call.CallId,
            terminalRequest.Authority.AuthorityId,
            terminalRequest.Receipt).Accepted);
        Assert.Equal(
            SidecarCapabilityErrors.TerminalAlreadyCalled,
            fixture.Session.RecordTerminal(
                request.Call.CallId,
                terminalRequest.Authority.AuthorityId,
                terminalRequest.Receipt).Code);
        Assert.True(fixture.Session.CompleteCall(request.Call.CallId, 1).Accepted);
        Assert.True(fixture.Session.CompleteHostActionEntryCarrier(
            carrierAuthority,
            HostActionEntryCarrierCompletionKind.Succeeded,
            fixture.Now).Accepted);
        Assert.Equal(
            SidecarCapabilityErrors.SpoofedIdentity,
            SidecarCapabilityTransportValidation.ValidateActionTerminalRequest(
                request,
                terminalRequest with
                {
                    Context = terminalRequest.Context! with
                    {
                        Caller = new RequestPrincipal("forged-caller", Roles: new HashSet<string>(["reader"])),
                    },
                },
                fixture.Binding,
                fixture.Now,
                (authority, bindingHash) => authority.Proof == "host-proof" &&
                    bindingHash == SidecarCapabilityTransportValidation.ComputeTerminalAuthorityBindingHash(authority)).Code);
        Assert.Equal(
            SidecarCapabilityErrors.SpoofedIdentity,
            SidecarCapabilityTransportValidation.ValidateActionTerminalRequest(
                request,
                terminalRequest with
                {
                    Context = terminalRequest.Context! with
                    {
                        Snapshot = new ActionPipelineSnapshot("forged-graph", []),
                    },
                },
                fixture.Binding,
                fixture.Now,
                (authority, bindingHash) => authority.Proof == "host-proof" &&
                    bindingHash == SidecarCapabilityTransportValidation.ComputeTerminalAuthorityBindingHash(authority)).Code);
        Assert.Equal(
            SidecarCapabilityErrors.SpoofedIdentity,
            SidecarCapabilityTransportValidation.ValidateActionTerminalRequest(
                request,
                terminalRequest with
                {
                    EffectiveAction = Payload(descriptor.InputTypeIdentity, "changed"),
                },
                fixture.Binding,
                fixture.Now,
                (authority, bindingHash) => authority.Proof == "host-proof" &&
                    bindingHash == SidecarCapabilityTransportValidation.ComputeTerminalAuthorityBindingHash(authority)).Code);
        Assert.Equal(
            SidecarCapabilityErrors.SpoofedIdentity,
            SidecarCapabilityTransportValidation.ValidateActionTerminalRequest(
                request,
                terminalRequest with
                {
                    Descriptor = descriptor with { Key = new SharpClawActionKey("module.other") },
                },
                fixture.Binding,
                fixture.Now,
                (authority, bindingHash) => authority.Proof == "host-proof" &&
                    bindingHash == SidecarCapabilityTransportValidation.ComputeTerminalAuthorityBindingHash(authority)).Code);
        Assert.Equal(
            SidecarCapabilityErrors.SpoofedIdentity,
            SidecarCapabilityTransportValidation.ValidateActionTerminalRequest(
                request,
                terminalRequest with
                {
                    Cancellation = terminalRequest.Cancellation with
                    {
                        CancellationId = Guid.NewGuid(),
                    },
                },
                fixture.Binding,
                fixture.Now,
                (authority, bindingHash) => authority.Proof == "host-proof" &&
                    bindingHash == SidecarCapabilityTransportValidation.ComputeTerminalAuthorityBindingHash(authority)).Code);
        var coherentCaller = new RequestPrincipal(
            "coherent-forgery",
            Roles: new HashSet<string>(["reader"]));
        Assert.Equal(
            SidecarCapabilityErrors.SpoofedIdentity,
            SidecarCapabilityTransportValidation.ValidateActionTerminalRequest(
                request,
                terminalRequest with
                {
                    Context = terminalRequest.Context! with { Caller = coherentCaller },
                    Authority = terminalRequest.Authority with { Caller = coherentCaller },
                },
                fixture.Binding,
                fixture.Now,
                (_, _) => true).Code);
    }

    [Fact]
    public void Nested_host_entry_requires_a_fresh_carrier_authority()
    {
        var fixture = CreateFixture(maxCalls: 3);
        var rootContext = IssueContext(
            fixture,
            new RequestPrincipal("root"),
            HostActionEntryIngress.Cli);
        var nestedContext = IssueContext(
            fixture,
            new RequestPrincipal("nested"),
            HostActionEntryIngress.CrossModule);
        var rootAuthority = ActivateContext(fixture, rootContext);
        var nestedAuthority = ActivateContext(fixture, nestedContext);
        var rootCall = fixture.Call with
        {
            Capability = SidecarCapabilityKind.Action,
            CallId = Guid.NewGuid(),
            ReplayNonce = "root-action",
            Sequence = 1,
        };
        var nestedCall = rootCall with
        {
            CallId = Guid.NewGuid(),
            ReplayNonce = "nested-action",
            Sequence = 2,
        };
        var payload = Payload(typeof(string).AssemblyQualifiedName!, "nested");

        Assert.True(fixture.Session.BeginCall(
            rootCall,
            SidecarCapabilityKind.Action,
            payload,
            payload.ByteLength,
            fixture.Now,
            rootContext).Accepted);
        Assert.Equal(
            SidecarCapabilityErrors.Replay,
            fixture.Session.BeginCall(
                nestedCall,
                SidecarCapabilityKind.Action,
                payload,
                payload.ByteLength,
                fixture.Now,
                rootContext).Code);
        Assert.True(fixture.Session.BeginCall(
            nestedCall,
            SidecarCapabilityKind.Action,
            payload,
            payload.ByteLength,
            fixture.Now,
            nestedContext).Accepted);
        Assert.True(fixture.Session.CompleteCall(rootCall.CallId, 0).Accepted);
        Assert.True(fixture.Session.CompleteCall(nestedCall.CallId, 0).Accepted);
        Assert.True(fixture.Session.CompleteHostActionEntryCarrier(
            rootAuthority,
            HostActionEntryCarrierCompletionKind.Succeeded,
            fixture.Now).Accepted);
        Assert.True(fixture.Session.CompleteHostActionEntryCarrier(
            nestedAuthority,
            HostActionEntryCarrierCompletionKind.Succeeded,
            fixture.Now).Accepted);
    }

    [Fact]
    public void Run_and_run_required_reject_nested_carriers()
    {
        var fixture = CreateFixture();
        var call = fixture.Call with
        {
            Capability = SidecarCapabilityKind.Action,
            CallId = Guid.NewGuid(),
            ReplayNonce = "non-host-nested",
        };
        var descriptor = new SidecarActionDescriptorIdentity(
            new SharpClawActionKey("module.run"),
            1,
            "module",
            typeof(string).AssemblyQualifiedName!,
            "run-input",
            1,
            typeof(string).AssemblyQualifiedName!,
            "run-result",
            1,
            "run-descriptor");
        var action = Payload(descriptor.InputTypeIdentity, "run");
        var carrier = new SidecarNestedHostActionEntryCarrier(
            Guid.NewGuid(),
            "nested-carrier",
            Guid.NewGuid(),
            call.CallId,
            Guid.NewGuid(),
            descriptor.Key,
            descriptor.Version,
            descriptor.DescriptorHash,
            action.ContentHash,
            action.ByteLength,
            1,
            fixture.Now.AddMinutes(1));

        foreach (var invocation in new[]
        {
            SidecarActionInvocationKind.Run,
            SidecarActionInvocationKind.RunRequired,
        })
        {
            var request = new SidecarActionCapabilityRequest(
                call,
                invocation,
                descriptor,
                action,
                new ActionPipelineSnapshot("host-graph", []),
                new SidecarCancellationIdentity(call.CancellationId, "cancel", call.Deadline),
                null,
                call.Deadline)
            {
                NestedCarrier = carrier,
            };

            Assert.Equal(
                SidecarCapabilityErrors.InvalidPayload,
                SidecarCapabilityTransportValidation.ValidateActionRequest(
                    request,
                    fixture.Binding,
                    fixture.Now).Code);
        }
    }

    [Fact]
    public void Session_issues_and_consumes_one_nested_carrier_through_action_call()
    {
        var fixture = CreateFixture(maxInFlight: 3, maxCalls: 4);
        var rootLineage = new HostActionEntryLineage(
            new SharpClawActionKey("parent.action"),
            1,
            "parent-descriptor",
            typeof(string).AssemblyQualifiedName!,
            1,
            "parent-input",
            null,
            null);
        var rootContext = IssueContext(
            fixture,
            new RequestPrincipal("parent-caller", Roles: new HashSet<string>(["reader"])),
            HostActionEntryIngress.Cli,
            lineage: rootLineage);
        var rootAuthority = ActivateContext(fixture, rootContext);
        var parentCall = fixture.Call with
        {
            Capability = SidecarCapabilityKind.Action,
            CallId = Guid.NewGuid(),
            ReplayNonce = "parent-call",
            Sequence = 1,
        };
        var parentPayload = Payload(typeof(string).AssemblyQualifiedName!, "parent");
        Assert.True(fixture.Session.BeginCall(
            parentCall,
            SidecarCapabilityKind.Action,
            parentPayload,
            parentPayload.ByteLength,
            fixture.Now,
            rootContext).Accepted);

        var childDescriptor = new SidecarActionDescriptorIdentity(
            new SharpClawActionKey("child.action"),
            1,
            "child",
            typeof(string).AssemblyQualifiedName!,
            "child-input",
            1,
            typeof(string).AssemblyQualifiedName!,
            "child-result",
            1,
            "child-descriptor");
        var childAction = Payload(typeof(string).AssemblyQualifiedName!, "child");
        var contribution = new HostActionEntryContribution(
            new HostActionEntryIngressBinding(
                HostActionEntryIngress.CrossModule,
                "module-a",
                "target-module"),
            new HostActionEntryLineage(
                childDescriptor.Key,
                childDescriptor.Version,
                childDescriptor.DescriptorHash,
                childDescriptor.InputTypeIdentity,
                childDescriptor.InputSchemaVersion,
                childDescriptor.InputSchemaHash,
                null,
                null));
        var childCall = parentCall with
        {
            CallId = Guid.NewGuid(),
            ReplayNonce = "child-call",
            Sequence = 2,
            Deadline = fixture.Now.AddSeconds(30),
        };
        var issued = fixture.Session.IssueNestedHostActionEntryCarrier(
            parentCall,
            childCall,
            childDescriptor,
            childAction,
            contribution,
            fixture.Now,
            out var carrier);

        Assert.True(issued.Accepted, issued.Message);
        Assert.NotNull(carrier);
        Assert.True(carrier!.IsWellFormed);
        Assert.Equal(parentCall.CallId, carrier.ParentCallId);
        Assert.Equal(childCall.CallId, carrier.CallId);
        var roundTrip = SidecarCapabilityTransportCodec.Deserialize<SidecarNestedHostActionEntryCarrier>(
            SidecarCapabilityTransportCodec.Serialize(carrier));
        Assert.Equal(carrier, roundTrip);

        var request = SidecarActionCapabilityRequest.HostEntryNested(
            childCall,
            childDescriptor,
            childAction,
            new SidecarCancellationIdentity(
                childCall.CancellationId,
                "child-cancellation",
                childCall.Deadline),
            childCall.Deadline,
            carrier,
            new SidecarActionTerminalRegistration(
                Guid.NewGuid(),
                childDescriptor.InputTypeIdentity,
                childDescriptor.InputSchemaVersion,
                childDescriptor.ResultTypeIdentity,
                childDescriptor.ResultSchemaVersion,
                childDescriptor.DescriptorHash));
        var begun = fixture.Session.BeginActionCall(
            request,
            childAction.ByteLength,
            fixture.Now,
            out var childContext);

        Assert.True(begun.Accepted, begun.Message);
        Assert.NotNull(childContext);
        Assert.Equal(rootContext.InvocationId, childContext!.ParentInvocationId);
        Assert.Equal(rootContext.Depth + 1, childContext.Depth);
        Assert.Equal(rootContext.Attempt, childContext.Attempt);
        Assert.Equal(rootContext.TraceId, childContext.TraceId);
        Assert.Equal(rootContext.IdempotencyKey, childContext.IdempotencyKey);
        Assert.Equal(rootContext.Caller.SubjectId, childContext.Caller.SubjectId);
        Assert.Equal(carrier.CarrierId, childContext.CapabilityId);
        Assert.Null(request.HostContext);
        Assert.Equal(
            SidecarCapabilityErrors.InvalidBinding,
            fixture.Session.CompleteCall(parentCall.CallId, 0).Code);
        Assert.True(fixture.Session.CompleteCall(childCall.CallId, 0).Accepted);
        Assert.True(fixture.Session.CompleteCall(parentCall.CallId, 0).Accepted);
        Assert.True(fixture.Session.CompleteHostActionEntryCarrier(
            rootAuthority,
            HostActionEntryCarrierCompletionKind.Succeeded,
            fixture.Now).Accepted);

        var replay = fixture.Session.BeginActionCall(
            request,
            childAction.ByteLength,
            fixture.Now,
            out _);
        Assert.Equal(SidecarCapabilityErrors.Replay, replay.Code);
    }

    [Fact]
    public void Nested_carrier_rejects_changed_payload_and_releases_on_parent_completion()
    {
        var fixture = CreateFixture(maxInFlight: 2, maxCalls: 4);
        var rootContext = IssueContext(
            fixture,
            new RequestPrincipal("parent-caller"),
            HostActionEntryIngress.Cli,
            lineage: new HostActionEntryLineage(
                new SharpClawActionKey("parent.action"),
                1,
                "parent-descriptor",
                typeof(string).AssemblyQualifiedName!,
                1,
                "parent-input",
                null,
                null));
        ActivateContext(fixture, rootContext);
        var parentCall = fixture.Call with
        {
            Capability = SidecarCapabilityKind.Action,
            CallId = Guid.NewGuid(),
            ReplayNonce = "parent-release",
            Sequence = 1,
        };
        var parentPayload = Payload(typeof(string).AssemblyQualifiedName!, "parent");
        Assert.True(fixture.Session.BeginCall(
            parentCall,
            SidecarCapabilityKind.Action,
            parentPayload,
            parentPayload.ByteLength,
            fixture.Now,
            rootContext).Accepted);
        var descriptor = new SidecarActionDescriptorIdentity(
            new SharpClawActionKey("child.release"),
            1,
            "child",
            typeof(string).AssemblyQualifiedName!,
            "child-input",
            1,
            typeof(string).AssemblyQualifiedName!,
            "child-result",
            1,
            "child-release-descriptor");
        var action = Payload(typeof(string).AssemblyQualifiedName!, "child");
        var contribution = new HostActionEntryContribution(
            new HostActionEntryIngressBinding(HostActionEntryIngress.CrossModule, "module-a", "target-module"),
            new HostActionEntryLineage(
                descriptor.Key,
                descriptor.Version,
                descriptor.DescriptorHash,
                descriptor.InputTypeIdentity,
                descriptor.InputSchemaVersion,
                descriptor.InputSchemaHash,
                null,
                null));
        var childCall = parentCall with
        {
            CallId = Guid.NewGuid(),
            ReplayNonce = "child-release",
            Sequence = 2,
        };
        Assert.True(fixture.Session.IssueNestedHostActionEntryCarrier(
            parentCall,
            childCall,
            descriptor,
            action,
            contribution,
            fixture.Now,
            out var carrier).Accepted);

        var changed = SidecarActionCapabilityRequest.HostEntryNested(
            childCall,
            descriptor,
            Payload(typeof(string).AssemblyQualifiedName!, "changed"),
            new SidecarCancellationIdentity(childCall.CancellationId, "cancel", childCall.Deadline),
            childCall.Deadline,
            carrier!,
            new SidecarActionTerminalRegistration(
                Guid.NewGuid(),
                descriptor.InputTypeIdentity,
                descriptor.InputSchemaVersion,
                descriptor.ResultTypeIdentity,
                descriptor.ResultSchemaVersion,
                descriptor.DescriptorHash));
        Assert.Equal(
            SidecarCapabilityErrors.SpoofedIdentity,
            fixture.Session.BeginActionCall(changed, changed.Action.ByteLength, fixture.Now, out _).Code);

        Assert.True(fixture.Session.CompleteCall(parentCall.CallId, 0).Accepted);
        Assert.Equal(
            SidecarCapabilityErrors.Replay,
            fixture.Session.BeginNestedHostActionEntryCall(
                carrier!,
                childCall,
                action,
                action.ByteLength,
                fixture.Now,
                out _).Code);
    }

    [Fact]
    public void Nested_carrier_rotation_and_expiry_revoke_unused_authority()
    {
        var fixture = CreateFixture(maxInFlight: 2, maxCalls: 4);
        var rootContext = IssueContext(
            fixture,
            new RequestPrincipal("parent-caller"),
            HostActionEntryIngress.Cli,
            lineage: new HostActionEntryLineage(
                new SharpClawActionKey("parent.action"),
                1,
                "parent-descriptor",
                typeof(string).AssemblyQualifiedName!,
                1,
                "parent-input",
                null,
                null));
        var rootAuthority = ActivateContext(fixture, rootContext);
        var parentCall = fixture.Call with
        {
            Capability = SidecarCapabilityKind.Action,
            CallId = Guid.NewGuid(),
            ReplayNonce = "parent-expiry",
            Sequence = 1,
        };
        var parentPayload = Payload(typeof(string).AssemblyQualifiedName!, "parent");
        Assert.True(fixture.Session.BeginCall(
            parentCall,
            SidecarCapabilityKind.Action,
            parentPayload,
            parentPayload.ByteLength,
            fixture.Now,
            rootContext).Accepted);
        var descriptor = new SidecarActionDescriptorIdentity(
            new SharpClawActionKey("child.expiry"),
            1,
            "child",
            typeof(string).AssemblyQualifiedName!,
            "child-input",
            1,
            typeof(string).AssemblyQualifiedName!,
            "child-result",
            1,
            "child-expiry-descriptor");
        var action = Payload(typeof(string).AssemblyQualifiedName!, "child");
        var contribution = new HostActionEntryContribution(
            new HostActionEntryIngressBinding(HostActionEntryIngress.CrossModule, "module-a", "target-module"),
            new HostActionEntryLineage(
                descriptor.Key,
                descriptor.Version,
                descriptor.DescriptorHash,
                descriptor.InputTypeIdentity,
                descriptor.InputSchemaVersion,
                descriptor.InputSchemaHash,
                null,
                null));
        var childCall = parentCall with
        {
            CallId = Guid.NewGuid(),
            ReplayNonce = "child-expiry",
            Sequence = 2,
            Deadline = fixture.Now.AddSeconds(1),
        };
        Assert.True(fixture.Session.IssueNestedHostActionEntryCarrier(
            parentCall,
            childCall,
            descriptor,
            action,
            contribution,
            fixture.Now,
            out var carrier).Accepted);
        var request = SidecarActionCapabilityRequest.HostEntryNested(
            childCall,
            descriptor,
            action,
            new SidecarCancellationIdentity(childCall.CancellationId, "child-expiry-cancel", childCall.Deadline),
            childCall.Deadline,
            carrier!,
            new SidecarActionTerminalRegistration(
                Guid.NewGuid(),
                descriptor.InputTypeIdentity,
                descriptor.InputSchemaVersion,
                descriptor.ResultTypeIdentity,
                descriptor.ResultSchemaVersion,
                descriptor.DescriptorHash));
        Assert.True(fixture.Session.BeginActionCall(
            request,
            action.ByteLength,
            fixture.Now,
            out _).Accepted);
        var rotated = CreateRotatedBinding(fixture, "nested-rotation");
        fixture.BindingHashes.Add(rotated.Authentication.BindingHash);
        Assert.Equal(
            SidecarCapabilityErrors.InvalidBinding,
            fixture.Session.RotateBinding(rotated, fixture.Now).Code);
        Assert.Equal(
            1,
            fixture.Session.SweepExpiredHostActionEntryCarriers(fixture.Now.AddSeconds(2)));
        Assert.Equal(1, fixture.Session.ActiveHostActionEntryCarrierCount);
        Assert.Equal(
            SidecarCapabilityErrors.InvalidBinding,
            fixture.Session.CompleteCall(parentCall.CallId, 0).Code);
        Assert.True(fixture.Session.CompleteCall(childCall.CallId, 0).Accepted);
        Assert.True(fixture.Session.CompleteCall(parentCall.CallId, 0).Accepted);
        Assert.True(fixture.Session.CompleteHostActionEntryCarrier(
            rootAuthority,
            HostActionEntryCarrierCompletionKind.Succeeded,
            fixture.Now.AddSeconds(2)).Accepted);
        Assert.Equal(
            SidecarCapabilityErrors.Replay,
            fixture.Session.BeginNestedHostActionEntryCall(
                carrier!,
                childCall,
                action,
                action.ByteLength,
                fixture.Now.AddSeconds(2),
                out _).Code);
    }

    private static SidecarActionCapabilityRequest SidecarCapabilityTransportValidationRequest(
        SidecarCapabilityCallIdentity call,
        SidecarActionDescriptorIdentity descriptor,
        SidecarSerializedPayload action,
        HostActionEntryRequestContext context) =>
        SidecarActionCapabilityRequest.HostEntry(
            call,
            descriptor,
            action,
            new SidecarCancellationIdentity(call.CancellationId, "entry-cancel", call.Deadline),
            call.Deadline,
            context,
            new SidecarActionTerminalRegistration(
                Guid.NewGuid(),
                descriptor.InputTypeIdentity,
                descriptor.InputSchemaVersion,
                descriptor.ResultTypeIdentity,
                descriptor.ResultSchemaVersion,
                descriptor.DescriptorHash));

    private static SidecarActionTerminalTransportRequest CreateTerminalRequest(
        Fixture fixture,
        SidecarActionCapabilityRequest request,
        ActionPipelineSnapshot snapshot)
    {
        var effectiveAction = request.Action;
        var receipt = new SidecarTerminalReceipt(
            "host-entry-receipt",
            request.Descriptor.Key,
            request.Descriptor.Version,
            request.Call.CallId,
            1,
            "host-entry-scope",
            effectiveAction.ContentHash);
        var hostContext = request.HostContext ?? throw new InvalidOperationException();
        var terminalContext = new SidecarActionTerminalExecutionContext(
            request.Call,
            request.Invocation,
            request.Descriptor,
            effectiveAction,
            snapshot,
            hostContext.InvocationId,
            hostContext.ParentInvocationId,
            hostContext.Depth,
            hostContext.Attempt,
            hostContext.Caller,
            hostContext.Features,
            hostContext.TraceId,
            hostContext.IdempotencyKey,
            request.Cancellation,
            receipt,
            request.Deadline);
        var authority = new SidecarHostTerminalAuthority(
            Guid.NewGuid(),
            fixture.Binding.SessionId,
            fixture.Binding.RequestId,
            fixture.Binding.CancellationId,
            request.Call.CallId,
            fixture.Binding.ModuleId,
            fixture.Binding.GraphId,
            request.Invocation,
            request.Descriptor.Key,
            request.Descriptor.Version,
            request.Descriptor.DescriptorHash,
            effectiveAction.TypeIdentity,
            effectiveAction.SchemaVersion,
            effectiveAction.ContentHash,
            effectiveAction.ByteLength,
            receipt.ReceiptId,
            receipt.ActionKey,
            receipt.ActionVersion,
            receipt.CallId,
            receipt.Attempt,
            receipt.IdempotencyScope,
            receipt.ContentHash,
            request.Deadline,
            fixture.Now.AddMinutes(-1),
            request.Deadline,
            "host-proof")
        {
            TerminalId = request.Terminal?.TerminalId ?? Guid.Empty,
            SnapshotContentHash = SidecarCapabilityTransportCodec.ComputeSha256(
                SidecarCapabilityTransportCodec.Serialize(snapshot)),
            Caller = terminalContext.Caller,
            Features = terminalContext.Features,
            TraceId = terminalContext.TraceId,
            IdempotencyKey = terminalContext.IdempotencyKey,
            InvocationId = terminalContext.InvocationId,
            ParentInvocationId = terminalContext.ParentInvocationId,
            Depth = terminalContext.Depth,
            Attempt = terminalContext.Attempt,
        };
        authority = authority with
        {
            CanonicalBindingHash = SidecarCapabilityTransportValidation.ComputeTerminalAuthorityBindingHash(authority),
        };
        return new SidecarActionTerminalTransportRequest(
            request.Call,
            request.Invocation,
            request.Descriptor,
            effectiveAction,
            authority,
            receipt,
            request.Cancellation,
            request.Deadline)
        {
            Context = terminalContext,
            TerminalId = request.Terminal?.TerminalId ?? Guid.Empty,
        };
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
        var bindingHashes = new HashSet<string>(StringComparer.Ordinal)
        {
            binding.Authentication.BindingHash,
        };
        var session = new SidecarCapabilitySession(
            binding,
            authority => bindingHashes.Contains(authority.BindingHash),
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
        return new Fixture(now, binding, session, call, safeFailure, nonces, bindingHashes);
    }

    private static HostActionEntryRequestContext IssueContext(
        Fixture fixture,
        RequestPrincipal caller,
        HostActionEntryIngress ingress,
        Guid? traceId = null,
        Guid? idempotencyKey = null,
        DateTimeOffset? actionDeadline = null,
        HostActionEntryLineage? lineage = null)
    {
        var request = new HostActionEntryContextRequest(
            ingress,
            Guid.NewGuid(),
            fixture.Binding.RequestId,
            fixture.Binding.CancellationId,
            caller,
            ExtensionFeatureSet.Empty,
            traceId ?? Guid.NewGuid(),
            idempotencyKey ?? Guid.NewGuid(),
            actionDeadline ?? fixture.Now.AddMinutes(1),
            fixture.Binding.ExpiresAt)
        {
            Contribution = new HostActionEntryContribution(
                ingress switch
                {
                    HostActionEntryIngress.Endpoint => new HostActionEntryIngressBinding(ingress, "/demo"),
                    HostActionEntryIngress.Cli => new HostActionEntryIngressBinding(ingress, "demo"),
                    HostActionEntryIngress.Tool => new HostActionEntryIngressBinding(ingress, "clock_now"),
                    _ => new HostActionEntryIngressBinding(ingress, "source.module", "target.module"),
                },
                LineageForContext(lineage)),
        };
        var result = fixture.Session.IssueHostActionEntryContext(
            request,
            fixture.Now,
            out var context);
        Assert.True(result.Accepted, result.Message);
        return context!;
    }

    private static HostActionEntryCarrierAuthority ActivateContext(
        Fixture fixture,
        HostActionEntryRequestContext context)
    {
        var carrier = new HostActionEntryCarrierIdentity(
            context.Ingress,
            context.InvocationId,
            context.Contribution!.IngressBinding);
        var result = fixture.Session.BeginHostActionEntryCarrier(
            context,
            carrier,
            fixture.Now,
            out var authority);
        Assert.True(result.Accepted, result.Message);
        Assert.NotNull(authority);
        return authority!;
    }

    private static SidecarCapabilitySessionBinding CreateRotatedBinding(
        Fixture fixture,
        string nonce,
        int? actionResultBytes = null)
    {
        var expiry = fixture.Binding.ExpiresAt.AddMinutes(1);
        var rotated = fixture.Binding with
        {
            SessionId = Guid.NewGuid(),
            RequestId = Guid.NewGuid(),
            CancellationId = Guid.NewGuid(),
            ExpiresAt = expiry,
            Grant = fixture.Binding.Grant with { ExpiresAt = expiry },
            PayloadLimits = actionResultBytes is null
                ? fixture.Binding.PayloadLimits
                : fixture.Binding.PayloadLimits with { ActionResultBytes = actionResultBytes.Value },
            Authentication = fixture.Binding.Authentication with
            {
                Nonce = nonce,
                ExpiresAt = expiry,
                BindingHash = string.Empty,
            },
        };
        return rotated with
        {
            Authentication = rotated.Authentication with
            {
                BindingHash = SidecarCapabilitySessionValidator.ComputeBindingHash(rotated),
            },
        };
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

    private static HostActionEntryLineage LineageForContext(HostActionEntryLineage? lineage)
    {
        var descriptorLineage = lineage ?? new HostActionEntryLineage(
            new SharpClawActionKey("entry.context"),
            1,
            "context-descriptor",
            typeof(string).AssemblyQualifiedName!,
            1,
            "context-input-schema",
            null,
            null);
        return descriptorLineage with
        {
            PayloadContentHash = null,
            PayloadByteLength = null,
        };
    }

    private static HostActionEntryLineage Lineage<TAction, TResult>(
        ActionDescriptor<TAction, TResult> descriptor,
        TAction action)
    {
        return new HostActionEntryLineage(
            descriptor.Key,
            descriptor.Version,
            HostActionEntryAuthorityValidator.ComputeDescriptorHash(descriptor),
            typeof(TAction).AssemblyQualifiedName!,
            descriptor.InputSchema!.Version,
            descriptor.InputSchema.ContentHash!,
            null,
            null);
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
        HashSet<string> Nonces,
        HashSet<string> BindingHashes);

    private sealed class SessionHostActionEntryProxy(
        SidecarCapabilitySession session,
        Guid callId,
        DateTimeOffset now)
    {
        public bool AuthorityIssued { get; private set; }
        public bool TransportValidated { get; private set; }

        public ValueTask<IActionOutcome<string>> InvokeAsync(
            HostActionEntryRequest<string, string> request)
        {
            var issued = session.IssueHostActionEntry(
                request,
                callId,
                now,
                authority => HostActionEntryAuthorityValidator.ComputeAuthorityHash(authority),
                out var transport);
            if (!issued.Accepted || transport is null)
                throw new InvalidOperationException(issued.Message);

            AuthorityIssued = true;
            var validated = session.ValidateHostActionEntry(
                transport,
                now,
                authority => authority.Proof == HostActionEntryAuthorityValidator.ComputeAuthorityHash(authority));
            if (!validated.Accepted)
                throw new InvalidOperationException(validated.Message);

            TransportValidated = true;
            return ValueTask.FromResult<IActionOutcome<string>>(new RecordedOutcome<string>(ActionOutcomeKind.Completed));
        }
    }

    private sealed class RecordingSidecarTransport(SidecarSafeFailureIdentity safeFailure) : ISidecarCapabilityTransport
    {
        public SidecarActionCapabilityRequest? Request { get; private set; }
        public int ActionCalls { get; private set; }

        public ValueTask<SidecarStorageCapabilityResponse> InvokeStorageAsync(
            SidecarStorageCapabilityRequest request,
            CancellationToken ct = default) =>
            throw new NotSupportedException();

        public ValueTask<SidecarActionCapabilityResponse> InvokeActionAsync(
            SidecarActionCapabilityRequest request,
            CancellationToken ct = default)
        {
            Request = request;
            ActionCalls++;
            return ValueTask.FromResult(new SidecarActionCapabilityResponse(
                null,
                new SidecarActionOutcomeEnvelope(
                    ActionOutcomeKind.Cancelled,
                    null,
                    null,
                    null,
                    null,
                    null,
                    safeFailure,
                    0),
                null,
                safeFailure,
                false));
        }

        public ValueTask<SidecarActionTerminalTransportResponse> InvokeActionTerminalAsync(
            SidecarActionTerminalTransportRequest request,
            CancellationToken ct = default) =>
            throw new NotSupportedException();
    }

    private sealed class TransportHostActionEntryProxy(
        ISidecarCapabilityTransport transport,
        SidecarCapabilityCallIdentity call) : IHostActionEntry
    {
        public async ValueTask<IActionOutcome<TResult>> InvokeAsync<TAction, TResult>(
            HostActionEntryRequest<TAction, TResult> request,
            IHostActionEntryTerminal<TAction, TResult> terminal,
            CancellationToken cancellationToken = default)
        {
            var inputSchema = request.Descriptor.InputSchema ?? throw new InvalidOperationException();
            var resultSchema = request.Descriptor.ResultSchema ?? throw new InvalidOperationException();
            var descriptor = new SidecarActionDescriptorIdentity(
                request.Descriptor.Key,
                request.Descriptor.Version,
                request.Descriptor.Category,
                typeof(TAction).AssemblyQualifiedName ?? typeof(TAction).FullName ?? typeof(TAction).Name,
                inputSchema.ContentHash!,
                inputSchema.Version,
                typeof(TResult).AssemblyQualifiedName ?? typeof(TResult).FullName ?? typeof(TResult).Name,
                resultSchema.ContentHash!,
                resultSchema.Version,
                HostActionEntryAuthorityValidator.ComputeDescriptorHash(request.Descriptor));
            var bytes = SidecarCapabilityTransportCodec.Serialize(request.Action);
            using var document = JsonDocument.Parse(bytes);
            var action = new SidecarSerializedPayload(
                descriptor.InputTypeIdentity,
                descriptor.InputSchemaVersion,
                SidecarCapabilityTransportCodec.ComputeSha256(bytes),
                document.RootElement.Clone(),
                bytes.Length);
            var sidecarRequest = SidecarActionCapabilityRequest.HostEntry(
                call,
                descriptor,
                action,
                new SidecarCancellationIdentity(call.CancellationId, "proxy-cancel", call.Deadline),
                request.Deadline,
                request.Context,
                new SidecarActionTerminalRegistration(
                    terminal.TerminalId,
                    descriptor.InputTypeIdentity,
                    descriptor.InputSchemaVersion,
                    descriptor.ResultTypeIdentity,
                    descriptor.ResultSchemaVersion,
                    descriptor.DescriptorHash));
            var response = await transport.InvokeActionAsync(sidecarRequest, cancellationToken);
            return new RecordedOutcome<TResult>(response.Outcome.Kind);
        }

        public ValueTask<IActionOutcome<TResult>> InvokeNestedAsync<TParentAction, TAction, TResult>(
            HostActionEntryNestedRequest<TParentAction, TAction, TResult> request,
            IHostActionEntryTerminal<TAction, TResult> terminal,
            CancellationToken cancellationToken = default) =>
            ValueTask.FromException<IActionOutcome<TResult>>(
                new NotSupportedException("The transport proxy test does not dispatch nested entries."));
    }

    private sealed class RecordingHostActionEntryTerminal<TAction, TResult>
        : IHostActionEntryTerminal<TAction, TResult>
    {
        public Guid TerminalId { get; } = Guid.NewGuid();

        public ValueTask<TResult> InvokeAsync(
            ActionContext<TAction> context,
            CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(default(TResult)!);
    }

    private sealed record RecordedOutcome<TResult>(ActionOutcomeKind Kind) : IActionOutcome<TResult>
    {
        public TResult? Result => default;
        public ContinuationToken? Continuation => null;
        public ExecutionError? Error => null;
        public ActionUncertainty? Uncertainty => null;
    }
}
