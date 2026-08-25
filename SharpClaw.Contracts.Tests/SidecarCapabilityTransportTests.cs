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
        Assert.NotEqual(authority, active);
        Assert.Equal(rotated.SessionId, active!.SessionId);
        Assert.Equal(rotated.RequestId, active.RequestId);
        Assert.True(fixture.Session.TryGetActiveHostActionEntryContext(
            authority.CapabilityId,
            out var rebasedContext));
        Assert.Equal(rotated.RequestId, rebasedContext!.RequestId);
        Assert.Equal(rotated.CancellationId, rebasedContext.CancellationId);
        Assert.True(fixture.Session.CompleteHostActionEntryCarrier(
            active,
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
        Assert.True(fixture.Session.TryGetActiveHostActionEntryContext(
            authority.CapabilityId,
            out var rebasedContext));

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
        Assert.Equal(
            SidecarCapabilityErrors.SpoofedIdentity,
            fixture.Session.BeginCall(
                nextCall,
                SidecarCapabilityKind.Action,
                nextPayload,
                nextPayload.ByteLength,
                fixture.Now,
                context).Code);
        Assert.True(fixture.Session.BeginCall(
            nextCall,
            SidecarCapabilityKind.Action,
            nextPayload,
            nextPayload.ByteLength,
            fixture.Now,
            rebasedContext).Accepted);
        Assert.True(fixture.Session.CompleteCall(nextCall.CallId, 0).Accepted);
        Assert.True(fixture.Session.TryGetActiveHostActionEntryCarrier(
            authority.CapabilityId,
            out var rebasedAuthority));
        Assert.True(fixture.Session.CompleteHostActionEntryCarrier(
            rebasedAuthority!,
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
    public void Production_session_verifies_and_consumes_one_external_authority()
    {
        var fixture = CreateExternalSessionFixture();

        var accepted = fixture.Session.ValidateAndConsume(
            fixture.Authority,
            fixture.Now);
        var replay = fixture.Session.ValidateAndConsume(
            fixture.Authority,
            fixture.Now);

        Assert.True(accepted.Accepted, accepted.Message);
        Assert.Equal(SidecarCapabilityErrors.Replay, replay.Code);
    }

    [Fact]
    public void Production_session_rejects_forged_proof_without_consuming_valid_authority()
    {
        var fixture = CreateExternalSessionFixture();
        var forged = fixture.Authority with
        {
            EffectiveHostEntry = fixture.Authority.EffectiveHostEntry with
            {
                Authority = fixture.Authority.EffectiveHostEntry.Authority with
                {
                    Proof = "forged-proof",
                },
            },
        };
        var recomputed = forged with
        {
            EffectiveHostEntry = forged.EffectiveHostEntry with
            {
                Authority = forged.EffectiveHostEntry.Authority with
                {
                    CanonicalBindingHash = SidecarCapabilityTransportValidation.ComputeTerminalAuthorityBindingHash(
                        forged.EffectiveHostEntry.Authority),
                },
            },
        };

        Assert.Equal(
            SidecarCapabilityErrors.Unauthenticated,
            fixture.Session.ValidateAndConsume(forged, fixture.Now).Code);
        Assert.Equal(
            SidecarCapabilityErrors.Unauthenticated,
            fixture.Session.ValidateAndConsume(recomputed, fixture.Now).Code);
        Assert.True(fixture.Session.ValidateAndConsume(fixture.Authority, fixture.Now).Accepted);
    }

    [Fact]
    public void Production_session_rejects_missing_callback_disconnect_and_expiry()
    {
        var missingCallback = CreateExternalSessionFixture(trustedProof: false);
        Assert.Equal(
            SidecarCapabilityErrors.Unauthenticated,
            missingCallback.Session.ValidateAndConsume(
                missingCallback.Authority,
                missingCallback.Now).Code);

        var disconnected = CreateExternalSessionFixture();
        disconnected.Session.Disconnect();
        Assert.Equal(
            SidecarCapabilityErrors.Disconnected,
            disconnected.Session.ValidateAndConsume(
                disconnected.Authority,
                disconnected.Now).Code);

        var expired = CreateExternalSessionFixture();
        Assert.Equal(
            SidecarCapabilityErrors.Expired,
            expired.Session.ValidateAndConsume(
                expired.Authority,
                expired.Now.AddMinutes(6)).Code);
    }

    [Fact]
    public void Production_session_rejects_changed_external_authority_fields_without_consuming_valid_call()
    {
        var mutations = new Func<SidecarExternalActionDispatchAuthority, SidecarExternalActionDispatchAuthority>[]
        {
            authority => authority with { ModuleId = "changed.module" },
            authority => authority with { GraphId = "changed.graph" },
            authority => authority with
            {
                Call = authority.Call with { SessionId = Guid.NewGuid() },
            },
            authority => authority with
            {
                Call = authority.Call with { RequestId = Guid.NewGuid() },
            },
            authority => authority with
            {
                Call = authority.Call with { CancellationId = Guid.NewGuid() },
            },
            authority => authority with
            {
                Call = authority.Call with { CallId = Guid.NewGuid() },
            },
            authority => authority with
            {
                Action = authority.Action with { ContentHash = "changed-payload-hash" },
            },
            authority => authority with
            {
                Action = authority.Action with { ByteLength = authority.Action.ByteLength + 1 },
            },
        };

        foreach (var mutate in mutations)
        {
            var fixture = CreateExternalSessionFixture();
            var rejected = fixture.Session.ValidateAndConsume(
                mutate(fixture.Authority),
                fixture.Now);

            Assert.False(rejected.Accepted, rejected.Message);
            Assert.True(
                fixture.Session.ValidateAndConsume(fixture.Authority, fixture.Now).Accepted,
                rejected.Message);
        }
    }

    [Fact]
    public async Task Production_session_consumes_external_authority_once_under_concurrent_replay()
    {
        var fixture = CreateExternalSessionFixture();
        var results = await Task.WhenAll(
            Enumerable.Range(0, 8).Select(_ => Task.Run(() =>
                fixture.Session.ValidateAndConsume(fixture.Authority, fixture.Now))));

        Assert.Equal(1, results.Count(result => result.Accepted));
        Assert.Equal(7, results.Count(result => result.Code == SidecarCapabilityErrors.Replay));
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
    public void Host_entry_effective_dispatcher_context_binds_replacement_and_snapshot()
    {
        var fixture = CreateFixture();
        var call = fixture.Call with
        {
            Capability = SidecarCapabilityKind.Action,
            CallId = Guid.NewGuid(),
            ReplayNonce = "effective-host-entry",
        };
        var descriptor = new SidecarActionDescriptorIdentity(
            new SharpClawActionKey("effective.host.entry"),
            1,
            "effective",
            typeof(string).AssemblyQualifiedName!,
            "effective-input",
            1,
            typeof(string).AssemblyQualifiedName!,
            "effective-result",
            1,
            "effective-descriptor");
        var original = Payload(descriptor.InputTypeIdentity, "action-a");
        var replacement = Payload(descriptor.InputTypeIdentity, "action-b");
        var hostContext = IssueContext(
            fixture,
            new RequestPrincipal("effective-caller", Roles: new HashSet<string>(["reader"])),
            HostActionEntryIngress.Endpoint,
            actionDeadline: call.Deadline,
            lineage: new HostActionEntryLineage(
                descriptor.Key,
                descriptor.Version,
                descriptor.DescriptorHash,
                descriptor.InputTypeIdentity,
                 descriptor.InputSchemaVersion,
                 descriptor.InputSchemaHash,
                 original.ContentHash,
                 original.ByteLength));
        var initiatingRequest = SidecarActionCapabilityRequest.HostEntry(
            call,
            descriptor,
            original,
            new SidecarCancellationIdentity(call.CancellationId, "effective-cancel", call.Deadline),
            call.Deadline,
            hostContext,
            new SidecarActionTerminalRegistration(
                Guid.NewGuid(),
                descriptor.InputTypeIdentity,
                descriptor.InputSchemaVersion,
                descriptor.ResultTypeIdentity,
                descriptor.ResultSchemaVersion,
                descriptor.DescriptorHash));
        var effectiveRequest = initiatingRequest with { Action = replacement };
        var terminalRequest = CreateTerminalRequest(
            fixture,
            effectiveRequest,
            new ActionPipelineSnapshot(
                "effective-host-graph",
                [new ActionCapabilityGrant(
                    descriptor.Key,
                    descriptor.Version,
                    ActionInterceptionCapabilities.Inspect)]));
        effectiveRequest = effectiveRequest with
        {
            EffectiveHostEntryContext = new SidecarActionEffectiveHostEntryContext(
                hostContext,
                terminalRequest.Context!,
                terminalRequest.Authority),
        };
        var roundTrip = SidecarCapabilityTransportCodec.Deserialize<SidecarActionCapabilityRequest>(
            SidecarCapabilityTransportCodec.Serialize(effectiveRequest));
        static bool Authenticate(SidecarHostTerminalAuthority authority, string proof) =>
            authority.Proof == "host-proof" &&
            proof == authority.CanonicalBindingHash;

        Assert.True(roundTrip.EffectiveHostEntryContext!.IsWellFormed);
        Assert.Equal(
            SidecarCapabilityTransportValidation.ComputeHostActionEntryContextBindingHash(hostContext),
            roundTrip.EffectiveHostEntryContext.Authority.HostContextBindingHash);
        Assert.Equal(
            SidecarCapabilityTransportValidation.ComputeSnapshotHash(
                roundTrip.EffectiveHostEntryContext.EffectiveContext.Snapshot),
            roundTrip.EffectiveHostEntryContext.Authority.SnapshotContentHash);
        Assert.Equal(
            SidecarCapabilityTransportValidation.ComputeTerminalAuthorityBindingHash(
                roundTrip.EffectiveHostEntryContext.Authority),
            roundTrip.EffectiveHostEntryContext.Authority.CanonicalBindingHash);
        Assert.Equal(hostContext.InvocationId, terminalRequest.Context!.InvocationId);
        Assert.Equal(hostContext.ParentInvocationId, terminalRequest.Context.ParentInvocationId);
        Assert.Equal(hostContext.Depth, terminalRequest.Context.Depth);
        Assert.Equal(hostContext.Attempt, terminalRequest.Context.Attempt);
        Assert.Equal(hostContext.TraceId, terminalRequest.Context.TraceId);
        Assert.Equal(hostContext.IdempotencyKey, terminalRequest.Context.IdempotencyKey);
        Assert.Equal(hostContext.Deadline, terminalRequest.Context.Deadline);
        Assert.Equal(hostContext.Contribution!.Lineage.ActionKey, terminalRequest.Descriptor.Key);
        Assert.Equal(hostContext.Contribution.Lineage.ActionVersion, terminalRequest.Descriptor.Version);
        Assert.Equal(hostContext.Contribution.Lineage.DescriptorHash, terminalRequest.Descriptor.DescriptorHash);
        Assert.Equal(hostContext.Contribution.Lineage.InputTypeIdentity, terminalRequest.EffectiveAction.TypeIdentity);
        Assert.Equal(hostContext.Contribution.Lineage.InputSchemaVersion, terminalRequest.EffectiveAction.SchemaVersion);
        Assert.Equal(hostContext.Contribution.Lineage.InputSchemaHash, terminalRequest.Descriptor.InputSchemaHash);
        var terminalValidation = SidecarCapabilityTransportValidation.ValidateActionTerminalRequest(
            roundTrip with { EffectiveHostEntryContext = null },
            terminalRequest,
            fixture.Binding,
            fixture.Now,
            Authenticate);
        Assert.True(terminalValidation.Accepted, $"{terminalValidation.Code}: {terminalValidation.Message}");

        var effectiveValidation = SidecarCapabilityTransportValidation.ValidateActionRequest(
            roundTrip,
            fixture.Binding,
            fixture.Now,
            Authenticate);
        Assert.True(effectiveValidation.Accepted, $"{effectiveValidation.Code}: {effectiveValidation.Message}");
        Assert.Equal("action-b", roundTrip.Action.Value.GetString());
        Assert.Equal(
            "action-b",
            roundTrip.EffectiveHostEntryContext!.EffectiveContext.EffectiveAction.Value.GetString());
        Assert.True(SidecarCapabilityTransportValidation.ValidateActionTerminalRequest(
            roundTrip,
            terminalRequest,
            fixture.Binding,
            fixture.Now,
            Authenticate).Accepted);
        ActivateContext(fixture, hostContext);
        var begin = fixture.Session.BeginActionCall(
            roundTrip,
            roundTrip.Action.ByteLength,
            fixture.Now,
            out _,
            static (_, _) => false,
            Authenticate);
        Assert.True(begin.Accepted, begin.Message);
        Assert.True(fixture.Session.CompleteCall(roundTrip.Call.CallId, 0).Accepted);
        var replay = fixture.Session.BeginActionCall(
            roundTrip,
            roundTrip.Action.ByteLength,
            fixture.Now,
            out _,
            static (_, _) => false,
            Authenticate);
        Assert.False(replay.Accepted);

        Assert.False(SidecarCapabilityTransportValidation.ValidateActionRequest(
            roundTrip with
            {
                Action = replacement with
                {
                    Value = JsonDocument.Parse("\"action-c\"").RootElement.Clone(),
                },
            },
            fixture.Binding,
            fixture.Now,
            Authenticate).Accepted);
        Assert.False(SidecarCapabilityTransportValidation.ValidateActionRequest(
                roundTrip with
                {
                    HostContext = roundTrip.HostContext! with
                    {
                        Contribution = roundTrip.HostContext.Contribution! with
                        {
                            Lineage = roundTrip.HostContext.Contribution.Lineage with
                            {
                                PayloadContentHash = new string('A', 64),
                            },
                        },
                    },
                },
                fixture.Binding,
                fixture.Now,
                Authenticate).Accepted);
        Assert.False(SidecarCapabilityTransportValidation.ValidateActionRequest(
                roundTrip with
                {
                    HostContext = roundTrip.HostContext! with
                    {
                        Contribution = roundTrip.HostContext.Contribution! with
                        {
                            Lineage = roundTrip.HostContext.Contribution.Lineage with
                            {
                                PayloadByteLength = original.ByteLength + 1,
                            },
                        },
                    },
                },
                fixture.Binding,
                fixture.Now,
                Authenticate).Accepted);
        Assert.Equal(
            SidecarCapabilityErrors.SpoofedIdentity,
            SidecarCapabilityTransportValidation.ValidateActionRequest(
                roundTrip with
                {
                    EffectiveHostEntryContext = roundTrip.EffectiveHostEntryContext with
                    {
                        EffectiveContext = roundTrip.EffectiveHostEntryContext.EffectiveContext with
                        {
                            Snapshot = new ActionPipelineSnapshot("forged-host-graph", []),
                        },
                    },
                },
                fixture.Binding,
                fixture.Now,
                Authenticate).Code);
        Assert.Equal(
            SidecarCapabilityErrors.Unauthorized,
            SidecarCapabilityTransportValidation.ValidateActionRequest(
                roundTrip with
                {
                    EffectiveHostEntryContext = roundTrip.EffectiveHostEntryContext with
                    {
                        Authority = roundTrip.EffectiveHostEntryContext.Authority with
                        {
                            Proof = "forged-proof",
                        },
                    },
                },
                fixture.Binding,
                fixture.Now,
                Authenticate).Code);
        Assert.Equal(
            SidecarCapabilityErrors.SpoofedIdentity,
            SidecarCapabilityTransportValidation.ValidateActionRequest(
                roundTrip with
                {
                    HostContext = roundTrip.HostContext! with { TraceId = Guid.NewGuid() },
                },
                fixture.Binding,
                fixture.Now,
                Authenticate).Code);
        Assert.Equal(
            SidecarCapabilityErrors.SpoofedIdentity,
            SidecarCapabilityTransportValidation.ValidateActionRequest(
                roundTrip,
                fixture.Binding with { RequestId = Guid.NewGuid() },
                fixture.Now,
                Authenticate).Code);
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
            descriptor,
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

        Assert.True(fixture.Session.RevokeNestedHostActionEntryRelay(parentCall.CallId, fixture.Now).Accepted);
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

    [Fact]
    public void Host_entry_credit_allows_root_child_grandchild_at_the_call_budget_boundary()
    {
        var fixture = CreateFixture(maxInFlight: 4, maxCalls: 8);
        var rootContext = IssueContext(
            fixture,
            new RequestPrincipal("budget-root"),
            HostActionEntryIngress.Cli);
        ActivateContext(fixture, rootContext);
        ConsumeStorageCalls(fixture, 6, "grandchild-boundary");

        var rootCall = ActionCall(fixture, 7, "budget-root-call");
        var rootAction = Payload(typeof(string).AssemblyQualifiedName!, "root");
        Assert.True(fixture.Session.BeginCall(
            rootCall,
            SidecarCapabilityKind.Action,
            rootAction,
            rootAction.ByteLength,
            fixture.Now,
            rootContext).Accepted);

        var childDescriptor = NestedDescriptor("budget.child", "budget.child.input");
        var childAction = Payload(childDescriptor.InputTypeIdentity, "child");
        var childCall = ActionCall(fixture, 8, "budget-child-call");
        Assert.True(fixture.Session.IssueNestedHostActionEntryCarrier(
            rootCall,
            childCall,
            childDescriptor,
            childAction,
            NestedContribution(childDescriptor),
            fixture.Now,
            out var childCarrier).Accepted);
        Assert.NotNull(childCarrier);
        Assert.True(fixture.Session.BeginNestedHostActionEntryCall(
            childCarrier!,
            childCall,
            childAction,
            childAction.ByteLength,
            fixture.Now,
            out _).Accepted);

        var grandchildDescriptor = NestedDescriptor("budget.grandchild", "budget.grandchild.input");
        var grandchildAction = Payload(grandchildDescriptor.InputTypeIdentity, "grandchild");
        var grandchildCall = ActionCall(fixture, 9, "budget-grandchild-call");
        Assert.True(fixture.Session.IssueNestedHostActionEntryCarrier(
            childCall,
            grandchildCall,
            grandchildDescriptor,
            grandchildAction,
            NestedContribution(grandchildDescriptor),
            fixture.Now,
            out var grandchildCarrier).Accepted);
        Assert.NotNull(grandchildCarrier);
        Assert.True(fixture.Session.BeginNestedHostActionEntryCall(
            grandchildCarrier!,
            grandchildCall,
            grandchildAction,
            grandchildAction.ByteLength,
            fixture.Now,
            out _).Accepted);

        Assert.True(fixture.Session.CompleteCall(grandchildCall.CallId, 0).Accepted);
        Assert.True(fixture.Session.CompleteCall(childCall.CallId, 0).Accepted);
        Assert.True(fixture.Session.CompleteCall(rootCall.CallId, 0).Accepted);
    }

    [Fact]
    public async Task HostEntryStorageContinuationUsesAuthenticatedSequenceNineAuthorityOnce()
    {
        var fixture = CreateFixture(
            maxInFlight: 4,
            maxCalls: 8,
            authenticateStorageContinuationAuthority: (authority, hash) =>
                hash == SidecarCapabilityTransportValidation.ComputeStorageContinuationBindingHash(authority));
        ConsumeStorageCalls(fixture, 6, "storage-continuation-boundary");

        var parentCall = ActionCall(fixture, 7, "storage-continuation-parent");
        var parentDescriptor = NestedDescriptor("storage.parent", "storage.parent.input");
        var parentContext = IssueContext(
            fixture,
            new RequestPrincipal("storage-parent-caller"),
            HostActionEntryIngress.CrossModule,
            lineage: new HostActionEntryLineage(
                parentDescriptor.Key,
                parentDescriptor.Version,
                parentDescriptor.DescriptorHash,
                parentDescriptor.InputTypeIdentity,
                parentDescriptor.InputSchemaVersion,
                parentDescriptor.InputSchemaHash,
                null,
                null));
        var parentAction = Payload(parentDescriptor.InputTypeIdentity, new { value = 1 });
        ActivateContext(fixture, parentContext);
        Assert.True(fixture.Session.BeginCall(
            parentCall,
            SidecarCapabilityKind.Action,
            parentAction,
            parentAction.ByteLength,
            fixture.Now,
            parentContext).Accepted);
        Assert.True(fixture.Session.RecordTerminal(
            parentCall.CallId,
            Guid.NewGuid(),
            new SidecarTerminalReceipt(
                "storage-parent-receipt",
                parentDescriptor.Key,
                parentDescriptor.Version,
                parentCall.CallId,
                1,
                "storage-parent-scope",
                parentAction.ContentHash)).Accepted);

        var ordinaryCall = fixture.Call with
        {
            CallId = Guid.NewGuid(),
            ReplayNonce = "storage-continuation-ordinary",
            Sequence = 8,
        };
        var ordinaryPayload = Payload("storage.request", new { value = 8 });
        Assert.True(fixture.Session.BeginCall(
            ordinaryCall,
            SidecarCapabilityKind.Storage,
            ordinaryPayload,
            ordinaryPayload.ByteLength,
            fixture.Now).Accepted);
        Assert.True(fixture.Session.CompleteCall(ordinaryCall.CallId, 0).Accepted);

        var continuationCall = fixture.Call with
        {
            CallId = Guid.NewGuid(),
            ReplayNonce = "storage-continuation-nine",
            Sequence = 9,
            Deadline = fixture.Now.AddMinutes(1),
        };
        var continuationPayload = Payload("agent_job_imports.request", new { jobId = "job-1" });
        var continuationRequest = SidecarStorageCapabilityRequest.Invoke(
            continuationCall,
            fixture.Binding.ModuleId,
            "agent_job_imports/get",
            continuationPayload,
            PayloadType("agent_job_imports.result"),
            Cancellation(fixture),
            continuationCall.Deadline);
        var issue = fixture.Session.IssueHostEntryStorageContinuation(
            fixture.Session,
            parentCall,
            parentCall,
            continuationRequest,
            fixture.Now,
            (_, hash) => hash,
            out var authority);
        Assert.True(issue.Accepted, issue.Message);
        Assert.NotNull(authority);

        var wireAuthority = SidecarCapabilityTransportCodec.Deserialize<SidecarHostEntryStorageContinuationAuthority>(
            SidecarCapabilityTransportCodec.Serialize(authority));
        var requestWithAuthority = continuationRequest with
        {
            HostEntryContinuationAuthority = wireAuthority,
        };

        Assert.True(fixture.Session.ImportHostEntryStorageContinuationAuthority(wireAuthority, fixture.Now).Accepted);

        var changedAuthority = wireAuthority with { RootBudgetId = Guid.NewGuid() };
        Assert.Equal(
            SidecarCapabilityErrors.SpoofedIdentity,
            fixture.Session.BeginStorageContinuationCall(
                requestWithAuthority with { HostEntryContinuationAuthority = changedAuthority },
                continuationPayload.ByteLength,
                fixture.Now,
                out _).Code);
        Assert.Equal(
            SidecarCapabilityErrors.SpoofedIdentity,
            fixture.Session.BeginStorageContinuationCall(
                requestWithAuthority with { RequestPayload = Payload("agent_job_imports.request", new { jobId = "job-2" }) },
                continuationPayload.ByteLength,
                fixture.Now,
                out _).Code);
        Assert.Equal(
            SidecarCapabilityErrors.SpoofedIdentity,
            fixture.Session.BeginStorageContinuationCall(
                requestWithAuthority with
                {
                    Cancellation = requestWithAuthority.Cancellation with { AuthorityHash = "changed-cancellation" },
                },
                continuationPayload.ByteLength,
                fixture.Now,
                out _).Code);

        var concurrent = await Task.WhenAll(
            Task.Run(() =>
            {
                var result = fixture.Session.BeginStorageContinuationCall(
                    requestWithAuthority,
                    continuationPayload.ByteLength,
                    fixture.Now,
                    out var context);
                return (result, context);
            }),
            Task.Run(() =>
            {
                var result = fixture.Session.BeginStorageContinuationCall(
                    requestWithAuthority,
                    continuationPayload.ByteLength,
                    fixture.Now,
                    out var context);
                return (result, context);
            }));
        Assert.Single(concurrent, attempt => attempt.result.Accepted);
        Assert.Single(concurrent, attempt => attempt.result.Code == SidecarCapabilityErrors.Replay);
        Assert.NotNull(concurrent.Single(attempt => attempt.result.Accepted).context);
        Assert.Equal(
            SidecarCapabilityErrors.Replay,
            fixture.Session.BeginStorageContinuationCall(
                requestWithAuthority,
                continuationPayload.ByteLength,
                fixture.Now,
                out _).Code);
        Assert.Equal(
            SidecarCapabilityErrors.InvalidBinding,
            fixture.Session.CompleteCall(parentCall.CallId, 1).Code);
        Assert.True(fixture.Session.CompleteCall(continuationCall.CallId, 0).Accepted);
        Assert.True(fixture.Session.CompleteCall(parentCall.CallId, 1).Accepted);
    }

    [Fact]
    public void HostEntryStorageContinuationRejectsAfterIssuerCallAndCarrierComplete()
    {
        var source = CreateFixture(maxInFlight: 4, maxCalls: 8);
        var target = CreateFixture(
            maxInFlight: 4,
            maxCalls: 8,
            moduleId: "module-b",
            graphId: "graph-b",
            authenticateStorageContinuationAuthority: (authority, hash) =>
                hash == SidecarCapabilityTransportValidation.ComputeStorageContinuationBindingHash(authority) &&
                source.Session.IsStorageContinuationAuthorityLive(authority, source.Now));
        ConsumeStorageCalls(source, 6, "issuer-lifetime-source");
        ConsumeStorageCalls(target, 6, "issuer-lifetime-target");

        var descriptor = NestedDescriptor("issuer.lifetime.parent", typeof(string).AssemblyQualifiedName!);
        var action = Payload(descriptor.InputTypeIdentity, "parent");
        var sourceContext = IssueContext(
            source,
            new RequestPrincipal("issuer-caller"),
            HostActionEntryIngress.CrossModule,
            lineage: new HostActionEntryLineage(
                descriptor.Key,
                descriptor.Version,
                descriptor.DescriptorHash,
                descriptor.InputTypeIdentity,
                descriptor.InputSchemaVersion,
                descriptor.InputSchemaHash,
                null,
                null));
        var targetContext = IssueContext(
            target,
            new RequestPrincipal("target-caller"),
            HostActionEntryIngress.CrossModule,
            lineage: new HostActionEntryLineage(
                descriptor.Key,
                descriptor.Version,
                descriptor.DescriptorHash,
                descriptor.InputTypeIdentity,
                descriptor.InputSchemaVersion,
                descriptor.InputSchemaHash,
                null,
                null));
        var sourceCall = ActionCall(source, 7, "issuer-lifetime-source-parent");
        var targetCall = ActionCall(target, 7, "issuer-lifetime-target-parent");
        var sourceCarrier = ActivateContext(source, sourceContext!);
        var targetCarrier = ActivateContext(target, targetContext!);
        Assert.True(source.Session.BeginCall(
            sourceCall,
            SidecarCapabilityKind.Action,
            action,
            action.ByteLength,
            source.Now,
            sourceContext).Accepted);
        Assert.True(target.Session.BeginCall(
            targetCall,
            SidecarCapabilityKind.Action,
            action,
            action.ByteLength,
            target.Now,
            targetContext).Accepted);
        Assert.True(source.Session.RecordTerminal(
            sourceCall.CallId,
            Guid.NewGuid(),
            new SidecarTerminalReceipt(
                "issuer-lifetime-source-receipt",
                descriptor.Key,
                descriptor.Version,
                sourceCall.CallId,
                1,
                "issuer-lifetime-source-scope",
                action.ContentHash)).Accepted);
        Assert.True(target.Session.RecordTerminal(
            targetCall.CallId,
            Guid.NewGuid(),
            new SidecarTerminalReceipt(
                "issuer-lifetime-target-receipt",
                descriptor.Key,
                descriptor.Version,
                targetCall.CallId,
                1,
                "issuer-lifetime-target-scope",
                action.ContentHash)).Accepted);

        var storageCall = target.Call with
        {
            Capability = SidecarCapabilityKind.Storage,
            CallId = Guid.NewGuid(),
            ReplayNonce = "issuer-lifetime-storage",
            Sequence = 8,
            Deadline = targetCall.Deadline,
        };
        var storagePayload = Payload("agent_job_imports.request", new { jobId = "issuer-lifetime-job" });
        var storageRequest = SidecarStorageCapabilityRequest.Invoke(
            storageCall,
            target.Binding.ModuleId,
            "agent_job_imports/get",
            storagePayload,
            PayloadType("agent_job_imports.result"),
            Cancellation(target),
            storageCall.Deadline);
        var issue = source.Session.IssueHostEntryStorageContinuation(
            target.Session,
            sourceCall,
            targetCall,
            storageRequest,
            source.Now,
            (_, hash) => hash,
            out var authority);
        Assert.True(issue.Accepted, issue.Message);
        Assert.NotNull(authority);

        var wireAuthority = SidecarCapabilityTransportCodec.Deserialize<SidecarHostEntryStorageContinuationAuthority>(
            SidecarCapabilityTransportCodec.Serialize(authority));
        var requestWithAuthority = storageRequest with
        {
            HostEntryContinuationAuthority = wireAuthority,
        };
        Assert.True(target.Session.ImportHostEntryStorageContinuationAuthority(wireAuthority, target.Now).Accepted);

        Assert.True(source.Session.CompleteCall(sourceCall.CallId, 1).Accepted);
        Assert.True(source.Session.CompleteHostActionEntryCarrier(
            sourceCarrier,
            HostActionEntryCarrierCompletionKind.Succeeded,
            source.Now).Accepted);

        Assert.Equal(
            SidecarCapabilityErrors.SpoofedIdentity,
            target.Session.BeginStorageContinuationCall(
                requestWithAuthority,
                storagePayload.ByteLength,
                target.Now,
                out _).Code);

        Assert.True(target.Session.CompleteCall(targetCall.CallId, 1).Accepted);
        Assert.True(target.Session.CompleteHostActionEntryCarrier(
            targetCarrier,
            HostActionEntryCarrierCompletionKind.Succeeded,
            target.Now).Accepted);
        var laterCall = target.Call with
        {
            CallId = Guid.NewGuid(),
            ReplayNonce = "issuer-lifetime-later",
            Sequence = 8,
        };
        Assert.True(target.Session.BeginCall(
            laterCall,
            SidecarCapabilityKind.Storage,
            storagePayload,
            storagePayload.ByteLength,
            target.Now).Accepted);
        Assert.True(target.Session.CompleteCall(laterCall.CallId, 0).Accepted);
    }

    [Fact]
    public void Host_entry_credit_allows_two_sequential_children_without_increasing_the_limit()
    {
        var fixture = CreateFixture(maxInFlight: 3, maxCalls: 8);
        var rootContext = IssueContext(
            fixture,
            new RequestPrincipal("sequential-root"),
            HostActionEntryIngress.Cli);
        ActivateContext(fixture, rootContext);
        ConsumeStorageCalls(fixture, 6, "sequential-boundary");

        var rootCall = ActionCall(fixture, 7, "sequential-root-call");
        var rootAction = Payload(typeof(string).AssemblyQualifiedName!, "root");
        Assert.True(fixture.Session.BeginCall(
            rootCall,
            SidecarCapabilityKind.Action,
            rootAction,
            rootAction.ByteLength,
            fixture.Now,
            rootContext).Accepted);

        for (var index = 1; index <= 2; index++)
        {
            var descriptor = NestedDescriptor($"budget.child.{index}", $"budget.child.{index}.input");
            var action = Payload(descriptor.InputTypeIdentity, $"child-{index}");
            var childCall = ActionCall(fixture, 7 + index, $"sequential-child-{index}");
            Assert.True(fixture.Session.IssueNestedHostActionEntryCarrier(
                rootCall,
                childCall,
                descriptor,
                action,
                NestedContribution(descriptor),
                fixture.Now,
                out var carrier).Accepted);
            Assert.NotNull(carrier);
            Assert.True(fixture.Session.BeginNestedHostActionEntryCall(
                carrier!,
                childCall,
                action,
                action.ByteLength,
                fixture.Now,
                out _).Accepted);
            Assert.True(fixture.Session.CompleteCall(childCall.CallId, 0).Accepted);
        }

        Assert.True(fixture.Session.CompleteCall(rootCall.CallId, 0).Accepted);
    }

    [Fact]
    public void Host_entry_credits_are_isolated_for_two_pending_contexts_and_replay_is_rejected()
    {
        var fixture = CreateFixture(maxInFlight: 4, maxCalls: 8);
        var firstContext = IssueContext(
            fixture,
            new RequestPrincipal("first-root"),
            HostActionEntryIngress.Cli);
        var secondContext = IssueContext(
            fixture,
            new RequestPrincipal("second-root"),
            HostActionEntryIngress.Cli);
        ActivateContext(fixture, firstContext);
        ActivateContext(fixture, secondContext);
        ConsumeStorageCalls(fixture, 6, "two-pending-boundary");

        var firstCall = ActionCall(fixture, 7, "first-root-call");
        var secondCall = ActionCall(fixture, 8, "second-root-call");
        var rootAction = Payload(typeof(string).AssemblyQualifiedName!, "root");
        Assert.True(fixture.Session.BeginCall(
            firstCall,
            SidecarCapabilityKind.Action,
            rootAction,
            rootAction.ByteLength,
            fixture.Now,
            firstContext).Accepted);
        Assert.True(fixture.Session.BeginCall(
            secondCall,
            SidecarCapabilityKind.Action,
            rootAction,
            rootAction.ByteLength,
            fixture.Now,
            secondContext).Accepted);

        var descriptor = NestedDescriptor("budget.pending.child", "budget.pending.child.input");
        var action = Payload(descriptor.InputTypeIdentity, "pending-child");
        var firstChildCall = ActionCall(fixture, 9, "first-child-call");
        var secondChildCall = ActionCall(fixture, 10, "second-child-call");
        Assert.True(fixture.Session.IssueNestedHostActionEntryCarrier(
            firstCall,
            firstChildCall,
            descriptor,
            action,
            NestedContribution(descriptor),
            fixture.Now,
            out var firstCarrier).Accepted);
        Assert.True(fixture.Session.IssueNestedHostActionEntryCarrier(
            secondCall,
            secondChildCall,
            descriptor,
            action,
            NestedContribution(descriptor),
            fixture.Now,
            out var secondCarrier).Accepted);
        Assert.NotNull(firstCarrier);
        Assert.NotNull(secondCarrier);
        var firstBegin = fixture.Session.BeginNestedHostActionEntryCall(
                firstCarrier!,
                firstChildCall,
                action,
                action.ByteLength,
                fixture.Now,
                out _);
        Assert.True(firstBegin.Accepted, firstBegin.Message);
        var replay = fixture.Session.BeginNestedHostActionEntryCall(
            firstCarrier!,
            firstChildCall,
            action,
            action.ByteLength,
            fixture.Now,
            out _);
        Assert.Equal(SidecarCapabilityErrors.Replay, replay.Code);
        Assert.True(fixture.Session.BeginNestedHostActionEntryCall(
            secondCarrier!,
            secondChildCall,
            action,
            action.ByteLength,
            fixture.Now,
            out _).Accepted);
        Assert.True(fixture.Session.CompleteCall(firstChildCall.CallId, 0).Accepted);
        Assert.True(fixture.Session.CompleteCall(secondChildCall.CallId, 0).Accepted);
        Assert.True(fixture.Session.CompleteCall(firstCall.CallId, 0).Accepted);
        Assert.True(fixture.Session.CompleteCall(secondCall.CallId, 0).Accepted);
    }

    [Fact]
    public void Host_entry_credit_is_revoked_on_expiry_cancellation_and_rotation()
    {
        var fixture = CreateFixture(maxCalls: 8);
        var expiredContext = IssueContext(
            fixture,
            new RequestPrincipal("expired"),
            HostActionEntryIngress.Cli,
            actionDeadline: fixture.Now.AddSeconds(1),
            contextExpiresAt: fixture.Now.AddSeconds(1));
        var expiredAuthority = ActivateContext(fixture, expiredContext);
        Assert.Equal(1, fixture.Session.SweepExpiredHostActionEntryCarriers(fixture.Now.AddSeconds(2)));
        Assert.Equal(
            SidecarCapabilityErrors.Replay,
            fixture.Session.CompleteHostActionEntryCarrier(
                expiredAuthority,
                HostActionEntryCarrierCompletionKind.Cancelled,
                fixture.Now.AddSeconds(2)).Code);

        var cancelledContext = IssueContext(
            fixture,
            new RequestPrincipal("cancelled"),
            HostActionEntryIngress.Cli);
        var cancelledAuthority = ActivateContext(fixture, cancelledContext);
        Assert.True(fixture.Session.CompleteHostActionEntryCarrier(
            cancelledAuthority,
            HostActionEntryCarrierCompletionKind.Cancelled,
            fixture.Now).Accepted);

        var rotatedContext = IssueContext(
            fixture,
            new RequestPrincipal("rotated"),
            HostActionEntryIngress.Cli);
        var rotatedAuthority = ActivateContext(fixture, rotatedContext);
        var replacement = CreateRotatedBinding(fixture, "budget-rotation");
        fixture.BindingHashes.Add(replacement.Authentication.BindingHash);
        Assert.True(fixture.Session.RotateBinding(replacement, fixture.Now).Accepted);
        Assert.True(fixture.Session.TryGetActiveHostActionEntryCarrier(
            rotatedAuthority.CapabilityId,
            out var rebasedAuthority));
        Assert.True(fixture.Session.CompleteHostActionEntryCarrier(
            rebasedAuthority!,
            HostActionEntryCarrierCompletionKind.Failed,
            fixture.Now).Accepted);
    }

    [Fact]
    public async Task Host_entry_carrier_concurrent_replay_consumes_one_child_only()
    {
        var fixture = CreateFixture(maxInFlight: 3, maxCalls: 4);
        var rootContext = IssueContext(
            fixture,
            new RequestPrincipal("concurrent-root"),
            HostActionEntryIngress.Cli);
        ActivateContext(fixture, rootContext);
        var rootCall = ActionCall(fixture, 1, "concurrent-root-call");
        var rootAction = Payload(typeof(string).AssemblyQualifiedName!, "root");
        Assert.True(fixture.Session.BeginCall(
            rootCall,
            SidecarCapabilityKind.Action,
            rootAction,
            rootAction.ByteLength,
            fixture.Now,
            rootContext).Accepted);

        var descriptor = NestedDescriptor("budget.concurrent.child", "budget.concurrent.input");
        var action = Payload(descriptor.InputTypeIdentity, "child");
        var childCall = ActionCall(fixture, 2, "concurrent-child-call");
        Assert.True(fixture.Session.IssueNestedHostActionEntryCarrier(
            rootCall,
            childCall,
            descriptor,
            action,
            NestedContribution(descriptor),
            fixture.Now,
            out var carrier).Accepted);
        Assert.NotNull(carrier);

        var results = await Task.WhenAll(
            Task.Run(() => fixture.Session.BeginNestedHostActionEntryCall(
                carrier!,
                childCall,
                action,
                action.ByteLength,
                fixture.Now,
                out _)),
            Task.Run(() => fixture.Session.BeginNestedHostActionEntryCall(
                carrier!,
                childCall,
                action,
                action.ByteLength,
                fixture.Now,
                out _)));

        Assert.Single(results, result => result.Accepted);
        Assert.Single(results, result => result.Code == SidecarCapabilityErrors.Replay);
        Assert.True(fixture.Session.CompleteCall(childCall.CallId, 0).Accepted);
        Assert.True(fixture.Session.CompleteCall(rootCall.CallId, 0).Accepted);
    }

    [Fact]
    public void Host_entry_credit_is_removed_on_disconnect()
    {
        var fixture = CreateFixture();
        var context = IssueContext(
            fixture,
            new RequestPrincipal("disconnect-root"),
            HostActionEntryIngress.Cli);
        var authority = ActivateContext(fixture, context);

        fixture.Session.Disconnect();

        Assert.Equal(
            SidecarCapabilityErrors.Disconnected,
            fixture.Session.CompleteHostActionEntryCarrier(
                authority,
                HostActionEntryCarrierCompletionKind.Cancelled,
                fixture.Now).Code);
        Assert.Equal(0, fixture.Session.IssuedHostActionEntryContextCount);
        Assert.Equal(0, fixture.Session.ActiveHostActionEntryCarrierCount);
    }

    [Fact]
    public void Host_terminal_relay_issues_one_fresh_child_carrier_and_blocks_parent_completion()
    {
        var fixture = CreateFixture(maxInFlight: 3, maxCalls: 4);
        var rootDescriptor = new SidecarActionDescriptorIdentity(
            new SharpClawActionKey("parent.relay"),
            1,
            "parent",
            typeof(string).AssemblyQualifiedName!,
            "parent-input",
            1,
            typeof(string).AssemblyQualifiedName!,
            "parent-result",
            1,
            "parent-relay-descriptor");
        var childDescriptor = new SidecarActionDescriptorIdentity(
            new SharpClawActionKey("child.relay"),
            1,
            "child",
            typeof(string).AssemblyQualifiedName!,
            "child-input",
            1,
            typeof(string).AssemblyQualifiedName!,
            "child-result",
            1,
            "child-relay-descriptor");
        var rootAction = Payload(rootDescriptor.InputTypeIdentity, "parent");
        var childAction = Payload(childDescriptor.InputTypeIdentity, "child");
        var rootContext = IssueContext(
            fixture,
            new RequestPrincipal("relay-caller", Roles: new HashSet<string>(["operator"])),
            HostActionEntryIngress.Cli,
            lineage: new HostActionEntryLineage(
                rootDescriptor.Key,
                rootDescriptor.Version,
                rootDescriptor.DescriptorHash,
                rootDescriptor.InputTypeIdentity,
                rootDescriptor.InputSchemaVersion,
                rootDescriptor.InputSchemaHash,
                null,
                null));
        var rootAuthority = ActivateContext(fixture, rootContext);
        var parentCall = fixture.Call with
        {
            Capability = SidecarCapabilityKind.Action,
            CallId = Guid.NewGuid(),
            ReplayNonce = "relay-parent",
            Sequence = 1,
        };
        var contribution = new HostActionEntryContribution(
            new HostActionEntryIngressBinding(
                HostActionEntryIngress.CrossModule,
                "module-a",
                "module-b"),
            new HostActionEntryLineage(
                childDescriptor.Key,
                childDescriptor.Version,
                childDescriptor.DescriptorHash,
                childDescriptor.InputTypeIdentity,
                childDescriptor.InputSchemaVersion,
                childDescriptor.InputSchemaHash,
                null,
                null));
        var nestedRequest = new SidecarNestedHostActionEntryRequest(
            childDescriptor.Key,
            childDescriptor.Version,
            childAction,
            fixture.Now.AddSeconds(20),
            fixture.Now.AddSeconds(25));
        var rootRequest = SidecarActionCapabilityRequest.HostEntry(
            parentCall,
            rootDescriptor,
            rootAction,
            new SidecarCancellationIdentity(parentCall.CancellationId, "relay-cancel", parentCall.Deadline),
            parentCall.Deadline,
            rootContext,
            new SidecarActionTerminalRegistration(
                Guid.NewGuid(),
                rootDescriptor.InputTypeIdentity,
                rootDescriptor.InputSchemaVersion,
                rootDescriptor.ResultTypeIdentity,
                rootDescriptor.ResultSchemaVersion,
                rootDescriptor.DescriptorHash));

        Assert.True(fixture.Session.BeginActionCall(
            rootRequest,
            rootAction.ByteLength,
            fixture.Now,
            out _).Accepted);

        var receipt = new SidecarTerminalReceipt(
            "relay-receipt",
            rootDescriptor.Key,
            rootDescriptor.Version,
            parentCall.CallId,
            1,
            "relay-scope",
            rootAction.ContentHash);
        Assert.True(fixture.Session.RecordTerminal(parentCall.CallId, Guid.NewGuid(), receipt).Accepted);
        Assert.Equal(
            SidecarCapabilityErrors.InvalidBinding,
            fixture.Session.IssueNestedHostActionEntryRelay(
                parentCall with { CallId = Guid.NewGuid(), ReplayNonce = "wrong-parent" },
                nestedRequest,
                childDescriptor,
                contribution,
                fixture.Now,
                out _).Code);
        Assert.True(fixture.Session.IssueNestedHostActionEntryRelay(
            parentCall,
            nestedRequest,
            childDescriptor,
            contribution,
            fixture.Now,
            out var relay).Accepted);
        Assert.NotNull(relay);
        Assert.True(relay!.IsWellFormed);
        Assert.Equal(parentCall.CallId, relay.Carrier.ParentCallId);
        Assert.Equal(relay.Call.CallId, relay.Carrier.CallId);
        Assert.Equal(
            SidecarCapabilityErrors.InvalidBinding,
            fixture.Session.CompleteCall(parentCall.CallId, 1).Code);

        var unrelatedBeforeChild = fixture.Call with
        {
            Capability = SidecarCapabilityKind.Storage,
            CallId = Guid.NewGuid(),
            ReplayNonce = "relay-unrelated-before-child",
            Sequence = 3,
        };
        Assert.True(fixture.Session.BeginCall(
            unrelatedBeforeChild,
            SidecarCapabilityKind.Storage,
            null,
            0,
            fixture.Now).Accepted);
        Assert.True(fixture.Session.CompleteCall(unrelatedBeforeChild.CallId, 0).Accepted);

        var terminalRequest = CreateTerminalRequest(
            fixture,
            rootRequest,
            new ActionPipelineSnapshot("relay-graph", [])) with
        {
            NestedCarrierRequest = nestedRequest,
        };
        var relayAuthority = terminalRequest.Authority with
        {
            NestedCarrierRelay = relay,
            NestedCarrierOutcomeKind = SidecarNestedHostActionEntryRelayOutcomeKind.Issued,
            NestedCarrierRequestFingerprint =
                SidecarCapabilityTransportValidation.ComputeNestedCarrierRequestFingerprint(nestedRequest),
            Proof = "relay-proof",
        };
        relayAuthority = relayAuthority with
        {
            CanonicalBindingHash =
                SidecarCapabilityTransportValidation.ComputeTerminalAuthorityBindingHash(
                    relayAuthority),
        };
        Assert.True(SidecarCapabilityTransportValidation.ValidateActionTerminalRequest(
            rootRequest,
            terminalRequest,
            fixture.Binding,
            fixture.Now,
            (authority, bindingHash) => authority.Proof == "host-proof" &&
                bindingHash == SidecarCapabilityTransportValidation.ComputeTerminalAuthorityBindingHash(authority)).Accepted);
        var parentResult = Payload(rootDescriptor.ResultTypeIdentity, "parent-result");
        var terminalResponse = new SidecarActionTerminalTransportResponse(
            new SidecarActionResultIdentity(
                Guid.NewGuid(),
                parentCall.CallId,
                rootDescriptor.Key,
                rootDescriptor.Version,
                rootDescriptor.ResultTypeIdentity,
                parentResult.ContentHash),
            new SidecarTerminalExecutionResult(parentResult, null, true),
            terminalRequest.Receipt,
            fixture.SafeFailure)
        {
            TerminalId = terminalRequest.TerminalId,
            NestedCarrierRelay = relay,
            NestedCarrierAuthority = relayAuthority,
            NestedCarrierOutcome = new(
                SidecarNestedHostActionEntryRelayOutcomeKind.Issued,
                null),
        };
        Assert.True(SidecarCapabilityTransportValidation.ValidateActionTerminalResponse(
            terminalRequest,
            terminalResponse,
            fixture.Binding,
            (authority, bindingHash) => authority.Proof == "relay-proof" &&
                bindingHash == SidecarCapabilityTransportValidation.ComputeTerminalAuthorityBindingHash(authority)).Accepted);
        Assert.Equal(
            SidecarCapabilityErrors.InvalidResponse,
            SidecarCapabilityTransportValidation.ValidateActionTerminalResponse(
                terminalRequest,
                terminalResponse with
                {
                    NestedCarrierRelay = relay! with
                    {
                        Carrier = relay!.Carrier with { ActionContentHash = "changed" },
                    },
                },
                fixture.Binding,
                (_, _) => true).Code);

        SidecarHostTerminalAuthority SignRelayOutcome(
            SidecarNestedHostActionEntryRelayOutcomeKind kind,
            string proof) =>
            (terminalRequest.Authority with
            {
                NestedCarrierOutcomeKind = kind,
                NestedCarrierRequestFingerprint =
                    SidecarCapabilityTransportValidation.ComputeNestedCarrierRequestFingerprint(nestedRequest),
                Proof = proof,
            }) with
            {
                CanonicalBindingHash =
                    SidecarCapabilityTransportValidation.ComputeTerminalAuthorityBindingHash(
                        terminalRequest.Authority with
                        {
                            NestedCarrierOutcomeKind = kind,
                            NestedCarrierRequestFingerprint =
                                SidecarCapabilityTransportValidation.ComputeNestedCarrierRequestFingerprint(nestedRequest),
                            Proof = proof,
                        }),
            };

        var failedAuthority = SignRelayOutcome(
            SidecarNestedHostActionEntryRelayOutcomeKind.Failed,
            "failed-proof");
        var failedResponse = terminalResponse with
        {
            NestedCarrierRelay = null,
            NestedCarrierAuthority = failedAuthority,
            NestedCarrierOutcome = new(
                SidecarNestedHostActionEntryRelayOutcomeKind.Failed,
                fixture.SafeFailure),
            ResultIdentity = null,
            Execution = new SidecarTerminalExecutionResult(null, fixture.SafeFailure, true),
        };
        var failedWireResponse = SidecarCapabilityTransportCodec.Deserialize<SidecarActionTerminalTransportResponse>(
            SidecarCapabilityTransportCodec.Serialize(failedResponse));
        Assert.True(SidecarCapabilityTransportValidation.ValidateActionTerminalResponse(
            terminalRequest,
            failedWireResponse,
            fixture.Binding,
            (authority, bindingHash) => authority.Proof == "failed-proof" &&
                bindingHash == SidecarCapabilityTransportValidation.ComputeTerminalAuthorityBindingHash(authority)).Accepted);

        var cancelledAuthority = SignRelayOutcome(
            SidecarNestedHostActionEntryRelayOutcomeKind.Cancelled,
            "cancelled-proof");
        var cancelledResponse = terminalResponse with
        {
            NestedCarrierRelay = null,
            NestedCarrierAuthority = cancelledAuthority,
            NestedCarrierOutcome = new(
                SidecarNestedHostActionEntryRelayOutcomeKind.Cancelled,
                fixture.SafeFailure),
            ResultIdentity = null,
            Execution = new SidecarTerminalExecutionResult(null, fixture.SafeFailure, true),
        };
        var cancelledWireResponse = SidecarCapabilityTransportCodec.Deserialize<SidecarActionTerminalTransportResponse>(
            SidecarCapabilityTransportCodec.Serialize(cancelledResponse));
        Assert.True(SidecarCapabilityTransportValidation.ValidateActionTerminalResponse(
            terminalRequest,
            cancelledWireResponse,
            fixture.Binding,
            (authority, bindingHash) => authority.Proof == "cancelled-proof" &&
                bindingHash == SidecarCapabilityTransportValidation.ComputeTerminalAuthorityBindingHash(authority)).Accepted);

        void AssertNestedRequestSubstitutionRejected(
            SidecarActionTerminalTransportResponse response,
            SidecarNestedHostActionEntryRequest substitutedRequest)
        {
            var substitutedTerminalRequest = SidecarCapabilityTransportCodec.Deserialize<SidecarActionTerminalTransportRequest>(
                SidecarCapabilityTransportCodec.Serialize(
                    terminalRequest with { NestedCarrierRequest = substitutedRequest }));
            var substitutedResponse = SidecarCapabilityTransportCodec.Deserialize<SidecarActionTerminalTransportResponse>(
                SidecarCapabilityTransportCodec.Serialize(response));
            Assert.False(SidecarCapabilityTransportValidation.ValidateActionTerminalResponse(
                substitutedTerminalRequest,
                substitutedResponse,
                fixture.Binding,
                (_, _) => true).Accepted);
        }

        var descriptorKeySubstitution = nestedRequest with
        {
            ActionKey = new SharpClawActionKey("nested.other"),
        };
        var descriptorVersionSubstitution = nestedRequest with
        {
            ActionVersion = nestedRequest.ActionVersion + 1,
        };
        var payloadSubstitution = nestedRequest with
        {
            Action = Payload(nestedRequest.Action.TypeIdentity, "changed-nested-payload"),
        };
        var deadlineSubstitution = nestedRequest with
        {
            Deadline = nestedRequest.Deadline.AddSeconds(-1),
        };
        var expirySubstitution = nestedRequest with
        {
            ExpiresAt = nestedRequest.ExpiresAt.AddSeconds(1),
        };
        foreach (var substitutedRequest in new[]
        {
            descriptorKeySubstitution,
            descriptorVersionSubstitution,
            payloadSubstitution,
            deadlineSubstitution,
            expirySubstitution,
        })
        {
            AssertNestedRequestSubstitutionRejected(failedResponse, substitutedRequest);
            AssertNestedRequestSubstitutionRejected(cancelledResponse, substitutedRequest);
        }

        Assert.Equal(
            SidecarCapabilityErrors.InvalidResponse,
            SidecarCapabilityTransportValidation.ValidateActionTerminalResponse(
                terminalRequest,
                SidecarCapabilityTransportCodec.Deserialize<SidecarActionTerminalTransportResponse>(
                    SidecarCapabilityTransportCodec.Serialize(
                        terminalResponse with
                        {
                            Execution = new SidecarTerminalExecutionResult(null, fixture.SafeFailure, true),
                            ResultIdentity = null,
                        })),
                fixture.Binding,
                (_, _) => true).Code);
        Assert.Equal(
            SidecarCapabilityErrors.InvalidResponse,
            SidecarCapabilityTransportValidation.ValidateActionTerminalResponse(
                terminalRequest,
                SidecarCapabilityTransportCodec.Deserialize<SidecarActionTerminalTransportResponse>(
                    SidecarCapabilityTransportCodec.Serialize(
                        failedResponse with
                        {
                            Execution = new SidecarTerminalExecutionResult(parentResult, null, true),
                            ResultIdentity = terminalResponse.ResultIdentity,
                        })),
                fixture.Binding,
                (_, _) => true).Code);
        Assert.Equal(
            SidecarCapabilityErrors.InvalidResponse,
            SidecarCapabilityTransportValidation.ValidateActionTerminalResponse(
                terminalRequest,
                SidecarCapabilityTransportCodec.Deserialize<SidecarActionTerminalTransportResponse>(
                    SidecarCapabilityTransportCodec.Serialize(
                        failedResponse with
                        {
                            NestedCarrierOutcome = new(
                                SidecarNestedHostActionEntryRelayOutcomeKind.Failed,
                                new SidecarSafeFailureIdentity(
                                    Guid.NewGuid(),
                                    fixture.SafeFailure.Code,
                                    fixture.SafeFailure.Message)),
                        })),
                fixture.Binding,
                (_, _) => true).Code);
        Assert.Equal(
            SidecarCapabilityErrors.InvalidResponse,
            SidecarCapabilityTransportValidation.ValidateActionTerminalResponse(
                terminalRequest,
                SidecarCapabilityTransportCodec.Deserialize<SidecarActionTerminalTransportResponse>(
                    SidecarCapabilityTransportCodec.Serialize(
                        failedResponse with
                        {
                            NestedCarrierOutcome = new(
                                SidecarNestedHostActionEntryRelayOutcomeKind.Cancelled,
                                fixture.SafeFailure),
                        })),
                fixture.Binding,
                (_, _) => true).Code);

        var childRequest = SidecarActionCapabilityRequest.HostEntryNested(
            relay.Call,
            childDescriptor,
            childAction,
            new SidecarCancellationIdentity(
                relay.Call.CancellationId,
                "relay-child-cancel",
                relay.Call.Deadline),
            relay.Call.Deadline,
            relay.Carrier,
            new SidecarActionTerminalRegistration(
                Guid.NewGuid(),
                childDescriptor.InputTypeIdentity,
                childDescriptor.InputSchemaVersion,
                childDescriptor.ResultTypeIdentity,
                childDescriptor.ResultSchemaVersion,
                childDescriptor.DescriptorHash));
        Assert.True(fixture.Session.BeginActionCall(
            childRequest,
            childAction.ByteLength,
            fixture.Now,
            out var childContext).Accepted);
        Assert.Equal(rootContext.InvocationId, childContext!.ParentInvocationId);
        var childReceipt = new SidecarTerminalReceipt(
            "relay-child-receipt",
            childDescriptor.Key,
            childDescriptor.Version,
            relay.Call.CallId,
            1,
            "relay-child-scope",
            childAction.ContentHash);
        Assert.True(fixture.Session.RecordTerminal(
            relay.Call.CallId,
            Guid.NewGuid(),
            childReceipt).Accepted);

        var grandchildAction = Payload(childDescriptor.InputTypeIdentity, "grandchild");
        var grandchildRequest = new SidecarNestedHostActionEntryRequest(
            childDescriptor.Key,
            childDescriptor.Version,
            grandchildAction,
            fixture.Now.AddSeconds(20),
            fixture.Now.AddSeconds(20));
        Assert.True(fixture.Session.IssueNestedHostActionEntryRelay(
            relay.Call,
            grandchildRequest,
            childDescriptor,
            contribution,
            fixture.Now,
            out var grandchildRelay).Accepted);
        Assert.NotNull(grandchildRelay);
        var grandchildCapabilityRequest = SidecarActionCapabilityRequest.HostEntryNested(
            grandchildRelay!.Call,
            childDescriptor,
            grandchildAction,
            new SidecarCancellationIdentity(
                grandchildRelay.Call.CancellationId,
                "relay-grandchild-cancel",
                grandchildRelay.Call.Deadline),
            grandchildRelay.Call.Deadline,
            grandchildRelay.Carrier,
            new SidecarActionTerminalRegistration(
                Guid.NewGuid(),
                childDescriptor.InputTypeIdentity,
                childDescriptor.InputSchemaVersion,
                childDescriptor.ResultTypeIdentity,
                childDescriptor.ResultSchemaVersion,
                childDescriptor.DescriptorHash));
        Assert.True(fixture.Session.BeginActionCall(
            grandchildCapabilityRequest,
            grandchildAction.ByteLength,
            fixture.Now,
            out _).Accepted);
        var grandchildReceipt = new SidecarTerminalReceipt(
            "relay-grandchild-receipt",
            childDescriptor.Key,
            childDescriptor.Version,
            grandchildRelay.Call.CallId,
            1,
            "relay-grandchild-scope",
            grandchildAction.ContentHash);
        Assert.True(fixture.Session.RecordTerminal(
            grandchildRelay.Call.CallId,
            Guid.NewGuid(),
            grandchildReceipt).Accepted);

        Assert.Equal(
            SidecarCapabilityErrors.InvalidBinding,
            fixture.Session.CompleteCall(parentCall.CallId, 1).Code);
        Assert.True(fixture.Session.CompleteCall(grandchildRelay.Call.CallId, 1).Accepted);
        var childCompletion = fixture.Session.CompleteCall(relay.Call.CallId, 1);
        Assert.True(childCompletion.Accepted, $"{childCompletion.Code}: {childCompletion.Message}");
        Assert.True(fixture.Session.CompleteCall(parentCall.CallId, 1).Accepted);
        Assert.True(fixture.Session.CompleteHostActionEntryCarrier(
            rootAuthority,
            HostActionEntryCarrierCompletionKind.Succeeded,
            fixture.Now).Accepted);

        Assert.Equal(
            SidecarCapabilityErrors.InvalidBinding,
            fixture.Session.IssueNestedHostActionEntryRelay(
                parentCall,
                nestedRequest,
                childDescriptor,
                contribution,
                fixture.Now,
                out _).Code);
    }

    [Fact]
    public void Nested_host_entry_resolution_binds_the_host_resolved_child_descriptor()
    {
        var fixture = CreateFixture(maxInFlight: 3, maxCalls: 4);
        var parentDescriptor = new SidecarActionDescriptorIdentity(
            new SharpClawActionKey("parent.resolve"),
            1,
            "parent",
            typeof(int).AssemblyQualifiedName!,
            "parent-resolve-input",
            2,
            typeof(bool).AssemblyQualifiedName!,
            "parent-resolve-result",
            3,
            "parent-resolve-descriptor");
        var childDescriptor = new SidecarActionDescriptorIdentity(
            new SharpClawActionKey("child.resolve"),
            2,
            "child",
            typeof(Guid).AssemblyQualifiedName!,
            "child-resolve-input",
            4,
            typeof(DateTime).AssemblyQualifiedName!,
            "child-resolve-result",
            5,
            "child-resolve-descriptor");
        var parentAction = Payload(parentDescriptor.InputTypeIdentity, 7) with
        {
            SchemaVersion = parentDescriptor.InputSchemaVersion,
        };
        var childAction = Payload(childDescriptor.InputTypeIdentity, Guid.NewGuid()) with
        {
            SchemaVersion = childDescriptor.InputSchemaVersion,
        };
        var parentContext = IssueContext(
            fixture,
            new RequestPrincipal("resolution-caller"),
            HostActionEntryIngress.Endpoint,
            lineage: new HostActionEntryLineage(
                parentDescriptor.Key,
                parentDescriptor.Version,
                parentDescriptor.DescriptorHash,
                parentDescriptor.InputTypeIdentity,
                parentDescriptor.InputSchemaVersion,
                parentDescriptor.InputSchemaHash,
                null,
                null));
        ActivateContext(fixture, parentContext);
        var parentCall = fixture.Call with
        {
            Capability = SidecarCapabilityKind.Action,
            CallId = Guid.NewGuid(),
            ReplayNonce = "resolve-parent",
            Sequence = 1,
        };
        var parentRequest = SidecarActionCapabilityRequest.HostEntry(
            parentCall,
            parentDescriptor,
            parentAction,
            new SidecarCancellationIdentity(parentCall.CancellationId, "resolve-cancel", parentCall.Deadline),
            parentCall.Deadline,
            parentContext,
            new SidecarActionTerminalRegistration(
                Guid.NewGuid(),
                parentDescriptor.InputTypeIdentity,
                parentDescriptor.InputSchemaVersion,
                parentDescriptor.ResultTypeIdentity,
                parentDescriptor.ResultSchemaVersion,
                parentDescriptor.DescriptorHash));
        var parentBegin = fixture.Session.BeginActionCall(
            SidecarCapabilityTransportCodec.Deserialize<SidecarActionCapabilityRequest>(
                SidecarCapabilityTransportCodec.Serialize(parentRequest)),
            parentAction.ByteLength,
            fixture.Now,
            out _);
        Assert.True(parentBegin.Accepted, $"{parentBegin.Code}: {parentBegin.Message}");
        Assert.True(fixture.Session.RecordTerminal(
            parentCall.CallId,
            Guid.NewGuid(),
            new SidecarTerminalReceipt(
                "resolve-receipt",
                parentDescriptor.Key,
                parentDescriptor.Version,
                parentCall.CallId,
                1,
                "resolve-scope",
                parentAction.ContentHash)).Accepted);

        var contribution = new HostActionEntryContribution(
            new HostActionEntryIngressBinding(HostActionEntryIngress.CrossModule, "parent", "child"),
            new HostActionEntryLineage(
                childDescriptor.Key,
                childDescriptor.Version,
                childDescriptor.DescriptorHash,
                childDescriptor.InputTypeIdentity,
                childDescriptor.InputSchemaVersion,
                childDescriptor.InputSchemaHash,
                null,
                null));
        var nestedRequest = new SidecarNestedHostActionEntryRequest(
            childDescriptor.Key,
            childDescriptor.Version,
            childAction,
            fixture.Now.AddSeconds(20),
            fixture.Now.AddSeconds(25));
        var wireRequest = SidecarCapabilityTransportCodec.Deserialize<SidecarNestedHostActionEntryRequest>(
            SidecarCapabilityTransportCodec.Serialize(nestedRequest));

        var wrongDescriptor = childDescriptor with
        {
            DescriptorHash = "child-resolve-wrong-descriptor",
        };
        Assert.Equal(
            SidecarCapabilityErrors.SpoofedIdentity,
            fixture.Session.IssueNestedHostActionEntryRelay(
                parentCall,
                wireRequest,
                wrongDescriptor,
                contribution,
                fixture.Now,
                out _).Code);

        var wrongSchemaDescriptor = childDescriptor with
        {
            InputSchemaHash = "child-resolve-wrong-schema",
        };
        Assert.Equal(
            SidecarCapabilityErrors.SpoofedIdentity,
            fixture.Session.IssueNestedHostActionEntryRelay(
                parentCall,
                wireRequest,
                wrongSchemaDescriptor,
                contribution,
                fixture.Now,
                out _).Code);

        var wrongContribution = contribution with
        {
            Lineage = contribution.Lineage with
            {
                DescriptorHash = "child-resolve-wrong-lineage",
            },
        };
        Assert.Equal(
            SidecarCapabilityErrors.SpoofedIdentity,
            fixture.Session.IssueNestedHostActionEntryRelay(
                parentCall,
                wireRequest,
                childDescriptor,
                wrongContribution,
                fixture.Now,
                out _).Code);

        Assert.True(fixture.Session.IssueNestedHostActionEntryRelay(
            parentCall,
            wireRequest,
            childDescriptor,
            contribution,
            fixture.Now,
            out var relay).Accepted);
        Assert.NotNull(relay);
        Assert.Equal(childDescriptor.Key, relay!.Carrier.ActionKey);
        Assert.Equal(childDescriptor.Version, relay.Carrier.ActionVersion);
        Assert.Equal(childDescriptor.DescriptorHash, relay.Carrier.DescriptorHash);
        Assert.Equal(childAction.ContentHash, relay.Carrier.ActionContentHash);
    }

    [Fact]
    public void Host_terminal_relay_requires_terminal_authority_and_revokes_pending_request()
    {
        var fixture = CreateFixture();
        var descriptor = new SidecarActionDescriptorIdentity(
            new SharpClawActionKey("parent.revoke"),
            1,
            "parent",
            typeof(string).AssemblyQualifiedName!,
            "parent-input",
            1,
            typeof(string).AssemblyQualifiedName!,
            "parent-result",
            1,
            "parent-revoke-descriptor");
        var context = IssueContext(
            fixture,
            new RequestPrincipal("revoke-caller"),
            HostActionEntryIngress.Endpoint,
            lineage: new HostActionEntryLineage(
                descriptor.Key,
                descriptor.Version,
                descriptor.DescriptorHash,
                descriptor.InputTypeIdentity,
                descriptor.InputSchemaVersion,
                descriptor.InputSchemaHash,
                null,
                null));
        ActivateContext(fixture, context);
        var parentCall = fixture.Call with
        {
            Capability = SidecarCapabilityKind.Action,
            CallId = Guid.NewGuid(),
            ReplayNonce = "relay-revoke-parent",
            Sequence = 1,
        };
        var action = Payload(descriptor.InputTypeIdentity, "parent");
        var child = new SidecarNestedHostActionEntryRequest(
            descriptor.Key,
            descriptor.Version,
            action,
            fixture.Now.AddSeconds(20),
            fixture.Now.AddSeconds(20));
        var request = SidecarActionCapabilityRequest.HostEntry(
            parentCall,
            descriptor,
            action,
            new SidecarCancellationIdentity(parentCall.CancellationId, "revoke-cancel", parentCall.Deadline),
            parentCall.Deadline,
            context,
            new SidecarActionTerminalRegistration(
                Guid.NewGuid(),
                descriptor.InputTypeIdentity,
                descriptor.InputSchemaVersion,
                descriptor.ResultTypeIdentity,
                descriptor.ResultSchemaVersion,
                descriptor.DescriptorHash));
        Assert.True(fixture.Session.BeginActionCall(request, action.ByteLength, fixture.Now, out _).Accepted);
        Assert.Equal(
            SidecarCapabilityErrors.InvalidBinding,
            fixture.Session.IssueNestedHostActionEntryRelay(
                parentCall,
                child,
                descriptor,
                new HostActionEntryContribution(
                    new HostActionEntryIngressBinding(HostActionEntryIngress.CrossModule, "module-a", "module-b"),
                    new HostActionEntryLineage(
                        descriptor.Key,
                        descriptor.Version,
                        descriptor.DescriptorHash,
                        descriptor.InputTypeIdentity,
                        descriptor.InputSchemaVersion,
                        descriptor.InputSchemaHash,
                        null,
                        null)),
                fixture.Now,
                out _).Code);
        Assert.Equal(
            SidecarCapabilityErrors.Duplicate,
            fixture.Session.RevokeNestedHostActionEntryRelay(parentCall.CallId, fixture.Now).Code);
        var receipt = new SidecarTerminalReceipt(
            "revoke-receipt",
            descriptor.Key,
            descriptor.Version,
            parentCall.CallId,
            1,
            "revoke-scope",
            action.ContentHash);
        Assert.True(fixture.Session.RecordTerminal(parentCall.CallId, Guid.NewGuid(), receipt).Accepted);
        Assert.True(fixture.Session.CompleteCall(parentCall.CallId, 1).Accepted);
    }

    [Fact]
    public async Task Public_host_entry_requests_nested_carrier_during_terminal_execution()
    {
        var fixture = CreateFixture(maxInFlight: 4, maxCalls: 8);
        var rootDescriptor = new SidecarActionDescriptorIdentity(
            new SharpClawActionKey("root.runtime"),
            1,
            "kernel",
            typeof(string).AssemblyQualifiedName!,
            "root-input",
            1,
            typeof(string).AssemblyQualifiedName!,
            "root-result",
            1,
            "root-runtime-descriptor");
        var childDescriptor = new SidecarActionDescriptorIdentity(
            new SharpClawActionKey("child.runtime"),
            1,
            "module",
            typeof(string).AssemblyQualifiedName!,
            "child-input",
            1,
            typeof(string).AssemblyQualifiedName!,
            "child-result",
            1,
            "child-runtime-descriptor");
        var rootAction = Payload(rootDescriptor.InputTypeIdentity, "root");
        var childAction = Payload(childDescriptor.InputTypeIdentity, "child");
        var rootContext = IssueContext(
            fixture,
            new RequestPrincipal("runtime-caller"),
            HostActionEntryIngress.Tool,
            lineage: new HostActionEntryLineage(
                rootDescriptor.Key,
                rootDescriptor.Version,
                rootDescriptor.DescriptorHash,
                rootDescriptor.InputTypeIdentity,
                rootDescriptor.InputSchemaVersion,
                rootDescriptor.InputSchemaHash,
                null,
                null));
        var rootAuthority = ActivateContext(fixture, rootContext);
        var parentCall = fixture.Call with
        {
            Capability = SidecarCapabilityKind.Action,
            CallId = Guid.NewGuid(),
            ReplayNonce = "runtime-parent",
            Sequence = 1,
        };
        var rootRequest = SidecarActionCapabilityRequest.HostEntry(
            parentCall,
            rootDescriptor,
            rootAction,
            new SidecarCancellationIdentity(parentCall.CancellationId, "runtime-cancel", parentCall.Deadline),
            parentCall.Deadline,
            rootContext,
            new SidecarActionTerminalRegistration(
                Guid.NewGuid(),
                rootDescriptor.InputTypeIdentity,
                rootDescriptor.InputSchemaVersion,
                rootDescriptor.ResultTypeIdentity,
                rootDescriptor.ResultSchemaVersion,
                rootDescriptor.DescriptorHash));
        Assert.True(fixture.Session.BeginActionCall(rootRequest, rootAction.ByteLength, fixture.Now, out _).Accepted);
        var rootReceipt = new SidecarTerminalReceipt(
            "runtime-parent-receipt",
            rootDescriptor.Key,
            rootDescriptor.Version,
            parentCall.CallId,
            1,
            "runtime-scope",
            rootAction.ContentHash);
        Assert.True(fixture.Session.RecordTerminal(parentCall.CallId, Guid.NewGuid(), rootReceipt).Accepted);
        var contribution = new HostActionEntryContribution(
            new HostActionEntryIngressBinding(HostActionEntryIngress.CrossModule, "module-a", "module-b"),
            new HostActionEntryLineage(
                childDescriptor.Key,
                childDescriptor.Version,
                childDescriptor.DescriptorHash,
                childDescriptor.InputTypeIdentity,
                childDescriptor.InputSchemaVersion,
                childDescriptor.InputSchemaHash,
                null,
                null));
        var nestedRequest = new SidecarNestedHostActionEntryRequest(
            childDescriptor.Key,
            childDescriptor.Version,
            childAction,
            fixture.Now.AddSeconds(20),
            fixture.Now.AddSeconds(20));
        var terminalRequest = CreateTerminalRequest(
            fixture,
            rootRequest,
            new ActionPipelineSnapshot("runtime-graph", []));
        var transport = new RuntimeNestedTransport(
            fixture,
            rootRequest,
            terminalRequest,
            childDescriptor,
            contribution);
        var entry = new RuntimeNestedHostActionEntryProxy(transport);
        var parentContext = new ActionContext<string>(
            rootContext.InvocationId,
            rootContext.ParentInvocationId,
            rootContext.TraceId,
            rootContext.IdempotencyKey,
            rootContext.Depth,
            rootContext.Attempt,
            rootContext.Deadline,
            rootDescriptor.Key,
            fixture.Binding.ModuleId,
            rootContext.Caller,
            "root",
            rootContext.Features,
            new ActionPipelineSnapshot("runtime-graph", []))
        {
            HostActionEntry = entry,
        };
        var nested = new HostActionEntryNestedRequest<string, string, string>(
            childDescriptor.Key,
            childDescriptor.Version,
            "child",
            parentContext);

        var outcome = await entry.InvokeNestedAsync(
            nested,
            new RecordingHostActionEntryTerminal<string, string>());

        Assert.Equal(ActionOutcomeKind.Completed, outcome.Kind);
        Assert.Equal(1, transport.NestedRequests);
        Assert.Equal(1, transport.ActionCalls);
        var unrelatedCall = fixture.Call with
        {
            Capability = SidecarCapabilityKind.Storage,
            CallId = Guid.NewGuid(),
            ReplayNonce = "runtime-unrelated",
            Sequence = 3,
        };
        Assert.True(fixture.Session.BeginCall(
            unrelatedCall,
            SidecarCapabilityKind.Storage,
            null,
            0,
            fixture.Now).Accepted);
        Assert.True(fixture.Session.CompleteCall(unrelatedCall.CallId, 0).Accepted);
        var secondOutcome = await entry.InvokeNestedAsync(
            nested,
            new RecordingHostActionEntryTerminal<string, string>());
        Assert.Equal(ActionOutcomeKind.Completed, secondOutcome.Kind);
        Assert.Equal(2, transport.NestedRequests);
        Assert.Equal(2, transport.ActionCalls);
        Assert.True(fixture.Session.CompleteCall(parentCall.CallId, 1).Accepted);
        Assert.True(fixture.Session.CompleteHostActionEntryCarrier(
            rootAuthority,
            HostActionEntryCarrierCompletionKind.Succeeded,
            fixture.Now).Accepted);
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
        ActionPipelineSnapshot snapshot,
        SidecarTerminalReceipt? receiptOverride = null)
    {
        var effectiveAction = request.Action;
        var receipt = receiptOverride ?? new SidecarTerminalReceipt(
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
            HostContextBindingHash = SidecarCapabilityTransportValidation.ComputeHostActionEntryContextBindingHash(hostContext),
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

    private static ExternalSessionFixture CreateExternalSessionFixture(bool trustedProof = true)
    {
        var fixture = CreateFixture(
            authenticateHostTerminalAuthority: trustedProof
                ? static (authority, hash) => authority.Proof == hash
                : null);
        var call = fixture.Call with
        {
            Capability = SidecarCapabilityKind.Action,
            CallId = Guid.NewGuid(),
            ReplayNonce = "external-action-call",
            Sequence = 1,
        };
        var descriptor = new SidecarActionDescriptorIdentity(
            new SharpClawActionKey("sidecar.external.action"),
            1,
            "sidecar",
            "external.input",
            "external-input-schema",
            1,
            "external.result",
            "external-result-schema",
            1,
            "external-descriptor");
        var action = Payload(descriptor.InputTypeIdentity, new { value = "external" });
        var context = IssueContext(
            fixture,
            new RequestPrincipal("external-user"),
            HostActionEntryIngress.Endpoint,
            lineage: new HostActionEntryLineage(
                descriptor.Key,
                descriptor.Version,
                descriptor.DescriptorHash,
                descriptor.InputTypeIdentity,
                descriptor.InputSchemaVersion,
                descriptor.InputSchemaHash,
                action.ContentHash,
                action.ByteLength),
            bindPayload: false);
        _ = ActivateContext(fixture, context);
        var begin = fixture.Session.BeginCall(
            call,
            SidecarCapabilityKind.Action,
            action,
            action.ByteLength,
            fixture.Now,
            context);
        Assert.True(begin.Accepted, begin.Message);
        var request = SidecarCapabilityTransportValidationRequest(
            call,
            descriptor,
            action,
            context);
        var terminalRequest = CreateTerminalRequest(
            fixture,
            request,
            new ActionPipelineSnapshot("external-snapshot", []));
        var hostAuthority = terminalRequest.Authority with
        {
            Proof = terminalRequest.Authority.CanonicalBindingHash,
        };
        var authority = new SidecarExternalActionDispatchAuthority(
            call.ModuleId,
            call.GraphId,
            call,
            descriptor,
            action,
            request.Terminal!,
            context,
            new SidecarActionEffectiveHostEntryContext(
                context,
                terminalRequest.Context!,
                hostAuthority));
        return new ExternalSessionFixture(fixture, authority);
    }

    [Fact]
    public async Task Peer_nested_relay_import_is_authenticated_and_one_use()
    {
        static bool VerifyHostProof(SidecarHostTerminalAuthority authority, string proof) =>
            string.Equals(authority.Proof, proof, StringComparison.Ordinal) &&
            string.Equals(
                authority.Proof,
                SidecarCapabilityTransportValidation.ComputeTerminalAuthorityBindingHash(authority),
                StringComparison.OrdinalIgnoreCase);

        var host = CreateFixture(maxInFlight: 4, maxCalls: 8, authenticateHostTerminalAuthority: VerifyHostProof);
        var peer = CreateFixture(
            maxInFlight: 4,
            maxCalls: 8,
            moduleId: "module-b",
            graphId: "graph-b",
            authenticateHostTerminalAuthority: VerifyHostProof,
            authenticateStorageContinuationAuthority: (authority, hash) =>
                hash == SidecarCapabilityTransportValidation.ComputeStorageContinuationBindingHash(authority) &&
                host.Session.IsStorageContinuationAuthorityLive(authority, host.Now));
        var parentDescriptor = NestedDescriptor("peer.parent", typeof(string).AssemblyQualifiedName!);
        var parentAction = Payload(parentDescriptor.InputTypeIdentity, "parent");
        var hostParentContext = IssueContext(
            host,
            new RequestPrincipal("peer-user"),
            HostActionEntryIngress.Cli,
            traceId: Guid.NewGuid(),
            idempotencyKey: Guid.NewGuid(),
            lineage: new HostActionEntryLineage(
                parentDescriptor.Key,
                parentDescriptor.Version,
                parentDescriptor.DescriptorHash,
                parentDescriptor.InputTypeIdentity,
                parentDescriptor.InputSchemaVersion,
                parentDescriptor.InputSchemaHash,
                null,
                null));
        ConsumeStorageCalls(host, 6, "peer-boundary-host");
        ConsumeStorageCalls(peer, 6, "peer-boundary-peer");
        var hostParentCall = ActionCall(host, 7, "peer-parent-host");
        var peerParentCall = ActionCall(peer, 7, "peer-parent-peer") with
        {
            CallId = hostParentCall.CallId,
            Deadline = hostParentCall.Deadline,
        };
        var hostRootAuthority = ActivateContext(host, hostParentContext!);
        Assert.True(host.Session.BeginCall(
            hostParentCall,
            SidecarCapabilityKind.Action,
            parentAction,
            parentAction.ByteLength,
            host.Now,
            hostParentContext).Accepted);
        var parentReceipt = new SidecarTerminalReceipt(
            "peer-parent-receipt",
            parentDescriptor.Key,
            parentDescriptor.Version,
            hostParentCall.CallId,
            1,
            "peer-parent-scope",
            parentAction.ContentHash);
        Assert.True(host.Session.RecordTerminal(hostParentCall.CallId, Guid.NewGuid(), parentReceipt).Accepted);

        var childDescriptor = NestedDescriptor("peer.child", typeof(int).AssemblyQualifiedName!);
        var childAction = Payload(childDescriptor.InputTypeIdentity, "child");
        var childRequest = new SidecarNestedHostActionEntryRequest(
            childDescriptor.Key,
            childDescriptor.Version,
            childAction,
            hostParentCall.Deadline,
            hostParentCall.Deadline);
        Assert.True(host.Session.IssueNestedHostActionEntryPeerRelay(
            hostParentCall,
            childRequest,
            childDescriptor,
            NestedContribution(childDescriptor),
            peer.Session,
            host.Now,
            out var issuedRelay).Accepted);
        Assert.NotNull(issuedRelay);

        var rootRequest = SidecarActionCapabilityRequest.HostEntry(
            hostParentCall,
            parentDescriptor,
            parentAction,
            Cancellation(host),
            hostParentCall.Deadline,
            hostParentContext,
            new SidecarActionTerminalRegistration(
                Guid.NewGuid(),
                parentDescriptor.InputTypeIdentity,
                parentDescriptor.InputSchemaVersion,
                parentDescriptor.ResultTypeIdentity,
                parentDescriptor.ResultSchemaVersion,
                parentDescriptor.DescriptorHash));
        var terminalRequest = CreateTerminalRequest(
            host,
            rootRequest,
            new ActionPipelineSnapshot("peer-host-snapshot", []),
            parentReceipt) with
        {
            NestedCarrierRequest = childRequest,
        };
        var authority = terminalRequest.Authority with
        {
            RootPeerCall = peerParentCall,
            NestedCarrierRelay = issuedRelay,
            NestedCarrierOutcomeKind = SidecarNestedHostActionEntryRelayOutcomeKind.Issued,
            NestedCarrierRequestFingerprint = SidecarCapabilityTransportValidation.ComputeNestedCarrierRequestFingerprint(childRequest),
            ReceivingRootBudgetId = hostParentContext.CapabilityId,
            ReceivingPeerBindingGeneration = peer.Session.BindingGeneration,
        };
        authority = authority with
        {
            CanonicalBindingHash = SidecarCapabilityTransportValidation.ComputeTerminalAuthorityBindingHash(authority),
        };
        authority = authority with { Proof = authority.CanonicalBindingHash };
        var wireRelay = SidecarCapabilityTransportCodec.Deserialize<SidecarNestedHostActionEntryRelay>(
            SidecarCapabilityTransportCodec.Serialize(issuedRelay));
        var wireAuthority = SidecarCapabilityTransportCodec.Deserialize<SidecarHostTerminalAuthority>(
            SidecarCapabilityTransportCodec.Serialize(authority));
        var rootRelay = authority;
        var rootIssue = host.Session.IssueHostActionEntryPeerRootRelay(
            hostParentCall,
            peerParentCall,
            parentDescriptor,
            parentAction,
            rootRequest.Terminal!,
            new ActionPipelineSnapshot("peer-host-snapshot", []),
            peer.Session,
            rootRelay,
            host.Now,
            out var rootRelayEnvelope);
        Assert.True(rootIssue.Accepted, rootIssue.Message);
        Assert.NotNull(rootRelayEnvelope);
        var wireRootRelay = SidecarCapabilityTransportCodec.Deserialize<SidecarHostActionEntryRootRelay>(
            SidecarCapabilityTransportCodec.Serialize(rootRelayEnvelope!));

        Assert.False(peer.Session.ImportHostActionEntryPeerRootRelay(
            wireRootRelay with
            {
                Authority = wireRootRelay.Authority with { Proof = "forged-root-proof" },
            },
            peer.Now,
            out _).Accepted);
        Assert.False(peer.Session.ImportHostActionEntryPeerRootRelay(
            wireRootRelay with
            {
                Context = wireRootRelay.Context with { TraceId = Guid.NewGuid() },
            },
            peer.Now,
            out _).Accepted);
        Assert.False(peer.Session.ImportHostActionEntryPeerRootRelay(
            wireRootRelay with
            {
                Context = wireRootRelay.Context with { CancellationId = Guid.NewGuid() },
            },
            peer.Now,
            out _).Accepted);
        Assert.False(peer.Session.ImportHostActionEntryPeerRootRelay(
            wireRootRelay with
            {
                Action = Payload(parentDescriptor.InputTypeIdentity, "changed-root"),
            },
            peer.Now,
            out _).Accepted);
        Assert.False(peer.Session.ImportHostActionEntryPeerRootRelay(
            wireRootRelay with
            {
                Descriptor = parentDescriptor with { Key = new SharpClawActionKey("peer.other") },
            },
            peer.Now,
            out _).Accepted);
        Assert.False(peer.Session.ImportHostActionEntryPeerRootRelay(
            wireRootRelay with
            {
                Terminal = wireRootRelay.Terminal with { TerminalId = Guid.NewGuid() },
            },
            peer.Now,
            out _).Accepted);
        Assert.False(peer.Session.ImportHostActionEntryPeerRootRelay(
            wireRootRelay with
            {
                PeerCall = wireRootRelay.PeerCall with { GraphId = "graph-forged" },
            },
            peer.Now,
            out _).Accepted);
        Assert.False(peer.Session.ImportHostActionEntryPeerRootRelay(
            wireRootRelay,
            wireRootRelay.PeerCall.Deadline,
            out _).Accepted);
        Assert.True(peer.Session.ImportHostActionEntryPeerRootRelay(
            wireRootRelay,
            peer.Now,
            out var peerParentContext).Accepted);
        Assert.True(peer.Session.TryGetActiveHostActionEntryCarrier(
            peerParentContext!.CapabilityId,
            out var peerRootAuthority));
        Assert.NotNull(peerRootAuthority);
        var peerRootRequest = SidecarActionCapabilityRequest.HostEntry(
            peerParentCall,
            parentDescriptor,
            parentAction,
            Cancellation(peer),
            peerParentCall.Deadline,
            peerParentContext,
            rootRequest.Terminal!);
        Assert.True(peer.Session.BeginActionCall(
            peerRootRequest,
            parentAction.ByteLength,
            peer.Now,
            out _).Accepted);
        Assert.True(peer.Session.RecordTerminal(
            peerParentCall.CallId,
            Guid.NewGuid(),
            parentReceipt with { CallId = peerParentCall.CallId }).Accepted);
        var rootReplays = await Task.WhenAll(
            Task.Run(() => peer.Session.ImportHostActionEntryPeerRootRelay(
                wireRootRelay,
                peer.Now,
                out _)),
            Task.Run(() => peer.Session.ImportHostActionEntryPeerRootRelay(
                wireRootRelay,
                peer.Now,
                out _)));
        Assert.All(rootReplays, result => Assert.False(result.Accepted));

        var changedPayload = childRequest with
        {
            Action = Payload(childDescriptor.InputTypeIdentity, "changed"),
        };
        Assert.Equal(
            SidecarCapabilityErrors.SpoofedIdentity,
            peer.Session.ImportNestedHostActionEntryRelay(
                wireRelay,
                changedPayload,
                wireAuthority,
                peerParentCall,
                peer.Now,
                out _).Code);
        Assert.Equal(
            SidecarCapabilityErrors.SpoofedIdentity,
            peer.Session.ImportNestedHostActionEntryRelay(
                wireRelay,
                childRequest,
                wireAuthority with { Proof = "forged" },
                peerParentCall,
                peer.Now,
                out _).Code);

        var imports = await Task.WhenAll(
            Task.Run(() => peer.Session.ImportNestedHostActionEntryRelay(
                wireRelay,
                childRequest,
                wireAuthority,
                peerParentCall,
                peer.Now,
                out _)),
            Task.Run(() => peer.Session.ImportNestedHostActionEntryRelay(
                wireRelay,
                childRequest,
                wireAuthority,
                peerParentCall,
                peer.Now,
                out _)));
        Assert.Single(imports, result => result.Accepted);
        Assert.Single(imports, result => result.Code == SidecarCapabilityErrors.Replay);
        var rotatedPeerBinding = CreateRotatedBinding(peer, "peer-pending-rotation");
        peer.BindingHashes.Add(rotatedPeerBinding.Authentication.BindingHash);
        Assert.Equal(
            SidecarCapabilityErrors.InvalidBinding,
            peer.Session.RotateBinding(rotatedPeerBinding, peer.Now).Code);
        Assert.Equal(
            SidecarCapabilityErrors.InvalidBinding,
            peer.Session.CompleteCall(peerParentCall.CallId, 1).Code);

        var peerChildCall = wireRelay.PeerCall!;
        Assert.True(host.Session.BeginNestedHostActionEntryCall(
            issuedRelay!.Carrier,
            issuedRelay.Call,
            childAction,
            childAction.ByteLength,
            host.Now,
            out var hostChildContext).Accepted);
        var childActionRequest = SidecarActionCapabilityRequest.HostEntryNested(
            peerChildCall,
            childDescriptor,
            childAction,
            new SidecarCancellationIdentity(peerChildCall.CancellationId, "peer-child-cancel", peerChildCall.Deadline),
            peerChildCall.Deadline,
            wireRelay.Carrier,
            new SidecarActionTerminalRegistration(
                Guid.NewGuid(),
                childDescriptor.InputTypeIdentity,
                childDescriptor.InputSchemaVersion,
                childDescriptor.ResultTypeIdentity,
                childDescriptor.ResultSchemaVersion,
                childDescriptor.DescriptorHash));
        Assert.True(peer.Session.BeginActionCall(
            childActionRequest,
            childAction.ByteLength,
            peer.Now,
            out _).Accepted);
        var childReceipt = new SidecarTerminalReceipt(
            "peer-child-receipt",
            childDescriptor.Key,
            childDescriptor.Version,
            peerChildCall.CallId,
            1,
            "peer-child-scope",
            childAction.ContentHash);
        Assert.True(host.Session.RecordTerminal(
            issuedRelay.Call.CallId,
            Guid.NewGuid(),
            childReceipt with { CallId = issuedRelay.Call.CallId }).Accepted);
        Assert.True(peer.Session.RecordTerminal(peerChildCall.CallId, Guid.NewGuid(), childReceipt).Accepted);

        var grandchildDescriptor = NestedDescriptor("peer.grandchild", typeof(Guid).AssemblyQualifiedName!);
        var grandchildAction = Payload(grandchildDescriptor.InputTypeIdentity, "grandchild");
        var grandchildRequest = new SidecarNestedHostActionEntryRequest(
            grandchildDescriptor.Key,
            grandchildDescriptor.Version,
            grandchildAction,
            issuedRelay.Call.Deadline,
            issuedRelay.Call.Deadline);
        Assert.True(host.Session.IssueNestedHostActionEntryPeerRelay(
            issuedRelay.Call,
            grandchildRequest,
            grandchildDescriptor,
            NestedContribution(grandchildDescriptor),
            peer.Session,
            host.Now,
            out var issuedGrandchildRelay).Accepted);
        Assert.NotNull(issuedGrandchildRelay);
        var childCapabilityRequest = SidecarActionCapabilityRequest.HostEntryNested(
            issuedRelay.Call,
            childDescriptor,
            childAction,
            new SidecarCancellationIdentity(
                issuedRelay.Call.CancellationId,
                "peer-host-child-cancel",
                issuedRelay.Call.Deadline),
            issuedRelay.Call.Deadline,
            issuedRelay.Carrier,
            new SidecarActionTerminalRegistration(
                Guid.NewGuid(),
                childDescriptor.InputTypeIdentity,
                childDescriptor.InputSchemaVersion,
                childDescriptor.ResultTypeIdentity,
                childDescriptor.ResultSchemaVersion,
                childDescriptor.DescriptorHash)) with
        {
            HostContext = hostChildContext,
        };
        var childTerminalRequest = CreateTerminalRequest(
            host,
            childCapabilityRequest,
            new ActionPipelineSnapshot("peer-child-snapshot", []),
            childReceipt) with
        {
            NestedCarrierRequest = grandchildRequest,
        };
        var childAuthority = childTerminalRequest.Authority with
        {
            NestedCarrierRelay = issuedGrandchildRelay,
            NestedCarrierOutcomeKind = SidecarNestedHostActionEntryRelayOutcomeKind.Issued,
            NestedCarrierRequestFingerprint = SidecarCapabilityTransportValidation.ComputeNestedCarrierRequestFingerprint(grandchildRequest),
        };
        childAuthority = childAuthority with
        {
            CanonicalBindingHash = SidecarCapabilityTransportValidation.ComputeTerminalAuthorityBindingHash(childAuthority),
        };
        childAuthority = childAuthority with { Proof = childAuthority.CanonicalBindingHash };
        var wireGrandchildRelay = SidecarCapabilityTransportCodec.Deserialize<SidecarNestedHostActionEntryRelay>(
            SidecarCapabilityTransportCodec.Serialize(issuedGrandchildRelay));
        var wireChildAuthority = SidecarCapabilityTransportCodec.Deserialize<SidecarHostTerminalAuthority>(
            SidecarCapabilityTransportCodec.Serialize(childAuthority));
        var peerGrandchildCall = wireGrandchildRelay.PeerCall!;
        Assert.True(peer.Session.ImportNestedHostActionEntryRelay(
            wireGrandchildRelay,
            grandchildRequest,
            wireChildAuthority,
            peerChildCall,
            peer.Now,
            out _).Accepted);
        var grandchildCapabilityRequest = SidecarActionCapabilityRequest.HostEntryNested(
            peerGrandchildCall,
            grandchildDescriptor,
            grandchildAction,
            new SidecarCancellationIdentity(
                peerGrandchildCall.CancellationId,
                "peer-grandchild-cancel",
                peerGrandchildCall.Deadline),
            peerGrandchildCall.Deadline,
            wireGrandchildRelay.Carrier,
            new SidecarActionTerminalRegistration(
                Guid.NewGuid(),
                grandchildDescriptor.InputTypeIdentity,
                grandchildDescriptor.InputSchemaVersion,
                grandchildDescriptor.ResultTypeIdentity,
                grandchildDescriptor.ResultSchemaVersion,
                grandchildDescriptor.DescriptorHash));
        Assert.True(peer.Session.BeginActionCall(
            grandchildCapabilityRequest,
            grandchildAction.ByteLength,
            peer.Now,
            out _).Accepted);
        var grandchildReceipt = new SidecarTerminalReceipt(
            "peer-grandchild-receipt",
            grandchildDescriptor.Key,
            grandchildDescriptor.Version,
            peerGrandchildCall.CallId,
            1,
            "peer-grandchild-scope",
            grandchildAction.ContentHash);
        Assert.True(peer.Session.RecordTerminal(
            peerGrandchildCall.CallId,
            Guid.NewGuid(),
            grandchildReceipt).Accepted);

        var storageCall = peer.Call with
        {
            Capability = SidecarCapabilityKind.Storage,
            CallId = Guid.NewGuid(),
            ReplayNonce = "peer-storage-continuation",
            Sequence = 10,
            Deadline = peerChildCall.Deadline,
        };
        var storagePayload = Payload("agent_job_imports.request", new { jobId = "nested-job" });
        var storageRequest = SidecarStorageCapabilityRequest.Invoke(
            storageCall,
            peer.Binding.ModuleId,
            "agent_job_imports/get",
            storagePayload,
            PayloadType("agent_job_imports.result"),
            Cancellation(peer),
            storageCall.Deadline);
        var storageIssue = host.Session.IssueHostEntryStorageContinuation(
            peer.Session,
            issuedRelay.Call,
            peerChildCall,
            storageRequest,
            host.Now,
            (_, hash) => hash,
            out var storageAuthority);
        Assert.True(storageIssue.Accepted, storageIssue.Message);
        Assert.NotNull(storageAuthority);
        var storageWireRequest = storageRequest with
        {
            HostEntryContinuationAuthority = SidecarCapabilityTransportCodec.Deserialize<SidecarHostEntryStorageContinuationAuthority>(
                SidecarCapabilityTransportCodec.Serialize(storageAuthority)),
        };
        Assert.True(peer.Session.ImportHostEntryStorageContinuationAuthority(
            storageWireRequest.HostEntryContinuationAuthority!,
            peer.Now).Accepted);
        Assert.True(peer.Session.BeginStorageContinuationCall(
            storageWireRequest,
            storagePayload.ByteLength,
            peer.Now,
            out var storageContext).Accepted);
        Assert.NotNull(storageContext);
        Assert.Equal(
            SidecarCapabilityErrors.InvalidBinding,
            peer.Session.CompleteCall(peerChildCall.CallId, 1).Code);
        Assert.True(peer.Session.CompleteCall(storageCall.CallId, 0).Accepted);

        Assert.True(peer.Session.CompleteCall(peerGrandchildCall.CallId, 1).Accepted);
        Assert.True(peer.Session.CompleteCall(peerChildCall.CallId, 1).Accepted);
        Assert.True(peer.Session.CompleteCall(peerParentCall.CallId, 1).Accepted);
        Assert.True(host.Session.RevokeNestedHostActionEntryRelay(
            issuedRelay.Call.CallId,
            host.Now).Accepted);
        Assert.True(host.Session.CompleteCall(issuedRelay.Call.CallId, 1).Accepted);
        Assert.True(host.Session.CompleteCall(hostParentCall.CallId, 1).Accepted);
        Assert.True(peer.Session.CompleteHostActionEntryCarrier(
            peerRootAuthority!,
            HostActionEntryCarrierCompletionKind.Succeeded,
            peer.Now).Accepted);
        Assert.True(host.Session.CompleteHostActionEntryCarrier(
            hostRootAuthority,
            HostActionEntryCarrierCompletionKind.Succeeded,
            host.Now).Accepted);
        Assert.Equal(
            SidecarCapabilityErrors.InvalidBinding,
            peer.Session.ImportNestedHostActionEntryRelay(
                wireRelay,
                childRequest,
                wireAuthority,
                peerParentCall,
                peer.Now,
                out _).Code);
        peer.Session.Disconnect();
        Assert.Equal(
            SidecarCapabilityErrors.Disconnected,
            peer.Session.ImportNestedHostActionEntryRelay(
                wireRelay,
                childRequest,
                wireAuthority,
                peerParentCall,
                peer.Now,
                out _).Code);
    }

    [Fact]
    public void Two_receiving_root_relays_use_distinct_reserved_credit_after_call_limit()
    {
        static bool VerifyHostProof(SidecarHostTerminalAuthority authority, string proof) =>
            string.Equals(authority.Proof, proof, StringComparison.Ordinal) &&
            string.Equals(
                authority.Proof,
                SidecarCapabilityTransportValidation.ComputeTerminalAuthorityBindingHash(authority),
                StringComparison.OrdinalIgnoreCase);

        var host = CreateFixture(
            maxInFlight: 4,
            maxCalls: 8,
            moduleId: "module-b",
            graphId: "graph-b",
            authenticateHostTerminalAuthority: VerifyHostProof);
        var peer = CreateFixture(
            maxInFlight: 4,
            maxCalls: 8,
            moduleId: "module-b",
            graphId: "graph-b",
            authenticateHostTerminalAuthority: VerifyHostProof);
        ConsumeStorageCalls(peer, 8, "two-root-boundary");

        (SidecarHostActionEntryRootRelay Relay,
            HostActionEntryCarrierAuthority HostAuthority,
            SidecarCapabilityCallIdentity HostCall,
            SidecarCapabilityCallIdentity PeerCall,
            SidecarActionTerminalRegistration Terminal,
            SidecarSerializedPayload Action) PrepareRoot(
                string key,
                long hostSequence,
                long peerSequence,
                string value)
        {
            var descriptor = NestedDescriptor(key, typeof(string).AssemblyQualifiedName!);
            var action = Payload(descriptor.InputTypeIdentity, value);
            var context = IssueContext(
                host,
                new RequestPrincipal($"{key}-caller"),
                HostActionEntryIngress.Cli,
                lineage: new HostActionEntryLineage(
                    descriptor.Key,
                    descriptor.Version,
                    descriptor.DescriptorHash,
                    descriptor.InputTypeIdentity,
                    descriptor.InputSchemaVersion,
                    descriptor.InputSchemaHash,
                    null,
                    null));
            var hostAuthority = ActivateContext(host, context);
            var hostCall = ActionCall(host, hostSequence, $"{key}-host");
            Assert.True(host.Session.BeginCall(
                hostCall,
                SidecarCapabilityKind.Action,
                action,
                action.ByteLength,
                host.Now,
                context).Accepted);
            var receipt = new SidecarTerminalReceipt(
                $"{key}-receipt",
                descriptor.Key,
                descriptor.Version,
                hostCall.CallId,
                1,
                $"{key}-scope",
                action.ContentHash);
            Assert.True(host.Session.RecordTerminal(hostCall.CallId, Guid.NewGuid(), receipt).Accepted);
            var peerCall = ActionCall(peer, peerSequence, $"{key}-peer") with
            {
                CallId = hostCall.CallId,
                Deadline = hostCall.Deadline,
            };
            var terminal = new SidecarActionTerminalRegistration(
                Guid.NewGuid(),
                descriptor.InputTypeIdentity,
                descriptor.InputSchemaVersion,
                descriptor.ResultTypeIdentity,
                descriptor.ResultSchemaVersion,
                descriptor.DescriptorHash);
            var rootRequest = SidecarActionCapabilityRequest.HostEntry(
                hostCall,
                descriptor,
                action,
                Cancellation(host),
                hostCall.Deadline,
                context,
                terminal);
            var terminalRequest = CreateTerminalRequest(
                host,
                rootRequest,
                new ActionPipelineSnapshot($"{key}-snapshot", []),
                receipt);
            var authority = terminalRequest.Authority with
            {
                RootPeerCall = peerCall,
                ReceivingRootBudgetId = hostAuthority.CapabilityId,
                ReceivingPeerBindingGeneration = peer.Session.BindingGeneration,
            };
            authority = authority with
            {
                CanonicalBindingHash = SidecarCapabilityTransportValidation.ComputeTerminalAuthorityBindingHash(authority),
            };
            authority = authority with { Proof = authority.CanonicalBindingHash };
            Assert.True(host.Session.IssueHostActionEntryPeerRootRelay(
                hostCall,
                peerCall,
                descriptor,
                action,
                terminal,
                new ActionPipelineSnapshot($"{key}-snapshot", []),
                peer.Session,
                authority,
                host.Now,
                out var relay).Accepted);
            Assert.NotNull(relay);
            return (
                SidecarCapabilityTransportCodec.Deserialize<SidecarHostActionEntryRootRelay>(
                    SidecarCapabilityTransportCodec.Serialize(relay!)),
                hostAuthority,
                hostCall,
                peerCall,
                terminal,
                action);
        }

        var first = PrepareRoot("reserved.first", 1, 9, "first");
        var second = PrepareRoot("reserved.second", 2, 10, "second");
        var third = PrepareRoot("reserved.third", 3, 11, "third");
        Assert.False(peer.Session.ImportHostActionEntryPeerRootRelay(
            first.Relay with { RootBudgetId = Guid.NewGuid() },
            peer.Now,
            out _).Accepted);
        Assert.False(peer.Session.ImportHostActionEntryPeerRootRelay(
            first.Relay with { PeerBindingGeneration = peer.Session.BindingGeneration + 1 },
            peer.Now,
            out _).Accepted);
        Assert.True(peer.Session.ImportHostActionEntryPeerRootRelay(
            first.Relay,
            peer.Now,
            out var firstContext).Accepted);
        Assert.True(peer.Session.ImportHostActionEntryPeerRootRelay(
            second.Relay,
            peer.Now,
            out var secondContext).Accepted);
        Assert.NotNull(firstContext);
        Assert.NotNull(secondContext);
        Assert.NotEqual(firstContext!.CapabilityId, secondContext!.CapabilityId);
        var unrelatedCall = peer.Call with
        {
            CallId = Guid.NewGuid(),
            ReplayNonce = "two-root-unrelated",
            Sequence = 11,
        };
        var unrelatedPayload = Payload("unrelated.storage", "unrelated");
        Assert.Equal(
            SidecarCapabilityErrors.ConcurrencyLimit,
            peer.Session.BeginCall(
                unrelatedCall,
                SidecarCapabilityKind.Storage,
                unrelatedPayload,
                unrelatedPayload.ByteLength,
                peer.Now).Code);
        Assert.Equal(
            SidecarCapabilityErrors.ConcurrencyLimit,
            peer.Session.ImportHostActionEntryPeerRootRelay(
                third.Relay,
                peer.Now,
                out _).Code);

        foreach (var root in new[]
        {
            (first.PeerCall, first.Terminal, first.Action, firstContext),
            (second.PeerCall, second.Terminal, second.Action, secondContext),
        })
        {
            var request = SidecarActionCapabilityRequest.HostEntry(
                root.Item1,
                NestedDescriptor(root.Item1 == first.PeerCall ? "reserved.first" : "reserved.second", typeof(string).AssemblyQualifiedName!),
                root.Item3,
                Cancellation(peer),
                root.Item1.Deadline,
                root.Item4,
                root.Item2);
            Assert.True(peer.Session.BeginActionCall(
                request,
                root.Item3.ByteLength,
                peer.Now,
                out _).Accepted);
            var receipt = new SidecarTerminalReceipt(
                $"{root.Item1.ReplayNonce}-result",
                request.Descriptor.Key,
                request.Descriptor.Version,
                root.Item1.CallId,
                1,
                $"{root.Item1.ReplayNonce}-scope",
                root.Item3.ContentHash);
            Assert.True(peer.Session.RecordTerminal(root.Item1.CallId, Guid.NewGuid(), receipt).Accepted);
            Assert.True(peer.Session.CompleteCall(root.Item1.CallId, 1).Accepted);
            Assert.True(peer.Session.TryGetActiveHostActionEntryCarrier(
                root.Item4.CapabilityId,
                out var carrier));
            Assert.True(peer.Session.CompleteHostActionEntryCarrier(
                carrier!,
                HostActionEntryCarrierCompletionKind.Succeeded,
                peer.Now).Accepted);
        }

        Assert.True(host.Session.CompleteCall(first.HostCall.CallId, 1).Accepted);
        Assert.True(host.Session.CompleteHostActionEntryCarrier(
            first.HostAuthority,
            HostActionEntryCarrierCompletionKind.Succeeded,
            host.Now).Accepted);
        Assert.True(host.Session.CompleteCall(second.HostCall.CallId, 1).Accepted);
        Assert.True(host.Session.CompleteHostActionEntryCarrier(
            second.HostAuthority,
            HostActionEntryCarrierCompletionKind.Succeeded,
            host.Now).Accepted);
        Assert.Equal(
            SidecarCapabilityErrors.ConcurrencyLimit,
            peer.Session.ImportHostActionEntryPeerRootRelay(
                third.Relay,
                peer.Now,
                out _).Code);
        Assert.Equal(0, peer.Session.ActiveHostActionEntryCarrierCount);
        Assert.False(peer.Session.ImportHostActionEntryPeerRootRelay(
            first.Relay,
            peer.Now,
            out _).Accepted);
    }

    [Fact]
    public void Peer_root_relay_uses_one_authenticated_reservation_after_call_limit()
    {
        static bool VerifyHostProof(SidecarHostTerminalAuthority authority, string proof) =>
            string.Equals(authority.Proof, proof, StringComparison.Ordinal) &&
            string.Equals(
                authority.Proof,
                SidecarCapabilityTransportValidation.ComputeTerminalAuthorityBindingHash(authority),
                StringComparison.OrdinalIgnoreCase);

        var host = CreateFixture(
            maxInFlight: 4,
            maxCalls: 8,
            moduleId: "module-b",
            graphId: "graph-b",
            authenticateHostTerminalAuthority: VerifyHostProof);
        var peer = CreateFixture(
            maxInFlight: 4,
            maxCalls: 8,
            moduleId: "module-b",
            graphId: "graph-b",
            authenticateHostTerminalAuthority: VerifyHostProof);
        ConsumeStorageCalls(peer, 8, "peer-root-reservation");

        var ordinaryCall = peer.Call with
        {
            CallId = Guid.NewGuid(),
            ReplayNonce = "peer-unrelated-call",
            Sequence = 9,
        };
        var ordinaryPayload = Payload("ordinary.storage", "unrelated");
        var ordinaryResult = peer.Session.BeginCall(
            ordinaryCall,
            SidecarCapabilityKind.Storage,
            ordinaryPayload,
            ordinaryPayload.ByteLength,
            peer.Now,
            null);
        Assert.Equal(SidecarCapabilityErrors.ConcurrencyLimit, ordinaryResult.Code);

        var descriptor = NestedDescriptor("peer.reserved-root", typeof(string).AssemblyQualifiedName!);
        var action = Payload(descriptor.InputTypeIdentity, "reserved-root");
        var hostContext = IssueContext(
            host,
            new RequestPrincipal("peer-user"),
            HostActionEntryIngress.Cli,
            lineage: new HostActionEntryLineage(
                descriptor.Key,
                descriptor.Version,
                descriptor.DescriptorHash,
                descriptor.InputTypeIdentity,
                descriptor.InputSchemaVersion,
                descriptor.InputSchemaHash,
                null,
                null));
        var hostRootAuthority = ActivateContext(host, hostContext!);
        var hostCall = ActionCall(host, 1, "reserved-root-host");
        Assert.True(host.Session.BeginCall(
            hostCall,
            SidecarCapabilityKind.Action,
            action,
            action.ByteLength,
            host.Now,
            hostContext).Accepted);
        var hostReceipt = new SidecarTerminalReceipt(
            "reserved-root-host-receipt",
            descriptor.Key,
            descriptor.Version,
            hostCall.CallId,
            1,
            "reserved-root-host-scope",
            action.ContentHash);
        Assert.True(host.Session.RecordTerminal(hostCall.CallId, Guid.NewGuid(), hostReceipt).Accepted);

        var peerCall = ActionCall(peer, 9, "reserved-root-peer") with
        {
            CallId = hostCall.CallId,
            Deadline = hostCall.Deadline,
        };
        var rootRequest = SidecarActionCapabilityRequest.HostEntry(
            hostCall,
            descriptor,
            action,
            Cancellation(host),
            hostCall.Deadline,
            hostContext,
            new SidecarActionTerminalRegistration(
                Guid.NewGuid(),
                descriptor.InputTypeIdentity,
                descriptor.InputSchemaVersion,
                descriptor.ResultTypeIdentity,
                descriptor.ResultSchemaVersion,
                descriptor.DescriptorHash));
        var terminalRequest = CreateTerminalRequest(
            host,
            rootRequest,
            new ActionPipelineSnapshot("reserved-root-snapshot", []),
            hostReceipt);
        var authority = terminalRequest.Authority with
        {
            RootPeerCall = peerCall,
            ReceivingRootBudgetId = hostRootAuthority.CapabilityId,
            ReceivingPeerBindingGeneration = peer.Session.BindingGeneration,
        };
        authority = authority with
        {
            CanonicalBindingHash = SidecarCapabilityTransportValidation.ComputeTerminalAuthorityBindingHash(authority),
        };
        authority = authority with { Proof = authority.CanonicalBindingHash };
        var rootIssue = host.Session.IssueHostActionEntryPeerRootRelay(
            hostCall,
            peerCall,
            descriptor,
            action,
            rootRequest.Terminal!,
            new ActionPipelineSnapshot("reserved-root-snapshot", []),
            peer.Session,
            authority,
            host.Now,
            out var issuedRootRelay);
        Assert.True(rootIssue.Accepted, rootIssue.Message);
        Assert.NotNull(issuedRootRelay);

        var wireRelay = SidecarCapabilityTransportCodec.Deserialize<SidecarHostActionEntryRootRelay>(
            SidecarCapabilityTransportCodec.Serialize(issuedRootRelay!));
        Assert.True(peer.Session.ImportHostActionEntryPeerRootRelay(
            wireRelay,
            peer.Now,
            out var peerContext).Accepted);
        Assert.NotNull(peerContext);

        var peerRequest = SidecarActionCapabilityRequest.HostEntry(
            peerCall,
            descriptor,
            action,
            Cancellation(peer),
            peerCall.Deadline,
            peerContext,
            rootRequest.Terminal!);
        Assert.True(peer.Session.BeginActionCall(
            peerRequest,
            action.ByteLength,
            peer.Now,
            out _).Accepted);
        Assert.True(peer.Session.TryGetActiveHostActionEntryCarrier(
            peerContext.CapabilityId,
            out var peerRootAuthority));
        var peerReceipt = hostReceipt with
        {
            CallId = peerCall.CallId,
            ReceiptId = "reserved-root-peer-receipt",
            IdempotencyScope = "reserved-root-peer-scope",
        };
        Assert.True(peer.Session.RecordTerminal(peerCall.CallId, Guid.NewGuid(), peerReceipt).Accepted);
        Assert.True(peer.Session.CompleteCall(peerCall.CallId, 1).Accepted);
        Assert.True(peer.Session.CompleteHostActionEntryCarrier(
            peerRootAuthority,
            HostActionEntryCarrierCompletionKind.Succeeded,
            peer.Now).Accepted);
        Assert.True(host.Session.CompleteCall(hostCall.CallId, 1).Accepted);
        Assert.True(host.Session.CompleteHostActionEntryCarrier(
            hostRootAuthority,
            HostActionEntryCarrierCompletionKind.Succeeded,
            host.Now).Accepted);
        Assert.False(peer.Session.ImportHostActionEntryPeerRootRelay(
            wireRelay,
            peer.Now,
            out _).Accepted);
    }

    private static Fixture CreateFixture(
        int maxInFlight = 2,
        int maxCalls = 4,
        IReadOnlyList<SidecarCapabilityKind>? capabilities = null,
        string moduleId = "module-a",
        string graphId = "graph-a",
        Func<SidecarHostTerminalAuthority, string, bool>? authenticateHostTerminalAuthority = null,
        Func<SidecarHostEntryStorageContinuationAuthority, string, bool>? authenticateStorageContinuationAuthority = null)
    {
        var now = new DateTimeOffset(2026, 8, 14, 12, 0, 0, TimeSpan.Zero);
        var expires = now.AddMinutes(5);
        var safeFailure = new SidecarSafeFailureIdentity(Guid.NewGuid(), "sidecar.test.failure", "The test failure is safe.");
        var proof = new SidecarAuthenticationProof("hmac-sha256", "host-a", "nonce-a", "signature", "", now, expires);
        var binding = new SidecarCapabilitySessionBinding(
            moduleId,
            graphId,
            1,
            new SidecarCapabilityGrant(
                "grant-a",
                moduleId,
                graphId,
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
            now,
            authenticateHostTerminalAuthority,
            authenticateStorageContinuationAuthority);
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

    [Fact]
    public void CrossSidecarEntryIssuesResolvesConsumesAndCompletesOnce()
    {
        var fixture = CreateFixture();
        var parentCall = fixture.Call with
        {
            Capability = SidecarCapabilityKind.Action,
            CallId = Guid.NewGuid(),
            ReplayNonce = "cross-parent",
            Sequence = 1,
            Deadline = fixture.Now.AddMinutes(1),
        };
        var parentContext = IssueContext(
            fixture,
            new RequestPrincipal("source-user"),
            HostActionEntryIngress.CrossModule,
            lineage: new HostActionEntryLineage(
                new SharpClawActionKey("source.action"),
                1,
                "source-descriptor",
                "source.input",
                1,
                "source-schema",
                null,
                null));
        var parentAction = Payload("source.input", new { value = 1 });
        ActivateContext(fixture, parentContext);
        Assert.True(fixture.Session.BeginCall(
            parentCall,
            SidecarCapabilityKind.Action,
            parentAction,
            parentAction.ByteLength,
            fixture.Now,
            parentContext).Accepted);
        var parentReceipt = new SidecarTerminalReceipt(
            "source-receipt",
            new SharpClawActionKey("source.action"),
            1,
            parentCall.CallId,
            1,
            "source-scope",
            parentAction.ContentHash);
        Assert.True(fixture.Session.RecordTerminal(parentCall.CallId, Guid.NewGuid(), parentReceipt).Accepted);

        var targetBinding = fixture.Binding with
        {
            ModuleId = "permission.module",
            GraphId = "permission.graph",
            SessionId = Guid.NewGuid(),
            RequestId = Guid.NewGuid(),
            CancellationId = Guid.NewGuid(),
            Grant = fixture.Binding.Grant with
            {
                ModuleId = "permission.module",
                GraphId = "permission.graph",
            },
            Authentication = fixture.Binding.Authentication with
            {
                Nonce = "target-binding",
                BindingHash = string.Empty,
            },
        };
        targetBinding = targetBinding with
        {
            Authentication = targetBinding.Authentication with
            {
                BindingHash = SidecarCapabilitySessionValidator.ComputeBindingHash(targetBinding),
            },
        };
        var targetHashes = new HashSet<string>(StringComparer.Ordinal)
        {
            targetBinding.Authentication.BindingHash,
        };
        var targetSession = new SidecarCapabilitySession(
            targetBinding,
            authority => targetHashes.Contains(authority.BindingHash),
            new HashSet<string>(StringComparer.Ordinal).Add,
            fixture.Now);
        var childKey = new SharpClawActionKey("permission.action");
        var childDescriptor = new SidecarActionDescriptorIdentity(
            childKey,
            1,
            "module-owned",
            "permission.input",
            "permission-input-schema",
            1,
            "permission.result",
            "permission-result-schema",
            1,
            "permission-descriptor");
        var childEntry = new SidecarModuleActionEntryDefinition(
            "permission.module",
            "permission.graph",
            childDescriptor,
            "permission.module",
            "permission.graph");
        var childRequest = new SidecarCrossSidecarActionEntryRequest(
            childKey,
            1,
            Payload("permission.input", new { value = 2 }),
            parentCall.Deadline,
            fixture.Now.AddMinutes(2));
        var snapshot = new ActionPipelineSnapshot("permission-snapshot", []);

        var relayResult = fixture.Session.IssueCrossSidecarActionEntryRelay(
            parentCall,
            childRequest,
            targetSession,
            childEntry,
            snapshot,
            fixture.Now,
            (authority, hash) => hash,
            out var relay);
        Assert.True(relayResult.Accepted, relayResult.Message);
        Assert.NotNull(relay);
        var relayBytes = SidecarCapabilityTransportCodec.Serialize(relay);
        var relayRoundTrip = SidecarCapabilityTransportCodec.Deserialize<SidecarCrossSidecarActionEntryRelay>(relayBytes);
        Assert.Equal(relayBytes, SidecarCapabilityTransportCodec.Serialize(relayRoundTrip));
        Assert.Equal(childDescriptor, relay!.Descriptor);
        Assert.Equal(SidecarCapabilityErrors.InvalidBinding, fixture.Session.CompleteCall(parentCall.CallId, 1).Code);

        var terminal = new SidecarActionTerminalRegistration(
            Guid.NewGuid(),
            childDescriptor.InputTypeIdentity,
            childDescriptor.InputSchemaVersion,
            childDescriptor.ResultTypeIdentity,
            childDescriptor.ResultSchemaVersion,
            childDescriptor.DescriptorHash);
        var begin = targetSession.BeginCrossSidecarActionEntryCall(
            relay.Carrier,
            terminal,
            relay.Carrier.Action.ByteLength,
            fixture.Now,
            out var childContext,
            (authority, hash) => authority.Proof == hash);
        Assert.True(begin.Accepted, begin.Message);
        Assert.NotNull(childContext);
        Assert.Equal(parentContext.InvocationId, childContext!.ParentInvocationId);
        Assert.Equal(childDescriptor, relay.Descriptor);

        var childReceipt = new SidecarTerminalReceipt(
            "permission-receipt",
            childKey,
            1,
            relay.Carrier.Authority.TargetChildCall.CallId,
            relay.Carrier.Authority.Attempt,
            "permission-scope",
            relay.Carrier.Action.ContentHash);
        Assert.True(targetSession.RecordTerminal(
            relay.Carrier.Authority.TargetChildCall.CallId,
            Guid.NewGuid(),
            childReceipt).Accepted);
        var childResult = Payload("permission.result", new { value = 3 });
        var childOutcome = new SidecarActionOutcomeEnvelope(
            ActionOutcomeKind.Completed,
            childResult,
            null,
            null,
            null,
            childReceipt,
            targetBinding.SafeFailure,
            1);
        var childExecution = new SidecarTerminalExecutionResult(childResult, null, true);
        var childResultIdentity = new SidecarActionResultIdentity(
            Guid.NewGuid(),
            relay.Carrier.Authority.TargetChildCall.CallId,
            childKey,
            1,
            childResult.TypeIdentity,
            childResult.ContentHash);
        var complete = targetSession.CompleteCrossSidecarActionEntry(
            relay.Carrier,
            childOutcome,
            childReceipt,
            childExecution,
            childResultIdentity,
            targetBinding.SafeFailure,
            fixture.Now,
            (authority, hash) => hash,
            out var completed);
        Assert.True(complete.Accepted, complete.Message);
        Assert.NotNull(completed);
        Assert.Equal(SidecarCrossSidecarActionEntryOutcomeKind.Completed, completed!.Kind);
        var sourceDescriptor = new SidecarActionDescriptorIdentity(
            new SharpClawActionKey("source.action"),
            1,
            "source.category",
            "source.input",
            "source-schema",
            1,
            "source.result",
            "source-result-schema",
            1,
            "source-descriptor");
        var parentTerminal = new SidecarActionTerminalRegistration(
            Guid.NewGuid(),
            sourceDescriptor.InputTypeIdentity,
            sourceDescriptor.InputSchemaVersion,
            sourceDescriptor.ResultTypeIdentity,
            sourceDescriptor.ResultSchemaVersion,
            sourceDescriptor.DescriptorHash);
        var parentRequest = SidecarActionCapabilityRequest.HostEntry(
            parentCall,
            sourceDescriptor,
            parentAction,
            new SidecarCancellationIdentity(parentCall.CancellationId, "source-cancellation", parentCall.Deadline),
            parentCall.Deadline,
            parentContext,
            parentTerminal);
        var terminalRequest = CreateTerminalRequest(
            fixture,
            parentRequest,
            new ActionPipelineSnapshot("source-snapshot", []),
            parentReceipt) with
        {
            CrossSidecarActionRequest = childRequest,
        };
        Assert.True(SidecarCapabilityTransportValidation.ValidateActionTerminalRequest(
            parentRequest,
            terminalRequest,
            fixture.Binding,
            fixture.Now,
            (_, _) => true).Accepted);
        var parentTerminalId = terminalRequest.TerminalId;
        var terminalResponse = new SidecarActionTerminalTransportResponse(
            childResultIdentity,
            childExecution,
            parentReceipt,
            targetBinding.SafeFailure)
        {
            TerminalId = parentTerminalId,
            CrossSidecarRelay = relay,
            CrossSidecarOutcome = completed,
        };
        Assert.Equal(
            SidecarCapabilityErrors.InvalidResponse,
            SidecarCapabilityTransportValidation.ValidateActionTerminalResponse(
                terminalRequest,
                terminalResponse,
                fixture.Binding).Code);
        var terminalValidation = SidecarCapabilityTransportValidation.ValidateActionTerminalResponse(
            terminalRequest,
            terminalResponse,
            fixture.Binding,
            targetBinding,
            fixture.Now,
            (authority, hash) => authority.Proof == hash);
        Assert.True(terminalValidation.Accepted, $"{terminalValidation.Code}: {terminalValidation.Message}");
        var relayOnlyResponse = terminalResponse with
        {
            ResultIdentity = null,
            Execution = new SidecarTerminalExecutionResult(null, null, false),
            Receipt = parentReceipt,
            SafeFailure = fixture.SafeFailure,
            TerminalId = parentTerminalId,
            CrossSidecarOutcome = null,
        };
        var relayOnlyRoundTrip = SidecarCapabilityTransportCodec.Deserialize<SidecarActionTerminalTransportResponse>(
            SidecarCapabilityTransportCodec.Serialize(relayOnlyResponse));
        Assert.True(SidecarCapabilityTransportValidation.ValidateActionTerminalResponse(
            terminalRequest,
            relayOnlyRoundTrip,
            fixture.Binding,
            targetBinding,
            fixture.Now,
            (authority, hash) => authority.Proof == hash).Accepted);
        var missingOutcomeAuthority = SidecarCapabilityTransportCodec.Deserialize<SidecarActionTerminalTransportResponse>(
            SidecarCapabilityTransportCodec.Serialize(terminalResponse with
            {
                CrossSidecarOutcome = completed with { Authority = null! },
            }));
        var missingOutcomeAuthorityResult = SidecarCapabilityTransportValidation.ValidateActionTerminalResponse(
            terminalRequest,
            missingOutcomeAuthority,
            fixture.Binding,
            targetBinding,
            fixture.Now,
            (authority, hash) => authority.Proof == hash);
        Assert.Equal(SidecarCapabilityErrors.InvalidResponse, missingOutcomeAuthorityResult.Code);
        var missingRelayExecution = SidecarCapabilityTransportCodec.Deserialize<SidecarActionTerminalTransportResponse>(
            SidecarCapabilityTransportCodec.Serialize(relayOnlyResponse with { Execution = null! }));
        var missingRelayExecutionResult = SidecarCapabilityTransportValidation.ValidateActionTerminalResponse(
            terminalRequest,
            missingRelayExecution,
            fixture.Binding,
            targetBinding,
            fixture.Now,
            (authority, hash) => authority.Proof == hash);
        Assert.Equal(SidecarCapabilityErrors.InvalidResponse, missingRelayExecutionResult.Code);
        Assert.False(SidecarCapabilityTransportValidation.ValidateActionTerminalResponse(
            terminalRequest,
            relayOnlyRoundTrip with { TerminalId = Guid.NewGuid() },
            fixture.Binding,
            targetBinding,
            fixture.Now,
            (authority, hash) => authority.Proof == hash).Accepted);
        Assert.False(SidecarCapabilityTransportValidation.ValidateActionTerminalResponse(
            terminalRequest,
            relayOnlyRoundTrip with
            {
                Execution = new SidecarTerminalExecutionResult(null, null, true),
            },
            fixture.Binding,
            targetBinding,
            fixture.Now,
            (authority, hash) => authority.Proof == hash).Accepted);
        Assert.False(SidecarCapabilityTransportValidation.ValidateActionTerminalResponse(
            terminalRequest,
            relayOnlyRoundTrip with
            {
                Receipt = parentReceipt with { ReceiptId = "changed-parent-receipt" },
            },
            fixture.Binding,
            targetBinding,
            fixture.Now,
            (authority, hash) => authority.Proof == hash).Accepted);
        Assert.True(SidecarCrossSidecarActionEntryValidation.ValidateOutcome(
            completed,
            targetBinding,
            fixture.Now,
            (authority, hash) => authority.Proof == hash).Accepted);
        Assert.False(SidecarCrossSidecarActionEntryValidation.ValidateOutcome(
            completed with
            {
                Authority = completed.Authority with { TerminalId = Guid.NewGuid() },
            },
            targetBinding,
            fixture.Now,
            (authority, hash) => authority.Proof == hash).Accepted);
        Assert.False(SidecarCrossSidecarActionEntryValidation.ValidateOutcome(
            completed with
            {
                Outcome = completed.Outcome! with { Result = Payload("permission.result", new { value = 4 }) },
            },
            targetBinding,
            fixture.Now,
            (authority, hash) => authority.Proof == hash).Accepted);
        Assert.False(SidecarCapabilityTransportValidation.ValidateActionTerminalResponse(
            terminalRequest,
            terminalResponse with { TerminalId = Guid.NewGuid() },
            fixture.Binding,
            targetBinding,
            fixture.Now,
            (authority, hash) => authority.Proof == hash).Accepted);
        Assert.False(SidecarCapabilityTransportValidation.ValidateActionTerminalResponse(
            terminalRequest,
            terminalResponse with
            {
                Execution = terminalResponse.Execution with { Result = Payload("permission.result", new { value = 5 }) },
            },
            fixture.Binding,
            targetBinding,
            fixture.Now,
            (authority, hash) => authority.Proof == hash).Accepted);
        Assert.False(SidecarCapabilityTransportValidation.ValidateActionTerminalResponse(
            terminalRequest,
            terminalResponse with
            {
                ResultIdentity = terminalResponse.ResultIdentity! with { ContentHash = "changed-result-hash" },
            },
            fixture.Binding,
            targetBinding,
            fixture.Now,
            (authority, hash) => authority.Proof == hash).Accepted);
        Assert.False(SidecarCapabilityTransportValidation.ValidateActionTerminalResponse(
            terminalRequest,
            terminalResponse with
            {
                Receipt = childReceipt with { ReceiptId = "changed-receipt" },
            },
            fixture.Binding,
            targetBinding,
            fixture.Now,
            (authority, hash) => authority.Proof == hash).Accepted);
        Assert.False(SidecarCapabilityTransportValidation.ValidateActionTerminalResponse(
            terminalRequest,
            terminalResponse with
            {
                SafeFailure = new SidecarSafeFailureIdentity(Guid.NewGuid(), "changed.failure", "Changed failure."),
            },
            fixture.Binding,
            targetBinding,
            fixture.Now,
            (authority, hash) => authority.Proof == hash).Accepted);
        Assert.Equal(SidecarCapabilityErrors.Replay, targetSession.BeginCrossSidecarActionEntryCall(
            relay.Carrier,
            terminal,
            relay.Carrier.Action.ByteLength,
            fixture.Now,
            out _,
            (authority, hash) => authority.Proof == hash).Code);

        Assert.True(fixture.Session.CompleteCrossSidecarActionEntry(relay.Carrier, fixture.Now).Accepted);
        Assert.True(fixture.Session.CompleteCall(parentCall.CallId, 1).Accepted);
    }

    [Fact]
    public void CrossSidecarFailedAndCancelledOutcomesUseCompletedTerminalExecution()
    {
        var failed = CreateCrossRelay(CreateFixture(), CreateFixture(moduleId: "module-b", graphId: "graph-b"));
        AssertCrossSidecarNonSuccessfulOutcome(failed, ActionOutcomeKind.Failed, includeError: true);

        var cancelled = CreateCrossRelay(CreateFixture(), CreateFixture(moduleId: "module-c", graphId: "graph-c"));
        AssertCrossSidecarNonSuccessfulOutcome(cancelled, ActionOutcomeKind.Cancelled, includeError: false);
    }

    private static void AssertCrossSidecarNonSuccessfulOutcome(
        CrossRelayFixture cross,
        ActionOutcomeKind kind,
        bool includeError)
    {
        var failure = new SidecarSafeFailureIdentity(Guid.NewGuid(), "cross.failure", "The cross-sidecar operation failed safely.");
        var terminal = new SidecarActionTerminalRegistration(
            Guid.NewGuid(),
            cross.Relay.Descriptor.InputTypeIdentity,
            cross.Relay.Descriptor.InputSchemaVersion,
            cross.Relay.Descriptor.ResultTypeIdentity,
            cross.Relay.Descriptor.ResultSchemaVersion,
            cross.Relay.Descriptor.DescriptorHash);
        var begin = cross.TargetSession.BeginCrossSidecarActionEntryCall(
            cross.Relay.Carrier,
            terminal,
            cross.Relay.Carrier.Action.ByteLength,
            cross.Now,
            out _,
            (authority, hash) => authority.Proof == hash);
        Assert.True(begin.Accepted, begin.Message);
        var receipt = new SidecarTerminalReceipt(
            $"{kind}-receipt",
            cross.Relay.Descriptor.Key,
            cross.Relay.Descriptor.Version,
            cross.Relay.Carrier.Authority.TargetChildCall.CallId,
            cross.Relay.Carrier.Authority.Attempt,
            "cross-scope",
            cross.Relay.Carrier.Action.ContentHash);
        Assert.True(cross.TargetSession.RecordTerminal(
            cross.Relay.Carrier.Authority.TargetChildCall.CallId,
            terminal.TerminalId,
            receipt).Accepted);
        var outcome = new SidecarActionOutcomeEnvelope(
            kind,
            null,
            null,
            includeError ? new ExecutionError("cross.error", "The operation failed.") : null,
            null,
            receipt,
            failure,
            1);
        var complete = cross.TargetSession.CompleteCrossSidecarActionEntry(
            cross.Relay.Carrier,
            outcome,
            receipt,
            new SidecarTerminalExecutionResult(null, failure, true),
            null,
            failure,
            cross.Now,
            (authority, hash) => hash,
            out var completed);
        Assert.True(complete.Accepted, complete.Message);
        Assert.NotNull(completed);
        Assert.True(SidecarCrossSidecarActionEntryValidation.ValidateOutcome(
            completed!,
            cross.TargetBinding,
            cross.Now,
            (authority, hash) => authority.Proof == hash).Accepted);
    }

    [Fact]
    public void CrossSidecarEntryRejectsChangedCarrierAndWrongTargetOwner()
    {
        var fixture = CreateFixture();
        var parentCall = fixture.Call with
        {
            Capability = SidecarCapabilityKind.Action,
            CallId = Guid.NewGuid(),
            ReplayNonce = "cross-parent-negative",
            Sequence = 1,
            Deadline = fixture.Now.AddMinutes(1),
        };
        var parentContext = IssueContext(
            fixture,
            new RequestPrincipal("source-user"),
            HostActionEntryIngress.CrossModule,
            lineage: new HostActionEntryLineage(
                new SharpClawActionKey("source.action"),
                1,
                "source-descriptor",
                "source.input",
                1,
                "source-schema",
                null,
                null));
        var parentAction = Payload("source.input", new { value = 1 });
        ActivateContext(fixture, parentContext);
        Assert.True(fixture.Session.BeginCall(parentCall, SidecarCapabilityKind.Action, parentAction, parentAction.ByteLength, fixture.Now, parentContext).Accepted);
        Assert.True(fixture.Session.RecordTerminal(
            parentCall.CallId,
            Guid.NewGuid(),
            new SidecarTerminalReceipt("source-receipt-negative", new SharpClawActionKey("source.action"), 1, parentCall.CallId, 1, "source-scope", parentAction.ContentHash)).Accepted);

        var targetBinding = fixture.Binding with
        {
            ModuleId = "permission.module",
            GraphId = "permission.graph",
            SessionId = Guid.NewGuid(),
            RequestId = Guid.NewGuid(),
            CancellationId = Guid.NewGuid(),
            Grant = fixture.Binding.Grant with { ModuleId = "permission.module", GraphId = "permission.graph" },
            Authentication = fixture.Binding.Authentication with { Nonce = "target-negative", BindingHash = string.Empty },
        };
        targetBinding = targetBinding with { Authentication = targetBinding.Authentication with { BindingHash = SidecarCapabilitySessionValidator.ComputeBindingHash(targetBinding) } };
        var targetSession = new SidecarCapabilitySession(targetBinding, _ => true, new HashSet<string>(StringComparer.Ordinal).Add, fixture.Now);
        var descriptor = new SidecarActionDescriptorIdentity(new SharpClawActionKey("permission.action"), 1, "module-owned", "permission.input", "permission-input-schema", 1, "permission.result", "permission-result-schema", 1, "permission-descriptor");
        var entry = new SidecarModuleActionEntryDefinition("permission.module", "permission.graph", descriptor, "permission.module", "permission.graph");
        var request = new SidecarCrossSidecarActionEntryRequest(descriptor.Key, 1, Payload("permission.input", new { value = 2 }), parentCall.Deadline, fixture.Now.AddMinutes(2));
        var relayResult = fixture.Session.IssueCrossSidecarActionEntryRelay(parentCall, request, targetSession, entry, new ActionPipelineSnapshot("snapshot", []), fixture.Now, (authority, hash) => hash, out var relay);
        Assert.True(relayResult.Accepted, relayResult.Message);
        Assert.NotNull(relay);
        var changed = relay!.Carrier with { Action = Payload("permission.input", new { value = 9 }) };
        var changedResult = targetSession.BeginCrossSidecarActionEntryCall(
            changed,
            new SidecarActionTerminalRegistration(Guid.NewGuid(), descriptor.InputTypeIdentity, 1, descriptor.ResultTypeIdentity, 1, descriptor.DescriptorHash),
            changed.Action.ByteLength,
            fixture.Now,
            out _,
            (authority, hash) => authority.Proof == hash);
        Assert.False(changedResult.Accepted);

        var wrongEntry = entry with { ModuleId = "other.module", TerminalOwnerModuleId = "other.module" };
        Assert.Equal(SidecarCapabilityErrors.SpoofedIdentity, fixture.Session.IssueCrossSidecarActionEntryRelay(parentCall, request, targetSession, wrongEntry, new ActionPipelineSnapshot("snapshot", []), fixture.Now, (authority, hash) => hash, out _).Code);
    }

    [Fact]
    public async Task CrossSidecarReciprocalRelayDoesNotDeadlock()
    {
        var source = CreateFixture(moduleId: "module-a", graphId: "graph-a");
        var target = CreateFixture(moduleId: "module-b", graphId: "graph-b");
        var sourceParent = PrepareCrossParent(source, "source.parent");
        var targetParent = PrepareCrossParent(target, "target.parent");
        var sourceEntry = new SidecarModuleActionEntryDefinition(
            source.Binding.ModuleId,
            source.Binding.GraphId,
            new SidecarActionDescriptorIdentity(
                new SharpClawActionKey("source.child"),
                1,
                "source.category",
                "source.child.input",
                "source-child-input-schema",
                1,
                "source.child.result",
                "source-child-result-schema",
                1,
                "source-child-descriptor"),
            source.Binding.ModuleId,
            source.Binding.GraphId);
        var targetEntry = sourceEntry with
        {
            ModuleId = target.Binding.ModuleId,
            GraphId = target.Binding.GraphId,
            Descriptor = sourceEntry.Descriptor with
            {
                Key = new SharpClawActionKey("target.child"),
                Category = "target.category",
                InputTypeIdentity = "target.child.input",
                InputSchemaHash = "target-child-input-schema",
                ResultTypeIdentity = "target.child.result",
                ResultSchemaHash = "target-child-result-schema",
                DescriptorHash = "target-child-descriptor",
            },
            TerminalOwnerModuleId = target.Binding.ModuleId,
            TerminalOwnerGraphId = target.Binding.GraphId,
        };
        var sourceRequest = new SidecarCrossSidecarActionEntryRequest(
            targetEntry.Descriptor.Key,
            targetEntry.Descriptor.Version,
            Payload(targetEntry.Descriptor.InputTypeIdentity, new { value = 2 }),
            sourceParent.Call.Deadline,
            source.Now.AddMinutes(2));
        var targetRequest = new SidecarCrossSidecarActionEntryRequest(
            sourceEntry.Descriptor.Key,
            sourceEntry.Descriptor.Version,
            Payload(sourceEntry.Descriptor.InputTypeIdentity, new { value = 3 }),
            targetParent.Call.Deadline,
            target.Now.AddMinutes(2));
        SidecarCrossSidecarActionEntryRelay? sourceRelay = null;
        SidecarCrossSidecarActionEntryRelay? targetRelay = null;
        var sourceTask = Task.Run(() => source.Session.IssueCrossSidecarActionEntryRelay(
            sourceParent.Call,
            sourceRequest,
            target.Session,
            targetEntry,
            new ActionPipelineSnapshot("target-snapshot", []),
            source.Now,
            (authority, hash) => hash,
            out sourceRelay));
        var targetTask = Task.Run(() => target.Session.IssueCrossSidecarActionEntryRelay(
            targetParent.Call,
            targetRequest,
            source.Session,
            sourceEntry,
            new ActionPipelineSnapshot("source-snapshot", []),
            target.Now,
            (authority, hash) => hash,
            out targetRelay));

        var all = Task.WhenAll(sourceTask, targetTask);
        Assert.Same(all, await Task.WhenAny(all, Task.Delay(TimeSpan.FromSeconds(2))));
        Assert.True((await sourceTask).Accepted);
        Assert.True((await targetTask).Accepted);
        Assert.NotNull(sourceRelay);
        Assert.NotNull(targetRelay);
    }

    [Fact]
    public void CrossSidecarTargetExpiryReleasesSourceParent()
    {
        var source = CreateFixture(moduleId: "module-a", graphId: "graph-a");
        var target = CreateFixture(moduleId: "module-b", graphId: "graph-b");
        var cross = CreateCrossRelay(source, target);

        var removed = target.Session.SweepExpiredHostActionEntryCarriers(
            cross.Relay.Carrier.ExpiresAt.AddSeconds(1));

        Assert.Equal(1, removed);
        Assert.True(source.Session.CompleteCall(cross.ParentCall.CallId, 1).Accepted);
    }

    [Fact]
    public void CrossSidecarTargetDisconnectAtReservationBarrierReleasesSourceParent()
    {
        var source = CreateFixture(moduleId: "module-a", graphId: "graph-a");
        var target = CreateFixture(moduleId: "module-b", graphId: "graph-b");
        var attempt = CreateCrossRelayAttempt(
            source,
            target,
            session => (authority, hash) =>
            {
                session.Disconnect();
                return hash;
            });

        Assert.False(attempt.Result.Accepted);
        Assert.Equal(SidecarCapabilityErrors.InvalidBinding, attempt.Result.Code);
        Assert.True(source.Session.CompleteCall(attempt.ParentCall.CallId, 1).Accepted);
    }

    [Fact]
    public void CrossSidecarTargetDisconnectReleasesSourceParent()
    {
        var source = CreateFixture(moduleId: "module-a", graphId: "graph-a");
        var target = CreateFixture(moduleId: "module-b", graphId: "graph-b");
        var cross = CreateCrossRelay(source, target);

        target.Session.Disconnect();

        Assert.True(source.Session.CompleteCall(cross.ParentCall.CallId, 1).Accepted);
    }

    [Fact]
    public void CrossSidecarNormalActivityDrainsExpiredPeerCleanup()
    {
        var source = CreateFixture(moduleId: "module-a", graphId: "graph-a");
        var target = CreateFixture(moduleId: "module-b", graphId: "graph-b");
        var cross = CreateCrossRelay(source, target);
        var now = cross.Relay.Carrier.ExpiresAt.AddSeconds(1);
        var call = target.Call with
        {
            Capability = SidecarCapabilityKind.Action,
            CallId = Guid.NewGuid(),
            ReplayNonce = "normal-activity-after-expiry",
            Sequence = 2,
            Deadline = now.AddSeconds(30),
        };
        var payload = Payload("normal.activity.input", new { value = 1 });

        Assert.True(target.Session.BeginCall(
            call,
            SidecarCapabilityKind.Action,
            payload,
            payload.ByteLength,
            now,
            null).Accepted);
        Assert.True(source.Session.CompleteCall(cross.ParentCall.CallId, 1).Accepted);
    }

    private static (SidecarCapabilityCallIdentity Call, HostActionEntryRequestContext Context, SidecarSerializedPayload Action)
        PrepareCrossParent(Fixture fixture, string key)
    {
        var call = fixture.Call with
        {
            Capability = SidecarCapabilityKind.Action,
            CallId = Guid.NewGuid(),
            ReplayNonce = $"{key}-nonce",
            Sequence = 1,
            Deadline = fixture.Now.AddMinutes(1),
        };
        var action = Payload($"{key}.input", new { value = 1 });
        var context = IssueContext(
            fixture,
            new RequestPrincipal($"{key}-caller"),
            HostActionEntryIngress.CrossModule,
            lineage: new HostActionEntryLineage(
                new SharpClawActionKey(key),
                1,
                $"{key}-descriptor",
                action.TypeIdentity,
                1,
                $"{key}-schema",
                null,
                null));
        ActivateContext(fixture, context);
        Assert.True(fixture.Session.BeginCall(
            call,
            SidecarCapabilityKind.Action,
            action,
            action.ByteLength,
            fixture.Now,
            context).Accepted);
        Assert.True(fixture.Session.RecordTerminal(
            call.CallId,
            Guid.NewGuid(),
            new SidecarTerminalReceipt(
                $"{key}-receipt",
                new SharpClawActionKey(key),
                1,
                call.CallId,
                1,
                $"{key}-scope",
                action.ContentHash)).Accepted);
        return (call, context, action);
    }

    private static CrossRelayFixture CreateCrossRelay(Fixture source, Fixture target)
    {
        var parent = PrepareCrossParent(source, "source.parent");
        var descriptor = new SidecarActionDescriptorIdentity(
            new SharpClawActionKey("target.child"),
            1,
            "target.category",
            "target.child.input",
            "target-child-input-schema",
            1,
            "target.child.result",
            "target-child-result-schema",
            1,
            "target-child-descriptor");
        var entry = new SidecarModuleActionEntryDefinition(
            target.Binding.ModuleId,
            target.Binding.GraphId,
            descriptor,
            target.Binding.ModuleId,
            target.Binding.GraphId);
        var request = new SidecarCrossSidecarActionEntryRequest(
            descriptor.Key,
            descriptor.Version,
            Payload(descriptor.InputTypeIdentity, new { value = 2 }),
            parent.Call.Deadline,
            source.Now.AddMinutes(2));
        var result = source.Session.IssueCrossSidecarActionEntryRelay(
            parent.Call,
            request,
            target.Session,
            entry,
            new ActionPipelineSnapshot("target-snapshot", []),
            source.Now,
            (authority, hash) => hash,
            out var relay);
        Assert.True(result.Accepted, result.Message);
        return new CrossRelayFixture(parent.Call, relay!, target.Session, target.Binding, source.Now);
    }

    private static CrossRelayAttempt CreateCrossRelayAttempt(
        Fixture source,
        Fixture target,
        Func<SidecarCapabilitySession, Func<SidecarCrossSidecarActionEntryAuthority, string, string>> proofFactory)
    {
        var parent = PrepareCrossParent(source, "source.parent.barrier");
        var descriptor = new SidecarActionDescriptorIdentity(
            new SharpClawActionKey("target.child.barrier"),
            1,
            "target.category",
            "target.child.barrier.input",
            "target-child-barrier-input-schema",
            1,
            "target.child.barrier.result",
            "target-child-barrier-result-schema",
            1,
            "target-child-barrier-descriptor");
        var entry = new SidecarModuleActionEntryDefinition(
            target.Binding.ModuleId,
            target.Binding.GraphId,
            descriptor,
            target.Binding.ModuleId,
            target.Binding.GraphId);
        var request = new SidecarCrossSidecarActionEntryRequest(
            descriptor.Key,
            descriptor.Version,
            Payload(descriptor.InputTypeIdentity, new { value = 2 }),
            parent.Call.Deadline,
            source.Now.AddMinutes(2));
        var result = source.Session.IssueCrossSidecarActionEntryRelay(
            parent.Call,
            request,
            target.Session,
            entry,
            new ActionPipelineSnapshot("target-barrier-snapshot", []),
            source.Now,
            proofFactory(target.Session),
            out var relay);
        return new CrossRelayAttempt(result, parent.Call, relay, target.Session, target.Binding, source.Now);
    }

    private static void ConsumeStorageCalls(Fixture fixture, int count, string noncePrefix)
    {
        for (var index = 0; index < count; index++)
        {
            var call = fixture.Call with
            {
                CallId = Guid.NewGuid(),
                ReplayNonce = $"{noncePrefix}-{index}",
                Sequence = index + 1,
            };
            var payload = Payload("storage.request", new { value = index });
            Assert.True(fixture.Session.BeginCall(
                call,
                SidecarCapabilityKind.Storage,
                payload,
                payload.ByteLength,
                fixture.Now).Accepted);
            Assert.True(fixture.Session.CompleteCall(call.CallId, 0).Accepted);
        }
    }

    private static SidecarCapabilityCallIdentity ActionCall(
        Fixture fixture,
        long sequence,
        string replayNonce) =>
        fixture.Call with
        {
            Capability = SidecarCapabilityKind.Action,
            CallId = Guid.NewGuid(),
            ReplayNonce = replayNonce,
            Sequence = sequence,
            Deadline = fixture.Now.AddMinutes(1),
        };

    private static SidecarActionDescriptorIdentity NestedDescriptor(
        string key,
        string inputType) =>
        new(
            new SharpClawActionKey(key),
            1,
            "budget",
            inputType,
            $"{inputType}-schema",
            1,
            $"{inputType}-result",
            $"{inputType}-result-schema",
            1,
            $"{inputType}-descriptor");

    private static HostActionEntryContribution NestedContribution(
        SidecarActionDescriptorIdentity descriptor) =>
        new(
            new HostActionEntryIngressBinding(HostActionEntryIngress.Cli, "budget"),
            new HostActionEntryLineage(
                descriptor.Key,
                descriptor.Version,
                descriptor.DescriptorHash,
                descriptor.InputTypeIdentity,
                descriptor.InputSchemaVersion,
                descriptor.InputSchemaHash,
                null,
                null));

    private static HostActionEntryRequestContext IssueContext(
        Fixture fixture,
        RequestPrincipal caller,
        HostActionEntryIngress ingress,
        Guid? traceId = null,
        Guid? idempotencyKey = null,
        DateTimeOffset? actionDeadline = null,
        DateTimeOffset? contextExpiresAt = null,
        HostActionEntryLineage? lineage = null,
        bool bindPayload = false)
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
            contextExpiresAt ?? fixture.Binding.ExpiresAt)
        {
            Contribution = new HostActionEntryContribution(
                ingress switch
                {
                    HostActionEntryIngress.Endpoint => new HostActionEntryIngressBinding(ingress, "/demo"),
                    HostActionEntryIngress.Cli => new HostActionEntryIngressBinding(ingress, "demo"),
                    HostActionEntryIngress.Tool => new HostActionEntryIngressBinding(ingress, "clock_now"),
                    _ => new HostActionEntryIngressBinding(ingress, "source.module", "target.module"),
                },
                bindPayload
                    ? lineage ?? throw new ArgumentException("A payload-bound context requires lineage.", nameof(lineage))
                    : LineageForContext(lineage)),
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

    private sealed record ExternalSessionFixture(
        Fixture SessionFixture,
        SidecarExternalActionDispatchAuthority Authority)
    {
        public DateTimeOffset Now => SessionFixture.Now;
        public SidecarCapabilitySession Session => SessionFixture.Session;
    }

    private sealed record CrossRelayFixture(
        SidecarCapabilityCallIdentity ParentCall,
        SidecarCrossSidecarActionEntryRelay Relay,
        SidecarCapabilitySession TargetSession,
        SidecarCapabilitySessionBinding TargetBinding,
        DateTimeOffset Now);

    private sealed record CrossRelayAttempt(
        SidecarCapabilityValidationResult Result,
        SidecarCapabilityCallIdentity ParentCall,
        SidecarCrossSidecarActionEntryRelay? Relay,
        SidecarCapabilitySession TargetSession,
        SidecarCapabilitySessionBinding TargetBinding,
        DateTimeOffset Now);

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

    private sealed class RuntimeNestedTransport(
        Fixture fixture,
        SidecarActionCapabilityRequest parentRequest,
        SidecarActionTerminalTransportRequest terminalRequest,
        SidecarActionDescriptorIdentity resolvedDescriptor,
        HostActionEntryContribution resolvedContribution) : ISidecarCapabilityTransport
    {
        public int NestedRequests { get; private set; }
        public int ActionCalls { get; private set; }

        public ValueTask<SidecarStorageCapabilityResponse> InvokeStorageAsync(
            SidecarStorageCapabilityRequest request,
            CancellationToken ct = default) =>
            throw new NotSupportedException();

        public ValueTask<SidecarActionCapabilityResponse> InvokeActionAsync(
            SidecarActionCapabilityRequest request,
            CancellationToken ct = default)
        {
            ActionCalls++;
            var begin = fixture.Session.BeginActionCall(
                request,
                request.Action.ByteLength,
                fixture.Now,
                out _);
            Assert.True(begin.Accepted, begin.Message);
            var receipt = new SidecarTerminalReceipt(
                "runtime-child-receipt",
                request.Descriptor.Key,
                request.Descriptor.Version,
                request.Call.CallId,
                1,
                "runtime-child-scope",
                request.Action.ContentHash);
            Assert.True(fixture.Session.RecordTerminal(request.Call.CallId, Guid.NewGuid(), receipt).Accepted);
            Assert.True(fixture.Session.CompleteCall(request.Call.CallId, 1).Accepted);
            var result = Payload(request.Descriptor.ResultTypeIdentity, "child-result");
            return ValueTask.FromResult(new SidecarActionCapabilityResponse(
                new SidecarActionResultIdentity(
                    Guid.NewGuid(),
                    request.Call.CallId,
                    request.Descriptor.Key,
                    request.Descriptor.Version,
                    request.Descriptor.ResultTypeIdentity,
                    result.ContentHash),
                new SidecarActionOutcomeEnvelope(
                    ActionOutcomeKind.Completed,
                    result,
                    null,
                    null,
                    null,
                    receipt,
                    fixture.SafeFailure,
                    1),
                null,
                fixture.SafeFailure,
                true));
        }

        public ValueTask<SidecarActionTerminalTransportResponse> InvokeActionTerminalAsync(
            SidecarActionTerminalTransportRequest request,
            CancellationToken ct = default)
        {
            NestedRequests++;
            var wireRequest = SidecarCapabilityTransportCodec.Deserialize<SidecarActionTerminalTransportRequest>(
                SidecarCapabilityTransportCodec.Serialize(request));
            var nestedRequest = wireRequest.NestedCarrierRequest ?? throw new InvalidOperationException();
            var issue = fixture.Session.IssueNestedHostActionEntryRelay(
                wireRequest.Call,
                nestedRequest,
                resolvedDescriptor,
                resolvedContribution,
                fixture.Now,
                out var relay);
            Assert.True(issue.Accepted, issue.Message);
            Assert.NotNull(relay);
            var relayAuthority = wireRequest.Authority with
            {
                NestedCarrierRelay = relay,
                NestedCarrierOutcomeKind = SidecarNestedHostActionEntryRelayOutcomeKind.Issued,
                NestedCarrierRequestFingerprint =
                    SidecarCapabilityTransportValidation.ComputeNestedCarrierRequestFingerprint(nestedRequest),
                Proof = "relay-proof",
            };
            relayAuthority = relayAuthority with
            {
                CanonicalBindingHash = SidecarCapabilityTransportValidation.ComputeTerminalAuthorityBindingHash(
                    relayAuthority),
            };
            Assert.True(SidecarCapabilityTransportValidation.ValidateActionTerminalRequest(
                parentRequest,
                wireRequest,
                fixture.Binding,
                fixture.Now,
                (_, _) => true).Accepted);
            var result = Payload(wireRequest.Descriptor.ResultTypeIdentity, "parent-result");
            var response = new SidecarActionTerminalTransportResponse(
                new SidecarActionResultIdentity(
                    Guid.NewGuid(),
                    wireRequest.Call.CallId,
                    wireRequest.Descriptor.Key,
                    wireRequest.Descriptor.Version,
                    wireRequest.Descriptor.ResultTypeIdentity,
                    result.ContentHash),
                new SidecarTerminalExecutionResult(result, null, true),
                wireRequest.Receipt,
                fixture.SafeFailure)
            {
                TerminalId = wireRequest.TerminalId,
                NestedCarrierRelay = relay,
                NestedCarrierAuthority = relayAuthority,
                NestedCarrierOutcome = new(
                    SidecarNestedHostActionEntryRelayOutcomeKind.Issued,
                    null),
            };
            var wireResponse = SidecarCapabilityTransportCodec.Deserialize<SidecarActionTerminalTransportResponse>(
                SidecarCapabilityTransportCodec.Serialize(response));
            Assert.Equal(wireRequest.TerminalId, wireResponse.TerminalId);
            Assert.Equal(wireRequest.Receipt, wireResponse.Receipt);
            Assert.Equal(response.NestedCarrierRelay!.Carrier.CarrierId, wireResponse.NestedCarrierRelay!.Carrier.CarrierId);
            Assert.Equal(resolvedDescriptor, wireResponse.NestedCarrierRelay.Descriptor);
            Assert.Equal(response.NestedCarrierAuthority!.AuthorityId, wireResponse.NestedCarrierAuthority!.AuthorityId);
            Assert.Equal(response.NestedCarrierOutcome!.Kind, wireResponse.NestedCarrierOutcome!.Kind);
            var responseValidation = SidecarCapabilityTransportValidation.ValidateActionTerminalResponse(
                wireRequest,
                wireResponse,
                fixture.Binding,
                (authority, bindingHash) => authority.Proof == "relay-proof" &&
                    bindingHash == SidecarCapabilityTransportValidation.ComputeTerminalAuthorityBindingHash(authority));
            Assert.True(responseValidation.Accepted, $"{responseValidation.Code}: {responseValidation.Message}");

            var validRelay = wireResponse.NestedCarrierRelay!;
            var validAuthority = wireResponse.NestedCarrierAuthority!;
            foreach (var mutatedDescriptor in new[]
            {
                resolvedDescriptor with { Key = new SharpClawActionKey("child.runtime.mutated") },
                resolvedDescriptor with { Version = resolvedDescriptor.Version + 1 },
                resolvedDescriptor with { Category = "mutated-category" },
                resolvedDescriptor with { InputTypeIdentity = typeof(Guid).AssemblyQualifiedName! },
                resolvedDescriptor with { InputSchemaHash = "mutated-input-schema" },
                resolvedDescriptor with { InputSchemaVersion = resolvedDescriptor.InputSchemaVersion + 1 },
                resolvedDescriptor with { ResultTypeIdentity = typeof(Guid).AssemblyQualifiedName! },
                resolvedDescriptor with { ResultSchemaHash = "mutated-result-schema" },
                resolvedDescriptor with { ResultSchemaVersion = resolvedDescriptor.ResultSchemaVersion + 1 },
                resolvedDescriptor with { DescriptorHash = "mutated-descriptor" },
            })
            {
                var mutatedRelay = validRelay with
                {
                    Carrier = validRelay.Carrier with
                    {
                        ActionKey = mutatedDescriptor.Key,
                        ActionVersion = mutatedDescriptor.Version,
                        DescriptorHash = mutatedDescriptor.DescriptorHash,
                        Descriptor = mutatedDescriptor,
                    },
                };
                var mutatedAuthority = validAuthority with
                {
                    NestedCarrierRelay = mutatedRelay,
                };
                mutatedAuthority = mutatedAuthority with
                {
                    CanonicalBindingHash = SidecarCapabilityTransportValidation.ComputeTerminalAuthorityBindingHash(
                        mutatedAuthority),
                };
                var mutatedResponse = wireResponse with
                {
                    NestedCarrierRelay = mutatedRelay,
                    NestedCarrierAuthority = mutatedAuthority,
                };
                var mutationValidation = SidecarCapabilityTransportValidation.ValidateActionTerminalResponse(
                    wireRequest,
                    mutatedResponse,
                    fixture.Binding,
                    (authority, bindingHash) => authority.Proof == "relay-proof" &&
                        bindingHash == validAuthority.CanonicalBindingHash);
                Assert.False(mutationValidation.Accepted, mutatedDescriptor.ToString());
            }

            Assert.Null(request.Authority.NestedCarrierRelay);
            return ValueTask.FromResult(wireResponse);
        }

        public SidecarActionTerminalTransportRequest CreateNestedTerminalRequest(
            SidecarNestedHostActionEntryRequest nestedRequest) =>
            terminalRequest with { NestedCarrierRequest = nestedRequest };
    }

    private sealed class RuntimeNestedHostActionEntryProxy(
        RuntimeNestedTransport transport) : IHostActionEntry
    {
        public ValueTask<IActionOutcome<TResult>> InvokeAsync<TAction, TResult>(
            HostActionEntryRequest<TAction, TResult> request,
            IHostActionEntryTerminal<TAction, TResult> terminal,
            CancellationToken cancellationToken = default) =>
            ValueTask.FromException<IActionOutcome<TResult>>(
                new NotSupportedException("The runtime nested test uses the nested entry only."));

        public async ValueTask<IActionOutcome<TResult>> InvokeNestedAsync<TParentAction, TAction, TResult>(
            HostActionEntryNestedRequest<TParentAction, TAction, TResult> request,
            IHostActionEntryTerminal<TAction, TResult> terminal,
            CancellationToken cancellationToken = default)
        {
            var action = Payload(
                typeof(TAction).AssemblyQualifiedName ?? typeof(TAction).FullName ?? typeof(TAction).Name,
                request.Action);
            var nestedRequest = new SidecarNestedHostActionEntryRequest(
                request.ActionKey,
                request.ActionVersion,
                action,
                request.ParentContext.Deadline,
                request.ParentContext.Deadline);
            var terminalResponse = await transport.InvokeActionTerminalAsync(
                transport.CreateNestedTerminalRequest(nestedRequest),
                cancellationToken);
            var relay = terminalResponse.NestedCarrierRelay ?? throw new InvalidOperationException();
            var descriptor = relay.Descriptor;
            var childRequest = SidecarActionCapabilityRequest.HostEntryNested(
                relay.Call,
                descriptor,
                action,
                new SidecarCancellationIdentity(relay.Call.CancellationId, "runtime-child-cancel", relay.Call.Deadline),
                relay.Call.Deadline,
                relay.Carrier,
                new SidecarActionTerminalRegistration(
                    Guid.NewGuid(),
                    descriptor.InputTypeIdentity,
                    descriptor.InputSchemaVersion,
                    descriptor.ResultTypeIdentity,
                    descriptor.ResultSchemaVersion,
                    descriptor.DescriptorHash));
            var response = await transport.InvokeActionAsync(childRequest, cancellationToken);
            return new RecordedOutcome<TResult>(response.Outcome.Kind);
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
