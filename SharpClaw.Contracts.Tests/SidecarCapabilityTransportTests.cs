using System.Security.Cryptography;
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
        var conversationId = Guid.NewGuid();
        var context = IssueContext(
            fixture,
            new RequestPrincipal("tool-user", Roles: new HashSet<string>(["reader"], StringComparer.Ordinal)),
            HostActionEntryIngress.Tool,
            conversationId: conversationId,
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
            context,
            conversationId);

        var encoded = SidecarCapabilityTransportCodec.Serialize(start);
        var roundTrip = SidecarCapabilityTransportCodec.Deserialize<SidecarToolHandlerInvokeStart>(encoded);

        Assert.Equal(encoded, SidecarCapabilityTransportCodec.Serialize(roundTrip));
        Assert.True(roundTrip.IsWellFormed(fixture.Now));
        Assert.Equal(context.CapabilityId, roundTrip.HostActionContext.CapabilityId);
        Assert.Equal(context.CancellationId, roundTrip.HostActionContext.CancellationId);
        Assert.Equal(conversationId, roundTrip.ConversationId);

        var nullConversationContext = roundTrip.HostActionContext with
        {
            Contribution = roundTrip.HostActionContext.Contribution! with
            {
                IngressBinding = roundTrip.HostActionContext.Contribution.IngressBinding with
                {
                    SecondaryIdentity = null,
                },
            },
        };
        Assert.True(
            (roundTrip with
            {
                ConversationId = null,
                HostActionContext = nullConversationContext,
            }).IsWellFormed(fixture.Now));

        var toolInvocation = new ToolInvocation(
            roundTrip.InvocationId,
            roundTrip.ConversationId,
            "tool-call",
            roundTrip.ToolName,
            roundTrip.Input,
            roundTrip.HostActionContext);
        var toolInvocationRoundTrip = SidecarCapabilityTransportCodec.Deserialize<ToolInvocation>(
            SidecarCapabilityTransportCodec.Serialize(toolInvocation));
        Assert.True(toolInvocationRoundTrip.IsWellFormed(fixture.Now));

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
        Assert.False((roundTrip with { ConversationId = null }).IsWellFormed(fixture.Now));
        Assert.False((roundTrip with { ConversationId = Guid.Empty }).IsWellFormed(fixture.Now));
        Assert.False((roundTrip with { ConversationId = Guid.NewGuid() }).IsWellFormed(fixture.Now));
        var nonCanonicalConversationContext = roundTrip.HostActionContext with
        {
            Contribution = roundTrip.HostActionContext.Contribution! with
            {
                IngressBinding = roundTrip.HostActionContext.Contribution.IngressBinding with
                {
                    SecondaryIdentity = conversationId.ToString("D").ToUpperInvariant(),
                },
            },
        };
        Assert.False(
            (roundTrip with { HostActionContext = nonCanonicalConversationContext })
                .IsWellFormed(fixture.Now));
        Assert.False(
            (toolInvocationRoundTrip with { ConversationId = null })
                .IsWellFormed(fixture.Now));
        Assert.False(
            (toolInvocationRoundTrip with { ConversationId = Guid.Empty })
                .IsWellFormed(fixture.Now));
        Assert.False(
            (toolInvocationRoundTrip with { ConversationId = Guid.NewGuid() })
                .IsWellFormed(fixture.Now));
        Assert.False(
            (toolInvocationRoundTrip with { HostActionContext = nonCanonicalConversationContext })
                .IsWellFormed(fixture.Now));
        Assert.True(
            (toolInvocationRoundTrip with
            {
                ConversationId = null,
                HostActionContext = nullConversationContext,
            }).IsWellFormed(fixture.Now));
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

    [Theory]
    [InlineData(HostEndpointTransport.Http)]
    [InlineData(HostEndpointTransport.WebSocket)]
    public void Endpoint_route_authority_round_trips_and_validates_before_carrier_admission(
        HostEndpointTransport transport)
    {
        static bool Authenticate(HostEndpointRouteAuthority authority, string hash) =>
            authority.Proof == hash;

        var fixture = CreateFixture(
            authenticateEndpointRouteAuthority: Authenticate,
            actionInputBytes: 4096,
            protocolMessageBytes: 4096);
        var context = IssueContext(
            fixture,
            new RequestPrincipal("endpoint-user"),
            HostActionEntryIngress.Endpoint);
        var request = EndpointRouteRequest(fixture, context, transport);
        var call = ActionCall(fixture, 1, $"endpoint-route-{transport}");

        var issued = fixture.Session.IssueHostEndpointRouteAuthority(
            request,
            call,
            fixture.Now,
            authority => HostEndpointRouteAuthorityValidator.ComputeBindingHash(authority),
            out var authority);

        Assert.True(issued.Accepted, issued.Message);
        Assert.NotNull(authority);
        var encodedRequest = SidecarCapabilityTransportCodec.Serialize(request);
        var encodedAuthority = SidecarCapabilityTransportCodec.Serialize(authority!);
        var requestRoundTrip =
            SidecarCapabilityTransportCodec.Deserialize<HostEndpointRouteRequest>(encodedRequest);
        var authorityRoundTrip =
            SidecarCapabilityTransportCodec.Deserialize<HostEndpointRouteAuthority>(encodedAuthority);

        Assert.Equal(encodedRequest, SidecarCapabilityTransportCodec.Serialize(requestRoundTrip));
        Assert.Equal(encodedAuthority, SidecarCapabilityTransportCodec.Serialize(authorityRoundTrip));
        Assert.True(
            HostEndpointRouteAuthorityValidator.Validate(
                requestRoundTrip,
                authorityRoundTrip,
                fixture.Now,
                Authenticate).Accepted);
        var carrier = new HostActionEntryCarrierIdentity(
            HostActionEntryIngress.Endpoint,
            context.InvocationId,
            context.Contribution!.IngressBinding);
        Assert.False(
            fixture.Session.BeginHostActionEntryCarrier(
                context,
                carrier,
                fixture.Now,
                out _).Accepted);
        Assert.False(
            fixture.Session.TryGetActiveHostActionEntryCarrier(
                context.CapabilityId,
                out _));

        var carrierResult = fixture.Session.BeginHostEndpointRouteCarrier(
            requestRoundTrip,
            authorityRoundTrip,
            carrier,
            fixture.Now,
            out _);
        Assert.True(carrierResult.Accepted, carrierResult.Message);

        Assert.False(
            fixture.Session.BeginHostEndpointRouteCarrier(
                requestRoundTrip,
                authorityRoundTrip,
                carrier,
                fixture.Now,
                out _).Accepted);
    }

    [Theory]
    [InlineData("authority", "call-id")]
    [InlineData("authority", "replay-nonce")]
    [InlineData("reservation", "call-id")]
    [InlineData("reservation", "replay-nonce")]
    public void Endpoint_route_rejects_invalid_call_identity_without_state(
        string path,
        string mutation)
    {
        static bool Authenticate(HostEndpointRouteAuthority authority, string hash) =>
            authority.Proof == hash;

        var fixture = CreateFixture(
            authenticateEndpointRouteAuthority: Authenticate,
            actionInputBytes: 4096,
            protocolMessageBytes: 4096);
        var context = IssueContext(
            fixture,
            new RequestPrincipal("endpoint-user"),
            HostActionEntryIngress.Endpoint,
            actionDeadline: fixture.Now.AddMinutes(1),
            contextExpiresAt: fixture.Now.AddMinutes(1));
        var request = EndpointRouteRequest(fixture, context, HostEndpointTransport.Http);
        var validCall = ActionCall(fixture, 1, $"invalid-call-{path}-{mutation}");
        var invalidCall = mutation == "call-id"
            ? validCall with { CallId = Guid.Empty }
            : validCall with { ReplayNonce = string.Empty };

        if (path == "authority")
        {
            var rejected = fixture.Session.IssueHostEndpointRouteAuthority(
                request,
                invalidCall,
                fixture.Now,
                HostEndpointRouteAuthorityValidator.ComputeBindingHash,
                out var rejectedAuthority);
            Assert.False(rejected.Accepted);
            Assert.Equal(SidecarCapabilityErrors.SpoofedIdentity, rejected.Code);
            Assert.Null(rejectedAuthority);
        }
        else
        {
            var rejected = fixture.Session.IssueHostEndpointRouteReservation(
                request,
                invalidCall,
                fixture.Now,
                reservation => SidecarCapabilityTransportValidation.ComputeEndpointRouteReservationBindingHash(
                    reservation),
                out var rejectedReservation);
            Assert.False(rejected.Accepted);
            Assert.Equal(SidecarCapabilityErrors.SpoofedIdentity, rejected.Code);
            Assert.Null(rejectedReservation);
        }

        Assert.Equal(0, fixture.Session.LastSequence);
        Assert.Equal(1, fixture.Session.IssuedHostActionEntryContextCount);
        Assert.Equal(0, fixture.Session.ActiveHostActionEntryCarrierCount);

        if (path == "authority")
        {
            var issued = fixture.Session.IssueHostEndpointRouteAuthority(
                request,
                validCall,
                fixture.Now,
                HostEndpointRouteAuthorityValidator.ComputeBindingHash,
                out var authority);
            Assert.True(issued.Accepted, issued.Message);
            Assert.NotNull(authority);
            var carrier = new HostActionEntryCarrierIdentity(
                HostActionEntryIngress.Endpoint,
                context.InvocationId,
                context.Contribution!.IngressBinding);
            var admitted = fixture.Session.BeginHostEndpointRouteCarrier(
                request,
                authority!,
                carrier,
                fixture.Now,
                out var carrierAuthority);
            Assert.True(admitted.Accepted, admitted.Message);
            Assert.True(
                fixture.Session.CompleteHostActionEntryCarrier(
                    carrierAuthority!,
                    HostActionEntryCarrierCompletionKind.Failed,
                    fixture.Now).Accepted);
        }
        else
        {
            var issued = fixture.Session.IssueHostEndpointRouteReservation(
                request,
                validCall,
                fixture.Now,
                reservation => SidecarCapabilityTransportValidation.ComputeEndpointRouteReservationBindingHash(
                    reservation),
                out var reservation);
            Assert.True(issued.Accepted, issued.Message);
            Assert.NotNull(reservation);
            Assert.True(
                fixture.Session.ReleaseHostEndpointRouteReservation(
                    reservation!,
                    fixture.Now).Accepted);
        }

        var rotated = CreateRotatedBinding(fixture, $"invalid-call-{path}-{mutation}-rotation");
        fixture.BindingHashes.Add(rotated.Authentication.BindingHash);
        var cleanupTime = fixture.Now.AddMinutes(1).AddSeconds(1);
        fixture.Session.SweepExpiredHostActionEntryCarriers(cleanupTime);
        Assert.True(fixture.Session.RotateBinding(rotated, cleanupTime).Accepted);
    }

    [Theory]
    [InlineData("/demo", "get")]
    [InlineData("/demo", "\u00C9")]
    [InlineData("/demo", "GET ")]
    [InlineData(" /demo", "GET")]
    [InlineData("/demo?value", "GET")]
    [InlineData("/demo#fragment", "GET")]
    [InlineData("/demo\\item", "GET")]
    [InlineData("//demo", "GET")]
    [InlineData("/./demo", "GET")]
    [InlineData("/../demo", "GET")]
    [InlineData("/demo//item", "GET")]
    [InlineData("/demo%2Fitem", "GET")]
    [InlineData("/demo%2", "GET")]
    [InlineData("/demo%ZZ", "GET")]
    [InlineData("/demo\u0001", "GET")]
    [InlineData("/demo\u0020item", "GET")]
    public void Endpoint_route_identity_rejects_noncanonical_forms_without_throwing(
        string path,
        string method)
    {
        var identity = new HostEndpointRouteIdentity(
            "/demo",
            path,
            method,
            HostEndpointTransport.Http);

        Assert.False(identity.IsWellFormed);
    }

    [Fact]
    public void Endpoint_route_metadata_uses_case_insensitive_headers_and_case_sensitive_queries()
    {
        static bool Authenticate(HostEndpointRouteAuthority authority, string hash) =>
            authority.Proof == hash;

        var fixture = CreateFixture(authenticateEndpointRouteAuthority: Authenticate);
        var context = IssueContext(
            fixture,
            new RequestPrincipal("endpoint-user"),
            HostActionEntryIngress.Endpoint);
        var request = EndpointRouteRequest(fixture, context, HostEndpointTransport.Http);
        var call = ActionCall(fixture, 1, "endpoint-metadata");
        var issue = fixture.Session.IssueHostEndpointRouteAuthority(
            request,
            call,
            fixture.Now,
            authority => HostEndpointRouteAuthorityValidator.ComputeBindingHash(authority),
            out var authority);

        Assert.True(issue.Accepted, issue.Message);
        var caseChangedHeaders = request with
        {
            Headers = new Dictionary<string, string[]>(StringComparer.Ordinal)
            {
                ["X-REQUEST"] = ["one", "two"],
                ["x-empty"] = [],
            },
        };
        Assert.True(
            HostEndpointRouteAuthorityValidator.Validate(
                caseChangedHeaders,
                authority!,
                fixture.Now,
                Authenticate).Accepted);

        var duplicateHeaders = request with
        {
            Headers = new Dictionary<string, string[]>(StringComparer.Ordinal)
            {
                ["x-request"] = ["one", "two"],
                ["X-REQUEST"] = ["one", "two"],
            },
        };
        Assert.False(duplicateHeaders.IsWellFormed(fixture.Now));

        var changedQueryKey = request with
        {
            Query = new Dictionary<string, string[]>(StringComparer.Ordinal)
            {
                ["Tag"] = ["one", "two"],
            },
        };
        Assert.False(
            HostEndpointRouteAuthorityValidator.Validate(
                changedQueryKey,
                authority!,
                fixture.Now,
                Authenticate).Accepted);

        var changedRouteValue = request with
        {
            RouteValues = new Dictionary<string, string[]>(StringComparer.Ordinal)
            {
                ["Id"] = request.RouteValues["id"],
            },
        };
        Assert.False(
            HostEndpointRouteAuthorityValidator.Validate(
                changedRouteValue,
                authority!,
                fixture.Now,
                Authenticate).Accepted);

        var multipleRouteValues = request with
        {
            RouteValues = new Dictionary<string, string[]>(StringComparer.Ordinal)
            {
                ["id"] = ["one", "two"],
            },
        };
        Assert.False(multipleRouteValues.IsWellFormed(fixture.Now));
    }

    [Theory]
    [InlineData("header name", "value")]
    [InlineData("header:name", "value")]
    [InlineData("h\u00E9ader", "value")]
    [InlineData("header", "bad\rvalue")]
    [InlineData("header", "bad\nvalue")]
    [InlineData("header", "bad\u0000value")]
    public void Endpoint_route_rejects_invalid_header_metadata_before_authority_storage(
        string name,
        string value)
    {
        static bool Authenticate(HostEndpointRouteAuthority authority, string hash) =>
            authority.Proof == hash;

        var fixture = CreateFixture(authenticateEndpointRouteAuthority: Authenticate);
        var context = IssueContext(
            fixture,
            new RequestPrincipal("endpoint-user"),
            HostActionEntryIngress.Endpoint);
        var request = EndpointRouteRequest(fixture, context, HostEndpointTransport.Http) with
        {
            Headers = new Dictionary<string, string[]>(StringComparer.Ordinal)
            {
                [name] = [value],
            },
        };

        var rejected = fixture.Session.IssueHostEndpointRouteAuthority(
            request,
            ActionCall(fixture, 1, "invalid-header"),
            fixture.Now,
            HostEndpointRouteAuthorityValidator.ComputeBindingHash,
            out _);

        Assert.False(rejected.Accepted);
        Assert.Equal(SidecarCapabilityErrors.InvalidBinding, rejected.Code);
        Assert.Equal(1, fixture.Session.IssuedHostActionEntryContextCount);
        Assert.Equal(0, fixture.Session.ActiveHostActionEntryCarrierCount);

        var validRequest = EndpointRouteRequest(fixture, context, HostEndpointTransport.Http);
        Assert.True(
            fixture.Session.IssueHostEndpointRouteAuthority(
                validRequest,
                ActionCall(fixture, 1, "valid-header"),
                fixture.Now,
                HostEndpointRouteAuthorityValidator.ComputeBindingHash,
                out _).Accepted);
    }

    [Fact]
    public void Endpoint_route_authority_uses_only_one_unconsumed_issued_context()
    {
        static bool Authenticate(HostEndpointRouteAuthority authority, string hash) =>
            authority.Proof == hash;

        var fixture = CreateFixture(authenticateEndpointRouteAuthority: Authenticate);
        var context = IssueContext(
            fixture,
            new RequestPrincipal("endpoint-user"),
            HostActionEntryIngress.Endpoint);
        var request = EndpointRouteRequest(fixture, context, HostEndpointTransport.Http);
        var firstCall = ActionCall(fixture, 1, "first-route");
        var firstIssue = fixture.Session.IssueHostEndpointRouteAuthority(
            request,
            firstCall,
            fixture.Now,
            HostEndpointRouteAuthorityValidator.ComputeBindingHash,
            out var firstAuthority);
        Assert.True(firstIssue.Accepted, firstIssue.Message);

        var firstCarrier = new HostActionEntryCarrierIdentity(
            HostActionEntryIngress.Endpoint,
            context.InvocationId,
            context.Contribution!.IngressBinding);
        var firstAdmission = fixture.Session.BeginHostEndpointRouteCarrier(
            request,
            firstAuthority!,
            firstCarrier,
            fixture.Now,
            out var firstCarrierAuthority);
        Assert.True(firstAdmission.Accepted, firstAdmission.Message);

        var secondIssue = fixture.Session.IssueHostEndpointRouteAuthority(
            request,
            firstCall with
            {
                CallId = Guid.NewGuid(),
                ReplayNonce = "second-route",
                Sequence = 2,
            },
            fixture.Now,
            HostEndpointRouteAuthorityValidator.ComputeBindingHash,
            out _);
        Assert.False(secondIssue.Accepted);
        Assert.Equal(SidecarCapabilityErrors.SpoofedIdentity, secondIssue.Code);

        var completed = fixture.Session.CompleteHostActionEntryCarrier(
            firstCarrierAuthority!,
            HostActionEntryCarrierCompletionKind.Failed,
            fixture.Now);
        Assert.True(completed.Accepted, completed.Message);

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
                Nonce = "endpoint-rotation",
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

        var rotation = fixture.Session.RotateBinding(rotated, fixture.Now);
        Assert.True(rotation.Accepted, rotation.Message);
    }

    [Theory]
    [InlineData(HostEndpointTransport.Http)]
    [InlineData(HostEndpointTransport.WebSocket)]
    public void Endpoint_typed_child_reservation_supports_exact_retry_and_explicit_release(
        HostEndpointTransport transport)
    {
        var test = CreateEndpointTypedActionChildCase(
            transport,
            maxInFlight: 2,
            maxCalls: 4);
        var original = test.Relay.ReceivingReservation;
        var descriptor = original.Child.Descriptor;

        var retry = test.Source.Session.IssueHostEndpointTypedActionChildReservation(
            test.SourceParent.Call,
            test.SourceParent.ActiveContext,
            test.ChildCall,
            descriptor,
            test.ChildAction,
            test.Source.Now,
            candidate => KeyedEndpointProof(
                "child-reservation",
                SidecarEndpointTypedActionChildValidation.ComputeReservationHash(candidate)),
            out var retriedReservation);
        Assert.True(retry.Accepted, retry.Message);
        Assert.NotNull(retriedReservation);
        Assert.True(
            SidecarCapabilityTransportCodec.Serialize(original)
                .SequenceEqual(SidecarCapabilityTransportCodec.Serialize(retriedReservation)));
        Assert.Equal(2, test.Source.Session.LastSequence);

        var abort = AbortUnimportedEndpointTypedActionChild(test, test.Source.Now);
        Assert.Equal(1, test.Source.Session.LastSequence);
        Assert.Equal(1, test.Receiving.Session.LastSequence);

        var laterCall = test.ChildCall with
        {
            CallId = Guid.NewGuid(),
            ReplayNonce = "endpoint-typed-child-later",
            Sequence = test.Source.Session.LastSequence + 1,
        };
        var later = test.Source.Session.IssueHostEndpointTypedActionChildReservation(
            test.SourceParent.Call,
            test.SourceParent.ActiveContext,
            laterCall,
            descriptor,
            test.ChildAction,
            test.Source.Now,
            candidate => KeyedEndpointProof(
                "child-reservation",
                SidecarEndpointTypedActionChildValidation.ComputeReservationHash(candidate)),
            out var laterReservation);
        Assert.True(later.Accepted, later.Message);
        Assert.NotNull(laterReservation);
        Assert.True(test.Source.Session.ReleaseHostEndpointTypedActionChildReservation(
            laterReservation!,
            test.Source.Now).Accepted);

        Assert.Equal(
            SidecarCapabilityErrors.Replay,
            test.Receiving.Session.ConsumeHostEndpointTypedActionChildImportAbort(
                abort,
                test.Receiving.Now).Code);
        Assert.True(test.Receiving.Session.CompleteCall(
            test.ReceivingParent.Call.CallId,
            0).Accepted);
        Assert.True(test.Receiving.Session.CompleteHostActionEntryCarrier(
            test.ReceivingParent.Carrier,
            HostActionEntryCarrierCompletionKind.Succeeded,
            test.Receiving.Now).Accepted);
        Assert.True(test.Source.Session.CompleteHostEndpointRouteRelay(
            test.RouteRelay,
            test.Source.Now).Accepted);
        var sourceParentCompletion = test.Source.Session.CompleteCall(
            test.SourceParent.Call.CallId,
            0);
        Assert.True(
            sourceParentCompletion.Accepted,
            $"{sourceParentCompletion.Code}: {sourceParentCompletion.Message}");
        Assert.True(test.Source.Session.CompleteHostActionEntryCarrier(
            test.SourceParent.Carrier,
            HostActionEntryCarrierCompletionKind.Succeeded,
            test.Source.Now).Code == SidecarCapabilityErrors.Replay);
    }

    [Fact]
    public void Endpoint_route_authority_rejects_second_pending_authority_for_context()
    {
        static bool Authenticate(HostEndpointRouteAuthority authority, string hash) =>
            authority.Proof == hash;

        var fixture = CreateFixture(
            authenticateEndpointRouteAuthority: Authenticate,
            actionInputBytes: 4096,
            protocolMessageBytes: 4096);
        var invocationType = typeof(HostEndpointInvocation).AssemblyQualifiedName!;
        var context = IssueContext(
            fixture,
            new RequestPrincipal("endpoint-user"),
            HostActionEntryIngress.Endpoint,
            lineage: new HostActionEntryLineage(
                new SharpClawActionKey("endpoint.action"),
                1,
                "endpoint-descriptor",
                invocationType,
                1,
                "endpoint-input-schema",
                null,
                null),
            bindPayload: true);
        var request = EndpointRouteRequest(fixture, context, HostEndpointTransport.Http);
        var firstCall = ActionCall(fixture, 1, "pending-context-first");
        var firstIssue = fixture.Session.IssueHostEndpointRouteAuthority(
            request,
            firstCall,
            fixture.Now,
            HostEndpointRouteAuthorityValidator.ComputeBindingHash,
            out var firstAuthority);
        Assert.True(firstIssue.Accepted, firstIssue.Message);
        Assert.NotNull(firstAuthority);

        var secondCall = firstCall with
        {
            CallId = Guid.NewGuid(),
            ReplayNonce = "pending-context-second",
            Sequence = 1,
        };
        var secondIssue = fixture.Session.IssueHostEndpointRouteAuthority(
            request,
            secondCall,
            fixture.Now,
            HostEndpointRouteAuthorityValidator.ComputeBindingHash,
            out var secondAuthority);
        Assert.False(secondIssue.Accepted);
        Assert.Equal(SidecarCapabilityErrors.Duplicate, secondIssue.Code);
        Assert.Null(secondAuthority);
        Assert.Equal(1, fixture.Session.IssuedHostActionEntryContextCount);
        Assert.Equal(0, fixture.Session.ActiveHostActionEntryCarrierCount);

        var carrier = new HostActionEntryCarrierIdentity(
            HostActionEntryIngress.Endpoint,
            context.InvocationId,
            context.Contribution!.IngressBinding);
        var admission = fixture.Session.BeginHostEndpointRouteCarrier(
            request,
            firstAuthority!,
            carrier,
            fixture.Now,
            out var carrierAuthority);
        Assert.True(admission.Accepted, admission.Message);

        var payload = EndpointInvocationPayload(invocationType, request.Invocation);
        Assert.True(
            fixture.Session.BeginCall(
                firstCall,
                SidecarCapabilityKind.Action,
                payload,
                payload.ByteLength,
                fixture.Now,
                context).Accepted);
        Assert.True(
            fixture.Session.RecordTerminal(
                firstCall.CallId,
                Guid.NewGuid(),
                new SidecarTerminalReceipt(
                    "pending-context-receipt",
                    new SharpClawActionKey("endpoint.action"),
                    1,
                    firstCall.CallId,
                    1,
                    payload.ContentHash,
                    "endpoint-scope")).Accepted);
        Assert.True(fixture.Session.CompleteCall(firstCall.CallId, 1).Accepted);
        Assert.True(
            fixture.Session.CompleteHostActionEntryCarrier(
                carrierAuthority!,
                HostActionEntryCarrierCompletionKind.Succeeded,
                fixture.Now).Accepted);

        var rotated = CreateRotatedBinding(fixture, "pending-context-rotation");
        fixture.BindingHashes.Add(rotated.Authentication.BindingHash);
        var rotation = fixture.Session.RotateBinding(rotated, fixture.Now);
        Assert.True(rotation.Accepted, rotation.Message);
    }

    [Fact]
    public void Endpoint_route_pending_authority_is_removed_when_context_expires()
    {
        static bool Authenticate(HostEndpointRouteAuthority authority, string hash) =>
            authority.Proof == hash;

        var fixture = CreateFixture(authenticateEndpointRouteAuthority: Authenticate);
        var context = IssueContext(
            fixture,
            new RequestPrincipal("endpoint-user"),
            HostActionEntryIngress.Endpoint,
            actionDeadline: fixture.Now.AddMilliseconds(500),
            contextExpiresAt: fixture.Now.AddSeconds(1));
        var request = EndpointRouteRequest(fixture, context, HostEndpointTransport.Http);
        var issue = fixture.Session.IssueHostEndpointRouteAuthority(
            request,
            ActionCall(fixture, 1, "pending-expiry"),
            fixture.Now,
            HostEndpointRouteAuthorityValidator.ComputeBindingHash,
            out var authority);
        Assert.True(issue.Accepted, issue.Message);
        Assert.NotNull(authority);
        Assert.Equal(1, fixture.Session.IssuedHostActionEntryContextCount);

        var removed = fixture.Session.SweepExpiredHostActionEntryCarriers(
            fixture.Now.AddSeconds(2));
        Assert.Equal(1, removed);
        Assert.Equal(0, fixture.Session.IssuedHostActionEntryContextCount);
        Assert.Equal(0, fixture.Session.ActiveHostActionEntryCarrierCount);

        var rotated = CreateRotatedBinding(fixture, "pending-expiry-rotation");
        fixture.BindingHashes.Add(rotated.Authentication.BindingHash);
        var rotation = fixture.Session.RotateBinding(rotated, fixture.Now);
        Assert.True(rotation.Accepted, rotation.Message);
    }

    [Theory]
    [InlineData(1, 4)]
    [InlineData(4, 1)]
    public void Endpoint_route_reservation_exact_retry_precedes_capacity_limits(
        int maxInFlight,
        int maxCalls)
    {
        var fixture = CreateFixture(
            maxInFlight: maxInFlight,
            maxCalls: maxCalls);
        var context = IssueContext(
            fixture,
            new RequestPrincipal("reservation-retry"),
            HostActionEntryIngress.Endpoint);
        var request = EndpointRouteRequest(fixture, context, HostEndpointTransport.Http);
        var call = ActionCall(fixture, 1, "reservation-retry");
        var issue = fixture.Session.IssueHostEndpointRouteReservation(
            request,
            call,
            fixture.Now,
            reservation => SidecarCapabilityTransportValidation.ComputeEndpointRouteReservationBindingHash(
                reservation),
            out var first);

        Assert.True(issue.Accepted, issue.Message);
        Assert.NotNull(first);
        var firstBytes = SidecarCapabilityTransportCodec.Serialize(first);
        var sequence = fixture.Session.LastSequence;

        var retry = fixture.Session.IssueHostEndpointRouteReservation(
            request,
            call,
            fixture.Now,
            reservation => SidecarCapabilityTransportValidation.ComputeEndpointRouteReservationBindingHash(
                reservation),
            out var second);

        Assert.True(retry.Accepted, retry.Message);
        Assert.NotNull(second);
        Assert.Equal(firstBytes, SidecarCapabilityTransportCodec.Serialize(second));
        Assert.Equal(sequence, fixture.Session.LastSequence);
        Assert.Equal(0, fixture.Session.ActiveHostActionEntryCarrierCount);

        Assert.True(fixture.Session.ReleaseHostEndpointRouteReservation(second!, fixture.Now).Accepted);
        Assert.Equal(
            SidecarCapabilityErrors.Replay,
            fixture.Session.ReleaseHostEndpointRouteReservation(second!, fixture.Now).Code);
        Assert.Equal(0, fixture.Session.LastSequence);
    }

    [Theory]
    [InlineData("signer-failure")]
    [InlineData("signer-mutation")]
    [InlineData("disconnect")]
    [InlineData("rotation")]
    [InlineData("expiry")]
    [InlineData("release")]
    [InlineData("abandoned")]
    public void Endpoint_route_reservation_direct_lifecycle_preserves_state(string lifecycle)
    {
        var fixture = CreateFixture(maxInFlight: 4, maxCalls: 4);
        var contextDeadline = fixture.Now.AddMinutes(1);
        var context = IssueContext(
            fixture,
            new RequestPrincipal("reservation-lifecycle"),
            HostActionEntryIngress.Endpoint,
            actionDeadline: contextDeadline,
            contextExpiresAt: contextDeadline);
        var request = EndpointRouteRequest(fixture, context, HostEndpointTransport.Http);
        var call = ActionCall(fixture, 1, "reservation-lifecycle");
        static string Proof(SidecarHostEndpointRouteReservation reservation) =>
            SidecarCapabilityTransportValidation.ComputeEndpointRouteReservationBindingHash(
                reservation);

        if (lifecycle is "signer-failure" or "signer-mutation" or "disconnect")
        {
            var failed = fixture.Session.IssueHostEndpointRouteReservation(
                request,
                call,
                fixture.Now,
                lifecycle == "signer-failure"
                    ? _ => throw new InvalidOperationException("test signer failure")
                    : lifecycle == "signer-mutation"
                        ? reservation =>
                        {
                            reservation.Request.Body[0] = 99;
                            return Proof(reservation);
                        }
                        : reservation =>
                        {
                            fixture.Session.Disconnect();
                            return Proof(reservation);
                        },
                out var rejectedReservation);

            Assert.False(failed.Accepted);
            Assert.Equal(
                lifecycle == "disconnect"
                    ? SidecarCapabilityErrors.Disconnected
                    : SidecarCapabilityErrors.Unauthenticated,
                failed.Code);
            Assert.Null(rejectedReservation);
            Assert.Equal(0, fixture.Session.LastSequence);
            Assert.Equal(0, fixture.Session.ActiveHostActionEntryCarrierCount);
            if (lifecycle == "disconnect")
                return;

            var retry = fixture.Session.IssueHostEndpointRouteReservation(
                request,
                call,
                fixture.Now,
                Proof,
                out var reservation);
            Assert.True(retry.Accepted, retry.Message);
            Assert.True(fixture.Session.ReleaseHostEndpointRouteReservation(reservation!, fixture.Now).Accepted);
            return;
        }

        var issued = fixture.Session.IssueHostEndpointRouteReservation(
            request,
            call,
            fixture.Now,
            Proof,
            out var reservationResult);
        Assert.True(issued.Accepted, issued.Message);
        Assert.NotNull(reservationResult);

        if (lifecycle == "rotation")
        {
            var rotated = CreateRotatedBinding(fixture, "reservation-lifecycle-rotation");
            fixture.BindingHashes.Add(rotated.Authentication.BindingHash);
            Assert.False(fixture.Session.RotateBinding(rotated, fixture.Now).Accepted);
            Assert.True(fixture.Session.ReleaseHostEndpointRouteReservation(reservationResult!, fixture.Now).Accepted);
            Assert.True(
                fixture.Session.SweepExpiredHostActionEntryCarriers(contextDeadline.AddSeconds(1)) > 0);
            Assert.True(fixture.Session.RotateBinding(rotated, contextDeadline.AddSeconds(1)).Accepted);
            return;
        }

        if (lifecycle is "expiry" or "abandoned")
        {
            Assert.True(
                fixture.Session.SweepExpiredHostActionEntryCarriers(
                    fixture.Now.AddMinutes(2)) > 0);
            var rotated = CreateRotatedBinding(fixture, "reservation-lifecycle-expiry");
            fixture.BindingHashes.Add(rotated.Authentication.BindingHash);
            Assert.True(fixture.Session.RotateBinding(rotated, contextDeadline.AddSeconds(1)).Accepted);
            return;
        }

        Assert.True(fixture.Session.ReleaseHostEndpointRouteReservation(reservationResult!, fixture.Now).Accepted);
        Assert.Equal(
            SidecarCapabilityErrors.Replay,
            fixture.Session.ReleaseHostEndpointRouteReservation(reservationResult!, fixture.Now).Code);
        var retryAfterRelease = fixture.Session.IssueHostEndpointRouteReservation(
            request,
            call,
            fixture.Now,
            Proof,
            out var retriedReservation);
        Assert.True(retryAfterRelease.Accepted, retryAfterRelease.Message);
        Assert.True(fixture.Session.ReleaseHostEndpointRouteReservation(retriedReservation!, fixture.Now).Accepted);
        var rotatedAfterRelease = CreateRotatedBinding(fixture, "reservation-lifecycle-release");
        fixture.BindingHashes.Add(rotatedAfterRelease.Authentication.BindingHash);
        Assert.True(
            fixture.Session.SweepExpiredHostActionEntryCarriers(contextDeadline.AddSeconds(1)) > 0);
        Assert.True(
            fixture.Session.RotateBinding(rotatedAfterRelease, contextDeadline.AddSeconds(1)).Accepted);
    }

    [Theory]
    [InlineData("session")]
    [InlineData("request")]
    [InlineData("cancellation")]
    [InlineData("module")]
    [InlineData("graph")]
    [InlineData("capability")]
    [InlineData("call")]
    [InlineData("nonce")]
    [InlineData("sequence")]
    [InlineData("deadline")]
    [InlineData("request-header")]
    [InlineData("request-query")]
    [InlineData("request-body")]
    public void Endpoint_route_reservation_changed_call_or_request_does_not_retrieve_existing(
        string mutation)
    {
        var fixture = CreateFixture(maxInFlight: 4, maxCalls: 4);
        var context = IssueContext(
            fixture,
            new RequestPrincipal("reservation-identity"),
            HostActionEntryIngress.Endpoint);
        var request = EndpointRouteRequest(fixture, context, HostEndpointTransport.Http);
        var call = ActionCall(fixture, 1, "reservation-identity");
        var issue = fixture.Session.IssueHostEndpointRouteReservation(
            request,
            call,
            fixture.Now,
            reservation => SidecarCapabilityTransportValidation.ComputeEndpointRouteReservationBindingHash(
                reservation),
            out var original);
        Assert.True(issue.Accepted, issue.Message);
        Assert.NotNull(original);
        var sequence = fixture.Session.LastSequence;

        var changedCall = call;
        var changedRequest = request;
        switch (mutation)
        {
            case "session":
                changedCall = call with { SessionId = Guid.NewGuid() };
                break;
            case "request":
                changedCall = call with { RequestId = Guid.NewGuid() };
                break;
            case "cancellation":
                changedCall = call with { CancellationId = Guid.NewGuid() };
                break;
            case "module":
                changedCall = call with { ModuleId = "other-module" };
                break;
            case "graph":
                changedCall = call with { GraphId = "other-graph" };
                break;
            case "capability":
                changedCall = call with { Capability = SidecarCapabilityKind.Storage };
                break;
            case "call":
                changedCall = call with { CallId = Guid.NewGuid() };
                break;
            case "nonce":
                changedCall = call with { ReplayNonce = "changed-reservation-nonce" };
                break;
            case "sequence":
                changedCall = call with { Sequence = call.Sequence + 1 };
                break;
            case "deadline":
                changedCall = call with { Deadline = call.Deadline.AddSeconds(1) };
                break;
            case "request-header":
                changedRequest = request with
                {
                    Headers = new Dictionary<string, string[]>(request.Headers)
                    {
                        ["x-request"] = ["changed"],
                    },
                };
                break;
            case "request-query":
                changedRequest = request with
                {
                    Query = new Dictionary<string, string[]>(request.Query)
                    {
                        ["tag"] = ["changed"],
                    },
                };
                break;
            case "request-body":
                changedRequest = request with { Body = [9, 8, 7] };
                break;
        }

        var rejected = fixture.Session.IssueHostEndpointRouteReservation(
            changedRequest,
            changedCall,
            fixture.Now,
            reservation => SidecarCapabilityTransportValidation.ComputeEndpointRouteReservationBindingHash(
                reservation),
            out var changedReservation);

        Assert.False(rejected.Accepted, rejected.Message);
        Assert.Null(changedReservation);
        Assert.Equal(sequence, fixture.Session.LastSequence);
        var retry = fixture.Session.IssueHostEndpointRouteReservation(
            request,
            call,
            fixture.Now,
            reservation => SidecarCapabilityTransportValidation.ComputeEndpointRouteReservationBindingHash(
                reservation),
            out var exactRetry);
        Assert.True(retry.Accepted, retry.Message);
        Assert.Equal(
            SidecarCapabilityTransportCodec.Serialize(original),
            SidecarCapabilityTransportCodec.Serialize(exactRetry));
        Assert.True(fixture.Session.ReleaseHostEndpointRouteReservation(exactRetry!, fixture.Now).Accepted);
    }

    [Fact]
    public void Endpoint_route_reservation_callbacks_use_detached_input_snapshots()
    {
        var features = new ExtensionFeatureSet(new List<ExtensionFeature>
        {
            new ExtensionFeature(
                "reservation.feature",
                1,
                "module-a",
                128,
                JsonDocument.Parse("{\"mode\":\"snapshot\"}").RootElement.Clone()),
        });
        var fixture = CreateFixture(maxInFlight: 4, maxCalls: 4);
        var context = IssueContext(
            fixture,
            new RequestPrincipal(
                "reservation-snapshot",
                Roles: new HashSet<string>(["reader"], StringComparer.Ordinal)),
            HostActionEntryIngress.Endpoint,
            features: features);
        var request = EndpointRouteRequest(fixture, context, HostEndpointTransport.Http);
        var call = ActionCall(fixture, 1, "reservation-snapshot");
        var pristineRequestBytes = SidecarCapabilityTransportCodec.Serialize(request);
        Exception? mutationError = null;

        var issue = fixture.Session.IssueHostEndpointRouteReservation(
            request,
            call,
            fixture.Now,
            reservation =>
            {
                try
                {
                    ((ISet<string>)request.Invocation.HostActionContext.Caller.Roles!).Add("mutated-role");
                    ((IList<ExtensionFeature>)request.Invocation.HostActionContext.Features.Items)[0] =
                        new ExtensionFeature(
                            "mutated.feature",
                            1,
                            "module-a",
                            1,
                            JsonDocument.Parse("{}").RootElement.Clone());
                    request.Headers["x-request"][0] = "mutated-header";
                    request.Query["tag"][0] = "mutated-query";
                    request.Body[0] = 99;
                }
                catch (Exception ex)
                {
                    mutationError = ex;
                }
                return SidecarCapabilityTransportValidation.ComputeEndpointRouteReservationBindingHash(
                    reservation);
            },
            out var reservation);

        Assert.Null(mutationError);
        Assert.True(issue.Accepted, issue.Message);
        Assert.NotNull(reservation);
        Assert.Equal(
            pristineRequestBytes,
            SidecarCapabilityTransportCodec.Serialize(reservation!.Request));

        var pristineRequest = SidecarCapabilityTransportCodec.Deserialize<HostEndpointRouteRequest>(
            pristineRequestBytes);
        var retry = fixture.Session.IssueHostEndpointRouteReservation(
            pristineRequest,
            call,
            fixture.Now,
            candidate => SidecarCapabilityTransportValidation.ComputeEndpointRouteReservationBindingHash(
                candidate),
            out var exactRetry);
        Assert.True(retry.Accepted, retry.Message);
        Assert.Equal(
            SidecarCapabilityTransportCodec.Serialize(reservation),
            SidecarCapabilityTransportCodec.Serialize(exactRetry));
        Assert.True(fixture.Session.ReleaseHostEndpointRouteReservation(exactRetry!, fixture.Now).Accepted);
    }

    [Theory]
    [InlineData(HostEndpointTransport.Http)]
    [InlineData(HostEndpointTransport.WebSocket)]
    public void Imported_endpoint_parent_cannot_issue_typed_child_reservation(
        HostEndpointTransport transport)
    {
        var test = CreateEndpointTypedActionChildCase(transport);
        var descriptor = NestedDescriptor(
            "endpoint.imported.parent.rejected",
            typeof(string).AssemblyQualifiedName!);
        var action = Payload(descriptor.InputTypeIdentity, "imported-parent-rejected");
        var childCall = test.ReceivingParent.Call with
        {
            CallId = Guid.NewGuid(),
            ReplayNonce = "imported-parent-rejected",
            Sequence = test.Receiving.Session.LastSequence + 1,
        };
        var sequence = test.Receiving.Session.LastSequence;
        var carriers = test.Receiving.Session.ActiveHostActionEntryCarrierCount;
        var result = test.Receiving.Session.IssueHostEndpointTypedActionChildReservation(
            test.ReceivingParent.Call,
            test.ReceivingParent.ActiveContext,
            childCall,
            descriptor,
            action,
            test.Receiving.Now,
            candidate => KeyedEndpointProof(
                "child-reservation",
                SidecarEndpointTypedActionChildValidation.ComputeReservationHash(candidate)),
            out var reservation);

        Assert.False(result.Accepted);
        Assert.Equal(SidecarCapabilityErrors.SpoofedIdentity, result.Code);
        Assert.Null(reservation);
        Assert.Equal(sequence, test.Receiving.Session.LastSequence);
        Assert.Equal(carriers, test.Receiving.Session.ActiveHostActionEntryCarrierCount);

        AbortUnimportedEndpointTypedActionChild(test, test.Source.Now);
        Assert.True(test.Source.Session.CompleteHostEndpointRouteRelay(
            test.RouteRelay,
            test.Source.Now).Accepted);
        var sourceParentCompletion = test.Source.Session.CompleteCall(
            test.SourceParent.Call.CallId,
            0);
        Assert.True(
            sourceParentCompletion.Accepted,
            $"{sourceParentCompletion.Code}: {sourceParentCompletion.Message}");
        Assert.Equal(
            SidecarCapabilityErrors.Replay,
            test.Source.Session.CompleteHostActionEntryCarrier(
                test.SourceParent.Carrier,
                HostActionEntryCarrierCompletionKind.Succeeded,
                test.Source.Now).Code);
        Assert.True(test.Receiving.Session.CompleteCall(
            test.ReceivingParent.Call.CallId,
            0).Accepted);
        Assert.True(test.Receiving.Session.CompleteHostActionEntryCarrier(
            test.ReceivingParent.Carrier,
            HostActionEntryCarrierCompletionKind.Succeeded,
            test.Receiving.Now).Accepted);
        var rotatedSource = CreateRotatedBinding(
            test.Source,
            "imported-parent-source-rotation");
        test.Source.BindingHashes.Add(rotatedSource.Authentication.BindingHash);
        Assert.True(test.Source.Session.RotateBinding(
            rotatedSource,
            test.Source.Now).Accepted);
        var rotatedReceiving = CreateRotatedBinding(
            test.Receiving,
            "imported-parent-receiving-rotation");
        test.Receiving.BindingHashes.Add(rotatedReceiving.Authentication.BindingHash);
        Assert.True(test.Receiving.Session.RotateBinding(
            rotatedReceiving,
            test.Receiving.Now).Accepted);
    }

    [Theory]
    [InlineData(HostEndpointTransport.Http)]
    [InlineData(HostEndpointTransport.WebSocket)]
    public void Direct_endpoint_parent_cannot_issue_typed_child_relay(
        HostEndpointTransport transport)
    {
        var test = CreateEndpointTypedActionChildCase(transport);
        AbortUnimportedEndpointTypedActionChild(test, test.Source.Now);

        var descriptor = NestedDescriptor(
            "endpoint.direct.parent.rejected",
            typeof(string).AssemblyQualifiedName!);
        var action = Payload(descriptor.InputTypeIdentity, "direct-parent-rejected");
        var childCall = test.SourceParent.Call with
        {
            CallId = Guid.NewGuid(),
            ReplayNonce = "direct-parent-rejected",
            Sequence = test.Source.Session.LastSequence + 1,
        };
        var reservationResult = test.Source.Session.IssueHostEndpointTypedActionChildReservation(
            test.SourceParent.Call,
            test.SourceParent.ActiveContext,
            childCall,
            descriptor,
            action,
            test.Source.Now,
            candidate => KeyedEndpointProof(
                "child-reservation",
                SidecarEndpointTypedActionChildValidation.ComputeReservationHash(candidate)),
            out var reservation);
        Assert.True(reservationResult.Accepted, reservationResult.Message);
        Assert.NotNull(reservation);
        var wireReservation = SidecarCapabilityTransportCodec.Deserialize<
            SidecarEndpointTypedActionChildReservation>(
                SidecarCapabilityTransportCodec.Serialize(reservation));
        var sourceSequence = test.Source.Session.LastSequence;
        var sourceCarriers = test.Source.Session.ActiveHostActionEntryCarrierCount;
        var relayResult = test.Source.Session.IssueHostEndpointTypedActionChildRelay(
            test.SourceParent.Authority,
            test.SourceParent.Call,
            test.SourceParent.ActiveContext,
            wireReservation,
            test.Source.Now,
            (candidate, hash) => candidate.Proof == KeyedEndpointProof(
                "child-reservation",
                hash),
            candidate => KeyedEndpointProof(
                "child-relay",
                SidecarEndpointTypedActionChildValidation.ComputeRelayHash(candidate)),
            out var relay);

        Assert.False(relayResult.Accepted);
        Assert.Equal(SidecarCapabilityErrors.SpoofedIdentity, relayResult.Code);
        Assert.Null(relay);
        Assert.Equal(sourceSequence, test.Source.Session.LastSequence);
        Assert.Equal(sourceCarriers, test.Source.Session.ActiveHostActionEntryCarrierCount);
        Assert.True(test.Source.Session.ReleaseHostEndpointTypedActionChildReservation(
            reservation!,
            test.Source.Now).Accepted);
        Assert.True(test.Source.Session.CompleteHostEndpointRouteRelay(
            test.RouteRelay,
            test.Source.Now).Accepted);
        var sourceParentCompletion = test.Source.Session.CompleteCall(
            test.SourceParent.Call.CallId,
            0);
        Assert.True(
            sourceParentCompletion.Accepted,
            $"{sourceParentCompletion.Code}: {sourceParentCompletion.Message}");
        Assert.Equal(
            SidecarCapabilityErrors.Replay,
            test.Source.Session.CompleteHostActionEntryCarrier(
                test.SourceParent.Carrier,
                HostActionEntryCarrierCompletionKind.Succeeded,
                test.Source.Now).Code);
        Assert.True(test.Receiving.Session.CompleteCall(
            test.ReceivingParent.Call.CallId,
            0).Accepted);
        Assert.True(test.Receiving.Session.CompleteHostActionEntryCarrier(
            test.ReceivingParent.Carrier,
            HostActionEntryCarrierCompletionKind.Succeeded,
            test.Receiving.Now).Accepted);
        var rotatedSource = CreateRotatedBinding(
            test.Source,
            "direct-parent-source-rotation");
        test.Source.BindingHashes.Add(rotatedSource.Authentication.BindingHash);
        Assert.True(test.Source.Session.RotateBinding(
            rotatedSource,
            test.Source.Now).Accepted);
        var rotatedReceiving = CreateRotatedBinding(
            test.Receiving,
            "direct-parent-receiving-rotation");
        test.Receiving.BindingHashes.Add(rotatedReceiving.Authentication.BindingHash);
        Assert.True(test.Receiving.Session.RotateBinding(
            rotatedReceiving,
            test.Receiving.Now).Accepted);
    }

    [Theory]
    [InlineData(HostEndpointTransport.Http)]
    [InlineData(HostEndpointTransport.WebSocket)]
    public void Endpoint_parent_can_admit_serialized_typed_child_authority(
        HostEndpointTransport transport)
    {
        static bool AuthenticateRoute(HostEndpointRouteAuthority authority, string hash) =>
            authority.Proof == KeyedEndpointProof("route", hash);
        static bool AuthenticateReservation(
            SidecarEndpointTypedActionChildReservation reservation,
            string hash) =>
            reservation.Proof == KeyedEndpointProof("child-reservation", hash);
        static bool AuthenticateChildRelay(
            SidecarEndpointTypedActionChildRelay relay,
            string hash) =>
            relay.Proof == KeyedEndpointProof("child-relay", hash);
        static (
            HostEndpointRouteRequest Request,
            SidecarCapabilityCallIdentity Call,
            HostEndpointRouteAuthority Authority,
            HostActionEntryCarrierAuthority Carrier,
            HostActionEntryRequestContext ActiveContext) AdmitEndpointParent(
            Fixture fixture,
            HostActionEntryRequestContext context,
            HostEndpointTransport transport,
            string nonce)
        {
            var request = EndpointRouteRequest(fixture, context, transport);
            var call = ActionCall(fixture, fixture.Session.LastSequence + 1, nonce);
            var issue = fixture.Session.IssueHostEndpointRouteAuthority(
                request,
                call,
                fixture.Now,
                authority => KeyedEndpointProof(
                    "route",
                    HostEndpointRouteAuthorityValidator.ComputeBindingHash(authority)),
                out var authority);
            Assert.True(issue.Accepted, issue.Message);
            Assert.NotNull(authority);

            var carrier = new HostActionEntryCarrierIdentity(
                HostActionEntryIngress.Endpoint,
                context.InvocationId,
                context.Contribution!.IngressBinding);
            var admission = fixture.Session.BeginHostEndpointRouteCarrier(
                request,
                authority!,
                carrier,
                fixture.Now,
                out var carrierAuthority);
            Assert.True(admission.Accepted, admission.Message);
            Assert.NotNull(carrierAuthority);

            var payload = EndpointInvocationPayload(
                typeof(HostEndpointInvocation).AssemblyQualifiedName!,
                request.Invocation);
            var begin = fixture.Session.BeginCall(
                call,
                SidecarCapabilityKind.Action,
                payload,
                payload.ByteLength,
                fixture.Now,
                context);
            Assert.True(begin.Accepted, begin.Message);
            Assert.True(fixture.Session.TryGetActiveHostActionEntryContext(
                context.CapabilityId,
                out var activeContext));
            Assert.NotNull(activeContext);
            return (request, call, authority!, carrierAuthority!, activeContext!);
        }

        var source = CreateFixture(
            actionInputBytes: 4096,
            protocolMessageBytes: 65536,
            authenticateEndpointRouteAuthority: AuthenticateRoute);
        var receiving = CreateFixture(
            moduleId: "module-receiving",
            graphId: "graph-receiving",
            actionInputBytes: 4096,
            protocolMessageBytes: 65536,
            authenticateEndpointRouteAuthority: AuthenticateRoute,
            authenticateEndpointTypedActionChildReservation: AuthenticateReservation,
            authenticateEndpointTypedActionChildRelay: AuthenticateChildRelay);

        var sourceContext = IssueContext(
            source,
            new RequestPrincipal("endpoint-user"),
            HostActionEntryIngress.Endpoint,
            lineage: new HostActionEntryLineage(
                new SharpClawActionKey("endpoint.invoke"),
                1,
                "endpoint-invoke-descriptor",
                typeof(HostEndpointInvocation).AssemblyQualifiedName!,
                1,
                "endpoint-invoke-schema",
                null,
                null));
        var sourceParent = AdmitEndpointParent(
            source,
            sourceContext,
            transport,
            "endpoint-child-source");

        var receivingContextRequest = new HostActionEntryContextRequest(
            HostActionEntryIngress.Endpoint,
            sourceContext.InvocationId,
            receiving.Binding.RequestId,
            receiving.Binding.CancellationId,
            sourceContext.Caller,
            sourceContext.Features,
            sourceContext.TraceId,
            sourceContext.IdempotencyKey,
            receiving.Now.AddMinutes(1),
            receiving.Binding.ExpiresAt)
        {
            Contribution = SidecarCapabilityTransportCodec.Deserialize<HostActionEntryContribution>(
                SidecarCapabilityTransportCodec.Serialize(sourceContext.Contribution!)),
        };
        Assert.True(receiving.Session.IssueHostActionEntryContext(
            receivingContextRequest,
            receiving.Now,
            out var receivingContext).Accepted);
        Assert.NotNull(receivingContext);
        var receivingParent = AdmitEndpointParent(
            receiving,
            receivingContext!,
            transport,
            "endpoint-child-receiving");

        var descriptor = NestedDescriptor(
            "endpoint.typed.child",
            typeof(string).AssemblyQualifiedName!);
        var action = Payload(descriptor.InputTypeIdentity, "typed-child");
        var childCall = receivingParent.Call with
        {
            CallId = Guid.NewGuid(),
            ReplayNonce = "endpoint-typed-child",
            Sequence = receiving.Session.LastSequence + 1,
            Deadline = receiving.Now.AddSeconds(30),
        };
        var reservationResult = receiving.Session.IssueHostEndpointTypedActionChildReservation(
            receivingParent.Call,
            receivingParent.ActiveContext,
            childCall,
            descriptor,
            action,
            receiving.Now,
            candidate => KeyedEndpointProof(
                "child-reservation",
                SidecarEndpointTypedActionChildValidation.ComputeReservationHash(candidate)),
            out var reservation);
        Assert.True(reservationResult.Accepted, reservationResult.Message);
        Assert.NotNull(reservation);
        var wireReservation = SidecarCapabilityTransportCodec.Deserialize<
            SidecarEndpointTypedActionChildReservation>(
                SidecarCapabilityTransportCodec.Serialize(reservation));
        var sourceSequence = source.Session.LastSequence;
        var sourceCarriers = source.Session.ActiveHostActionEntryCarrierCount;
        var relayResult = source.Session.IssueHostEndpointTypedActionChildRelay(
            sourceParent.Authority,
            sourceParent.Call,
            sourceParent.ActiveContext,
            wireReservation,
            source.Now,
            (candidate, hash) => candidate.Proof == KeyedEndpointProof("child-reservation", hash),
            candidate => KeyedEndpointProof(
                "child-relay",
                SidecarEndpointTypedActionChildValidation.ComputeRelayHash(candidate)),
            out var relay);
        Assert.False(relayResult.Accepted, relayResult.Message);
        Assert.Equal(SidecarCapabilityErrors.SpoofedIdentity, relayResult.Code);
        Assert.Null(relay);
        Assert.Equal(sourceSequence, source.Session.LastSequence);
        Assert.Equal(sourceCarriers, source.Session.ActiveHostActionEntryCarrierCount);
        Assert.True(receiving.Session.ReleaseHostEndpointTypedActionChildReservation(
            reservation!,
            receiving.Now).Accepted);

        Assert.True(source.Session.CompleteCall(sourceParent.Call.CallId, 0).Accepted);
        Assert.True(source.Session.CompleteHostActionEntryCarrier(
            sourceParent.Carrier,
            HostActionEntryCarrierCompletionKind.Succeeded,
            source.Now).Accepted);
        Assert.True(receiving.Session.CompleteCall(receivingParent.Call.CallId, 0).Accepted);
        Assert.True(receiving.Session.CompleteHostActionEntryCarrier(
            receivingParent.Carrier,
            HostActionEntryCarrierCompletionKind.Succeeded,
            receiving.Now).Accepted);

        var rotatedSource = CreateRotatedBinding(source, "endpoint-child-source-rotation");
        source.BindingHashes.Add(rotatedSource.Authentication.BindingHash);
        Assert.True(source.Session.RotateBinding(rotatedSource, source.Now).Accepted);
        var rotatedReceiving = CreateRotatedBinding(receiving, "endpoint-child-receiving-rotation");
        receiving.BindingHashes.Add(rotatedReceiving.Authentication.BindingHash);
        Assert.True(receiving.Session.RotateBinding(rotatedReceiving, receiving.Now).Accepted);
    }

    [Theory]
    [InlineData("advance-sequence")]
    [InlineData("child-call")]
    [InlineData("child-nonce")]
    [InlineData("in-flight")]
    [InlineData("total-call")]
    [InlineData("budget-extension")]
    [InlineData("disconnect")]
    [InlineData("rotate")]
    [InlineData("mutation")]
    [InlineData("exception")]
    public void Endpoint_typed_child_reservation_rechecks_after_reentrant_signer(
        string mutation)
    {
        var test = CreateEndpointTypedActionChildCase(
            HostEndpointTransport.Http,
            maxInFlight: 16,
            maxCalls: 4);
        var descriptor = NestedDescriptor(
            $"endpoint.typed.reentrant.{mutation}",
            typeof(string).AssemblyQualifiedName!);
        var action = Payload(descriptor.InputTypeIdentity, $"reentrant-{mutation}");
        Guid? inFlightCallId = null;
        var childCall = test.SourceParent.Call with
        {
            CallId = Guid.NewGuid(),
            ReplayNonce = $"reentrant-{mutation}",
            Sequence = test.Source.Session.LastSequence + 1,
            Deadline = test.Source.Now.AddSeconds(30),
        };

        void ConsumeCall(SidecarCapabilityCallIdentity call)
        {
            var begin = test.Source.Session.BeginCall(
                call,
                SidecarCapabilityKind.Action,
                action,
                action.ByteLength,
                test.Source.Now);
            Assert.True(begin.Accepted, begin.Message);
            Assert.True(test.Source.Session.CompleteCall(call.CallId, 0).Accepted);
        }

        var issue = test.Source.Session.IssueHostEndpointTypedActionChildReservation(
            test.SourceParent.Call,
            test.SourceParent.ActiveContext,
            childCall,
            descriptor,
            action,
            test.Source.Now,
            candidate =>
            {
                switch (mutation)
                {
                    case "advance-sequence":
                        ConsumeCall(candidate.Child.Call with
                        {
                            CallId = Guid.NewGuid(),
                            ReplayNonce = "reentrant-sequence",
                        });
                        break;
                    case "child-call":
                        ConsumeCall(candidate.Child.Call);
                        break;
                    case "child-nonce":
                        ConsumeCall(candidate.Child.Call with
                        {
                            CallId = Guid.NewGuid(),
                        });
                        break;
                    case "in-flight":
                        var inFlightCall = candidate.Child.Call with
                        {
                            CallId = Guid.NewGuid(),
                            ReplayNonce = "reentrant-in-flight",
                        };
                        inFlightCallId = inFlightCall.CallId;
                        var inFlight = test.Source.Session.BeginCall(
                            inFlightCall,
                            SidecarCapabilityKind.Action,
                            action,
                            action.ByteLength,
                            test.Source.Now);
                        Assert.True(inFlight.Accepted, inFlight.Message);
                        break;
                    case "total-call":
                        ConsumeCall(candidate.Child.Call with
                        {
                            CallId = Guid.NewGuid(),
                            ReplayNonce = "reentrant-total-one",
                        });
                        ConsumeCall(candidate.Child.Call with
                        {
                            CallId = Guid.NewGuid(),
                            ReplayNonce = "reentrant-total-two",
                            Sequence = candidate.Child.Call.Sequence + 1,
                        });
                        break;
                    case "budget-extension":
                        ConsumeCall(candidate.Child.Call with
                        {
                            CallId = Guid.NewGuid(),
                            ReplayNonce = "reentrant-budget-one",
                        });
                        ConsumeCall(candidate.Child.Call with
                        {
                            CallId = Guid.NewGuid(),
                            ReplayNonce = "reentrant-budget-two",
                            Sequence = candidate.Child.Call.Sequence + 1,
                        });
                        break;
                    case "disconnect":
                        test.Source.Session.Disconnect();
                        break;
                    case "rotate":
                        var parentCompletion = test.Source.Session.CompleteCall(
                            test.SourceParent.Call.CallId,
                            0);
                        if (!parentCompletion.Accepted)
                            throw new InvalidOperationException($"parent-completion:{parentCompletion.Code}");
                        var rotated = CreateRotatedBinding(
                            test.Source,
                            "reentrant-rotation");
                        test.Source.BindingHashes.Add(
                            rotated.Authentication.BindingHash);
                        var rotationResult = test.Source.Session.RotateBinding(
                            rotated,
                            test.Source.Now);
                        if (!rotationResult.Accepted)
                            throw new InvalidOperationException($"rotation-result:{rotationResult.Code}");
                        break;
                    case "mutation":
                        ((HashSet<string>)candidate.ChildContext.Caller!.Roles!).Add("reentrant-mutation");
                        break;
                    case "exception":
                        throw new InvalidOperationException("reentrant signer failure");
                    default:
                        throw new ArgumentOutOfRangeException(nameof(mutation));
                }

                return KeyedEndpointProof(
                    "child-reservation",
                    SidecarEndpointTypedActionChildValidation.ComputeReservationHash(candidate));
            },
            out var reservation);

        Assert.False(issue.Accepted, $"{mutation}: {issue.Message}");
        Assert.Null(reservation);
        Assert.Equal(
            mutation == "disconnect" ? 0 : 1,
            test.Source.Session.ActiveHostActionEntryCarrierCount);

        if (inFlightCallId is not null)
        {
            Assert.True(test.Source.Session.CompleteCall(inFlightCallId.Value, 0).Accepted);
        }
    }

    [Theory]
    [InlineData("parent-call")]
    [InlineData("parent-context")]
    [InlineData("route")]
    [InlineData("child-call")]
    [InlineData("child-descriptor")]
    [InlineData("contribution")]
    [InlineData("payload")]
    [InlineData("child-context")]
    [InlineData("session")]
    [InlineData("binding")]
    [InlineData("cancellation")]
    [InlineData("generation")]
    [InlineData("sequence")]
    [InlineData("nonce")]
    [InlineData("deadline")]
    [InlineData("expiry")]
    [InlineData("carrier")]
    [InlineData("reservation")]
    [InlineData("proof")]
    public void Endpoint_typed_child_mutations_reject_before_import_and_preserve_authority(
        string mutation)
    {
        var test = CreateEndpointTypedActionChildCase(HostEndpointTransport.Http);
        var mutated = test.WireRelay;
        var reservation = mutated.ReceivingReservation;
        var child = reservation.Child;
        switch (mutation)
        {
            case "parent-call":
                reservation = reservation with
                {
                    ParentEndpointCall = reservation.ParentEndpointCall with { CallId = Guid.NewGuid() },
                };
                mutated = mutated with
                {
                    ReceivingReservation = reservation,
                };
                break;
            case "parent-context":
                mutated = mutated with
                {
                    SourceParentContext = mutated.SourceParentContext with { TraceId = Guid.NewGuid() },
                };
                break;
            case "route":
                mutated = mutated with
                {
                    ParentRouteAuthority = mutated.ParentRouteAuthority with
                    {
                        Route = mutated.ParentRouteAuthority.Route with { Path = "/changed" },
                    },
                };
                break;
            case "child-call":
                reservation = reservation with
                {
                    Child = child with { Call = child.Call with { CallId = Guid.NewGuid() } },
                };
                mutated = mutated with { ReceivingReservation = reservation };
                break;
            case "child-descriptor":
                var otherDescriptor = NestedDescriptor(
                    "endpoint.typed.other",
                    typeof(string).AssemblyQualifiedName!);
                reservation = reservation with
                {
                    Child = child with
                    {
                        Carrier = child.Carrier with { Descriptor = otherDescriptor },
                    },
                };
                mutated = mutated with { ReceivingReservation = reservation };
                break;
            case "contribution":
                reservation = reservation with
                {
                    Child = child with
                    {
                        Contribution = NestedContribution(
                            NestedDescriptor("endpoint.typed.other", typeof(string).AssemblyQualifiedName!)),
                    },
                };
                mutated = mutated with { ReceivingReservation = reservation };
                break;
            case "payload":
                reservation = reservation with
                {
                    Action = Payload(child.Descriptor.InputTypeIdentity, "changed-child"),
                };
                mutated = mutated with { ReceivingReservation = reservation };
                break;
            case "child-context":
                reservation = reservation with
                {
                    ChildContext = reservation.ChildContext with { TraceId = Guid.NewGuid() },
                };
                mutated = mutated with { ReceivingReservation = reservation };
                break;
            case "session":
                reservation = reservation with
                {
                    ParentEndpointCall = reservation.ParentEndpointCall with { SessionId = Guid.NewGuid() },
                };
                mutated = mutated with { ReceivingReservation = reservation };
                break;
            case "binding":
                reservation = reservation with
                {
                    ParentEndpointCall = reservation.ParentEndpointCall with { RequestId = Guid.NewGuid() },
                };
                mutated = mutated with { ReceivingReservation = reservation };
                break;
            case "cancellation":
                reservation = reservation with
                {
                    ParentEndpointCall = reservation.ParentEndpointCall with { CancellationId = Guid.NewGuid() },
                };
                mutated = mutated with { ReceivingReservation = reservation };
                break;
            case "generation":
                reservation = reservation with
                {
                    ReceivingBindingGeneration = reservation.ReceivingBindingGeneration + 1,
                };
                mutated = mutated with { ReceivingReservation = reservation };
                break;
            case "sequence":
                reservation = reservation with
                {
                    Child = child with { Call = child.Call with { Sequence = child.Call.Sequence + 1 } },
                };
                mutated = mutated with { ReceivingReservation = reservation };
                break;
            case "nonce":
                reservation = reservation with
                {
                    Child = child with { Call = child.Call with { ReplayNonce = "changed-child-nonce" } },
                };
                mutated = mutated with { ReceivingReservation = reservation };
                break;
            case "deadline":
                reservation = reservation with
                {
                    Child = child with
                    {
                        Call = child.Call with { Deadline = child.Call.Deadline.AddSeconds(1) },
                    },
                };
                mutated = mutated with { ReceivingReservation = reservation };
                break;
            case "expiry":
                reservation = reservation with { ExpiresAt = reservation.ExpiresAt.AddSeconds(1) };
                mutated = mutated with { ReceivingReservation = reservation };
                break;
            case "carrier":
                reservation = reservation with
                {
                    Child = child with { Carrier = child.Carrier with { ParentCallId = Guid.NewGuid() } },
                };
                mutated = mutated with { ReceivingReservation = reservation };
                break;
            case "reservation":
                reservation = reservation with { ReservationId = Guid.NewGuid() };
                mutated = mutated with { ReceivingReservation = reservation };
                break;
            case "proof":
                mutated = mutated with { Proof = "forged-child-relay-proof" };
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(mutation));
        }

        if (mutation != "proof" && mutation != "route")
        {
            var reservationHash = SidecarEndpointTypedActionChildValidation.ComputeReservationHash(reservation);
            reservation = reservation with
            {
                CanonicalBindingHash = reservationHash,
                Proof = KeyedEndpointProof("child-reservation", reservationHash),
            };
            mutated = mutated with { ReceivingReservation = reservation };
            var relayHash = SidecarEndpointTypedActionChildValidation.ComputeRelayHash(mutated);
            mutated = mutated with
            {
                CanonicalBindingHash = relayHash,
                Proof = KeyedEndpointProof("child-relay", relayHash),
            };
        }

        var sequence = test.Source.Session.LastSequence;
        var contexts = test.Source.Session.IssuedHostActionEntryContextCount;
        var carriers = test.Source.Session.ActiveHostActionEntryCarrierCount;
        var rejected = test.Source.Session.ImportHostEndpointTypedActionChildRelay(
            SidecarCapabilityTransportCodec.Deserialize<SidecarEndpointTypedActionChildRelay>(
                SidecarCapabilityTransportCodec.Serialize(mutated)),
            test.Source.Now,
            IssueEndpointChildImportAcknowledgment,
            out var rejectedRelay,
            out var rejectedContext,
            out var rejectedAcknowledgment);
        Assert.False(rejected.Accepted, rejected.Message);
        Assert.Null(rejectedRelay);
        Assert.Null(rejectedContext);
        Assert.Null(rejectedAcknowledgment);
        Assert.Equal(sequence, test.Source.Session.LastSequence);
        Assert.Equal(contexts, test.Source.Session.IssuedHostActionEntryContextCount);
        Assert.Equal(carriers, test.Source.Session.ActiveHostActionEntryCarrierCount);

        var imported = test.Source.Session.ImportHostEndpointTypedActionChildRelay(
            test.WireRelay,
            test.Source.Now,
            IssueEndpointChildImportAcknowledgment,
            out var childRelay,
            out var importContext,
            out var importAcknowledgment);
        Assert.True(imported.Accepted, imported.Message);
        Assert.NotNull(importContext);
        Assert.NotNull(importAcknowledgment);
        Assert.True(test.Source.Session.BeginNestedHostActionEntryCall(
            childRelay!.Carrier,
            test.ChildCall,
            test.ChildAction,
            test.ChildAction.ByteLength,
            test.Source.Now,
            out _).Accepted);
        Assert.True(test.Source.Session.CompleteCall(test.ChildCall.CallId, 0).Accepted);
        Assert.True(test.Receiving.Session.CompleteHostEndpointTypedActionChildRelay(
            test.Relay,
            importAcknowledgment!,
            test.Receiving.Now).Accepted);
        Assert.True(test.Receiving.Session.CompleteCall(
            test.ReceivingParent.Call.CallId,
            0).Accepted);
        Assert.True(test.Receiving.Session.CompleteHostActionEntryCarrier(
            test.ReceivingParent.Carrier,
            HostActionEntryCarrierCompletionKind.Succeeded,
            test.Receiving.Now).Accepted);
        Assert.True(test.Source.Session.CompleteHostEndpointRouteRelay(
            test.RouteRelay,
            test.Source.Now).Accepted);
        var mutationSourceParentCompletion = test.Source.Session.CompleteCall(
            test.SourceParent.Call.CallId,
            0);
        Assert.True(
            mutationSourceParentCompletion.Accepted,
            $"{mutationSourceParentCompletion.Code}: {mutationSourceParentCompletion.Message}");
        Assert.Equal(
            SidecarCapabilityErrors.Replay,
            test.Source.Session.CompleteHostActionEntryCarrier(
            test.SourceParent.Carrier,
            HostActionEntryCarrierCompletionKind.Succeeded,
            test.Source.Now).Code);
    }

    [Theory]
    [InlineData(HostEndpointTransport.Http)]
    [InlineData(HostEndpointTransport.WebSocket)]
    public void Endpoint_route_relay_imports_exact_invocation_and_allows_authenticated_nested_action(
        HostEndpointTransport transport)
    {
        static bool AuthenticateAuthority(HostEndpointRouteAuthority authority, string hash) =>
            authority.Proof == KeyedEndpointProof("route", hash);
        static bool AuthenticateRelay(SidecarHostEndpointRouteRelay relay, string hash) =>
            relay.Proof == KeyedEndpointProof("relay", hash);
        static bool AuthenticateChildReservation(
            SidecarEndpointTypedActionChildReservation reservation,
            string hash) =>
            reservation.Proof == KeyedEndpointProof("child-reservation", hash);
        static bool AuthenticateChildRelay(
            SidecarEndpointTypedActionChildRelay relay,
            string hash) =>
            relay.Proof == KeyedEndpointProof("child-relay", hash);
        static bool AuthenticateImportAcknowledgment(
            SidecarEndpointTypedActionChildImportAcknowledgment acknowledgment,
            string hash) =>
            acknowledgment.Proof == KeyedEndpointProof("child-import", hash);
        var source = CreateFixture(
            actionInputBytes: 4096,
            protocolMessageBytes: 65536,
            authenticateEndpointRouteAuthority: AuthenticateAuthority,
            authenticateEndpointTypedActionChildReservation: AuthenticateChildReservation,
            authenticateEndpointTypedActionChildRelay: AuthenticateChildRelay);
        var receiving = CreateMirroredFixture(
            source,
            authenticateEndpointRouteAuthority: AuthenticateAuthority,
            authenticateEndpointRouteRelay: AuthenticateRelay,
            authenticateEndpointTypedActionChildReservation: AuthenticateChildReservation,
            authenticateEndpointTypedActionChildRelay: AuthenticateChildRelay,
            protocolMessageBytes: 65536,
            authenticateEndpointTypedActionChildImportAcknowledgment: AuthenticateImportAcknowledgment);
        var sourceContext = IssueContext(
            source,
            new RequestPrincipal(
                "endpoint-user",
                Roles: new HashSet<string>(["reader"], StringComparer.Ordinal)),
            HostActionEntryIngress.Endpoint,
            lineage: new HostActionEntryLineage(
                new SharpClawActionKey("endpoint.invoke"),
                1,
                "endpoint-invoke-descriptor",
                typeof(HostEndpointInvocation).AssemblyQualifiedName!,
                1,
                "endpoint-invoke-schema",
                null,
                null));
        var request = EndpointRouteRequest(source, sourceContext, transport);
        var sourceCall = ActionCall(source, 1, "endpoint-relay-source");
        var receivingCall = ActionCall(receiving, 1, "endpoint-relay-receiving");

        var reservationIssue = receiving.Session.IssueHostEndpointRouteReservation(
            request,
            receivingCall,
            receiving.Now,
            reservation => KeyedEndpointProof(
                "reservation",
                SidecarCapabilityTransportValidation.ComputeEndpointRouteReservationBindingHash(
                    reservation)),
            out var reservation);
        Assert.True(reservationIssue.Accepted, reservationIssue.Message);
        Assert.NotNull(reservation);
        var wireRouteReservation = SidecarCapabilityTransportCodec.Deserialize<
            SidecarHostEndpointRouteReservation>(
            SidecarCapabilityTransportCodec.Serialize(reservation));

        var issued = source.Session.IssueHostEndpointRouteRelay(
            request,
            sourceCall,
            wireRouteReservation,
            source.Now,
            authority => KeyedEndpointProof(
                "route",
                HostEndpointRouteAuthorityValidator.ComputeBindingHash(authority)),
            (candidate, hash) => candidate.Proof == KeyedEndpointProof("reservation", hash),
            (relay, hash) => KeyedEndpointProof("relay", hash),
            out var relay);
        Assert.True(issued.Accepted, issued.Message);
        Assert.NotNull(relay);
        var wireRelay = SidecarCapabilityTransportCodec.Deserialize<SidecarHostEndpointRouteRelay>(
            SidecarCapabilityTransportCodec.Serialize(relay));

        var sourceCarrier = new HostActionEntryCarrierIdentity(
            HostActionEntryIngress.Endpoint,
            sourceContext.InvocationId,
            sourceContext.Contribution!.IngressBinding);
        Assert.True(
            source.Session.BeginHostEndpointRouteCarrier(
                request,
                relay!.Authority,
                sourceCarrier,
                source.Now,
                out var sourceCarrierAuthority).Accepted);
        var sourceEndpointPayload = EndpointInvocationPayload(
            typeof(HostEndpointInvocation).AssemblyQualifiedName!,
            request.Invocation);
        var sourceBegin = source.Session.BeginCall(
            sourceCall,
            SidecarCapabilityKind.Action,
            sourceEndpointPayload,
            sourceEndpointPayload.ByteLength,
            source.Now,
            sourceContext);
        Assert.True(sourceBegin.Accepted, sourceBegin.Message);

        var imported = receiving.Session.ImportHostEndpointRouteRelay(
            wireRelay,
            receiving.Now,
            out var receivingContext);
        Assert.True(imported.Accepted, imported.Message);
        Assert.NotNull(receivingContext);
        Assert.Equal(
            SidecarCapabilityErrors.SpoofedIdentity,
            receiving.Session.ImportHostEndpointRouteRelay(
                wireRelay,
                receiving.Now,
                out _).Code);
        Assert.False(
            receiving.Session.BeginHostActionEntryCarrier(
                receivingContext!,
                receivingContext.Contribution is null
                    ? throw new InvalidOperationException("The relay context has no contribution.")
                    : new HostActionEntryCarrierIdentity(
                        HostActionEntryIngress.Endpoint,
                        receivingContext.InvocationId,
                        receivingContext.Contribution.IngressBinding),
                receiving.Now,
                out _).Accepted);

        var endpointPayload = EndpointInvocationPayload(
            typeof(HostEndpointInvocation).AssemblyQualifiedName!,
            wireRelay.Request.Invocation);
        Assert.True(
            receiving.Session.BeginCall(
                receivingCall,
                SidecarCapabilityKind.Action,
                endpointPayload,
                endpointPayload.ByteLength,
                receiving.Now,
                receivingContext).Accepted);

        var childDescriptor = NestedDescriptor(
            "endpoint.nested.action",
            typeof(string).AssemblyQualifiedName!);
        var childAction = Payload(childDescriptor.InputTypeIdentity, "nested-result");
        var childCall = sourceCall with
        {
            CallId = Guid.NewGuid(),
            ReplayNonce = "endpoint-relay-child",
            Sequence = 2,
        };
        var childReservationResult = source.Session.IssueHostEndpointTypedActionChildReservation(
            sourceCall,
            sourceContext,
            childCall,
            childDescriptor,
            childAction,
            source.Now,
            candidate => KeyedEndpointProof(
                "child-reservation",
                SidecarEndpointTypedActionChildValidation.ComputeReservationHash(candidate)),
            out var childReservation);
        Assert.True(childReservationResult.Accepted, childReservationResult.Message);
        Assert.NotNull(childReservation);
        var wireReservation = SidecarCapabilityTransportCodec.Deserialize<
            SidecarEndpointTypedActionChildReservation>(
            SidecarCapabilityTransportCodec.Serialize(childReservation));
        var childRelayResult = receiving.Session.IssueHostEndpointTypedActionChildRelay(
            wireRelay.Authority,
            receivingCall,
            receivingContext!,
            wireReservation,
            receiving.Now,
            (candidate, hash) => candidate.Proof == KeyedEndpointProof("child-reservation", hash),
            candidate => KeyedEndpointProof(
                "child-relay",
                SidecarEndpointTypedActionChildValidation.ComputeRelayHash(candidate)),
            out var childRelay);
        Assert.True(childRelayResult.Accepted, childRelayResult.Message);
        Assert.NotNull(childRelay);
        Assert.Equal(2, receiving.Session.LastSequence);
        var childRelayRetryResult = receiving.Session.IssueHostEndpointTypedActionChildRelay(
            wireRelay.Authority,
            receivingCall,
            receivingContext!,
            wireReservation,
            receiving.Now,
            (candidate, hash) => candidate.Proof == KeyedEndpointProof("child-reservation", hash),
            candidate => KeyedEndpointProof(
                "child-relay",
                SidecarEndpointTypedActionChildValidation.ComputeRelayHash(candidate)),
            out var childRelayRetry);
        Assert.True(childRelayRetryResult.Accepted, childRelayRetryResult.Message);
        Assert.NotNull(childRelayRetry);
        Assert.True(
            SidecarCapabilityTransportCodec.Serialize(childRelay)
                .SequenceEqual(SidecarCapabilityTransportCodec.Serialize(childRelayRetry)));
        Assert.Equal(2, receiving.Session.LastSequence);
        var wireChildRelay = SidecarCapabilityTransportCodec.Deserialize<
            SidecarEndpointTypedActionChildRelay>(
                SidecarCapabilityTransportCodec.Serialize(childRelay));
        var childImportResult = source.Session.ImportHostEndpointTypedActionChildRelay(
            wireChildRelay,
            source.Now,
            IssueEndpointChildImportAcknowledgment,
            out var importedChildRelay,
            out _,
            out var childAcknowledgment);
        Assert.True(childImportResult.Accepted, childImportResult.Message);
        Assert.NotNull(importedChildRelay);
        Assert.NotNull(childAcknowledgment);
        Assert.True(
            source.Session.BeginNestedHostActionEntryCall(
                importedChildRelay!.Carrier,
                childCall,
                childAction,
                childAction.ByteLength,
                source.Now,
                out var childContext).Accepted);
        Assert.True(source.Session.CompleteCall(childCall.CallId, 0).Accepted);
        Assert.NotNull(childContext);
        Assert.True(receiving.Session.CompleteHostEndpointTypedActionChildRelay(
            wireChildRelay,
            childAcknowledgment!,
            receiving.Now).Accepted);
        Assert.True(receiving.Session.TryGetActiveHostActionEntryCarrier(
            receivingContext!.CapabilityId,
            out var receivingCarrier));
        Assert.True(receiving.Session.CompleteCall(receivingCall.CallId, 0).Accepted);
        Assert.True(
            receiving.Session.CompleteHostActionEntryCarrier(
                receivingCarrier!,
                HostActionEntryCarrierCompletionKind.Succeeded,
                receiving.Now).Accepted);
        Assert.True(source.Session.CompleteHostEndpointRouteRelay(relay!, source.Now).Accepted);
        Assert.Equal(
            SidecarCapabilityErrors.Replay,
            source.Session.CompleteHostEndpointRouteRelay(relay!, source.Now).Code);
        Assert.True(source.Session.CompleteCall(sourceCall.CallId, 0).Accepted);
        Assert.Equal(
            SidecarCapabilityErrors.Replay,
            source.Session.CompleteHostActionEntryCarrier(
                sourceCarrierAuthority!,
                HostActionEntryCarrierCompletionKind.Succeeded,
                source.Now).Code);
        Assert.Equal(0, source.Session.IssuedHostActionEntryContextCount);
        var sourceRotated = CreateRotatedBinding(source, "endpoint-relay-source-rotation");
        source.BindingHashes.Add(sourceRotated.Authentication.BindingHash);
        Assert.True(source.Session.RotateBinding(sourceRotated, source.Now).Accepted);
        Assert.Equal(0, receiving.Session.ActiveHostActionEntryCarrierCount);
        var rotated = CreateRotatedBinding(receiving, "endpoint-relay-rotation");
        receiving.BindingHashes.Add(rotated.Authentication.BindingHash);
        var rotation = receiving.Session.RotateBinding(rotated, receiving.Now);
        Assert.True(rotation.Accepted, rotation.Message);
    }

    [Theory]
    [InlineData(HostEndpointTransport.Http)]
    [InlineData(HostEndpointTransport.WebSocket)]
    public void Endpoint_typed_child_rejects_an_arbitrary_receiving_sequence(
        HostEndpointTransport transport)
    {
        var test = CreateEndpointTypedActionChildCase(transport, maxInFlight: 3);
        var laterCall = test.ChildCall with
        {
            CallId = Guid.NewGuid(),
            ReplayNonce = "endpoint-typed-child-gap",
            Sequence = test.Source.Session.LastSequence + 1,
        };
        var issue = test.Source.Session.IssueHostEndpointTypedActionChildReservation(
            test.SourceParent.Call,
            test.SourceParent.ActiveContext,
            laterCall,
            test.Relay.Child.Descriptor,
            test.ChildAction,
            test.Source.Now,
            candidate => KeyedEndpointProof(
                "child-reservation",
                SidecarEndpointTypedActionChildValidation.ComputeReservationHash(candidate)),
            out var reservation);
        Assert.True(issue.Accepted, issue.Message);
        Assert.NotNull(reservation);

        var receivingSequence = test.Receiving.Session.LastSequence;
        var gapReservation = reservation! with
        {
            Child = reservation.Child with
            {
                Call = reservation.Child.Call with
                {
                    Sequence = receivingSequence + 2,
                },
            },
        };
        gapReservation = gapReservation with
        {
            CanonicalBindingHash = SidecarEndpointTypedActionChildValidation.ComputeReservationHash(
                gapReservation),
        };
        gapReservation = gapReservation with
        {
            Proof = KeyedEndpointProof(
                "child-reservation",
                gapReservation.CanonicalBindingHash),
        };

        var gapIssue = test.Receiving.Session.IssueHostEndpointTypedActionChildRelay(
            test.ReceivingParent.Authority,
            test.ReceivingParent.Call,
            test.ReceivingParent.ActiveContext,
            gapReservation,
            test.Receiving.Now,
            (candidate, hash) => candidate.Proof == KeyedEndpointProof("child-reservation", hash),
            candidate => KeyedEndpointProof(
                "child-relay",
                SidecarEndpointTypedActionChildValidation.ComputeRelayHash(candidate)),
            out var gapRelay);
        Assert.False(gapIssue.Accepted);
        Assert.Equal(SidecarCapabilityErrors.SpoofedIdentity, gapIssue.Code);
        Assert.Null(gapRelay);
        Assert.Equal(receivingSequence, test.Receiving.Session.LastSequence);

        Assert.True(test.Source.Session.ReleaseHostEndpointTypedActionChildReservation(
            reservation,
            test.Source.Now).Accepted);
        AbortUnimportedEndpointTypedActionChild(test, test.Source.Now);
        Assert.True(test.Receiving.Session.CompleteCall(
            test.ReceivingParent.Call.CallId,
            0).Accepted);
        Assert.True(test.Receiving.Session.CompleteHostActionEntryCarrier(
            test.ReceivingParent.Carrier,
            HostActionEntryCarrierCompletionKind.Succeeded,
            test.Receiving.Now).Accepted);
        Assert.True(test.Source.Session.CompleteHostEndpointRouteRelay(
            test.RouteRelay,
            test.Source.Now).Accepted);
        Assert.True(test.Source.Session.CompleteCall(
            test.SourceParent.Call.CallId,
            0).Accepted);
        Assert.Equal(
            SidecarCapabilityErrors.Replay,
            test.Source.Session.CompleteHostActionEntryCarrier(
                test.SourceParent.Carrier,
                HostActionEntryCarrierCompletionKind.Succeeded,
                test.Source.Now).Code);
        var sourceRotated = CreateRotatedBinding(test.Source, "endpoint-gap-source-rotation");
        test.Source.BindingHashes.Add(sourceRotated.Authentication.BindingHash);
        var sourceRotation = test.Source.Session.RotateBinding(sourceRotated, test.Source.Now);
        Assert.True(sourceRotation.Accepted, sourceRotation.Message);
        var receivingRotated = CreateRotatedBinding(test.Receiving, "endpoint-gap-receiving-rotation");
        test.Receiving.BindingHashes.Add(receivingRotated.Authentication.BindingHash);
        var receivingRotation = test.Receiving.Session.RotateBinding(receivingRotated, test.Receiving.Now);
        Assert.True(receivingRotation.Accepted, receivingRotation.Message);
    }

    [Theory]
    [InlineData(HostEndpointTransport.Http)]
    [InlineData(HostEndpointTransport.WebSocket)]
    public void Endpoint_typed_child_release_preserves_sequence_for_next_root_relay(
        HostEndpointTransport transport)
    {
        var test = CreateEndpointTypedActionChildCase(transport, maxInFlight: 3);
        Assert.Equal(2, test.Source.Session.LastSequence);
        Assert.Equal(2, test.Receiving.Session.LastSequence);

        var childImport = test.Source.Session.ImportHostEndpointTypedActionChildRelay(
            test.WireRelay,
            test.Source.Now,
            IssueEndpointChildImportAcknowledgment,
            out var importedChildRelay,
            out var importedChildContext,
            out var childAcknowledgment);
        Assert.True(childImport.Accepted, childImport.Message);
        Assert.NotNull(importedChildRelay);
        Assert.NotNull(importedChildContext);
        Assert.NotNull(childAcknowledgment);
        Assert.True(test.Source.Session.TryGetActiveHostActionEntryCarrier(
            importedChildContext!.CapabilityId,
            out var importedChildCarrier));
        Assert.NotNull(importedChildCarrier);
        Assert.True(test.Source.Session.BeginNestedHostActionEntryCall(
            importedChildRelay!.Carrier,
            test.ChildCall,
            test.ChildAction,
            test.ChildAction.ByteLength,
            test.Source.Now,
            out _).Accepted);
        Assert.True(test.Source.Session.CompleteCall(
            test.ChildCall.CallId,
            0).Accepted);
        var childCarrierCompletion = test.Source.Session.CompleteHostActionEntryCarrier(
            importedChildCarrier!,
            HostActionEntryCarrierCompletionKind.Failed,
            test.Source.Now);
        Assert.Equal(SidecarCapabilityErrors.Replay, childCarrierCompletion.Code);
        Assert.Equal(2, test.Source.Session.LastSequence);
        var completion = test.Receiving.Session.CompleteHostEndpointTypedActionChildRelay(
            test.Relay,
            childAcknowledgment!,
            test.Receiving.Now);
        Assert.True(completion.Accepted, completion.Message);
        Assert.Equal(2, test.Receiving.Session.LastSequence);
        Assert.Equal(
            SidecarCapabilityErrors.Replay,
            test.Receiving.Session.ReleaseHostEndpointTypedActionChildRelay(
                test.Relay,
                test.Receiving.Now).Code);
        Assert.Equal(
            SidecarCapabilityErrors.Replay,
            test.Receiving.Session.CompleteHostEndpointTypedActionChildRelay(
                test.Relay,
                childAcknowledgment,
                test.Receiving.Now).Code);

        CleanupEndpointTypedActionChildParents(test);
        CompleteNextNormalRootRelay(test.Source, test.Receiving, transport, "endpoint-sequence-three");
    }

    [Theory]
    [InlineData(HostEndpointTransport.Http)]
    [InlineData(HostEndpointTransport.WebSocket)]
    public void Endpoint_typed_child_pre_relay_release_rolls_back_sequence_for_next_root_relay(
        HostEndpointTransport transport)
    {
        var test = CreateEndpointTypedActionChildReservationOnlyCase(transport);
        Assert.Equal(2, test.Source.Session.LastSequence);
        Assert.Equal(1, test.Receiving.Session.LastSequence);

        var release = test.Source.Session.ReleaseHostEndpointTypedActionChildReservation(
            test.Reservation,
            test.Source.Now);
        Assert.True(release.Accepted, release.Message);
        Assert.Equal(1, test.Source.Session.LastSequence);
        Assert.Equal(
            SidecarCapabilityErrors.Replay,
            test.Source.Session.ReleaseHostEndpointTypedActionChildReservation(
                test.Reservation,
                test.Source.Now).Code);

        Assert.True(test.Receiving.Session.CompleteCall(
            test.ReceivingParent.Call.CallId,
            0).Accepted);
        Assert.True(test.Receiving.Session.CompleteHostActionEntryCarrier(
            test.ReceivingParent.Carrier,
            HostActionEntryCarrierCompletionKind.Succeeded,
            test.Receiving.Now).Accepted);
        Assert.True(test.Source.Session.CompleteHostEndpointRouteRelay(
            test.RouteRelay,
            test.Source.Now).Accepted);
        Assert.True(test.Source.Session.CompleteCall(
            test.SourceParent.Call.CallId,
            0).Accepted);
        Assert.Equal(SidecarCapabilityErrors.Replay, test.Source.Session.CompleteHostActionEntryCarrier(
            test.SourceParent.Carrier,
            HostActionEntryCarrierCompletionKind.Succeeded,
            test.Source.Now).Code);

        CompleteNextNormalRootRelay(
            test.Source,
            test.Receiving,
            transport,
            "endpoint-sequence-two",
            2);
    }

    [Theory]
    [InlineData(HostEndpointTransport.Http)]
    [InlineData(HostEndpointTransport.WebSocket)]
    public void Endpoint_typed_child_expiry_preserves_sequence_and_replay_protection(
        HostEndpointTransport transport)
    {
        var test = CreateEndpointTypedActionChildCase(transport, maxInFlight: 3);
        var expiredAt = test.Relay.ExpiresAt.AddSeconds(1);
        var abort = AbortUnimportedEndpointTypedActionChild(test, expiredAt);
        Assert.Equal(1, test.Source.Session.LastSequence);
        Assert.Equal(1, test.Receiving.Session.LastSequence);
        Assert.Equal(
            SidecarCapabilityErrors.Replay,
            test.Receiving.Session.ConsumeHostEndpointTypedActionChildImportAbort(
                abort,
                expiredAt).Code);

        CleanupEndpointTypedActionChildParents(test);
        CompleteNextNormalRootRelay(
            test.Source,
            test.Receiving,
            transport,
            "endpoint-expiry-sequence-two",
            2);
    }

    [Theory]
    [InlineData(HostEndpointTransport.Http)]
    [InlineData(HostEndpointTransport.WebSocket)]
    public void Endpoint_typed_child_receiving_release_before_source_import_rolls_back_sequence(
        HostEndpointTransport transport)
    {
        var test = CreateEndpointTypedActionChildCase(transport, maxInFlight: 3);
        Assert.Equal(2, test.Source.Session.LastSequence);
        Assert.Equal(2, test.Receiving.Session.LastSequence);

        var abort = AbortUnimportedEndpointTypedActionChild(test, test.Source.Now);
        Assert.Equal(1, test.Source.Session.LastSequence);
        Assert.Equal(1, test.Receiving.Session.LastSequence);
        Assert.Equal(
            SidecarCapabilityErrors.Replay,
            test.Receiving.Session.ConsumeHostEndpointTypedActionChildImportAbort(
                abort,
                test.Receiving.Now).Code);
        CleanupEndpointTypedActionChildParents(test);

        CompleteNextNormalRootRelay(
            test.Source,
            test.Receiving,
            transport,
            "endpoint-release-sequence-two",
            2);
    }

    [Theory]
    [InlineData(HostEndpointTransport.Http)]
    [InlineData(HostEndpointTransport.WebSocket)]
    public void Endpoint_typed_child_completion_requires_source_import_acknowledgment(
        HostEndpointTransport transport)
    {
        var test = CreateEndpointTypedActionChildCase(transport, maxInFlight: 3);
        var sourceSequence = test.Source.Session.LastSequence;
        var receivingSequence = test.Receiving.Session.LastSequence;
        var sourceCarriers = test.Source.Session.ActiveHostActionEntryCarrierCount;
        var receivingCarriers = test.Receiving.Session.ActiveHostActionEntryCarrierCount;

        var rejected = test.Receiving.Session.CompleteHostEndpointTypedActionChildRelay(
            test.WireRelay,
            null,
            test.Receiving.Now);
        Assert.False(rejected.Accepted);
        Assert.Equal(SidecarCapabilityErrors.Unauthenticated, rejected.Code);
        Assert.Equal(sourceSequence, test.Source.Session.LastSequence);
        Assert.Equal(receivingSequence, test.Receiving.Session.LastSequence);
        Assert.Equal(sourceCarriers, test.Source.Session.ActiveHostActionEntryCarrierCount);
        Assert.Equal(receivingCarriers, test.Receiving.Session.ActiveHostActionEntryCarrierCount);

        var retry = test.Receiving.Session.CompleteHostEndpointTypedActionChildRelay(
            test.WireRelay,
            null,
            test.Receiving.Now);
        Assert.Equal(SidecarCapabilityErrors.Unauthenticated, retry.Code);
        Assert.Equal(receivingSequence, test.Receiving.Session.LastSequence);

        AbortUnimportedEndpointTypedActionChild(test, test.Source.Now);
        Assert.Equal(1, test.Source.Session.LastSequence);
        Assert.Equal(1, test.Receiving.Session.LastSequence);

        CleanupEndpointTypedActionChildParents(test);
        CompleteNextNormalRootRelay(
            test.Source,
            test.Receiving,
            transport,
            "endpoint-ack-sequence-two",
            2);
    }

    [Theory]
    [InlineData(HostEndpointTransport.Http)]
    [InlineData(HostEndpointTransport.WebSocket)]
    public void Endpoint_typed_child_import_retry_returns_exact_acknowledgment(
        HostEndpointTransport transport)
    {
        var test = CreateEndpointTypedActionChildCase(transport, maxInFlight: 3);
        var import = test.Source.Session.ImportHostEndpointTypedActionChildRelay(
            test.WireRelay,
            test.Source.Now,
            IssueEndpointChildImportAcknowledgment,
            out var importedChildRelay,
            out var importedChildContext,
            out var acknowledgment);
        Assert.True(import.Accepted, import.Message);
        Assert.NotNull(importedChildRelay);
        Assert.NotNull(importedChildContext);
        Assert.NotNull(acknowledgment);
        var acknowledgmentBytes = SidecarCapabilityTransportCodec.Serialize(acknowledgment!);

        var retry = test.Source.Session.ImportHostEndpointTypedActionChildRelay(
            SidecarCapabilityTransportCodec.Deserialize<SidecarEndpointTypedActionChildRelay>(
                SidecarCapabilityTransportCodec.Serialize(test.WireRelay)),
            test.Source.Now,
            IssueEndpointChildImportAcknowledgment,
            out var retriedChildRelay,
            out var retriedChildContext,
            out var retriedAcknowledgment);
        Assert.True(retry.Accepted, retry.Message);
        Assert.NotNull(retriedChildRelay);
        Assert.NotNull(retriedChildContext);
        Assert.NotNull(retriedAcknowledgment);
        Assert.True(acknowledgmentBytes.SequenceEqual(
            SidecarCapabilityTransportCodec.Serialize(retriedAcknowledgment!)));

        Assert.True(test.Source.Session.TryGetActiveHostActionEntryCarrier(
            importedChildContext!.CapabilityId,
            out var childCarrier));
        Assert.True(test.Source.Session.BeginNestedHostActionEntryCall(
            importedChildRelay!.Carrier,
            test.ChildCall,
            test.ChildAction,
            test.ChildAction.ByteLength,
            test.Source.Now,
            out _).Accepted);
        Assert.True(test.Source.Session.CompleteCall(test.ChildCall.CallId, 0).Accepted);

        var completion = test.Receiving.Session.CompleteHostEndpointTypedActionChildRelay(
            test.WireRelay,
            retriedAcknowledgment!,
            test.Receiving.Now);
        Assert.True(completion.Accepted, completion.Message);
        Assert.Equal(2, test.Receiving.Session.LastSequence);
        Assert.Equal(
            SidecarCapabilityErrors.Replay,
            test.Receiving.Session.CompleteHostEndpointTypedActionChildRelay(
                test.WireRelay,
                retriedAcknowledgment,
                test.Receiving.Now).Code);
        Assert.Equal(
            SidecarCapabilityErrors.Replay,
            test.Receiving.Session.ReleaseHostEndpointTypedActionChildRelay(
                test.WireRelay,
                test.Receiving.Now).Code);
        Assert.Equal(
            SidecarCapabilityErrors.Replay,
            test.Source.Session.CompleteHostActionEntryCarrier(
                childCarrier!,
                HostActionEntryCarrierCompletionKind.Succeeded,
                test.Source.Now).Code);

        CleanupEndpointTypedActionChildParents(test);
        CompleteNextNormalRootRelay(
            test.Source,
            test.Receiving,
            transport,
            "endpoint-ack-sequence-three",
            3);
    }

    [Theory]
    [InlineData(HostEndpointTransport.Http, "relay-hash")]
    [InlineData(HostEndpointTransport.Http, "reservation")]
    [InlineData(HostEndpointTransport.Http, "child-call")]
    [InlineData(HostEndpointTransport.Http, "parent")]
    [InlineData(HostEndpointTransport.Http, "binding")]
    [InlineData(HostEndpointTransport.Http, "generation")]
    [InlineData(HostEndpointTransport.Http, "deadline")]
    [InlineData(HostEndpointTransport.Http, "cancellation")]
    [InlineData(HostEndpointTransport.Http, "proof")]
    [InlineData(HostEndpointTransport.Http, "expiry")]
    [InlineData(HostEndpointTransport.WebSocket, "relay-hash")]
    [InlineData(HostEndpointTransport.WebSocket, "reservation")]
    [InlineData(HostEndpointTransport.WebSocket, "child-call")]
    [InlineData(HostEndpointTransport.WebSocket, "parent")]
    [InlineData(HostEndpointTransport.WebSocket, "binding")]
    [InlineData(HostEndpointTransport.WebSocket, "generation")]
    [InlineData(HostEndpointTransport.WebSocket, "deadline")]
    [InlineData(HostEndpointTransport.WebSocket, "cancellation")]
    [InlineData(HostEndpointTransport.WebSocket, "proof")]
    [InlineData(HostEndpointTransport.WebSocket, "expiry")]
    public void Endpoint_typed_child_import_acknowledgment_mutations_preserve_state(
        HostEndpointTransport transport,
        string mutation)
    {
        var test = CreateEndpointTypedActionChildCase(transport, maxInFlight: 3);
        var import = test.Source.Session.ImportHostEndpointTypedActionChildRelay(
            test.WireRelay,
            test.Source.Now,
            IssueEndpointChildImportAcknowledgment,
            out var importedChildRelay,
            out var importedChildContext,
            out var acknowledgment);
        Assert.True(import.Accepted, import.Message);
        Assert.NotNull(importedChildRelay);
        Assert.NotNull(importedChildContext);
        Assert.NotNull(acknowledgment);

        var sourceSequence = test.Source.Session.LastSequence;
        var receivingSequence = test.Receiving.Session.LastSequence;
        var sourceCarriers = test.Source.Session.ActiveHostActionEntryCarrierCount;
        var receivingCarriers = test.Receiving.Session.ActiveHostActionEntryCarrierCount;
        var mutated = MutateEndpointChildImportAcknowledgment(acknowledgment!, mutation);
        var wireMutation = SidecarCapabilityTransportCodec.Deserialize<
            SidecarEndpointTypedActionChildImportAcknowledgment>(
            SidecarCapabilityTransportCodec.Serialize(mutated));
        var rejected = test.Receiving.Session.CompleteHostEndpointTypedActionChildRelay(
            test.WireRelay,
            wireMutation,
            test.Receiving.Now);
        Assert.False(rejected.Accepted, rejected.Message);
        Assert.Equal(
            mutation == "proof"
                ? SidecarCapabilityErrors.Unauthenticated
                : SidecarCapabilityErrors.SpoofedIdentity,
            rejected.Code);
        Assert.Equal(sourceSequence, test.Source.Session.LastSequence);
        Assert.Equal(receivingSequence, test.Receiving.Session.LastSequence);
        Assert.Equal(sourceCarriers, test.Source.Session.ActiveHostActionEntryCarrierCount);
        Assert.Equal(receivingCarriers, test.Receiving.Session.ActiveHostActionEntryCarrierCount);

        var validRetry = test.Source.Session.ImportHostEndpointTypedActionChildRelay(
            test.WireRelay,
            test.Source.Now,
            IssueEndpointChildImportAcknowledgment,
            out var retryChildRelay,
            out var retryChildContext,
            out var retryAcknowledgment);
        Assert.True(validRetry.Accepted, validRetry.Message);
        Assert.NotNull(retryChildRelay);
        Assert.NotNull(retryChildContext);
        Assert.NotNull(retryAcknowledgment);
        Assert.True(
            SidecarCapabilityTransportCodec.Serialize(acknowledgment!)
                .SequenceEqual(SidecarCapabilityTransportCodec.Serialize(retryAcknowledgment!)));

        Assert.True(test.Source.Session.TryGetActiveHostActionEntryCarrier(
            importedChildContext!.CapabilityId,
            out var childCarrier));
        Assert.True(test.Source.Session.BeginNestedHostActionEntryCall(
            importedChildRelay!.Carrier,
            test.ChildCall,
            test.ChildAction,
            test.ChildAction.ByteLength,
            test.Source.Now,
            out _).Accepted);
        Assert.True(test.Source.Session.CompleteCall(test.ChildCall.CallId, 0).Accepted);
        Assert.Equal(
            SidecarCapabilityErrors.Replay,
            test.Source.Session.CompleteHostActionEntryCarrier(
                childCarrier!,
                HostActionEntryCarrierCompletionKind.Succeeded,
                test.Source.Now).Code);
        Assert.True(test.Receiving.Session.CompleteHostEndpointTypedActionChildRelay(
            test.WireRelay,
            retryAcknowledgment!,
            test.Receiving.Now).Accepted);

        CleanupEndpointTypedActionChildParents(test);
        CompleteNextNormalRootRelay(
            test.Source,
            test.Receiving,
            transport,
            $"endpoint-ack-mutation-{mutation}",
            3);
    }

    [Theory]
    [InlineData(HostEndpointTransport.Http)]
    [InlineData(HostEndpointTransport.WebSocket)]
    public void Endpoint_typed_child_acknowledgment_after_expiry_cleans_up_with_committed_sequence(
        HostEndpointTransport transport)
    {
        var test = CreateEndpointTypedActionChildCase(transport, maxInFlight: 3);
        var import = test.Source.Session.ImportHostEndpointTypedActionChildRelay(
            test.WireRelay,
            test.Source.Now,
            IssueEndpointChildImportAcknowledgment,
            out var importedChildRelay,
            out var importedChildContext,
            out var acknowledgment);
        Assert.True(import.Accepted, import.Message);
        Assert.NotNull(importedChildRelay);
        Assert.NotNull(importedChildContext);
        Assert.NotNull(acknowledgment);
        Assert.Equal(2, test.Source.Session.LastSequence);
        Assert.Equal(2, test.Receiving.Session.LastSequence);
        var acknowledgmentBytes = SidecarCapabilityTransportCodec.Serialize(acknowledgment!);

        Assert.True(test.Source.Session.TryGetActiveHostActionEntryCarrier(
            importedChildContext!.CapabilityId,
            out var childCarrier));
        Assert.True(test.Source.Session.BeginNestedHostActionEntryCall(
            importedChildRelay!.Carrier,
            test.ChildCall,
            test.ChildAction,
            test.ChildAction.ByteLength,
            test.Source.Now,
            out _).Accepted);
        Assert.True(test.Source.Session.CompleteCall(test.ChildCall.CallId, 0).Accepted);

        var expiry = test.Relay.ExpiresAt.AddSeconds(1);
        test.Receiving.Session.SweepExpiredHostActionEntryCarriers(expiry);
        Assert.Equal(2, test.Source.Session.LastSequence);
        Assert.Equal(2, test.Receiving.Session.LastSequence);
        var retry = test.Source.Session.ImportHostEndpointTypedActionChildRelay(
            SidecarCapabilityTransportCodec.Deserialize<SidecarEndpointTypedActionChildRelay>(
                SidecarCapabilityTransportCodec.Serialize(test.WireRelay)),
            expiry,
            IssueEndpointChildImportAcknowledgment,
            out var retriedChildRelay,
            out var retriedChildContext,
            out var retriedAcknowledgment);
        Assert.True(retry.Accepted, retry.Message);
        Assert.Null(retriedChildRelay);
        Assert.Null(retriedChildContext);
        Assert.NotNull(retriedAcknowledgment);
        Assert.True(acknowledgmentBytes.SequenceEqual(
            SidecarCapabilityTransportCodec.Serialize(retriedAcknowledgment!)));
        var delayed = test.Receiving.Session.CompleteHostEndpointTypedActionChildRelay(
            test.WireRelay,
            retriedAcknowledgment!,
            expiry);
        Assert.True(delayed.Accepted, delayed.Message);
        Assert.Equal(2, test.Receiving.Session.LastSequence);
        Assert.Equal(
            SidecarCapabilityErrors.Replay,
            test.Receiving.Session.CompleteHostEndpointTypedActionChildRelay(
                test.WireRelay,
                retriedAcknowledgment,
                expiry).Code);
        Assert.Equal(
            SidecarCapabilityErrors.Replay,
            test.Source.Session.CompleteHostActionEntryCarrier(
                childCarrier!,
                HostActionEntryCarrierCompletionKind.Failed,
                test.Source.Now).Code);

        CleanupEndpointTypedActionChildParents(test);
        CompleteNextNormalRootRelay(
            test.Source,
            test.Receiving,
            transport,
            "endpoint-ack-expiry-sequence-three",
            3);
    }

    [Theory]
    [InlineData(HostEndpointTransport.Http)]
    [InlineData(HostEndpointTransport.WebSocket)]
    public void Endpoint_typed_child_unimported_expiry_sweep_rolls_back_sequence(
        HostEndpointTransport transport)
    {
        var test = CreateEndpointTypedActionChildCase(transport, maxInFlight: 3);
        Assert.Equal(2, test.Source.Session.LastSequence);
        Assert.Equal(2, test.Receiving.Session.LastSequence);

        var expiry = test.Relay.ExpiresAt.AddSeconds(1);
        test.Receiving.Session.SweepExpiredHostActionEntryCarriers(expiry);
        Assert.Equal(2, test.Receiving.Session.LastSequence);
        Assert.Equal(
            SidecarCapabilityErrors.Unauthenticated,
            test.Receiving.Session.CompleteHostEndpointTypedActionChildRelay(
                test.WireRelay,
                null,
                expiry).Code);
        Assert.Equal(
            SidecarCapabilityErrors.Unauthenticated,
            test.Receiving.Session.ReleaseHostEndpointTypedActionChildRelay(
                test.WireRelay,
                expiry).Code);

        test.Source.Session.SweepExpiredHostActionEntryCarriers(expiry);
        Assert.Equal(2, test.Source.Session.LastSequence);
        var abort = AbortUnimportedEndpointTypedActionChild(test, expiry);
        Assert.Equal(1, test.Source.Session.LastSequence);
        Assert.Equal(1, test.Receiving.Session.LastSequence);
        Assert.Equal(
            SidecarCapabilityErrors.Replay,
            test.Receiving.Session.ConsumeHostEndpointTypedActionChildImportAbort(
                abort,
                expiry).Code);

        CleanupEndpointTypedActionChildParents(test);
        CompleteNextNormalRootRelay(
            test.Source,
            test.Receiving,
            transport,
            "endpoint-ack-unimported-expiry-sequence-two",
            2);
    }

    [Theory]
    [InlineData(HostEndpointTransport.Http)]
    [InlineData(HostEndpointTransport.WebSocket)]
    public void Endpoint_typed_child_completed_import_recovers_exact_acknowledgment_without_execution_authority(
        HostEndpointTransport transport)
    {
        var test = CreateEndpointTypedActionChildCase(transport, maxInFlight: 3);
        var imported = test.Source.Session.ImportHostEndpointTypedActionChildRelay(
            test.WireRelay,
            test.Source.Now,
            IssueEndpointChildImportAcknowledgment,
            out var childRelay,
            out var childContext,
            out var acknowledgment);
        Assert.True(imported.Accepted, imported.Message);
        Assert.NotNull(childRelay);
        Assert.NotNull(childContext);
        Assert.NotNull(acknowledgment);
        Assert.Equal(2, test.Source.Session.LastSequence);
        Assert.Equal(2, test.Receiving.Session.LastSequence);

        var competingAbort = test.Source.Session.IssueHostEndpointTypedActionChildImportAbort(
            test.WireRelay,
            test.Source.Now,
            IssueEndpointChildImportAbort,
            out var abort);
        Assert.Equal(SidecarCapabilityErrors.Replay, competingAbort.Code);
        Assert.Null(abort);
        Assert.Equal(2, test.Source.Session.LastSequence);
        Assert.Equal(2, test.Receiving.Session.LastSequence);

        Assert.True(test.Source.Session.TryGetActiveHostActionEntryCarrier(
            childContext!.CapabilityId,
            out var childCarrier));
        Assert.NotNull(childCarrier);
        Assert.True(test.Source.Session.BeginNestedHostActionEntryCall(
            childRelay!.Carrier,
            test.ChildCall,
            test.ChildAction,
            test.ChildAction.ByteLength,
            test.Source.Now,
            out _).Accepted);
        Assert.True(test.Source.Session.CompleteCall(test.ChildCall.CallId, 0).Accepted);
        Assert.Equal(
            SidecarCapabilityErrors.Replay,
            test.Source.Session.CompleteHostActionEntryCarrier(
                childCarrier!,
                HostActionEntryCarrierCompletionKind.Failed,
                test.Source.Now).Code);
        var activeCarriersAfterCompletion = test.Source.Session.ActiveHostActionEntryCarrierCount;
        var issuedContextsAfterCompletion = test.Source.Session.IssuedHostActionEntryContextCount;
        var sequenceAfterCompletion = test.Source.Session.LastSequence;

        var retry = test.Source.Session.ImportHostEndpointTypedActionChildRelay(
            SidecarCapabilityTransportCodec.Deserialize<SidecarEndpointTypedActionChildRelay>(
                SidecarCapabilityTransportCodec.Serialize(test.WireRelay)),
            test.Source.Now,
            IssueEndpointChildImportAcknowledgment,
            out var retryRelay,
            out var retryContext,
            out var retryAcknowledgment);
        Assert.True(retry.Accepted, retry.Message);
        Assert.Null(retryRelay);
        Assert.Null(retryContext);
        Assert.NotNull(retryAcknowledgment);
        Assert.Equal(activeCarriersAfterCompletion, test.Source.Session.ActiveHostActionEntryCarrierCount);
        Assert.Equal(issuedContextsAfterCompletion, test.Source.Session.IssuedHostActionEntryContextCount);
        Assert.Equal(sequenceAfterCompletion, test.Source.Session.LastSequence);
        Assert.True(SidecarCapabilityTransportCodec.Serialize(acknowledgment!).SequenceEqual(
            SidecarCapabilityTransportCodec.Serialize(retryAcknowledgment!)));
        var repeatedAbort = test.Source.Session.IssueHostEndpointTypedActionChildImportAbort(
            test.WireRelay,
            test.Source.Now,
            IssueEndpointChildImportAbort,
            out var repeatedAbortAuthority);
        Assert.Equal(SidecarCapabilityErrors.Replay, repeatedAbort.Code);
        Assert.Null(repeatedAbortAuthority);
        Assert.Equal(
            SidecarCapabilityErrors.Replay,
            test.Source.Session.BeginNestedHostActionEntryCall(
                childRelay!.Carrier,
                test.ChildCall,
                test.ChildAction,
                test.ChildAction.ByteLength,
                test.Source.Now,
                out _).Code);
        var completed = test.Receiving.Session.CompleteHostEndpointTypedActionChildRelay(
            test.WireRelay,
            retryAcknowledgment,
            test.Receiving.Now);
        Assert.True(completed.Accepted, completed.Message);
        Assert.Equal(2, test.Source.Session.LastSequence);
        Assert.Equal(2, test.Receiving.Session.LastSequence);
        Assert.Equal(
            SidecarCapabilityErrors.Replay,
            test.Receiving.Session.CompleteHostEndpointTypedActionChildRelay(
                test.WireRelay,
                retryAcknowledgment,
                test.Receiving.Now).Code);

        CleanupEndpointTypedActionChildParents(test);
        CompleteNextNormalRootRelay(
            test.Source,
            test.Receiving,
            transport,
            "endpoint-ack-lost-sequence-three",
            3);

        var replayExpiry = DateTimeOffset.UtcNow.AddMinutes(6);
        test.Source.Session.SweepExpiredHostActionEntryCarriers(replayExpiry);
        var expiredReplay = test.Source.Session.ImportHostEndpointTypedActionChildRelay(
            test.WireRelay,
            replayExpiry,
            IssueEndpointChildImportAcknowledgment,
            out var expiredChildRelay,
            out var expiredChildContext,
            out var expiredAcknowledgment);
        Assert.False(expiredReplay.Accepted);
        Assert.Null(expiredChildRelay);
        Assert.Null(expiredChildContext);
        Assert.Null(expiredAcknowledgment);
    }

    [Theory]
    [InlineData(HostEndpointTransport.Http, true)]
    [InlineData(HostEndpointTransport.Http, false)]
    [InlineData(HostEndpointTransport.WebSocket, true)]
    [InlineData(HostEndpointTransport.WebSocket, false)]
    public void Endpoint_typed_child_permanent_acknowledgment_loss_commits_at_shared_deadline(
        HostEndpointTransport transport,
        bool sweepSourceFirst)
    {
        var test = CreateEndpointTypedActionChildCase(transport, maxInFlight: 3);
        var imported = test.Source.Session.ImportHostEndpointTypedActionChildRelay(
            test.WireRelay,
            test.Source.Now,
            IssueEndpointChildImportAcknowledgment,
            out var childRelay,
            out var childContext,
            out var acknowledgment);
        Assert.True(imported.Accepted, imported.Message);
        Assert.NotNull(childRelay);
        Assert.NotNull(childContext);
        Assert.NotNull(acknowledgment);
        Assert.True(test.Source.Session.BeginNestedHostActionEntryCall(
            childRelay!.Carrier,
            test.ChildCall,
            test.ChildAction,
            test.ChildAction.ByteLength,
            test.Source.Now,
            out _).Accepted);
        Assert.True(test.Source.Session.CompleteCall(test.ChildCall.CallId, 0).Accepted);

        var outcomeDecisionAt = test.WireRelay.ReceivingReservation.OutcomeDecisionAt;
        Assert.True(outcomeDecisionAt > test.WireRelay.ExpiresAt);
        SweepEndpointTypedActionChildOutcome(test, outcomeDecisionAt, sweepSourceFirst);
        Assert.Equal(2, test.Source.Session.LastSequence);
        Assert.Equal(2, test.Receiving.Session.LastSequence);

        var retry = test.Source.Session.ImportHostEndpointTypedActionChildRelay(
            test.WireRelay,
            outcomeDecisionAt,
            IssueEndpointChildImportAcknowledgment,
            out var retryRelay,
            out var retryContext,
            out var retryAcknowledgment);
        Assert.False(retry.Accepted);
        Assert.Null(retryRelay);
        Assert.Null(retryContext);
        Assert.Null(retryAcknowledgment);
        Assert.Equal(
            SidecarCapabilityErrors.Replay,
            test.Receiving.Session.CompleteHostEndpointTypedActionChildRelay(
                test.WireRelay,
                acknowledgment,
                outcomeDecisionAt).Code);
        Assert.Equal(
            SidecarCapabilityErrors.Expired,
            test.Source.Session.IssueHostEndpointTypedActionChildImportAbort(
                test.WireRelay,
                outcomeDecisionAt,
                IssueEndpointChildImportAbort,
                out _).Code);

        var rotated = CompleteAndRotateAfterEndpointTypedActionChildOutcome(
            test,
            outcomeDecisionAt,
            $"permanent-ack-{transport}-{sweepSourceFirst}");
        CompleteNextNormalRootRelay(
            rotated.Source,
            rotated.Receiving,
            transport,
            $"endpoint-permanent-ack-{transport}-{sweepSourceFirst}",
            1);
    }

    [Theory]
    [InlineData(HostEndpointTransport.Http, true)]
    [InlineData(HostEndpointTransport.Http, false)]
    [InlineData(HostEndpointTransport.WebSocket, true)]
    [InlineData(HostEndpointTransport.WebSocket, false)]
    public void Endpoint_typed_child_lost_abort_commits_at_shared_deadline(
        HostEndpointTransport transport,
        bool sweepSourceFirst)
    {
        var test = CreateEndpointTypedActionChildCase(transport, maxInFlight: 3);
        var issue = test.Source.Session.IssueHostEndpointTypedActionChildImportAbort(
            test.WireRelay,
            test.Source.Now,
            IssueEndpointChildImportAbort,
            out var abort);
        Assert.True(issue.Accepted, issue.Message);
        Assert.NotNull(abort);
        Assert.Equal(2, test.Source.Session.LastSequence);
        Assert.Equal(2, test.Receiving.Session.LastSequence);

        var outcomeDecisionAt = test.WireRelay.ReceivingReservation.OutcomeDecisionAt;
        SweepEndpointTypedActionChildOutcome(test, outcomeDecisionAt, sweepSourceFirst);
        Assert.Equal(2, test.Source.Session.LastSequence);
        Assert.Equal(2, test.Receiving.Session.LastSequence);
        Assert.Equal(
            SidecarCapabilityErrors.Replay,
            test.Receiving.Session.ConsumeHostEndpointTypedActionChildImportAbort(
                abort!,
                outcomeDecisionAt).Code);
        Assert.Equal(
            SidecarCapabilityErrors.Replay,
            test.Source.Session.CompleteHostEndpointTypedActionChildImportAbort(
                abort!,
                outcomeDecisionAt).Code);

        var rotated = CompleteAndRotateAfterEndpointTypedActionChildOutcome(
            test,
            outcomeDecisionAt,
            $"lost-abort-{transport}-{sweepSourceFirst}");
        CompleteNextNormalRootRelay(
            rotated.Source,
            rotated.Receiving,
            transport,
            $"endpoint-lost-abort-{transport}-{sweepSourceFirst}",
            1);
    }

    [Theory]
    [InlineData(HostEndpointTransport.Http)]
    [InlineData(HostEndpointTransport.WebSocket)]
    public void Endpoint_typed_child_expired_parent_uses_authenticated_abort(
        HostEndpointTransport transport)
    {
        var test = CreateEndpointTypedActionChildCase(transport, maxInFlight: 3);
        var parentExpiry = test.ReceivingParent.Carrier.ExpiresAt.AddSeconds(1);
        var receivingRemoved = test.Receiving.Session.SweepExpiredHostActionEntryCarriers(parentExpiry);
        Assert.True(receivingRemoved > 0);
        Assert.Equal(2, test.Source.Session.LastSequence);
        Assert.Equal(2, test.Receiving.Session.LastSequence);

        var abort = AbortUnimportedEndpointTypedActionChild(test, parentExpiry);
        Assert.Equal(1, test.Source.Session.LastSequence);
        Assert.Equal(1, test.Receiving.Session.LastSequence);
        Assert.Equal(
            SidecarCapabilityErrors.Replay,
            test.Receiving.Session.ConsumeHostEndpointTypedActionChildImportAbort(
                abort,
                parentExpiry).Code);

        Assert.True(test.Receiving.Session.CompleteCall(
            test.ReceivingParent.Call.CallId,
            0).Accepted);
        Assert.Equal(
            SidecarCapabilityErrors.Replay,
            test.Receiving.Session.CompleteHostActionEntryCarrier(
                test.ReceivingParent.Carrier,
                HostActionEntryCarrierCompletionKind.Succeeded,
                parentExpiry).Code);
        Assert.Equal(
            SidecarCapabilityErrors.Replay,
            test.Source.Session.CompleteHostEndpointRouteRelay(
                test.RouteRelay,
                test.Source.Now).Code);
        Assert.True(test.Source.Session.CompleteCall(
            test.SourceParent.Call.CallId,
            0).Accepted);
        Assert.True(test.Source.Session.CompleteHostActionEntryCarrier(
            test.SourceParent.Carrier,
            HostActionEntryCarrierCompletionKind.Succeeded,
            test.Source.Now).Accepted);

        CompleteNextNormalRootRelay(
            test.Source,
            test.Receiving,
            transport,
            "endpoint-parent-expiry-sequence-two",
            2);
    }

    [Theory]
    [InlineData(HostEndpointTransport.Http)]
    [InlineData(HostEndpointTransport.WebSocket)]
    public void Endpoint_typed_child_import_acknowledgment_survives_parent_expiry(
        HostEndpointTransport transport)
    {
        var test = CreateEndpointTypedActionChildCase(transport, maxInFlight: 3);
        var imported = test.Source.Session.ImportHostEndpointTypedActionChildRelay(
            test.WireRelay,
            test.Source.Now,
            IssueEndpointChildImportAcknowledgment,
            out var childRelay,
            out var childContext,
            out var acknowledgment);
        Assert.True(imported.Accepted, imported.Message);
        Assert.NotNull(childRelay);
        Assert.NotNull(childContext);
        Assert.NotNull(acknowledgment);
        var acknowledgmentBytes = SidecarCapabilityTransportCodec.Serialize(acknowledgment!);
        Assert.True(test.Source.Session.TryGetActiveHostActionEntryCarrier(
            childContext!.CapabilityId,
            out var childCarrier));
        Assert.NotNull(childCarrier);
        Assert.True(test.Source.Session.BeginNestedHostActionEntryCall(
            childRelay!.Carrier,
            test.ChildCall,
            test.ChildAction,
            test.ChildAction.ByteLength,
            test.Source.Now,
            out _).Accepted);
        Assert.True(test.Source.Session.CompleteCall(test.ChildCall.CallId, 0).Accepted);

        var parentExpiry = test.ReceivingParent.Carrier.ExpiresAt.AddSeconds(1);
        Assert.True(test.Receiving.Session.SweepExpiredHostActionEntryCarriers(parentExpiry) > 0);
        Assert.Equal(2, test.Source.Session.LastSequence);
        Assert.Equal(2, test.Receiving.Session.LastSequence);
        var competingAbort = test.Source.Session.IssueHostEndpointTypedActionChildImportAbort(
            test.WireRelay,
            test.Source.Now,
            IssueEndpointChildImportAbort,
            out var abort);
        Assert.Equal(SidecarCapabilityErrors.Replay, competingAbort.Code);
        Assert.Null(abort);

        var retry = test.Source.Session.ImportHostEndpointTypedActionChildRelay(
            test.WireRelay,
            parentExpiry,
            IssueEndpointChildImportAcknowledgment,
            out var retryRelay,
            out var retryContext,
            out var retryAcknowledgment);
        Assert.True(retry.Accepted, retry.Message);
        Assert.Null(retryRelay);
        Assert.Null(retryContext);
        Assert.NotNull(retryAcknowledgment);
        Assert.True(acknowledgmentBytes.SequenceEqual(
            SidecarCapabilityTransportCodec.Serialize(retryAcknowledgment!)));

        var completion = test.Receiving.Session.CompleteHostEndpointTypedActionChildRelay(
            test.WireRelay,
            retryAcknowledgment,
            parentExpiry);
        Assert.True(completion.Accepted, completion.Message);
        Assert.Equal(
            SidecarCapabilityErrors.Replay,
            test.Source.Session.CompleteHostActionEntryCarrier(
                childCarrier!,
                HostActionEntryCarrierCompletionKind.Failed,
                test.Source.Now).Code);

        Assert.True(test.Receiving.Session.CompleteCall(
            test.ReceivingParent.Call.CallId,
            0).Accepted);
        Assert.Equal(
            SidecarCapabilityErrors.Replay,
            test.Receiving.Session.CompleteHostActionEntryCarrier(
                test.ReceivingParent.Carrier,
                HostActionEntryCarrierCompletionKind.Succeeded,
                parentExpiry).Code);
        Assert.True(test.Source.Session.CompleteHostEndpointRouteRelay(
            test.RouteRelay,
            test.Source.Now).Accepted);
        Assert.True(test.Source.Session.CompleteCall(
            test.SourceParent.Call.CallId,
            0).Accepted);
        Assert.Equal(
            SidecarCapabilityErrors.Replay,
            test.Source.Session.CompleteHostActionEntryCarrier(
                test.SourceParent.Carrier,
                HostActionEntryCarrierCompletionKind.Succeeded,
                test.Source.Now).Code);

        CompleteNextNormalRootRelay(
            test.Source,
            test.Receiving,
            transport,
            "endpoint-parent-expiry-commit-sequence-three",
            3);
    }

    [Theory]
    [InlineData(HostEndpointTransport.Http)]
    [InlineData(HostEndpointTransport.WebSocket)]
    public void Endpoint_typed_child_failed_import_signer_cannot_admit_pending_child(
        HostEndpointTransport transport)
    {
        var test = CreateEndpointTypedActionChildCase(transport, maxInFlight: 3);
        var sourceSequence = test.Source.Session.LastSequence;
        var receivingSequence = test.Receiving.Session.LastSequence;
        var sourceCarriers = test.Source.Session.ActiveHostActionEntryCarrierCount;
        var receivingCarriers = test.Receiving.Session.ActiveHostActionEntryCarrierCount;
        SidecarCapabilityValidationResult? reentrantAdmission = null;

        var rejected = test.Source.Session.ImportHostEndpointTypedActionChildRelay(
            test.WireRelay,
            test.Source.Now,
            candidate =>
            {
                reentrantAdmission = test.Source.Session.BeginNestedHostActionEntryCall(
                    candidate.Relay.ReceivingReservation.Child.Carrier!,
                    candidate.Relay.ReceivingReservation.Child.Call,
                    candidate.Relay.ReceivingReservation.Action,
                    candidate.Relay.ReceivingReservation.Action.ByteLength,
                    test.Source.Now,
                    out _);
                return string.Empty;
            },
            out var rejectedChildRelay,
            out var rejectedContext,
            out var rejectedAcknowledgment);

        Assert.False(rejected.Accepted);
        Assert.Equal(SidecarCapabilityErrors.Unauthenticated, rejected.Code);
        Assert.NotNull(reentrantAdmission);
        Assert.Equal(SidecarCapabilityErrors.Replay, reentrantAdmission!.Code);
        Assert.Null(rejectedChildRelay);
        Assert.Null(rejectedContext);
        Assert.Null(rejectedAcknowledgment);
        Assert.Equal(sourceSequence, test.Source.Session.LastSequence);
        Assert.Equal(receivingSequence, test.Receiving.Session.LastSequence);
        Assert.Equal(sourceCarriers, test.Source.Session.ActiveHostActionEntryCarrierCount);
        Assert.Equal(receivingCarriers, test.Receiving.Session.ActiveHostActionEntryCarrierCount);

        var retry = test.Source.Session.ImportHostEndpointTypedActionChildRelay(
            test.WireRelay,
            test.Source.Now,
            IssueEndpointChildImportAcknowledgment,
            out var childRelay,
            out var childContext,
            out var acknowledgment);
        Assert.True(retry.Accepted, retry.Message);
        Assert.NotNull(childRelay);
        Assert.NotNull(childContext);
        Assert.NotNull(acknowledgment);
        Assert.True(test.Source.Session.BeginNestedHostActionEntryCall(
            childRelay!.Carrier,
            test.ChildCall,
            test.ChildAction,
            test.ChildAction.ByteLength,
            test.Source.Now,
            out _).Accepted);
        Assert.True(test.Source.Session.CompleteCall(test.ChildCall.CallId, 0).Accepted);
        Assert.True(test.Receiving.Session.CompleteHostEndpointTypedActionChildRelay(
            test.WireRelay,
            acknowledgment!,
            test.Receiving.Now).Accepted);

        CleanupEndpointTypedActionChildParents(test);
        CompleteNextNormalRootRelay(
            test.Source,
            test.Receiving,
            transport,
            "endpoint-ack-failed-signer",
            3);
    }

    [Theory]
    [InlineData(HostEndpointTransport.Http)]
    [InlineData(HostEndpointTransport.WebSocket)]
    public void Endpoint_typed_child_valid_import_signer_cannot_admit_before_finalization(
        HostEndpointTransport transport)
    {
        var test = CreateEndpointTypedActionChildCase(transport, maxInFlight: 3);
        SidecarCapabilityValidationResult? reentrantAdmission = null;

        var imported = test.Source.Session.ImportHostEndpointTypedActionChildRelay(
            test.WireRelay,
            test.Source.Now,
            candidate =>
            {
                reentrantAdmission = test.Source.Session.BeginNestedHostActionEntryCall(
                    candidate.Relay.ReceivingReservation.Child.Carrier!,
                    candidate.Relay.ReceivingReservation.Child.Call,
                    candidate.Relay.ReceivingReservation.Action,
                    candidate.Relay.ReceivingReservation.Action.ByteLength,
                    test.Source.Now,
                    out _);
                return IssueEndpointChildImportAcknowledgment(candidate);
            },
            out var childRelay,
            out var childContext,
            out var acknowledgment);

        Assert.True(imported.Accepted, imported.Message);
        Assert.NotNull(reentrantAdmission);
        Assert.Equal(SidecarCapabilityErrors.Replay, reentrantAdmission!.Code);
        Assert.NotNull(childRelay);
        Assert.NotNull(childContext);
        Assert.NotNull(acknowledgment);
        Assert.True(test.Source.Session.BeginNestedHostActionEntryCall(
            childRelay!.Carrier,
            test.ChildCall,
            test.ChildAction,
            test.ChildAction.ByteLength,
            test.Source.Now,
            out _).Accepted);
        Assert.True(test.Source.Session.CompleteCall(test.ChildCall.CallId, 0).Accepted);
        Assert.True(test.Receiving.Session.CompleteHostEndpointTypedActionChildRelay(
            test.WireRelay,
            acknowledgment!,
            test.Receiving.Now).Accepted);

        CleanupEndpointTypedActionChildParents(test);
        CompleteNextNormalRootRelay(
            test.Source,
            test.Receiving,
            transport,
            "endpoint-ack-valid-signer",
            3);
    }

    [Fact]
    public void Endpoint_route_relay_round_trip_preserves_roles_and_features()
    {
        static bool AuthenticateAuthority(HostEndpointRouteAuthority authority, string hash) =>
            authority.Proof == KeyedEndpointProof("route", hash);
        static bool AuthenticateRelay(SidecarHostEndpointRouteRelay relay, string hash) =>
            relay.Proof == KeyedEndpointProof("relay", hash);

        var source = CreateFixture(actionInputBytes: 4096, protocolMessageBytes: 4096);
        var receiving = CreateMirroredFixture(
            source,
            authenticateEndpointRouteAuthority: AuthenticateAuthority,
            authenticateEndpointRouteRelay: AuthenticateRelay);
        var features = new ExtensionFeatureSet([
            new ExtensionFeature(
                "endpoint.test",
                1,
                "module-a",
                128,
                JsonDocument.Parse("{\"mode\":\"wire\"}").RootElement.Clone()),
        ]);
        var inputs = CreateEndpointRelayInputs(
            source,
            receiving,
            "codec",
            new RequestPrincipal(
                "endpoint-user",
                Roles: new HashSet<string>(["reader", "writer"], StringComparer.Ordinal)),
            features);
        var issue = source.Session.IssueHostEndpointRouteRelay(
            inputs.Request,
            inputs.SourceCall,
            inputs.ReceivingCall,
            receiving.Session,
            source.Now,
            authority => KeyedEndpointProof(
                "route",
                HostEndpointRouteAuthorityValidator.ComputeBindingHash(authority)),
            (relay, hash) => KeyedEndpointProof("relay", hash),
            out var relay);

        Assert.True(issue.Accepted, issue.Message);
        Assert.NotNull(relay);
        var wireRelay = SidecarCapabilityTransportCodec.Deserialize<SidecarHostEndpointRouteRelay>(
            SidecarCapabilityTransportCodec.Serialize(relay));
        var imported = receiving.Session.ImportHostEndpointRouteRelay(
            wireRelay,
            receiving.Now,
            out var context);

        Assert.True(imported.Accepted, imported.Message);
        Assert.NotNull(context);
        Assert.Equal(inputs.Request.Invocation.HostActionContext.Caller.SubjectId, context!.Caller.SubjectId);
        Assert.True(context.Caller.Roles!.SetEquals(["reader", "writer"]));
        Assert.Equal(
            SidecarCapabilityTransportCodec.Serialize(inputs.Request.Invocation.HostActionContext.Features),
            SidecarCapabilityTransportCodec.Serialize(context.Features));
    }

    [Fact]
    public void Endpoint_route_relay_import_detaches_input_and_returned_context()
    {
        static bool AuthenticateAuthority(HostEndpointRouteAuthority authority, string hash) =>
            authority.Proof == KeyedEndpointProof("route", hash);
        static bool AuthenticateRelay(SidecarHostEndpointRouteRelay relay, string hash) =>
            relay.Proof == KeyedEndpointProof("relay", hash);

        var source = CreateFixture(actionInputBytes: 4096, protocolMessageBytes: 4096);
        var receiving = CreateMirroredFixture(
            source,
            authenticateEndpointRouteAuthority: AuthenticateAuthority,
            authenticateEndpointRouteRelay: AuthenticateRelay);
        var features = new ExtensionFeatureSet([
            new ExtensionFeature(
                "endpoint.test",
                1,
                "module-a",
                128,
                JsonDocument.Parse("{\"mode\":\"owned\"}").RootElement.Clone()),
        ]);
        var inputs = CreateEndpointRelayInputs(
            source,
            receiving,
            "detached-import",
            new RequestPrincipal(
                "endpoint-user",
                Roles: new HashSet<string>(["reader"], StringComparer.Ordinal)),
            features);
        var issue = source.Session.IssueHostEndpointRouteRelay(
            inputs.Request,
            inputs.SourceCall,
            inputs.ReceivingCall,
            receiving.Session,
            source.Now,
            authority => KeyedEndpointProof(
                "route",
                HostEndpointRouteAuthorityValidator.ComputeBindingHash(authority)),
            (relay, hash) => KeyedEndpointProof("relay", hash),
            out var relay);
        Assert.True(issue.Accepted, issue.Message);
        Assert.NotNull(relay);

        var wireRelay = SidecarCapabilityTransportCodec.Deserialize<SidecarHostEndpointRouteRelay>(
            SidecarCapabilityTransportCodec.Serialize(relay));
        var pristineRelay = SidecarCapabilityTransportCodec.Deserialize<SidecarHostEndpointRouteRelay>(
            SidecarCapabilityTransportCodec.Serialize(wireRelay));
        var pristineContext = SidecarCapabilityTransportCodec.Deserialize<HostActionEntryRequestContext>(
            SidecarCapabilityTransportCodec.Serialize(wireRelay.ReceivingContext));
        var imported = receiving.Session.ImportHostEndpointRouteRelay(
            wireRelay,
            receiving.Now,
            out var returnedContext);
        Assert.True(imported.Accepted, imported.Message);
        Assert.NotNull(returnedContext);

        var sequence = receiving.Session.LastSequence;
        var contexts = receiving.Session.IssuedHostActionEntryContextCount;
        var carriers = receiving.Session.ActiveHostActionEntryCarrierCount;
        ((ISet<string>)wireRelay.ReceivingContext.Caller.Roles!).Add("mutated-input-role");
        ((IList<ExtensionFeature>)wireRelay.ReceivingContext.Features.Items).Add(
            new ExtensionFeature(
                "mutated.input.feature",
                1,
                "module-a",
                1,
                JsonDocument.Parse("{}").RootElement.Clone()));
        ((ISet<string>)returnedContext!.Caller.Roles!).Add("mutated-returned-role");
        ((IList<ExtensionFeature>)returnedContext.Features.Items).Add(
            new ExtensionFeature(
                "mutated.returned.feature",
                1,
                "module-a",
                1,
                JsonDocument.Parse("{}").RootElement.Clone()));
        wireRelay.Request.Headers["x-request"][0] = "mutated-input-header";
        wireRelay.Request.Query["tag"][0] = "mutated-input-query";
        wireRelay.Request.Body[0] = 99;

        var endpointPayload = EndpointInvocationPayload(
            typeof(HostEndpointInvocation).AssemblyQualifiedName!,
            wireRelay.Request.Invocation);
        var rejected = receiving.Session.BeginCall(
            wireRelay.ReceivingParentCall,
            SidecarCapabilityKind.Action,
            endpointPayload,
            endpointPayload.ByteLength,
            receiving.Now,
            returnedContext);
        Assert.False(rejected.Accepted, rejected.Message);
        Assert.Equal(sequence, receiving.Session.LastSequence);
        Assert.Equal(contexts, receiving.Session.IssuedHostActionEntryContextCount);
        Assert.Equal(carriers, receiving.Session.ActiveHostActionEntryCarrierCount);

        Assert.True(
            receiving.Session.BeginCall(
                wireRelay.ReceivingParentCall,
                SidecarCapabilityKind.Action,
                endpointPayload,
                endpointPayload.ByteLength,
                receiving.Now,
                pristineContext).Accepted);
        Assert.True(receiving.Session.CompleteCall(wireRelay.ReceivingParentCall.CallId, 0).Accepted);
        Assert.True(receiving.Session.TryGetActiveHostActionEntryCarrier(
            wireRelay.ReceivingContext.CapabilityId,
            out var carrier));
        Assert.True(
            receiving.Session.CompleteHostActionEntryCarrier(
                carrier!,
                HostActionEntryCarrierCompletionKind.Succeeded,
                receiving.Now).Accepted);
        Assert.True(source.Session.CompleteHostEndpointRouteRelay(pristineRelay, source.Now).Accepted);
        var rotated = CreateRotatedBinding(receiving, "detached-import-rotation");
        receiving.BindingHashes.Add(rotated.Authentication.BindingHash);
        Assert.True(receiving.Session.RotateBinding(rotated, receiving.Now).Accepted);
    }

    [Fact]
    public void Endpoint_route_relay_collision_ignores_remote_session_call_identity()
    {
        static bool AuthenticateAuthority(HostEndpointRouteAuthority authority, string hash) =>
            authority.Proof == KeyedEndpointProof("route", hash);
        static bool AuthenticateRelay(SidecarHostEndpointRouteRelay relay, string hash) =>
            relay.Proof == KeyedEndpointProof("relay", hash);

        var source = CreateFixture(
            moduleId: "module-source",
            graphId: "graph-source");
        var remote = CreateFixture(
            moduleId: "module-remote",
            graphId: "graph-remote",
            authenticateEndpointRouteAuthority: AuthenticateAuthority,
            authenticateEndpointRouteRelay: AuthenticateRelay);
        var receiving = CreateFixture(
            moduleId: "module-receiving",
            graphId: "graph-receiving",
            authenticateEndpointRouteAuthority: AuthenticateAuthority,
            authenticateEndpointRouteRelay: AuthenticateRelay);
        var remoteInputs = CreateEndpointRelayInputs(receiving, remote, "remote") with
        {
            ReceivingCall = CreateEndpointRelayInputs(receiving, remote, "remote-call").ReceivingCall with
            {
                ReplayNonce = "shared-peer-and-local-nonce",
            },
        };
        var remoteIssue = receiving.Session.IssueHostEndpointRouteRelay(
            remoteInputs.Request,
            remoteInputs.SourceCall,
            remoteInputs.ReceivingCall,
            remote.Session,
            receiving.Now,
            authority => KeyedEndpointProof(
                "route",
                HostEndpointRouteAuthorityValidator.ComputeBindingHash(authority)),
            (relay, hash) => KeyedEndpointProof("relay", hash),
            out var remoteRelay);
        Assert.True(remoteIssue.Accepted, remoteIssue.Message);
        Assert.NotNull(remoteRelay);

        var localInputs = CreateEndpointRelayInputs(source, receiving, "local");
        localInputs = localInputs with
        {
            ReceivingCall = localInputs.ReceivingCall with
            {
                ReplayNonce = "shared-peer-and-local-nonce",
            },
        };
        var localIssue = source.Session.IssueHostEndpointRouteRelay(
            localInputs.Request,
            localInputs.SourceCall,
            localInputs.ReceivingCall,
            receiving.Session,
            source.Now,
            authority => KeyedEndpointProof(
                "route",
                HostEndpointRouteAuthorityValidator.ComputeBindingHash(authority)),
            (relay, hash) => KeyedEndpointProof("relay", hash),
            out var localRelay);
        Assert.True(localIssue.Accepted, localIssue.Message);
        Assert.NotNull(localRelay);

        var imported = receiving.Session.ImportHostEndpointRouteRelay(
            SidecarCapabilityTransportCodec.Deserialize<SidecarHostEndpointRouteRelay>(
                SidecarCapabilityTransportCodec.Serialize(localRelay)),
            receiving.Now,
            out _);

        Assert.True(imported.Accepted, imported.Message);
    }

    [Theory]
    [InlineData("roles")]
    [InlineData("features")]
    [InlineData("route-values")]
    [InlineData("headers")]
    [InlineData("query")]
    public void Endpoint_route_authority_signer_cannot_mutate_shared_input(string mutation)
    {
        var fixture = CreateFixture();
        var features = new ExtensionFeatureSet([
            new ExtensionFeature(
                "endpoint.test",
                1,
                "module-a",
                128,
                JsonDocument.Parse("{\"mode\":\"sign\"}").RootElement.Clone()),
        ]);
        var context = IssueContext(
            fixture,
            new RequestPrincipal(
                "endpoint-user",
                Roles: new HashSet<string>(["reader"], StringComparer.Ordinal)),
            HostActionEntryIngress.Endpoint,
            features: features);
        var request = EndpointRouteRequest(fixture, context, HostEndpointTransport.Http);
        var call = ActionCall(fixture, 1, "detached-route-signer");

        var rejected = fixture.Session.IssueHostEndpointRouteAuthority(
            request,
            call,
            fixture.Now,
            authority =>
            {
                switch (mutation)
                {
                    case "roles":
                        ((ISet<string>)authority.HostActionContext.Caller.Roles!).Add("mutated");
                        break;
                    case "features":
                        ((IList<ExtensionFeature>)authority.HostActionContext.Features.Items)
                            .Add(new ExtensionFeature(
                                "mutated.feature",
                                1,
                                "module-a",
                                1,
                                JsonDocument.Parse("{}").RootElement.Clone()));
                        break;
                    case "route-values":
                        authority.RouteValues["id"][0] = "mutated";
                        break;
                    case "headers":
                        authority.Headers["x-request"][0] = "mutated";
                        break;
                    case "query":
                        authority.Query["tag"][0] = "mutated";
                        break;
                }

                return HostEndpointRouteAuthorityValidator.ComputeBindingHash(authority);
            },
            out var rejectedAuthority);

        Assert.False(rejected.Accepted, rejected.Message);
        Assert.Null(rejectedAuthority);
        var retry = fixture.Session.IssueHostEndpointRouteAuthority(
            request,
            call,
            fixture.Now,
            HostEndpointRouteAuthorityValidator.ComputeBindingHash,
            out var authority);
        Assert.True(retry.Accepted, retry.Message);
        Assert.NotNull(authority);
    }

    [Theory]
    [InlineData("roles")]
    [InlineData("features")]
    [InlineData("route-values")]
    [InlineData("headers")]
    [InlineData("query")]
    [InlineData("body")]
    public void Endpoint_route_relay_signer_cannot_mutate_shared_input(string mutation)
    {
        static bool AuthenticateAuthority(HostEndpointRouteAuthority authority, string hash) =>
            authority.Proof == KeyedEndpointProof("route", hash);
        static bool AuthenticateRelay(SidecarHostEndpointRouteRelay relay, string hash) =>
            relay.Proof == KeyedEndpointProof("relay", hash);

        var source = CreateFixture();
        var receiving = CreateMirroredFixture(
            source,
            authenticateEndpointRouteAuthority: AuthenticateAuthority,
            authenticateEndpointRouteRelay: AuthenticateRelay);
        var features = new ExtensionFeatureSet([
            new ExtensionFeature(
                "endpoint.test",
                1,
                "module-a",
                128,
                JsonDocument.Parse("{\"mode\":\"relay\"}").RootElement.Clone()),
        ]);
        var inputs = CreateEndpointRelayInputs(
            source,
            receiving,
            "detached-relay-signer",
            new RequestPrincipal(
                "endpoint-user",
                Roles: new HashSet<string>(["reader"], StringComparer.Ordinal)),
            features);
        var rejected = source.Session.IssueHostEndpointRouteRelay(
            inputs.Request,
            inputs.SourceCall,
            inputs.ReceivingCall,
            receiving.Session,
            source.Now,
            authority => KeyedEndpointProof(
                "route",
                HostEndpointRouteAuthorityValidator.ComputeBindingHash(authority)),
            (relay, hash) =>
            {
                switch (mutation)
                {
                    case "roles":
                        ((ISet<string>)relay.Request.Invocation.HostActionContext.Caller.Roles!).Add("mutated");
                        break;
                    case "features":
                        ((IList<ExtensionFeature>)relay.Request.Invocation.HostActionContext.Features.Items)
                            .Add(new ExtensionFeature(
                                "mutated.feature",
                                1,
                                "module-a",
                                1,
                                JsonDocument.Parse("{}").RootElement.Clone()));
                        break;
                    case "route-values":
                        relay.Request.RouteValues["id"][0] = "mutated";
                        break;
                    case "headers":
                        relay.Request.Headers["x-request"][0] = "mutated";
                        break;
                    case "query":
                        relay.Request.Query["tag"][0] = "mutated";
                        break;
                    case "body":
                        relay.Request.Body[0] = 99;
                        break;
                }

                return KeyedEndpointProof("relay", hash);
            },
            out var rejectedRelay);

        Assert.False(rejected.Accepted, rejected.Message);
        Assert.Null(rejectedRelay);
        var retry = source.Session.IssueHostEndpointRouteRelay(
            inputs.Request,
            inputs.SourceCall,
            inputs.ReceivingCall,
            receiving.Session,
            source.Now,
            authority => KeyedEndpointProof(
                "route",
                HostEndpointRouteAuthorityValidator.ComputeBindingHash(authority)),
            (relay, hash) => KeyedEndpointProof("relay", hash),
            out var relay);
        Assert.True(retry.Accepted, retry.Message);
        Assert.NotNull(relay);
    }

    [Fact]
    public void Endpoint_route_relay_callbacks_use_detached_input_snapshots()
    {
        static bool AuthenticateAuthority(HostEndpointRouteAuthority authority, string hash) =>
            authority.Proof == KeyedEndpointProof("route", hash);

        static bool AuthenticateRelay(SidecarHostEndpointRouteRelay relay, string hash) =>
            relay.Proof == KeyedEndpointProof("relay", hash);

        var source = CreateFixture(actionInputBytes: 4096, protocolMessageBytes: 4096);
        var receiving = CreateMirroredFixture(
            source,
            authenticateEndpointRouteAuthority: AuthenticateAuthority,
            authenticateEndpointRouteRelay: AuthenticateRelay);
        var features = new ExtensionFeatureSet(new List<ExtensionFeature>
        {
            new ExtensionFeature(
                "relay.snapshot.feature",
                1,
                "module-a",
                128,
                JsonDocument.Parse("{\"mode\":\"relay-snapshot\"}").RootElement.Clone()),
        });
        var inputs = CreateEndpointRelayInputs(
            source,
            receiving,
            "relay-input-snapshot",
            new RequestPrincipal(
                "relay-snapshot",
                Roles: new HashSet<string>(["reader"], StringComparer.Ordinal)),
            features);
        var reservationIssue = receiving.Session.IssueHostEndpointRouteReservation(
            inputs.Request,
            inputs.ReceivingCall,
            source.Now,
            reservation => KeyedEndpointProof(
                "reservation",
                SidecarCapabilityTransportValidation.ComputeEndpointRouteReservationBindingHash(
                    reservation)),
            out var reservation);
        Assert.True(reservationIssue.Accepted, reservationIssue.Message);
        Assert.NotNull(reservation);

        var pristineRequestBytes = SidecarCapabilityTransportCodec.Serialize(inputs.Request);
        var pristineReservationBytes = SidecarCapabilityTransportCodec.Serialize(reservation);
        Exception? reservationMutationError = null;
        Exception? requestMutationError = null;
        var issue = source.Session.IssueHostEndpointRouteRelay(
            inputs.Request,
            inputs.SourceCall,
            reservation!,
            source.Now,
            authority => KeyedEndpointProof(
                "route",
                HostEndpointRouteAuthorityValidator.ComputeBindingHash(authority)),
            (candidate, hash) =>
            {
                try
                {
                    ((ISet<string>)reservation!.ReceivingContext.Caller.Roles!).Add("mutated-reservation-role");
                }
                catch (Exception ex)
                {
                    reservationMutationError = ex;
                }
                try
                {
                    ((IList<ExtensionFeature>)reservation.ReceivingContext.Features.Items)[0] =
                        new ExtensionFeature(
                            "mutated.reservation.feature",
                            1,
                            "module-a",
                            1,
                            JsonDocument.Parse("{}").RootElement.Clone());
                    reservation.Request.Headers["x-request"][0] = "mutated-reservation-header";
                    reservation.Request.Query["tag"][0] = "mutated-reservation-query";
                    reservation.Request.Body[0] = 99;
                }
                catch (Exception ex)
                {
                    reservationMutationError = ex;
                }
                return candidate.Proof == KeyedEndpointProof("reservation", hash);
            },
            (candidate, hash) =>
            {
                try
                {
                    ((ISet<string>)inputs.Request.Invocation.HostActionContext.Caller.Roles!).Add(
                        "mutated-request-role");
                    ((IList<ExtensionFeature>)inputs.Request.Invocation.HostActionContext.Features.Items)[0] =
                        new ExtensionFeature(
                            "mutated.request.feature",
                            1,
                            "module-a",
                            1,
                            JsonDocument.Parse("{}").RootElement.Clone());
                    inputs.Request.Headers["x-request"][0] = "mutated-request-header";
                    inputs.Request.Query["tag"][0] = "mutated-request-query";
                    inputs.Request.Body[0] = 98;
                }
                catch (Exception ex)
                {
                    requestMutationError = ex;
                }
                return KeyedEndpointProof("relay", hash);
            },
            out var relay);

        Assert.Null(reservationMutationError);
        Assert.Null(requestMutationError);
        Assert.True(issue.Accepted, issue.Message);
        Assert.NotNull(relay);
        Assert.Equal(
            pristineRequestBytes,
            SidecarCapabilityTransportCodec.Serialize(relay!.Request));
        Assert.Equal(
            pristineReservationBytes,
            SidecarCapabilityTransportCodec.Serialize(relay.ReceivingReservation));

        var pristineReservation = SidecarCapabilityTransportCodec.Deserialize<SidecarHostEndpointRouteReservation>(
            pristineReservationBytes);
        Assert.True(source.Session.CompleteHostEndpointRouteRelay(relay, source.Now).Accepted);
        Assert.True(
            receiving.Session.ReleaseHostEndpointRouteReservation(
                pristineReservation,
                receiving.Now).Accepted);
    }

    [Theory]
    [InlineData("invocation")]
    [InlineData("route")]
    [InlineData("route-values")]
    [InlineData("headers")]
    [InlineData("query")]
    [InlineData("metadata-array")]
    [InlineData("metadata-value")]
    [InlineData("body")]
    public void Endpoint_route_relay_malformed_input_rejects_without_throw(string mutation)
    {
        static bool AuthenticateAuthority(HostEndpointRouteAuthority authority, string hash) =>
            authority.Proof == KeyedEndpointProof("route", hash);
        static bool AuthenticateRelay(SidecarHostEndpointRouteRelay relay, string hash) =>
            relay.Proof == KeyedEndpointProof("relay", hash);

        var issueSource = CreateFixture();
        var issueReceiving = CreateMirroredFixture(
            issueSource,
            authenticateEndpointRouteAuthority: AuthenticateAuthority,
            authenticateEndpointRouteRelay: AuthenticateRelay);
        var issueInputs = CreateEndpointRelayInputs(issueSource, issueReceiving, $"malformed-issue-{mutation}");
        var malformedIssueRequest = MalformedEndpointRouteRequest(issueInputs.Request, mutation);
        SidecarHostEndpointRouteRelay? issueRelay = null;
        var issueException = Record.Exception(() =>
        {
            var result = issueSource.Session.IssueHostEndpointRouteRelay(
                malformedIssueRequest,
                issueInputs.SourceCall,
                issueInputs.ReceivingCall,
                issueReceiving.Session,
                issueSource.Now,
                authority => KeyedEndpointProof(
                    "route",
                    HostEndpointRouteAuthorityValidator.ComputeBindingHash(authority)),
                (relay, hash) => KeyedEndpointProof("relay", hash),
                out issueRelay);
            Assert.False(result.Accepted, result.Message);
        });
        Assert.Null(issueException);
        Assert.Null(issueRelay);

        var source = CreateFixture();
        var receiving = CreateMirroredFixture(
            source,
            authenticateEndpointRouteAuthority: AuthenticateAuthority,
            authenticateEndpointRouteRelay: AuthenticateRelay);
        var valid = CreateEndpointRelay(source, receiving, $"malformed-import-{mutation}");
        var malformedRelay = valid.Relay with
        {
            Request = MalformedEndpointRouteRequest(valid.Relay.Request, mutation),
        };
        var sequence = receiving.Session.LastSequence;
        var carriers = receiving.Session.ActiveHostActionEntryCarrierCount;
        SidecarCapabilityValidationResult? importResult = null;
        var importException = Record.Exception(() =>
            importResult = receiving.Session.ImportHostEndpointRouteRelay(
                SidecarCapabilityTransportCodec.Deserialize<SidecarHostEndpointRouteRelay>(
                    SidecarCapabilityTransportCodec.Serialize(malformedRelay)),
                receiving.Now,
                out _));
        Assert.Null(importException);
        Assert.NotNull(importResult);
        Assert.False(importResult!.Accepted, importResult.Message);
        Assert.Equal(sequence, receiving.Session.LastSequence);
        Assert.Equal(carriers, receiving.Session.ActiveHostActionEntryCarrierCount);
    }

    [Theory]
    [InlineData("handler")]
    [InlineData("path")]
    [InlineData("method")]
    [InlineData("transport")]
    [InlineData("route-values")]
    [InlineData("headers")]
    [InlineData("query")]
    [InlineData("body")]
    [InlineData("proof")]
    [InlineData("call")]
    [InlineData("session")]
    [InlineData("generation")]
    [InlineData("deadline")]
    [InlineData("cancellation")]
    public void Endpoint_route_relay_mutations_reject_before_receiving_reservation(string mutation)
    {
        static bool AuthenticateAuthority(HostEndpointRouteAuthority authority, string hash) =>
            authority.Proof == KeyedEndpointProof("route", hash);
        static bool AuthenticateRelay(SidecarHostEndpointRouteRelay relay, string hash) =>
            relay.Proof == KeyedEndpointProof("relay", hash);

        var source = CreateFixture(actionInputBytes: 4096, protocolMessageBytes: 4096);
        var receiving = CreateMirroredFixture(
            source,
            authenticateEndpointRouteAuthority: AuthenticateAuthority,
            authenticateEndpointRouteRelay: AuthenticateRelay);
        var context = IssueContext(
            source,
            new RequestPrincipal("endpoint-user"),
            HostActionEntryIngress.Endpoint);
        var request = EndpointRouteRequest(source, context, HostEndpointTransport.Http);
        var sourceCall = ActionCall(source, 1, $"relay-mutation-source-{mutation}");
        var receivingCall = ActionCall(receiving, 1, $"relay-mutation-receiving-{mutation}");
        Assert.True(source.Session.IssueHostEndpointRouteRelay(
            request,
            sourceCall,
            receivingCall,
            receiving.Session,
            source.Now,
            authority => KeyedEndpointProof(
                "route",
                HostEndpointRouteAuthorityValidator.ComputeBindingHash(authority)),
            (relay, hash) => KeyedEndpointProof("relay", hash),
            out var relay).Accepted);
        var reservedSequence = receiving.Session.LastSequence;
        var original = SidecarCapabilityTransportCodec.Deserialize<SidecarHostEndpointRouteRelay>(
            SidecarCapabilityTransportCodec.Serialize(relay));
        var mutated = original;
        switch (mutation)
        {
            case "handler":
                mutated = original with { Request = original.Request with { Route = original.Request.Route with { HandlerIdentity = "/other" } } };
                break;
            case "path":
                mutated = original with { Request = original.Request with { Route = original.Request.Route with { Path = "/other" } } };
                break;
            case "method":
                mutated = original with { Request = original.Request with { Route = original.Request.Route with { Method = "PATCH" } } };
                break;
            case "transport":
                mutated = original with { Request = original.Request with { Route = original.Request.Route with { Transport = HostEndpointTransport.WebSocket } } };
                break;
            case "route-values":
                mutated = original with
                {
                    Request = original.Request with
                    {
                        RouteValues = new Dictionary<string, string[]>(original.Request.RouteValues)
                        {
                            ["id"] = ["changed"],
                        },
                    },
                };
                break;
            case "headers":
                mutated = original with { Request = original.Request with { Headers = new Dictionary<string, string[]>(original.Request.Headers) { ["x-request"] = ["changed"] } } };
                break;
            case "query":
                mutated = original with { Request = original.Request with { Query = new Dictionary<string, string[]>(original.Request.Query) { ["tag"] = ["changed"] } } };
                break;
            case "body":
                mutated = original with { Request = original.Request with { Body = [9, 8, 7] } };
                break;
            case "proof":
                mutated = original with { Proof = "forged" };
                break;
            case "call":
                mutated = original with { Authority = original.Authority with { Call = original.Authority.Call with { CallId = Guid.NewGuid() } } };
                break;
            case "session":
                mutated = original with { ReceivingParentCall = original.ReceivingParentCall with { SessionId = Guid.NewGuid() } };
                break;
            case "generation":
                mutated = original with { ReceivingBindingGeneration = original.ReceivingBindingGeneration + 1 };
                break;
            case "deadline":
                mutated = original with { ReceivingParentCall = original.ReceivingParentCall with { Deadline = original.ReceivingParentCall.Deadline.AddSeconds(-1) } };
                break;
            case "cancellation":
                mutated = original with { ReceivingParentCall = original.ReceivingParentCall with { CancellationId = Guid.NewGuid() } };
                break;
        }

        var rejected = receiving.Session.ImportHostEndpointRouteRelay(
            mutated,
            receiving.Now,
            out _);
        Assert.False(rejected.Accepted, rejected.Message);
        Assert.Equal(
            mutation == "proof"
                ? SidecarCapabilityErrors.Unauthenticated
                : SidecarCapabilityErrors.SpoofedIdentity,
            rejected.Code);
        Assert.Equal(reservedSequence, receiving.Session.LastSequence);
        Assert.Equal(0, receiving.Session.ActiveHostActionEntryCarrierCount);

        var accepted = receiving.Session.ImportHostEndpointRouteRelay(
            original,
            receiving.Now,
            out _);
        Assert.True(accepted.Accepted, accepted.Message);
    }

    [Theory]
    [InlineData("caller")]
    [InlineData("roles")]
    [InlineData("features")]
    [InlineData("trace")]
    [InlineData("idempotency")]
    [InlineData("parent")]
    [InlineData("depth")]
    [InlineData("attempt")]
    [InlineData("endpoint")]
    [InlineData("action")]
    [InlineData("version")]
    [InlineData("descriptor")]
    [InlineData("input-type")]
    [InlineData("input-schema")]
    public void Endpoint_route_relay_context_transformations_reject_before_reservation(string mutation)
    {
        static bool AuthenticateAuthority(HostEndpointRouteAuthority authority, string hash) =>
            authority.Proof == KeyedEndpointProof("route", hash);
        static bool AuthenticateRelay(SidecarHostEndpointRouteRelay relay, string hash) =>
            relay.Proof == KeyedEndpointProof("relay", hash);

        var source = CreateFixture(actionInputBytes: 4096, protocolMessageBytes: 4096);
        var receiving = CreateMirroredFixture(
            source,
            authenticateEndpointRouteAuthority: AuthenticateAuthority,
            authenticateEndpointRouteRelay: AuthenticateRelay);
        var original = CreateEndpointRelay(source, receiving, $"context-{mutation}").Relay;
        var reservedSequence = receiving.Session.LastSequence;
        var context = original.ReceivingContext;
        var changed = context;
        switch (mutation)
        {
            case "caller":
                changed = context with { Caller = new RequestPrincipal("other-caller") };
                break;
            case "roles":
                changed = context with
                {
                    Caller = context.Caller with { Roles = new HashSet<string>(["other-role"]) },
                };
                break;
            case "features":
                changed = context with
                {
                    Features = new ExtensionFeatureSet([
                        new ExtensionFeature("other.feature", 1, "module-a", 1, JsonDocument.Parse("{}").RootElement.Clone()),
                    ]),
                };
                break;
            case "trace":
                changed = context with { TraceId = Guid.NewGuid() };
                break;
            case "idempotency":
                changed = context with { IdempotencyKey = Guid.NewGuid() };
                break;
            case "parent":
                changed = context with { ParentInvocationId = Guid.NewGuid() };
                break;
            case "depth":
                changed = context with { Depth = context.Depth + 1 };
                break;
            case "attempt":
                changed = context with { Attempt = context.Attempt + 1 };
                break;
            case "endpoint":
                changed = context with
                {
                    Contribution = context.Contribution! with
                    {
                        IngressBinding = context.Contribution.IngressBinding with { PrimaryIdentity = "/other" },
                    },
                };
                break;
            case "action":
                changed = context with
                {
                    Contribution = context.Contribution! with
                    {
                        Lineage = context.Contribution.Lineage with { ActionKey = new SharpClawActionKey("other.action") },
                    },
                };
                break;
            case "version":
                changed = context with
                {
                    Contribution = context.Contribution! with
                    {
                        Lineage = context.Contribution.Lineage with { ActionVersion = context.Contribution.Lineage.ActionVersion + 1 },
                    },
                };
                break;
            case "descriptor":
                changed = context with
                {
                    Contribution = context.Contribution! with
                    {
                        Lineage = context.Contribution.Lineage with { DescriptorHash = "other-descriptor" },
                    },
                };
                break;
            case "input-type":
                changed = context with
                {
                    Contribution = context.Contribution! with
                    {
                        Lineage = context.Contribution.Lineage with { InputTypeIdentity = "other.input" },
                    },
                };
                break;
            case "input-schema":
                changed = context with
                {
                    Contribution = context.Contribution! with
                    {
                        Lineage = context.Contribution.Lineage with
                        {
                            InputSchemaVersion = context.Contribution.Lineage.InputSchemaVersion + 1,
                            InputSchemaHash = "other-schema",
                        },
                    },
                };
                break;
        }

        var mutated = ResignEndpointRelay(original with { ReceivingContext = changed });
        var rejected = receiving.Session.ImportHostEndpointRouteRelay(mutated, receiving.Now, out _);

        Assert.False(rejected.Accepted, rejected.Message);
        Assert.Equal(SidecarCapabilityErrors.SpoofedIdentity, rejected.Code);
        Assert.Equal(reservedSequence, receiving.Session.LastSequence);
        Assert.Equal(0, receiving.Session.ActiveHostActionEntryCarrierCount);
        Assert.True(receiving.Session.ImportHostEndpointRouteRelay(original, receiving.Now, out _).Accepted);
    }

    [Fact]
    public void Endpoint_route_relay_rejects_public_route_hash_without_authenticated_proof()
    {
        var source = CreateFixture(actionInputBytes: 4096, protocolMessageBytes: 4096);
        var receiving = CreateMirroredFixture(
            source,
            authenticateEndpointRouteAuthority: (authority, hash) =>
                authority.Proof == KeyedEndpointProof("route", hash),
            authenticateEndpointRouteRelay: (relay, hash) =>
                relay.Proof == KeyedEndpointProof("relay", hash));
        var fixture = CreateEndpointRelay(source, receiving, "public-route-hash");
        var reservedSequence = receiving.Session.LastSequence;
        var unsignedAuthority = fixture.Relay.Authority with
        {
            Proof = fixture.Relay.Authority.CanonicalBindingHash,
        };
        var unsignedRelay = fixture.Relay with { Authority = unsignedAuthority };
        var relayHash = SidecarCapabilityTransportValidation.ComputeEndpointRouteRelayBindingHash(unsignedRelay);
        var forgedRelay = unsignedRelay with
        {
            CanonicalBindingHash = relayHash,
            Proof = KeyedEndpointProof("relay", relayHash),
        };

        var result = receiving.Session.ImportHostEndpointRouteRelay(forgedRelay, receiving.Now, out _);

        Assert.False(result.Accepted);
        Assert.Equal(SidecarCapabilityErrors.Unauthenticated, result.Code);
        Assert.Equal(reservedSequence, receiving.Session.LastSequence);
        Assert.Equal(0, receiving.Session.ActiveHostActionEntryCarrierCount);
        Assert.True(receiving.Session.ImportHostEndpointRouteRelay(
            fixture.Relay,
            receiving.Now,
            out _).Accepted);
    }

    [Theory]
    [InlineData("grant")]
    [InlineData("inflight")]
    [InlineData("calls")]
    [InlineData("payload")]
    [InlineData("protocol")]
    public void Endpoint_route_relay_applies_receiving_admission_before_state_change(string limit)
    {
        var source = CreateFixture(actionInputBytes: 4096, protocolMessageBytes: 4096);
        var issuer = CreateMirroredFixture(
            source,
            authenticateEndpointRouteAuthority: (authority, hash) =>
                authority.Proof == KeyedEndpointProof("route", hash),
            authenticateEndpointRouteRelay: (relay, hash) =>
                relay.Proof == KeyedEndpointProof("relay", hash),
            actionInputBytes: 4096,
            protocolMessageBytes: 4096);
        var receiving = CreateMirroredFixture(
            issuer,
            authenticateEndpointRouteAuthority: (authority, hash) =>
                authority.Proof == KeyedEndpointProof("route", hash),
            authenticateEndpointRouteRelay: (relay, hash) =>
                relay.Proof == KeyedEndpointProof("relay", hash),
            capabilities: limit == "grant" ? [SidecarCapabilityKind.Storage] : null,
            maxInFlight: limit == "inflight" ? 1 : null,
            maxCalls: limit == "calls" ? 1 : null,
            actionInputBytes: limit == "payload" ? 1 : null,
            protocolMessageBytes: limit == "payload" ? 4096 : limit == "protocol" ? 1 : null);

        if (limit is "inflight" or "calls")
        {
            var priorCall = receiving.Call with
            {
                Capability = SidecarCapabilityKind.Storage,
                CallId = Guid.NewGuid(),
                ReplayNonce = $"relay-admission-prior-{limit}",
                Sequence = 1,
            };
            var priorPayload = Payload("storage.request", "prior");
            Assert.True(receiving.Session.BeginCall(
                priorCall,
                SidecarCapabilityKind.Storage,
                priorPayload,
                priorPayload.ByteLength,
                receiving.Now).Accepted);
            if (limit == "calls")
                Assert.True(receiving.Session.CompleteCall(priorCall.CallId, 0).Accepted);
        }

        var inputs = CreateEndpointRelayInputs(source, receiving, $"limit-{limit}");
        var lastSequence = receiving.Session.LastSequence;
        var result = EndpointRouteRelayTestExtensions.IssueHostEndpointRouteRelay(
            source.Session,
            inputs.Request,
            inputs.SourceCall,
            inputs.ReceivingCall,
            receiving.Session,
            receiving.Now,
            authority => KeyedEndpointProof(
                "route",
                HostEndpointRouteAuthorityValidator.ComputeBindingHash(authority)),
            (_, hash) => KeyedEndpointProof("relay", hash),
            out _);

        Assert.False(result.Accepted);
        Assert.Equal(
            limit == "grant"
                ? SidecarCapabilityErrors.Unauthorized
                : limit is "payload" or "protocol"
                    ? SidecarCapabilityErrors.PayloadTooLarge
                    : SidecarCapabilityErrors.ConcurrencyLimit,
            result.Code);
        Assert.Equal(lastSequence, receiving.Session.LastSequence);
        Assert.Equal(0, receiving.Session.ActiveHostActionEntryCarrierCount);
    }

    [Fact]
    public void Endpoint_route_relay_import_catches_verifier_failure_without_state_change()
    {
        var source = CreateFixture(actionInputBytes: 4096, protocolMessageBytes: 4096);
        var receiving = CreateMirroredFixture(
            source,
            authenticateEndpointRouteAuthority: (authority, hash) =>
                authority.Proof == KeyedEndpointProof("route", hash),
            authenticateEndpointRouteRelay: (_, _) => throw new InvalidOperationException("test verifier failure"));
        var fixture = CreateEndpointRelay(source, receiving, "verifier-failure");
        var reservedSequence = receiving.Session.LastSequence;

        var result = receiving.Session.ImportHostEndpointRouteRelay(fixture.Relay, receiving.Now, out _);

        Assert.False(result.Accepted);
        Assert.Equal(SidecarCapabilityErrors.Unauthenticated, result.Code);
        Assert.Equal(reservedSequence, receiving.Session.LastSequence);
        Assert.Equal(0, receiving.Session.ActiveHostActionEntryCarrierCount);
    }

    [Fact]
    public void Endpoint_route_relay_issue_cleans_source_authority_when_relay_signer_fails()
    {
        var source = CreateFixture(actionInputBytes: 4096, protocolMessageBytes: 4096);
        var receiving = CreateMirroredFixture(source);
        var fixture = CreateEndpointRelayInputs(source, receiving, "signer-failure");

        var failed = source.Session.IssueHostEndpointRouteRelay(
            fixture.Request,
            fixture.SourceCall,
            fixture.ReceivingCall,
            receiving.Session,
            source.Now,
            authority => KeyedEndpointProof(
                "route",
                HostEndpointRouteAuthorityValidator.ComputeBindingHash(authority)),
            (_, _) => throw new InvalidOperationException("test signer failure"),
            out _);

        Assert.False(failed.Accepted);
        Assert.Equal(SidecarCapabilityErrors.Unauthenticated, failed.Code);

        var retry = source.Session.IssueHostEndpointRouteRelay(
            fixture.Request,
            fixture.SourceCall,
            fixture.ReceivingCall,
            receiving.Session,
            source.Now,
            authority => KeyedEndpointProof(
                "route",
                HostEndpointRouteAuthorityValidator.ComputeBindingHash(authority)),
            (_, hash) => KeyedEndpointProof("relay", hash),
            out var relay);

        Assert.True(retry.Accepted, retry.Message);
        Assert.NotNull(relay);
    }

    [Fact]
    public void Endpoint_route_authority_signer_disconnect_does_not_store_authority()
    {
        var fixture = CreateFixture(
            authenticateEndpointRouteAuthority: (authority, hash) =>
                authority.Proof == HostEndpointRouteAuthorityValidator.ComputeBindingHash(authority));
        var context = IssueContext(
            fixture,
            new RequestPrincipal("endpoint-user"),
            HostActionEntryIngress.Endpoint);
        var request = EndpointRouteRequest(fixture, context, HostEndpointTransport.Http);
        var call = ActionCall(fixture, 1, "route-signer-disconnect");

        var result = fixture.Session.IssueHostEndpointRouteAuthority(
            request,
            call,
            fixture.Now,
            authority =>
            {
                fixture.Session.Disconnect();
                return HostEndpointRouteAuthorityValidator.ComputeBindingHash(authority);
            },
            out var authority);

        Assert.False(result.Accepted);
        Assert.Equal(SidecarCapabilityErrors.Disconnected, result.Code);
        Assert.Null(authority);
        Assert.Equal(0, fixture.Session.IssuedHostActionEntryContextCount);
        Assert.Equal(0, fixture.Session.ActiveHostActionEntryCarrierCount);
    }

    [Fact]
    public void Endpoint_route_relay_signer_disconnect_returns_null_and_cleans_source_authority()
    {
        var source = CreateFixture(actionInputBytes: 4096, protocolMessageBytes: 4096);
        var receiving = CreateMirroredFixture(source);
        var inputs = CreateEndpointRelayInputs(source, receiving, "relay-signer-disconnect");

        var result = source.Session.IssueHostEndpointRouteRelay(
            inputs.Request,
            inputs.SourceCall,
            inputs.ReceivingCall,
            receiving.Session,
            source.Now,
            authority => HostEndpointRouteAuthorityValidator.ComputeBindingHash(authority),
            (candidate, hash) =>
            {
                source.Session.Disconnect();
                return KeyedEndpointProof("relay", hash);
            },
            out var relay);

        Assert.False(result.Accepted);
        Assert.Equal(SidecarCapabilityErrors.Disconnected, result.Code);
        Assert.Null(relay);
        Assert.Equal(0, source.Session.ActiveHostActionEntryCarrierCount);
    }

    [Fact]
    public void Endpoint_route_relay_verifier_disconnect_does_not_reserve_receiving_state()
    {
        var source = CreateFixture(actionInputBytes: 4096, protocolMessageBytes: 4096);
        Fixture? receiving = null;
        receiving = CreateMirroredFixture(
            source,
            authenticateEndpointRouteAuthority: (authority, hash) =>
                authority.Proof == KeyedEndpointProof("route", hash),
            authenticateEndpointRouteRelay: (_, _) =>
            {
                receiving!.Session.Disconnect();
                return true;
            });
        var fixture = CreateEndpointRelay(source, receiving, "relay-verifier-disconnect");
        var reservedSequence = receiving.Session.LastSequence;

        var result = receiving.Session.ImportHostEndpointRouteRelay(
            fixture.Relay,
            receiving.Now,
            out var hostContext);

        Assert.False(result.Accepted);
        Assert.Equal(SidecarCapabilityErrors.Disconnected, result.Code);
        Assert.Null(hostContext);
        Assert.Equal(reservedSequence, receiving.Session.LastSequence);
        Assert.Equal(0, receiving.Session.ActiveHostActionEntryCarrierCount);
    }

    [Fact]
    public void Endpoint_route_relay_verifier_rotation_does_not_reserve_old_generation()
    {
        var source = CreateFixture(actionInputBytes: 4096, protocolMessageBytes: 4096);
        Fixture? receiving = null;
        receiving = CreateMirroredFixture(
            source,
            authenticateEndpointRouteAuthority: (authority, hash) =>
                authority.Proof == KeyedEndpointProof("route", hash),
            authenticateEndpointRouteRelay: (_, _) =>
            {
                var rotated = CreateRotatedBinding(receiving!, "relay-verifier-rotation");
                receiving!.BindingHashes.Add(rotated.Authentication.BindingHash);
                return receiving.Session.RotateBinding(rotated, receiving.Now).Accepted;
            });
        var fixture = CreateEndpointRelay(source, receiving, "relay-verifier-rotation");
        var reservedSequence = receiving.Session.LastSequence;

        var result = receiving.Session.ImportHostEndpointRouteRelay(
            fixture.Relay,
            receiving.Now,
            out var hostContext);

        Assert.False(result.Accepted);
        Assert.Equal(SidecarCapabilityErrors.Unauthenticated, result.Code);
        Assert.Null(hostContext);
        Assert.Equal(0, receiving.Session.ActiveHostActionEntryCarrierCount);
        Assert.Equal(reservedSequence, receiving.Session.LastSequence);
    }

    [Fact]
    public void Endpoint_route_authority_issue_cleans_state_when_route_signer_fails()
    {
        var fixture = CreateFixture(authenticateEndpointRouteAuthority: (authority, hash) =>
            authority.Proof == hash);
        var context = IssueContext(
            fixture,
            new RequestPrincipal("endpoint-user"),
            HostActionEntryIngress.Endpoint);
        var request = EndpointRouteRequest(fixture, context, HostEndpointTransport.Http);
        var call = ActionCall(fixture, 1, "route-signer-failure");

        var failed = fixture.Session.IssueHostEndpointRouteAuthority(
            request,
            call,
            fixture.Now,
            _ => throw new InvalidOperationException("test signer failure"),
            out _);

        Assert.False(failed.Accepted);
        Assert.Equal(SidecarCapabilityErrors.Unauthenticated, failed.Code);
        Assert.Equal(1, fixture.Session.IssuedHostActionEntryContextCount);

        var retry = fixture.Session.IssueHostEndpointRouteAuthority(
            request,
            call,
            fixture.Now,
            HostEndpointRouteAuthorityValidator.ComputeBindingHash,
            out var authority);

        Assert.True(retry.Accepted, retry.Message);
        Assert.NotNull(authority);
    }

    [Fact]
    public void Endpoint_route_relay_rejects_disconnected_target_before_source_authority_storage()
    {
        var source = CreateFixture(actionInputBytes: 4096, protocolMessageBytes: 4096);
        var receiving = CreateMirroredFixture(
            source,
            authenticateEndpointRouteAuthority: (authority, hash) =>
                authority.Proof == KeyedEndpointProof("route", hash),
            authenticateEndpointRouteRelay: (relay, hash) =>
                relay.Proof == KeyedEndpointProof("relay", hash));
        var inputs = CreateEndpointRelayInputs(source, receiving, "disconnected-target");
        receiving.Session.Disconnect();

        var result = source.Session.IssueHostEndpointRouteRelay(
            inputs.Request,
            inputs.SourceCall,
            inputs.ReceivingCall,
            receiving.Session,
            source.Now,
            authority => KeyedEndpointProof(
                "route",
                HostEndpointRouteAuthorityValidator.ComputeBindingHash(authority)),
            (_, hash) => KeyedEndpointProof("relay", hash),
            out _);

        Assert.False(result.Accepted);
        Assert.Equal(SidecarCapabilityErrors.Disconnected, result.Code);

        var retry = source.Session.IssueHostEndpointRouteAuthority(
            inputs.Request,
            inputs.SourceCall,
            source.Now,
            authority => KeyedEndpointProof(
                "route",
                HostEndpointRouteAuthorityValidator.ComputeBindingHash(authority)),
            out var authority);

        Assert.True(retry.Accepted, retry.Message);
        Assert.NotNull(authority);
    }

    [Fact]
    public void Endpoint_route_relay_rejects_incompatible_receiving_lifetime_without_source_authority_storage()
    {
        var source = CreateFixture(actionInputBytes: 4096, protocolMessageBytes: 4096);
        var receiving = CreateMirroredFixture(
            source,
            authenticateEndpointRouteAuthority: (authority, hash) =>
                authority.Proof == KeyedEndpointProof("route", hash),
            authenticateEndpointRouteRelay: (relay, hash) =>
                relay.Proof == KeyedEndpointProof("relay", hash));
        var inputs = CreateEndpointRelayInputs(source, receiving, "incompatible-lifetime");
        inputs = inputs with
        {
            ReceivingCall = inputs.ReceivingCall with
            {
                Deadline = receiving.Binding.ExpiresAt.AddSeconds(1),
            },
        };

        var result = source.Session.IssueHostEndpointRouteRelay(
            inputs.Request,
            inputs.SourceCall,
            inputs.ReceivingCall,
            receiving.Session,
            source.Now,
            authority => KeyedEndpointProof(
                "route",
                HostEndpointRouteAuthorityValidator.ComputeBindingHash(authority)),
            (_, hash) => KeyedEndpointProof("relay", hash),
            out _);

        Assert.False(result.Accepted);
        Assert.Equal(SidecarCapabilityErrors.SpoofedIdentity, result.Code);

        var retry = source.Session.IssueHostEndpointRouteAuthority(
            inputs.Request,
            inputs.SourceCall,
            source.Now,
            authority => KeyedEndpointProof(
                "route",
                HostEndpointRouteAuthorityValidator.ComputeBindingHash(authority)),
            out var authority);

        Assert.True(retry.Accepted, retry.Message);
        Assert.NotNull(authority);
    }

    [Fact]
    public void Endpoint_route_relay_rejects_source_expiry_before_receiving_deadline_without_leak()
    {
        static bool AuthenticateAuthority(HostEndpointRouteAuthority authority, string hash) =>
            authority.Proof == KeyedEndpointProof("route", hash);
        static bool AuthenticateRelay(SidecarHostEndpointRouteRelay relay, string hash) =>
            relay.Proof == KeyedEndpointProof("relay", hash);

        var source = CreateFixture(actionInputBytes: 4096, protocolMessageBytes: 4096);
        var receiving = CreateMirroredFixture(
            source,
            authenticateEndpointRouteAuthority: AuthenticateAuthority,
            authenticateEndpointRouteRelay: AuthenticateRelay);
        var sourceExpiry = source.Now.AddSeconds(10);
        var context = IssueContext(
            source,
            new RequestPrincipal("endpoint-user"),
            HostActionEntryIngress.Endpoint,
            actionDeadline: source.Now.AddSeconds(5),
            contextExpiresAt: sourceExpiry);
        var request = EndpointRouteRequest(source, context, HostEndpointTransport.Http);
        var sourceCall = ActionCall(source, 1, "source-expiry-call") with
        {
            Deadline = source.Now.AddSeconds(5),
        };
        var receivingCall = ActionCall(receiving, 1, "receiving-longer-call") with
        {
            Deadline = source.Now.AddSeconds(30),
        };

        var result = source.Session.IssueHostEndpointRouteRelay(
            request,
            sourceCall,
            receivingCall,
            receiving.Session,
            source.Now,
            authority => KeyedEndpointProof(
                "route",
                HostEndpointRouteAuthorityValidator.ComputeBindingHash(authority)),
            (_, hash) => KeyedEndpointProof("relay", hash),
            out _);

        Assert.False(result.Accepted);
        Assert.Equal(SidecarCapabilityErrors.Expired, result.Code);
        Assert.Equal(1, source.Session.IssuedHostActionEntryContextCount);
        var retry = source.Session.IssueHostEndpointRouteAuthority(
            request,
            sourceCall,
            source.Now,
            authority => KeyedEndpointProof(
                "route",
                HostEndpointRouteAuthorityValidator.ComputeBindingHash(authority)),
            out var authority);
        Assert.True(retry.Accepted, retry.Message);
        Assert.NotNull(authority);
    }

    [Theory]
    [InlineData("domain")]
    [InlineData("future-issued")]
    [InlineData("early-issued")]
    [InlineData("extended-expiry")]
    [InlineData("shorter-source-lifetime")]
    [InlineData("capability-collision")]
    [InlineData("direct-admission-call-collision")]
    [InlineData("reserved-call-collision")]
    [InlineData("pending-authority-call-collision")]
    [InlineData("pending-authority-nonce-collision")]
    public void Endpoint_route_relay_re_signed_domain_mutations_reject_before_state_change(string mutation)
    {
        static bool AuthenticateAuthority(HostEndpointRouteAuthority authority, string hash) =>
            authority.Proof == KeyedEndpointProof("route", hash);
        static bool AuthenticateRelay(SidecarHostEndpointRouteRelay relay, string hash) =>
            relay.Proof == KeyedEndpointProof("relay", hash);

        var source = CreateFixture(actionInputBytes: 4096, protocolMessageBytes: 4096);
        var receiving = CreateMirroredFixture(
            source,
            authenticateEndpointRouteAuthority: AuthenticateAuthority,
            authenticateEndpointRouteRelay: AuthenticateRelay,
            maxInFlight: 4,
            maxCalls: 8);
        SidecarCapabilityCallIdentity? collisionCall = null;
        HostActionEntryRequestContext? collisionContext = null;

        if (mutation == "capability-collision")
        {
            collisionContext = IssueContext(
                receiving,
                new RequestPrincipal("collision-user"),
                HostActionEntryIngress.Tool);
        }
        else if (mutation == "direct-admission-call-collision")
        {
            var context = IssueContext(receiving, new RequestPrincipal("route-user"), HostActionEntryIngress.Endpoint);
            var request = EndpointRouteRequest(receiving, context, HostEndpointTransport.Http);
            collisionCall = ActionCall(receiving, 1, "existing-route-admission");
            Assert.True(receiving.Session.IssueHostEndpointRouteAuthority(
                request,
                collisionCall,
                receiving.Now,
                authority => KeyedEndpointProof(
                    "route",
                    HostEndpointRouteAuthorityValidator.ComputeBindingHash(authority)),
                out var authority).Accepted);
            Assert.True(receiving.Session.BeginHostEndpointRouteCarrier(
                request,
                authority!,
                new HostActionEntryCarrierIdentity(
                    HostActionEntryIngress.Endpoint,
                    context.InvocationId,
                    context.Contribution!.IngressBinding),
                receiving.Now,
                out _).Accepted);
        }
        else if (mutation == "reserved-call-collision")
        {
            var rootCall = ActionCall(receiving, 1, "existing-root-call");
            var rootContext = IssueContext(receiving, new RequestPrincipal("root-user"), HostActionEntryIngress.Tool);
            var rootAction = Payload(typeof(string).AssemblyQualifiedName!, "root");
            Assert.NotNull(ActivateContext(receiving, rootContext));
            Assert.True(receiving.Session.BeginCall(
                rootCall,
                SidecarCapabilityKind.Action,
                rootAction,
                rootAction.ByteLength,
                receiving.Now,
                rootContext).Accepted);
            var childDescriptor = NestedDescriptor("existing-child", typeof(string).AssemblyQualifiedName!);
            var childAction = Payload(childDescriptor.InputTypeIdentity, "child");
            collisionCall = ActionCall(receiving, 2, "existing-reserved-child");
            Assert.True(receiving.Session.IssueNestedHostActionEntryCarrier(
                rootCall,
                collisionCall,
                childDescriptor,
                childAction,
                NestedContribution(childDescriptor),
                receiving.Now,
                out _).Accepted);
        }
        else if (mutation is "pending-authority-call-collision" or "pending-authority-nonce-collision")
        {
            var pendingContext = IssueContext(
                receiving,
                new RequestPrincipal("pending-route-user"),
                HostActionEntryIngress.Endpoint);
            var pendingRequest = EndpointRouteRequest(
                receiving,
                pendingContext,
                HostEndpointTransport.Http);
            collisionCall = ActionCall(
                receiving,
                1,
                $"{mutation}-pending") with
            {
                CallId = Guid.NewGuid(),
                ReplayNonce = mutation == "pending-authority-nonce-collision"
                    ? "pending-authority-nonce"
                    : "pending-authority-call-nonce",
                Deadline = receiving.Now.AddSeconds(1),
            };
            Assert.True(receiving.Session.IssueHostEndpointRouteAuthority(
                pendingRequest,
                collisionCall,
                receiving.Now,
                authority => KeyedEndpointProof(
                    "route",
                    HostEndpointRouteAuthorityValidator.ComputeBindingHash(authority)),
                out _).Accepted);
        }

        var fixture = CreateEndpointRelay(source, receiving, $"domain-{mutation}");
        var original = fixture.Relay;
        var originalSequence = receiving.Session.LastSequence;
        var originalContexts = receiving.Session.IssuedHostActionEntryContextCount;
        var originalCarriers = receiving.Session.ActiveHostActionEntryCarrierCount;
        var originalTombstones = receiving.Session.CompletedHostActionEntryTombstoneCount;
        var mutated = original;

        switch (mutation)
        {
            case "domain":
                mutated = original with
                {
                    ReceivingParentCall = original.ReceivingParentCall with
                    {
                        Capability = SidecarCapabilityKind.Storage,
                    },
                };
                break;
            case "future-issued":
                mutated = original with { IssuedAt = receiving.Now.AddSeconds(1) };
                break;
            case "early-issued":
                mutated = original with { IssuedAt = original.Authority.IssuedAt.AddSeconds(-1) };
                break;
            case "extended-expiry":
                mutated = original with
                {
                    ReceivingContext = original.ReceivingContext with
                    {
                        ExpiresAt = original.Authority.ExpiresAt.AddSeconds(1),
                    },
                    ExpiresAt = original.Authority.ExpiresAt.AddSeconds(1),
                };
                break;
            case "shorter-source-lifetime":
                var authority = original.Authority with
                {
                    ExpiresAt = original.ExpiresAt.AddSeconds(-1),
                };
                var authorityHash = HostEndpointRouteAuthorityValidator.ComputeBindingHash(authority);
                authority = authority with
                {
                    CanonicalBindingHash = authorityHash,
                    Proof = KeyedEndpointProof("route", authorityHash),
                };
                mutated = original with { Authority = authority };
                break;
            case "capability-collision":
                mutated = original with
                {
                    ReceivingContext = original.ReceivingContext with
                    {
                        CapabilityId = collisionContext!.CapabilityId,
                    },
                };
                break;
            case "direct-admission-call-collision":
            case "reserved-call-collision":
            case "pending-authority-call-collision":
                mutated = original with
                {
                    ReceivingParentCall = original.ReceivingParentCall with
                    {
                        CallId = collisionCall!.CallId,
                    },
                };
                break;
            case "pending-authority-nonce-collision":
                mutated = original with
                {
                    ReceivingParentCall = original.ReceivingParentCall with
                    {
                        ReplayNonce = collisionCall!.ReplayNonce,
                    },
                };
                break;
        }

        mutated = ResignEndpointRelay(mutated);
        var rejected = receiving.Session.ImportHostEndpointRouteRelay(mutated, receiving.Now, out _);
        Assert.False(rejected.Accepted, rejected.Message);
        Assert.Equal(SidecarCapabilityErrors.SpoofedIdentity, rejected.Code);
        Assert.Equal(originalSequence, receiving.Session.LastSequence);
        Assert.Equal(originalContexts, receiving.Session.IssuedHostActionEntryContextCount);
        Assert.Equal(originalCarriers, receiving.Session.ActiveHostActionEntryCarrierCount);
        Assert.Equal(originalTombstones, receiving.Session.CompletedHostActionEntryTombstoneCount);

        if (mutation is "pending-authority-call-collision" or "pending-authority-nonce-collision")
            receiving.Session.SweepExpiredHostActionEntryCarriers(receiving.Now.AddSeconds(2));

        Assert.True(
            receiving.Session.ImportHostEndpointRouteRelay(original, receiving.Now, out _).Accepted);
    }

    [Theory]
    [InlineData("disconnect")]
    [InlineData("rotate")]
    [InlineData("consume")]
    public void Endpoint_route_relay_rejects_after_target_lifecycle_change_and_cleans_source(string lifecycle)
    {
        static bool AuthenticateAuthority(HostEndpointRouteAuthority authority, string hash) =>
            authority.Proof == KeyedEndpointProof("route", hash);
        static bool AuthenticateRelay(SidecarHostEndpointRouteRelay relay, string hash) =>
            relay.Proof == KeyedEndpointProof("relay", hash);

        var source = CreateFixture(actionInputBytes: 4096, protocolMessageBytes: 4096);
        var receiving = CreateMirroredFixture(
            source,
            authenticateEndpointRouteAuthority: AuthenticateAuthority,
            authenticateEndpointRouteRelay: AuthenticateRelay);
        var fixture = CreateEndpointRelay(source, receiving, $"lifecycle-{lifecycle}");

        if (lifecycle == "disconnect")
        {
            receiving.Session.Disconnect();
        }
        else if (lifecycle == "rotate")
        {
            var rotated = CreateRotatedBinding(receiving, "endpoint-relay-target-rotation");
            receiving.BindingHashes.Add(rotated.Authentication.BindingHash);
            Assert.False(receiving.Session.RotateBinding(rotated, receiving.Now).Accepted);
            Assert.True(receiving.Session.ReleaseHostEndpointRouteReservation(
                fixture.Relay.ReceivingReservation!,
                receiving.Now).Accepted);
            Assert.True(receiving.Session.RotateBinding(rotated, receiving.Now).Accepted);
        }
        else
        {
            Assert.True(receiving.Session.ReleaseHostEndpointRouteReservation(
                fixture.Relay.ReceivingReservation!,
                receiving.Now).Accepted);
        }

        var import = receiving.Session.ImportHostEndpointRouteRelay(
            SidecarCapabilityTransportCodec.Deserialize<SidecarHostEndpointRouteRelay>(
                SidecarCapabilityTransportCodec.Serialize(fixture.Relay)),
            receiving.Now,
            out _);
        Assert.False(import.Accepted, import.Message);
        Assert.Equal(
            lifecycle == "disconnect"
                ? SidecarCapabilityErrors.Disconnected
                : lifecycle == "rotate"
                    ? SidecarCapabilityErrors.SpoofedIdentity
                    : SidecarCapabilityErrors.Replay,
            import.Code);

        Assert.True(source.Session.CompleteHostEndpointRouteRelay(fixture.Relay, source.Now).Accepted);
        Assert.Equal(
            SidecarCapabilityErrors.Replay,
            source.Session.CompleteHostEndpointRouteRelay(fixture.Relay, source.Now).Code);
        var rotatedSource = CreateRotatedBinding(source, $"endpoint-relay-source-{lifecycle}");
        source.BindingHashes.Add(rotatedSource.Authentication.BindingHash);
        Assert.True(source.Session.RotateBinding(rotatedSource, source.Now).Accepted);
    }

    private static EndpointRelayInputs CreateEndpointRelayInputs(
        Fixture source,
        Fixture receiving,
        string suffix,
        RequestPrincipal? caller = null,
        ExtensionFeatureSet? features = null)
    {
        var context = IssueContext(
            source,
            caller ?? new RequestPrincipal("endpoint-user"),
            HostActionEntryIngress.Endpoint,
            features: features);
        var request = EndpointRouteRequest(source, context, HostEndpointTransport.Http);
        var sourceCall = ActionCall(source, 1, $"endpoint-relay-source-{suffix}");
        var receivingCall = ActionCall(
            receiving,
            receiving.Session.LastSequence + 1,
            $"endpoint-relay-receiving-{suffix}");
        return new EndpointRelayInputs(source, receiving, request, sourceCall, receivingCall);
    }

    private static EndpointRelayFixture CreateEndpointRelay(
        Fixture source,
        Fixture receiving,
        string suffix)
    {
        var inputs = CreateEndpointRelayInputs(source, receiving, suffix);
        var issue = source.Session.IssueHostEndpointRouteRelay(
            inputs.Request,
            inputs.SourceCall,
            inputs.ReceivingCall,
            receiving.Session,
            source.Now,
            authority => KeyedEndpointProof(
                "route",
                HostEndpointRouteAuthorityValidator.ComputeBindingHash(authority)),
            (_, hash) => KeyedEndpointProof("relay", hash),
            out var relay);
        Assert.True(issue.Accepted, issue.Message);
        Assert.NotNull(relay);
        return new EndpointRelayFixture(inputs, relay!);
    }

    [Theory]
    [InlineData("handler")]
    [InlineData("path")]
    [InlineData("method")]
    [InlineData("transport")]
    [InlineData("route-values")]
    [InlineData("headers")]
    [InlineData("query")]
    [InlineData("body")]
    [InlineData("content-hash")]
    [InlineData("content-length")]
    [InlineData("request-deadline")]
    [InlineData("context")]
    [InlineData("session")]
    [InlineData("request")]
    [InlineData("cancellation")]
    [InlineData("call")]
    [InlineData("replay-nonce")]
    [InlineData("sequence")]
    [InlineData("deadline")]
    [InlineData("expiry")]
    [InlineData("proof")]
    [InlineData("invocation-id")]
    [InlineData("invocation-handler")]
    [InlineData("invocation-context")]
    [InlineData("invocation-hash")]
    [InlineData("invocation-length")]
    public void Endpoint_route_mutations_reject_before_reservation_and_preserve_original(
        string mutation)
    {
        static bool Authenticate(HostEndpointRouteAuthority authority, string hash) =>
            authority.Proof == hash;

        var fixture = CreateFixture(authenticateEndpointRouteAuthority: Authenticate);
        var context = IssueContext(
            fixture,
            new RequestPrincipal("endpoint-user"),
            HostActionEntryIngress.Endpoint);
        var request = EndpointRouteRequest(fixture, context, HostEndpointTransport.Http);
        var call = ActionCall(fixture, 1, "endpoint-route-mutation");
        var issue = fixture.Session.IssueHostEndpointRouteAuthority(
            request,
            call,
            fixture.Now,
            authority => HostEndpointRouteAuthorityValidator.ComputeBindingHash(authority),
            out var authority);
        Assert.True(issue.Accepted, issue.Message);
        var original = authority!;
        var mutatedRequest = request;
        var mutatedAuthority = original;

        switch (mutation)
        {
            case "handler":
                mutatedRequest = request with
                {
                    Route = request.Route with { HandlerIdentity = "/other" },
                };
                break;
            case "path":
                mutatedRequest = request with
                {
                    Route = request.Route with { Path = "/other" },
                };
                break;
            case "method":
                mutatedRequest = request with
                {
                    Route = request.Route with { Method = "PATCH" },
                };
                break;
            case "transport":
                mutatedRequest = request with
                {
                    Route = request.Route with { Transport = HostEndpointTransport.WebSocket },
                };
                break;
            case "route-values":
                mutatedRequest = request with
                {
                    RouteValues = new Dictionary<string, string[]>(request.RouteValues)
                    {
                        ["id"] = ["changed"],
                    },
                };
                break;
            case "headers":
                mutatedRequest = request with
                {
                    Headers = new Dictionary<string, string[]>(request.Headers)
                    {
                        ["x-request"] = ["changed"],
                    },
                };
                break;
            case "query":
                mutatedRequest = request with
                {
                    Query = new Dictionary<string, string[]>(request.Query)
                    {
                        ["tag"] = ["changed", "value"],
                    },
                };
                break;
            case "body":
                mutatedRequest = request with { Body = [0, 255, 2] };
                break;
            case "content-hash":
                mutatedAuthority = ResignEndpointAuthority(
                    original with { RequestContentHash = new string('0', 64) });
                break;
            case "content-length":
                mutatedAuthority = ResignEndpointAuthority(
                    original with { RequestContentByteLength = original.RequestContentByteLength + 1 });
                break;
            case "request-deadline":
                mutatedRequest = request with
                {
                    Invocation = request.Invocation with
                    {
                        HostActionContext = request.Invocation.HostActionContext with
                        {
                            Deadline = request.Invocation.HostActionContext.Deadline.AddSeconds(-1),
                        },
                    },
                };
                break;
            case "context":
                mutatedAuthority = ResignEndpointAuthority(
                    original with
                    {
                        HostActionContext = original.HostActionContext with { TraceId = Guid.NewGuid() },
                    });
                break;
            case "session":
                mutatedAuthority = ResignEndpointAuthority(
                    original with { Call = original.Call with { SessionId = Guid.NewGuid() } });
                break;
            case "request":
                mutatedAuthority = ResignEndpointAuthority(
                    original with { Call = original.Call with { RequestId = Guid.NewGuid() } });
                break;
            case "cancellation":
                mutatedAuthority = ResignEndpointAuthority(
                    original with { Call = original.Call with { CancellationId = Guid.NewGuid() } });
                break;
            case "call":
                mutatedAuthority = ResignEndpointAuthority(
                    original with { Call = original.Call with { CallId = Guid.NewGuid() } });
                break;
            case "replay-nonce":
                mutatedAuthority = ResignEndpointAuthority(
                    original with { Call = original.Call with { ReplayNonce = "changed-replay" } });
                break;
            case "sequence":
                mutatedAuthority = ResignEndpointAuthority(
                    original with { Call = original.Call with { Sequence = original.Call.Sequence + 1 } });
                break;
            case "deadline":
                mutatedAuthority = ResignEndpointAuthority(
                    original with
                    {
                        Call = original.Call with { Deadline = fixture.Now.AddSeconds(10) },
                    });
                break;
            case "expiry":
                mutatedAuthority = ResignEndpointAuthority(
                    original with { ExpiresAt = original.ExpiresAt.AddSeconds(1) });
                break;
            case "proof":
                mutatedAuthority = original with { Proof = "forged" };
                break;
            case "invocation-id":
                mutatedRequest = request with
                {
                    Invocation = request.Invocation with { InvocationId = Guid.NewGuid() },
                };
                break;
            case "invocation-handler":
                mutatedRequest = request with
                {
                    Invocation = request.Invocation with { Endpoint = "/other" },
                };
                break;
            case "invocation-context":
                mutatedRequest = request with
                {
                    Invocation = request.Invocation with
                    {
                        HostActionContext = request.Invocation.HostActionContext with
                        {
                            TraceId = Guid.NewGuid(),
                        },
                    },
                };
                break;
            case "invocation-hash":
                mutatedAuthority = ResignEndpointAuthority(
                    original with { InvocationContentHash = new string('0', 64) });
                break;
            case "invocation-length":
                mutatedAuthority = ResignEndpointAuthority(
                    original with { InvocationByteLength = original.InvocationByteLength + 1 });
                break;
        }

        var carrier = new HostActionEntryCarrierIdentity(
            HostActionEntryIngress.Endpoint,
            context.InvocationId,
            context.Contribution!.IngressBinding);
        var bypass = fixture.Session.BeginHostActionEntryCarrier(
            context,
            carrier,
            fixture.Now,
            out _);
        Assert.False(bypass.Accepted);

        var rejected = fixture.Session.BeginHostEndpointRouteCarrier(
            mutatedRequest,
            mutatedAuthority,
            carrier,
            fixture.Now,
            out _);
        Assert.False(rejected.Accepted, rejected.Message);
        Assert.False(
            fixture.Session.TryGetActiveHostActionEntryCarrier(
                context.CapabilityId,
                out _));

        var originalResult = fixture.Session.BeginHostEndpointRouteCarrier(
            request,
            original,
            carrier,
            fixture.Now,
            out _);
        Assert.True(originalResult.Accepted, originalResult.Message);
    }

    [Fact]
    public void Endpoint_route_admission_binds_one_call_and_serialized_invocation()
    {
        static bool Authenticate(HostEndpointRouteAuthority authority, string hash) =>
            authority.Proof == hash;

        var fixture = CreateFixture(
            authenticateEndpointRouteAuthority: Authenticate,
            actionInputBytes: 4096,
            protocolMessageBytes: 4096);
        var invocationType = typeof(HostEndpointInvocation).AssemblyQualifiedName!;
        var context = IssueContext(
            fixture,
            new RequestPrincipal("endpoint-user"),
            HostActionEntryIngress.Endpoint,
            lineage: new HostActionEntryLineage(
                new SharpClawActionKey("endpoint.action"),
                1,
                "endpoint-descriptor",
                invocationType,
                1,
                "endpoint-input-schema",
                null,
                null));
        var request = EndpointRouteRequest(fixture, context, HostEndpointTransport.Http);
        var call = ActionCall(fixture, 1, "endpoint-bound-call");
        var authorityResult = fixture.Session.IssueHostEndpointRouteAuthority(
            request,
            call,
            fixture.Now,
            HostEndpointRouteAuthorityValidator.ComputeBindingHash,
            out var authority);
        Assert.True(authorityResult.Accepted, authorityResult.Message);

        var carrier = new HostActionEntryCarrierIdentity(
            HostActionEntryIngress.Endpoint,
            context.InvocationId,
            context.Contribution!.IngressBinding);
        Assert.True(
            fixture.Session.BeginHostEndpointRouteCarrier(
                request,
                authority!,
                carrier,
                fixture.Now,
                out var carrierAuthority).Accepted);

        var invocationPayload = EndpointInvocationPayload(invocationType, request.Invocation);
        var otherCall = call with
        {
            CallId = Guid.NewGuid(),
            ReplayNonce = "endpoint-other-call",
            Sequence = 2,
        };
        var otherResult = fixture.Session.BeginCall(
            otherCall,
            SidecarCapabilityKind.Action,
            invocationPayload,
            invocationPayload.ByteLength,
            fixture.Now,
            context);
        Assert.False(otherResult.Accepted);
        Assert.Equal(SidecarCapabilityErrors.SpoofedIdentity, otherResult.Code);

        var changedPayload = EndpointInvocationPayload(
            invocationType,
            request.Invocation with { Endpoint = "/changed" });
        var changedResult = fixture.Session.BeginCall(
            call,
            SidecarCapabilityKind.Action,
            changedPayload,
            changedPayload.ByteLength,
            fixture.Now,
            context);
        Assert.False(changedResult.Accepted);
        Assert.Equal(SidecarCapabilityErrors.SpoofedIdentity, changedResult.Code);

        Assert.Equal(authority!.InvocationContentHash, invocationPayload.ContentHash);
        Assert.Equal(authority.InvocationByteLength, invocationPayload.ByteLength);
        var canonicalInvocationBytes =
            SidecarCapabilityTransportCodec.Serialize(invocationPayload.Value);
        Assert.Equal(invocationPayload.ByteLength, canonicalInvocationBytes.Length);
        Assert.Equal(
            invocationPayload.ContentHash,
            SidecarCapabilityTransportCodec.ComputeSha256(canonicalInvocationBytes));
        var invocationPayloadValidation =
            SidecarCapabilityTransportValidation.ValidateSerializedPayload(
                invocationPayload,
                required: true,
                fixture.Binding.PayloadLimits.ActionInputBytes);
        Assert.True(invocationPayloadValidation.Accepted, invocationPayloadValidation.Message);
        var originalResult = fixture.Session.BeginCall(
            call,
            SidecarCapabilityKind.Action,
            invocationPayload,
            invocationPayload.ByteLength,
            fixture.Now,
            context);
        Assert.True(originalResult.Accepted, originalResult.Message);
        Assert.True(
            fixture.Session.RecordTerminal(
                call.CallId,
                Guid.NewGuid(),
                new SidecarTerminalReceipt(
                    "endpoint-receipt",
                    new SharpClawActionKey("endpoint.action"),
                    1,
                    call.CallId,
                    1,
                    invocationPayload.ContentHash,
                    "endpoint-scope")).Accepted);
        Assert.True(fixture.Session.CompleteCall(call.CallId, 1).Accepted);
        Assert.True(
            fixture.Session.CompleteHostActionEntryCarrier(
                carrierAuthority!,
                HostActionEntryCarrierCompletionKind.Succeeded,
                fixture.Now).Accepted);
    }

    [Fact]
    public void Endpoint_route_authority_rejects_duplicate_admission_call_without_consuming_context()
    {
        static bool Authenticate(HostEndpointRouteAuthority authority, string hash) =>
            authority.Proof == hash;

        var fixture = CreateFixture(
            authenticateEndpointRouteAuthority: Authenticate,
            actionInputBytes: 4096,
            protocolMessageBytes: 4096);
        var invocationType = typeof(HostEndpointInvocation).AssemblyQualifiedName!;
        var lineage = new HostActionEntryLineage(
            new SharpClawActionKey("endpoint.action"),
            1,
            "endpoint-descriptor",
            invocationType,
            1,
            "endpoint-input-schema",
            null,
            null);
        var firstContext = IssueContext(
            fixture,
            new RequestPrincipal("endpoint-one"),
            HostActionEntryIngress.Endpoint,
            lineage: lineage,
            bindPayload: true);
        var secondContext = IssueContext(
            fixture,
            new RequestPrincipal("endpoint-two"),
            HostActionEntryIngress.Endpoint,
            lineage: lineage,
            bindPayload: true);
        var firstRequest = EndpointRouteRequest(fixture, firstContext, HostEndpointTransport.Http);
        var secondRequest = EndpointRouteRequest(fixture, secondContext, HostEndpointTransport.Http);
        var firstCall = ActionCall(fixture, 1, "duplicate-admission-first");
        var firstIssue = fixture.Session.IssueHostEndpointRouteAuthority(
            firstRequest,
            firstCall,
            fixture.Now,
            HostEndpointRouteAuthorityValidator.ComputeBindingHash,
            out var firstAuthority);
        Assert.True(firstIssue.Accepted, firstIssue.Message);

        var firstCarrier = new HostActionEntryCarrierIdentity(
            HostActionEntryIngress.Endpoint,
            firstContext.InvocationId,
            firstContext.Contribution!.IngressBinding);
        var firstAdmission = fixture.Session.BeginHostEndpointRouteCarrier(
            firstRequest,
            firstAuthority!,
            firstCarrier,
            fixture.Now,
            out var firstCarrierAuthority);
        Assert.True(firstAdmission.Accepted, firstAdmission.Message);
        Assert.Equal(1, fixture.Session.ActiveHostActionEntryCarrierCount);

        var duplicateCall = firstCall with
        {
            ReplayNonce = "duplicate-admission-second",
            Sequence = 2,
        };
        var duplicateIssue = fixture.Session.IssueHostEndpointRouteAuthority(
            secondRequest,
            duplicateCall,
            fixture.Now,
            HostEndpointRouteAuthorityValidator.ComputeBindingHash,
            out _);
        Assert.False(duplicateIssue.Accepted);
        Assert.Equal(SidecarCapabilityErrors.Duplicate, duplicateIssue.Code);
        Assert.Equal(1, fixture.Session.ActiveHostActionEntryCarrierCount);

        var firstPayload = EndpointInvocationPayload(invocationType, firstRequest.Invocation);
        Assert.True(
            fixture.Session.BeginCall(
                firstCall,
                SidecarCapabilityKind.Action,
                firstPayload,
                firstPayload.ByteLength,
                fixture.Now,
                firstContext).Accepted);
        Assert.True(
            fixture.Session.RecordTerminal(
                firstCall.CallId,
                Guid.NewGuid(),
                new SidecarTerminalReceipt(
                    "duplicate-admission-first-receipt",
                    new SharpClawActionKey("endpoint.action"),
                    1,
                    firstCall.CallId,
                    1,
                    firstPayload.ContentHash,
                    "endpoint-scope")).Accepted);
        Assert.True(fixture.Session.CompleteCall(firstCall.CallId, 1).Accepted);
        Assert.True(
            fixture.Session.CompleteHostActionEntryCarrier(
                firstCarrierAuthority!,
                HostActionEntryCarrierCompletionKind.Succeeded,
                fixture.Now).Accepted);

        var secondCall = duplicateCall with
        {
            CallId = Guid.NewGuid(),
            ReplayNonce = "duplicate-admission-fresh",
        };
        var secondIssue = fixture.Session.IssueHostEndpointRouteAuthority(
            secondRequest,
            secondCall,
            fixture.Now,
            HostEndpointRouteAuthorityValidator.ComputeBindingHash,
            out var secondAuthority);
        Assert.True(secondIssue.Accepted, secondIssue.Message);

        var secondCarrier = new HostActionEntryCarrierIdentity(
            HostActionEntryIngress.Endpoint,
            secondContext.InvocationId,
            secondContext.Contribution!.IngressBinding);
        var secondAdmission = fixture.Session.BeginHostEndpointRouteCarrier(
            secondRequest,
            secondAuthority!,
            secondCarrier,
            fixture.Now,
            out var secondCarrierAuthority);
        Assert.True(secondAdmission.Accepted, secondAdmission.Message);

        var secondPayload = EndpointInvocationPayload(invocationType, secondRequest.Invocation);
        Assert.True(
            fixture.Session.BeginCall(
                secondCall,
                SidecarCapabilityKind.Action,
                secondPayload,
                secondPayload.ByteLength,
                fixture.Now,
                secondContext).Accepted);
        Assert.True(
            fixture.Session.RecordTerminal(
                secondCall.CallId,
                Guid.NewGuid(),
                new SidecarTerminalReceipt(
                    "duplicate-admission-second-receipt",
                    new SharpClawActionKey("endpoint.action"),
                    1,
                    secondCall.CallId,
                    1,
                    secondPayload.ContentHash,
                    "endpoint-scope")).Accepted);
        Assert.True(fixture.Session.CompleteCall(secondCall.CallId, 1).Accepted);
        Assert.True(
            fixture.Session.CompleteHostActionEntryCarrier(
                secondCarrierAuthority!,
                HostActionEntryCarrierCompletionKind.Succeeded,
                fixture.Now).Accepted);

        var rotated = CreateRotatedBinding(fixture, "duplicate-admission-rotation");
        fixture.BindingHashes.Add(rotated.Authentication.BindingHash);
        var rotation = fixture.Session.RotateBinding(rotated, fixture.Now);
        Assert.True(rotation.Accepted, rotation.Message);
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
        var activeContext = contexts[1];
        ActivateContext(fixture, activeContext);
        Assert.True(fixture.Session.BeginCall(
            firstCall,
            SidecarCapabilityKind.Action,
            firstPayload,
            firstPayload.ByteLength,
            fixture.Now,
            activeContext).Accepted);

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
            contexts[0]);
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
            contexts[0]);
        Assert.Equal(SidecarCapabilityErrors.SpoofedIdentity, wrongGraph.Code);

        var replay = fixture.Session.BeginCall(
            firstCall with { ReplayNonce = "entry-context-replay", Sequence = 2 },
            SidecarCapabilityKind.Action,
            firstPayload,
            firstPayload.ByteLength,
            fixture.Now,
            activeContext);
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
        var mismatch = fixture.Session.CompleteCall(terminalCall.CallId, 1);
        Assert.Equal(SidecarCapabilityErrors.TerminalAlreadyCalled, mismatch.Code);
        Assert.Equal(
            "The action completion count does not match the recorded terminal authority.",
            mismatch.Message);
        Assert.Equal(
            SidecarCapabilityErrors.InvalidBinding,
            fixture.Session.RecordTerminal(
                terminalCall.CallId,
                Guid.NewGuid(),
                new SidecarTerminalReceipt(
                    "terminal-receipt",
                    new SharpClawActionKey("sample.action"),
                    1,
                    terminalCall.CallId,
                    1,
                    "terminal-scope",
                    "terminal-hash")).Code);
        Assert.Equal(
            SidecarCapabilityErrors.Duplicate,
            fixture.Session.CompleteCall(terminalCall.CallId, 0).Code);
    }

    [Fact]
    public void Non_retryable_completion_rejection_releases_call_but_leaves_outer_carrier_completable()
    {
        var fixture = CreateFixture();
        var context = IssueContext(
            fixture,
            new RequestPrincipal("failed-entry"),
            HostActionEntryIngress.Cli);
        var carrier = ActivateContext(fixture, context);
        var call = ActionCall(fixture, 1, "failed-entry-call");
        var action = Payload(typeof(string).AssemblyQualifiedName!, "failed-entry");

        Assert.True(fixture.Session.BeginCall(
            call,
            SidecarCapabilityKind.Action,
            action,
            action.ByteLength,
            fixture.Now,
            context).Accepted);

        var rejection = fixture.Session.CompleteCall(call.CallId, 1);

        Assert.Equal(SidecarCapabilityErrors.TerminalAlreadyCalled, rejection.Code);
        Assert.Equal(
            "The action completion count does not match the recorded terminal authority.",
            rejection.Message);
        var carrierCompletion = fixture.Session.CompleteHostActionEntryCarrier(
            carrier,
            HostActionEntryCarrierCompletionKind.Failed,
            fixture.Now);
        Assert.True(carrierCompletion.Accepted, $"{carrierCompletion.Code}: {carrierCompletion.Message}");
        Assert.Equal(
            SidecarCapabilityErrors.Duplicate,
            fixture.Session.CompleteCall(call.CallId, 0).Code);
    }

    [Fact]
    public void Unknown_and_completed_call_completion_does_not_remove_another_active_call()
    {
        var fixture = CreateFixture(maxInFlight: 2);
        var first = fixture.Call with
        {
            CallId = Guid.NewGuid(),
            ReplayNonce = "completion-first",
            Sequence = 1,
        };
        var second = first with
        {
            CallId = Guid.NewGuid(),
            ReplayNonce = "completion-second",
            Sequence = 2,
        };
        var payload = Payload("sample.input", new { value = 1 });

        Assert.True(fixture.Session.BeginCall(
            first,
            SidecarCapabilityKind.Storage,
            payload,
            payload.ByteLength,
            fixture.Now).Accepted);
        Assert.True(fixture.Session.BeginCall(
            second,
            SidecarCapabilityKind.Storage,
            payload,
            payload.ByteLength,
            fixture.Now).Accepted);
        Assert.Equal(
            SidecarCapabilityErrors.Duplicate,
            fixture.Session.CompleteCall(Guid.NewGuid(), 0).Code);
        Assert.True(fixture.Session.CompleteCall(first.CallId, 0).Accepted);
        Assert.Equal(
            SidecarCapabilityErrors.Duplicate,
            fixture.Session.CompleteCall(first.CallId, 0).Code);
        Assert.True(fixture.Session.CompleteCall(second.CallId, 0).Accepted);
    }

    [Fact]
    public void Invalid_action_count_releases_call_and_keeps_outer_carrier_completable()
    {
        var fixture = CreateFixture();
        var context = IssueContext(
            fixture,
            new RequestPrincipal("invalid-count-entry"),
            HostActionEntryIngress.Cli);
        var carrier = ActivateContext(fixture, context);
        var call = ActionCall(fixture, 1, "invalid-count-call");
        var action = Payload(typeof(string).AssemblyQualifiedName!, "invalid-count");

        Assert.True(fixture.Session.BeginCall(
            call,
            SidecarCapabilityKind.Action,
            action,
            action.ByteLength,
            fixture.Now,
            context).Accepted);

        var rejection = fixture.Session.CompleteCall(call.CallId, 2);

        Assert.Equal(SidecarCapabilityErrors.InvalidBinding, rejection.Code);
        Assert.Equal("The terminal call count must be zero or one.", rejection.Message);
        var carrierCompletion = fixture.Session.CompleteHostActionEntryCarrier(
            carrier,
            HostActionEntryCarrierCompletionKind.Failed,
            fixture.Now);
        Assert.True(carrierCompletion.Accepted, $"{carrierCompletion.Code}: {carrierCompletion.Message}");
        Assert.Equal(SidecarCapabilityErrors.Duplicate, fixture.Session.CompleteCall(call.CallId, 2).Code);

        var laterCall = ActionCall(fixture, 2, "invalid-count-later");
        Assert.True(fixture.Session.BeginCall(
            laterCall,
            SidecarCapabilityKind.Action,
            action,
            action.ByteLength,
            fixture.Now).Accepted);
        Assert.True(fixture.Session.CompleteCall(laterCall.CallId, 0).Accepted);
    }

    [Fact]
    public async Task Concurrent_invalid_completion_attempts_clean_once_and_preserve_other_call()
    {
        var fixture = CreateFixture(maxInFlight: 2);
        var first = ActionCall(fixture, 1, "concurrent-invalid-first");
        var second = ActionCall(fixture, 2, "concurrent-invalid-second");
        var action = Payload("concurrent.invalid.input", new { value = 1 });
        Assert.True(fixture.Session.BeginCall(
            first,
            SidecarCapabilityKind.Action,
            action,
            action.ByteLength,
            fixture.Now).Accepted);
        Assert.True(fixture.Session.BeginCall(
            second,
            SidecarCapabilityKind.Action,
            action,
            action.ByteLength,
            fixture.Now).Accepted);

        var results = await Task.WhenAll(
            Task.Run(() => fixture.Session.CompleteCall(first.CallId, 2)),
            Task.Run(() => fixture.Session.CompleteCall(first.CallId, 2)));

        Assert.Single(results, result => result.Code == SidecarCapabilityErrors.InvalidBinding);
        Assert.Single(results, result => result.Code == SidecarCapabilityErrors.Duplicate);
        Assert.True(fixture.Session.CompleteCall(second.CallId, 0).Accepted);
        Assert.Equal(SidecarCapabilityErrors.Duplicate, fixture.Session.CompleteCall(first.CallId, 0).Code);
    }

    [Fact]
    public void Invalid_action_count_with_active_child_is_retryable_and_preserves_state()
    {
        var fixture = CreateFixture(maxInFlight: 2, maxCalls: 4);
        var rootContext = IssueContext(
            fixture,
            new RequestPrincipal("count-parent"),
            HostActionEntryIngress.Cli,
            lineage: new HostActionEntryLineage(
                new SharpClawActionKey("count.parent"),
                1,
                "count-parent-descriptor",
                typeof(string).AssemblyQualifiedName!,
                1,
                "count-parent-schema",
                null,
                null));
        var rootAuthority = ActivateContext(fixture, rootContext);
        var parentCall = ActionCall(fixture, 1, "count-parent-call");
        var parentAction = Payload(typeof(string).AssemblyQualifiedName!, "parent");
        Assert.True(fixture.Session.BeginCall(
            parentCall,
            SidecarCapabilityKind.Action,
            parentAction,
            parentAction.ByteLength,
            fixture.Now,
            rootContext).Accepted);

        var childDescriptor = NestedDescriptor("count.child", typeof(string).AssemblyQualifiedName!);
        var childAction = Payload(childDescriptor.InputTypeIdentity, "child");
        var childCall = ActionCall(fixture, 2, "count-child-call");
        var issued = fixture.Session.IssueNestedHostActionEntryCarrier(
            parentCall,
            childCall,
            childDescriptor,
            childAction,
            NestedContribution(childDescriptor),
            fixture.Now,
            out var carrier);
        Assert.True(issued.Accepted, issued.Message);
        Assert.NotNull(carrier);
        var childRequest = SidecarActionCapabilityRequest.HostEntryNested(
            childCall,
            childDescriptor,
            childAction,
            new SidecarCancellationIdentity(
                childCall.CancellationId,
                "count-child-cancellation",
                childCall.Deadline),
            childCall.Deadline,
            carrier!,
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
            out _).Accepted);

        var retryable = fixture.Session.CompleteCall(parentCall.CallId, 2);

        Assert.Equal(SidecarCapabilityErrors.InvalidBinding, retryable.Code);
        Assert.Equal("A parent action cannot complete while a nested action is active.", retryable.Message);
        Assert.True(fixture.Session.CompleteCall(childCall.CallId, 0).Accepted);

        var final = fixture.Session.CompleteCall(parentCall.CallId, 2);

        Assert.Equal(SidecarCapabilityErrors.InvalidBinding, final.Code);
        Assert.Equal("The terminal call count must be zero or one.", final.Message);
        var rootCarrierCompletion = fixture.Session.CompleteHostActionEntryCarrier(
            rootAuthority,
            HostActionEntryCarrierCompletionKind.Failed,
            fixture.Now);
        Assert.True(rootCarrierCompletion.Accepted, $"{rootCarrierCompletion.Code}: {rootCarrierCompletion.Message}");
        Assert.Equal(SidecarCapabilityErrors.Duplicate, fixture.Session.CompleteCall(parentCall.CallId, 0).Code);
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
            HostActionEntryIngress.Cli,
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
            HostActionEntryIngress.Cli,
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
            HostActionEntryIngress.Cli,
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
        var fixture = CreateFixture(
            maxCalls: 8,
            authenticateEndpointRouteAuthority: static (authority, hash) => authority.Proof == hash,
            actionInputBytes: 4096,
            protocolMessageBytes: 4096);
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
            var inputType = ingress == HostActionEntryIngress.Endpoint
                ? typeof(HostEndpointInvocation).AssemblyQualifiedName!
                : typeof(string).AssemblyQualifiedName!;
            var descriptor = new SidecarActionDescriptorIdentity(
                key,
                1,
                "module",
                inputType,
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
            var endpointRequest = ingress == HostActionEntryIngress.Endpoint
                ? EndpointRouteRequest(fixture, context, HostEndpointTransport.Http)
                : null;
            if (endpointRequest is not null)
                action = EndpointInvocationPayload(descriptor.InputTypeIdentity, endpointRequest.Invocation);
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
            var authority = ingress == HostActionEntryIngress.Endpoint
                ? ActivateContext(fixture, context, call)
                : ActivateContext(fixture, context);
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
    public async Task HostEntryStorageContinuationAcceptsMirroredUnboundParentWithActiveReceiptOnce()
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
        var continuationNow = fixture.Now.AddMilliseconds(1);
        var issue = fixture.Session.IssueHostEntryStorageContinuation(
            fixture.Session,
            parentCall,
            parentCall,
            continuationRequest,
            continuationNow,
            (_, hash) => hash,
            out var authority);
        Assert.True(issue.Accepted, issue.Message);
        Assert.NotNull(authority);

        var wireAuthority = SidecarCapabilityTransportCodec.Deserialize<SidecarHostEntryStorageContinuationAuthority>(
            SidecarCapabilityTransportCodec.Serialize(authority));
        Assert.True(wireAuthority.ParentContext.Contribution!.Lineage.IsPayloadBound);
        wireAuthority = wireAuthority with
        {
            CarrierAuthority = wireAuthority.CarrierAuthority with
            {
                IssuedAt = wireAuthority.IssuedAt,
            },
            ParentContext = wireAuthority.ParentContext with
            {
                Contribution = wireAuthority.ParentContext.Contribution! with
                {
                    Lineage = wireAuthority.ParentContext.Contribution.Lineage with
                    {
                        PayloadContentHash = null,
                        PayloadByteLength = null,
                    },
                },
            },
        };
        wireAuthority = wireAuthority with
        {
            CanonicalBindingHash = SidecarCapabilityTransportValidation.ComputeStorageContinuationBindingHash(
                wireAuthority),
        };
        wireAuthority = wireAuthority with { Proof = wireAuthority.CanonicalBindingHash };
        Assert.False(wireAuthority.ParentContext.Contribution!.Lineage.IsPayloadBound);
        var requestWithAuthority = continuationRequest with
        {
            HostEntryContinuationAuthority = wireAuthority,
        };

        var changedDescriptorAuthority = wireAuthority with
        {
            ParentContext = wireAuthority.ParentContext with
            {
                Contribution = wireAuthority.ParentContext.Contribution! with
                {
                    Lineage = wireAuthority.ParentContext.Contribution.Lineage with
                    {
                        ActionKey = new SharpClawActionKey("storage.changed"),
                    },
                },
            },
        };
        changedDescriptorAuthority = changedDescriptorAuthority with
        {
            CanonicalBindingHash = SidecarCapabilityTransportValidation.ComputeStorageContinuationBindingHash(
                changedDescriptorAuthority),
        };
        changedDescriptorAuthority = changedDescriptorAuthority with
        {
            Proof = changedDescriptorAuthority.CanonicalBindingHash,
        };
        Assert.Equal(
            SidecarCapabilityErrors.SpoofedIdentity,
            fixture.Session.ImportHostEntryStorageContinuationAuthority(
                changedDescriptorAuthority,
                continuationNow).Code);

        Assert.True(fixture.Session.ImportHostEntryStorageContinuationAuthority(
            wireAuthority,
            continuationNow).Accepted);

        var changedAuthority = wireAuthority with { RootBudgetId = Guid.NewGuid() };
        Assert.Equal(
            SidecarCapabilityErrors.SpoofedIdentity,
            fixture.Session.BeginStorageContinuationCall(
                requestWithAuthority with { HostEntryContinuationAuthority = changedAuthority },
                continuationPayload.ByteLength,
                continuationNow,
                out _).Code);
        Assert.Equal(
            SidecarCapabilityErrors.SpoofedIdentity,
            fixture.Session.BeginStorageContinuationCall(
                requestWithAuthority with { RequestPayload = Payload("agent_job_imports.request", new { jobId = "job-2" }) },
                continuationPayload.ByteLength,
                continuationNow,
                out _).Code);
        Assert.Equal(
            SidecarCapabilityErrors.SpoofedIdentity,
            fixture.Session.BeginStorageContinuationCall(
                requestWithAuthority with
                {
                    Cancellation = requestWithAuthority.Cancellation with { AuthorityHash = "changed-cancellation" },
                },
                continuationPayload.ByteLength,
                continuationNow,
                out _).Code);

        var concurrent = await Task.WhenAll(
            Task.Run(() =>
            {
                var result = fixture.Session.BeginStorageContinuationCall(
                    requestWithAuthority,
                    continuationPayload.ByteLength,
                    continuationNow,
                    out var context);
                return (result, context);
            }),
            Task.Run(() =>
            {
                var result = fixture.Session.BeginStorageContinuationCall(
                    requestWithAuthority,
                    continuationPayload.ByteLength,
                    continuationNow,
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
                continuationNow,
                out _).Code);
        Assert.Equal(
            SidecarCapabilityErrors.InvalidBinding,
            fixture.Session.CompleteCall(parentCall.CallId, 1).Code);
        Assert.True(fixture.Session.CompleteCall(continuationCall.CallId, 0).Accepted);
        Assert.True(fixture.Session.CompleteCall(parentCall.CallId, 1).Accepted);
    }

    [Fact]
    public void HostEntryStorageContinuationRejectsReceiptForDifferentActivePayload()
    {
        var fixture = CreateFixture(
            maxInFlight: 2,
            maxCalls: 1,
            authenticateStorageContinuationAuthority: (authority, hash) =>
                hash == SidecarCapabilityTransportValidation.ComputeStorageContinuationBindingHash(authority));
        var parentCall = ActionCall(fixture, 1, "storage-receipt-parent");
        var parentDescriptor = NestedDescriptor("storage.receipt.parent", "storage.receipt.input");
        var parentContext = IssueContext(
            fixture,
            new RequestPrincipal("storage-receipt-caller"),
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
                "storage-receipt-mismatch",
                parentDescriptor.Key,
                parentDescriptor.Version,
                parentCall.CallId,
                1,
                "storage-receipt-scope",
                Payload(parentDescriptor.InputTypeIdentity, new { value = 2 }).ContentHash)).Accepted);

        var storageCall = fixture.Call with
        {
            CallId = Guid.NewGuid(),
            ReplayNonce = "storage-receipt-continuation",
            Sequence = 2,
            Deadline = parentCall.Deadline,
        };
        var storagePayload = Payload("storage.receipt.request", new { value = 3 });
        var storageRequest = SidecarStorageCapabilityRequest.Invoke(
            storageCall,
            fixture.Binding.ModuleId,
            "storage_receipt/get",
            storagePayload,
            PayloadType("storage.receipt.result"),
            Cancellation(fixture),
            storageCall.Deadline);
        Assert.True(fixture.Session.IssueHostEntryStorageContinuation(
            fixture.Session,
            parentCall,
            parentCall,
            storageRequest,
            fixture.Now,
            (_, hash) => hash,
            out var authority).Accepted);
        Assert.NotNull(authority);

        var import = fixture.Session.ImportHostEntryStorageContinuationAuthority(
            authority!,
            fixture.Now);
        Assert.Equal(SidecarCapabilityErrors.SpoofedIdentity, import.Code);
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
            HostActionEntryIngress.Cli,
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
            HostActionEntryIngress.Cli,
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
        var cancelledRootAuthority = wireRootRelay.Authority with
        {
            CancellationState = SidecarHostTerminalCancellationState.Cancelled,
            CancellationAt = peer.Now,
        };
        cancelledRootAuthority = cancelledRootAuthority with
        {
            CanonicalBindingHash = SidecarCapabilityTransportValidation.ComputeTerminalAuthorityBindingHash(
                cancelledRootAuthority),
        };
        cancelledRootAuthority = cancelledRootAuthority with
        {
            Proof = cancelledRootAuthority.CanonicalBindingHash,
        };
        Assert.False(peer.Session.ImportHostActionEntryPeerRootRelay(
            wireRootRelay with { Authority = cancelledRootAuthority },
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

    [Fact]
    public void Peer_root_relay_storage_continuation_accepts_mirrored_carrier_once()
    {
        static bool VerifyHostProof(SidecarHostTerminalAuthority authority, string proof) =>
            string.Equals(authority.Proof, proof, StringComparison.Ordinal) &&
            string.Equals(
                authority.Proof,
                SidecarCapabilityTransportValidation.ComputeTerminalAuthorityBindingHash(authority),
                StringComparison.OrdinalIgnoreCase);

        static bool VerifyStorageProof(
            SidecarHostEntryStorageContinuationAuthority authority,
            string hash) =>
            string.Equals(
                hash,
                SidecarCapabilityTransportValidation.ComputeStorageContinuationBindingHash(authority),
                StringComparison.OrdinalIgnoreCase);

        var host = CreateFixture(
            maxInFlight: 4,
            maxCalls: 8,
            moduleId: "module-root-storage",
            graphId: "graph-root-storage",
            authenticateHostTerminalAuthority: VerifyHostProof,
            authenticateStorageContinuationAuthority: VerifyStorageProof);
        var peer = CreateMirroredFixture(
            host,
            authenticateHostTerminalAuthority: VerifyHostProof,
            authenticateStorageContinuationAuthority: VerifyStorageProof,
            maxInFlight: 4,
            maxCalls: 8) with
        {
            Now = host.Now.AddMilliseconds(1),
        };
        ConsumeStorageCalls(host, 5, "root-storage-host-prefix");
        ConsumeStorageCalls(peer, 5, "root-storage-peer-prefix");

        var descriptor = NestedDescriptor(
            "peer.root.storage",
            typeof(string).AssemblyQualifiedName!);
        var action = Payload(descriptor.InputTypeIdentity, "root-storage");
        var hostContext = IssueContext(
            host,
            new RequestPrincipal("root-storage-user"),
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
        var hostCarrier = ActivateContext(host, hostContext!);
        var hostCall = ActionCall(host, 6, "root-storage-host");
        var peerCall = hostCall with
        {
            ReplayNonce = "root-storage-peer",
        };
        Assert.True(host.Session.BeginCall(
            hostCall,
            SidecarCapabilityKind.Action,
            action,
            action.ByteLength,
            host.Now,
            hostContext).Accepted);
        var terminal = new SidecarActionTerminalRegistration(
            Guid.NewGuid(),
            descriptor.InputTypeIdentity,
            descriptor.InputSchemaVersion,
            descriptor.ResultTypeIdentity,
            descriptor.ResultSchemaVersion,
            descriptor.DescriptorHash);
        var hostReceipt = new SidecarTerminalReceipt(
            "root-storage-host-receipt",
            descriptor.Key,
            descriptor.Version,
            hostCall.CallId,
            1,
            "root-storage-host-scope",
            action.ContentHash);
        Assert.True(host.Session.RecordTerminal(
            hostCall.CallId,
            terminal.TerminalId,
            hostReceipt).Accepted);
        var request = SidecarActionCapabilityRequest.HostEntry(
            hostCall,
            descriptor,
            action,
            Cancellation(host),
            hostCall.Deadline,
            hostContext,
            terminal);
        var rootAuthority = CreateTerminalRequest(
            host,
            request,
            new ActionPipelineSnapshot("root-storage-snapshot", []),
            hostReceipt).Authority with
        {
            RootPeerCall = peerCall,
            ReceivingRootBudgetId = hostCarrier.CapabilityId,
            ReceivingPeerBindingGeneration = peer.Session.BindingGeneration,
        };
        rootAuthority = rootAuthority with
        {
            CanonicalBindingHash = SidecarCapabilityTransportValidation.ComputeTerminalAuthorityBindingHash(
                rootAuthority),
        };
        rootAuthority = rootAuthority with { Proof = rootAuthority.CanonicalBindingHash };
        Assert.True(host.Session.IssueHostActionEntryPeerRootRelay(
            hostCall,
            peerCall,
            descriptor,
            action,
            terminal,
            new ActionPipelineSnapshot("root-storage-snapshot", []),
            peer.Session,
            rootAuthority,
            host.Now,
            out var relay).Accepted);
        Assert.NotNull(relay);
        var wireRelay = SidecarCapabilityTransportCodec.Deserialize<SidecarHostActionEntryRootRelay>(
            SidecarCapabilityTransportCodec.Serialize(relay!));
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
            terminal);
        Assert.True(peer.Session.BeginActionCall(
            peerRequest,
            action.ByteLength,
            peer.Now,
            out _).Accepted);
        Assert.True(peer.Session.TryGetActiveHostActionEntryCarrier(
            peerContext!.CapabilityId,
            out var peerCarrier));
        var peerReceipt = hostReceipt with
        {
            ReceiptId = "root-storage-peer-receipt",
            IdempotencyScope = "root-storage-peer-scope",
        };
        Assert.True(peer.Session.RecordTerminal(
            peerCall.CallId,
            terminal.TerminalId,
            peerReceipt).Accepted);

        ConsumeStorageCalls(host, 2, "root-storage-host-boundary", startingSequence: 7);
        ConsumeStorageCalls(peer, 2, "root-storage-peer-boundary", startingSequence: 7);
        var storageCall = peer.Call with
        {
            Capability = SidecarCapabilityKind.Storage,
            CallId = Guid.NewGuid(),
            ReplayNonce = "root-storage-continuation",
            Sequence = 9,
            Deadline = peerCall.Deadline,
        };
        var storagePayload = Payload("root.storage.request", "payload");
        var storageRequest = SidecarStorageCapabilityRequest.Invoke(
            storageCall,
            peer.Binding.ModuleId,
            "root_storage/get",
            storagePayload,
            PayloadType("root.storage.result"),
            Cancellation(peer),
            storageCall.Deadline);
        Assert.True(peer.Session.IssueHostEntryStorageContinuation(
            peer.Session,
            peerCall,
            peerCall,
            storageRequest,
            peer.Now,
            (_, hash) => hash,
            out var continuation).Accepted);
        Assert.NotNull(continuation);
        var wireContinuation = SidecarCapabilityTransportCodec.Deserialize<
            SidecarHostEntryStorageContinuationAuthority>(
            SidecarCapabilityTransportCodec.Serialize(continuation!));
        var continuedRequest = storageRequest with
        {
            HostEntryContinuationAuthority = wireContinuation,
        };
        Assert.True(peer.Session.ImportHostEntryStorageContinuationAuthority(
            wireContinuation,
            peer.Now).Accepted);
        Assert.True(peer.Session.BeginStorageContinuationCall(
            continuedRequest,
            storagePayload.ByteLength,
            peer.Now,
            out _).Accepted);
        var changedCarrierAuthority = wireContinuation with
        {
            CarrierAuthority = wireContinuation.CarrierAuthority with
            {
                IssuedAt = wireContinuation.IssuedAt.AddTicks(1),
            },
        };
        changedCarrierAuthority = changedCarrierAuthority with
        {
            CanonicalBindingHash = SidecarCapabilityTransportValidation.ComputeStorageContinuationBindingHash(
                changedCarrierAuthority),
        };
        changedCarrierAuthority = changedCarrierAuthority with
        {
            Proof = changedCarrierAuthority.CanonicalBindingHash,
        };
        Assert.Equal(
            SidecarCapabilityErrors.SpoofedIdentity,
            host.Session.ImportHostEntryStorageContinuationAuthority(
                changedCarrierAuthority,
                peer.Now).Code);
        var hostImport = host.Session.ImportHostEntryStorageContinuationAuthority(
            wireContinuation,
            peer.Now);
        Assert.True(hostImport.Accepted, $"{hostImport.Code}: {hostImport.Message}");
        Assert.True(host.Session.BeginStorageContinuationCall(
            continuedRequest,
            storagePayload.ByteLength,
            peer.Now,
            out _).Accepted);
        Assert.Equal(
            SidecarCapabilityErrors.Replay,
            host.Session.ImportHostEntryStorageContinuationAuthority(
                wireContinuation,
                peer.Now).Code);

        Assert.True(peer.Session.CompleteCall(storageCall.CallId, 0).Accepted);
        Assert.True(host.Session.CompleteCall(storageCall.CallId, 0).Accepted);
        Assert.True(peer.Session.CompleteCall(peerCall.CallId, 1).Accepted);
        Assert.True(host.Session.CompleteCall(hostCall.CallId, 1).Accepted);
        Assert.True(peer.Session.CompleteHostActionEntryCarrier(
            peerCarrier!,
            HostActionEntryCarrierCompletionKind.Succeeded,
            peer.Now).Accepted);
        Assert.True(host.Session.CompleteHostActionEntryCarrier(
            hostCarrier,
            HostActionEntryCarrierCompletionKind.Succeeded,
            peer.Now).Accepted);
    }

    private static Fixture CreateMirroredFixture(
        Fixture template,
        Func<SidecarHostTerminalAuthority, string, bool>? authenticateHostTerminalAuthority = null,
        Func<SidecarHostEntryStorageContinuationAuthority, string, bool>? authenticateStorageContinuationAuthority = null,
        Func<HostEndpointRouteAuthority, string, bool>? authenticateEndpointRouteAuthority = null,
        Func<SidecarHostEndpointRouteRelay, string, bool>? authenticateEndpointRouteRelay = null,
        Func<SidecarEndpointTypedActionChildReservation, string, bool>? authenticateEndpointTypedActionChildReservation = null,
        Func<SidecarEndpointTypedActionChildRelay, string, bool>? authenticateEndpointTypedActionChildRelay = null,
        Func<SidecarEndpointTypedActionChildImportAcknowledgment, string, bool>? authenticateEndpointTypedActionChildImportAcknowledgment = null,
        Func<SidecarEndpointTypedActionChildImportAbort, string, bool>? authenticateEndpointTypedActionChildImportAbort = null,
        IReadOnlyList<SidecarCapabilityKind>? capabilities = null,
        int? maxInFlight = null,
        int? maxCalls = null,
        int? actionInputBytes = null,
        int? protocolMessageBytes = null)
    {
        var binding = template.Binding with
        {
            Grant = capabilities is null
                ? template.Binding.Grant
                : template.Binding.Grant with { Capabilities = capabilities },
            ConcurrencyLimits = maxInFlight is null && maxCalls is null
                ? template.Binding.ConcurrencyLimits
                : template.Binding.ConcurrencyLimits with
                {
                    MaximumInFlightCalls = maxInFlight ?? template.Binding.ConcurrencyLimits.MaximumInFlightCalls,
                    MaximumCallsPerRequest = maxCalls ?? template.Binding.ConcurrencyLimits.MaximumCallsPerRequest,
                },
            PayloadLimits = actionInputBytes is null && protocolMessageBytes is null
                ? template.Binding.PayloadLimits
                : template.Binding.PayloadLimits with
                {
                    ActionInputBytes = actionInputBytes ?? template.Binding.PayloadLimits.ActionInputBytes,
                    ProtocolMessageBytes = protocolMessageBytes ?? template.Binding.PayloadLimits.ProtocolMessageBytes,
                },
        };
        binding = binding with
        {
            Authentication = binding.Authentication with
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
            template.Now,
            authenticateHostTerminalAuthority,
            authenticateStorageContinuationAuthority,
            authenticateEndpointRouteAuthority,
            authenticateEndpointRouteRelay,
            authenticateEndpointTypedActionChildReservation,
            authenticateEndpointTypedActionChildRelay,
            authenticateEndpointTypedActionChildImportAcknowledgment,
            authenticateEndpointTypedActionChildImportAbort);
        var call = new SidecarCapabilityCallIdentity(
            binding.SessionId,
            binding.RequestId,
            binding.CancellationId,
            Guid.NewGuid(),
            "mirrored-call-nonce-1",
            binding.ModuleId,
            binding.GraphId,
            SidecarCapabilityKind.Storage,
            1,
            template.Now.AddMinutes(1));
        return new Fixture(template.Now, binding, session, call, template.SafeFailure, nonces, bindingHashes);
    }

    private static Fixture CreateFixture(
        int maxInFlight = 2,
        int maxCalls = 4,
        IReadOnlyList<SidecarCapabilityKind>? capabilities = null,
        string moduleId = "module-a",
        string graphId = "graph-a",
        Func<SidecarHostTerminalAuthority, string, bool>? authenticateHostTerminalAuthority = null,
        Func<SidecarHostEntryStorageContinuationAuthority, string, bool>? authenticateStorageContinuationAuthority = null,
        Func<HostEndpointRouteAuthority, string, bool>? authenticateEndpointRouteAuthority = null,
        Func<SidecarHostEndpointRouteRelay, string, bool>? authenticateEndpointRouteRelay = null,
        Func<SidecarEndpointTypedActionChildReservation, string, bool>? authenticateEndpointTypedActionChildReservation = null,
        Func<SidecarEndpointTypedActionChildRelay, string, bool>? authenticateEndpointTypedActionChildRelay = null,
        int actionInputBytes = 1024,
        int protocolMessageBytes = 65536,
        Func<SidecarEndpointTypedActionChildImportAcknowledgment, string, bool>? authenticateEndpointTypedActionChildImportAcknowledgment = null,
        Func<SidecarEndpointTypedActionChildImportAbort, string, bool>? authenticateEndpointTypedActionChildImportAbort = null)
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
            new SidecarPayloadLimits(
                ActionInputBytes: actionInputBytes,
                ActionResultBytes: 1024,
                EventPayloadBytes: 1024,
                ProtocolMessageBytes: protocolMessageBytes,
                StreamChunkBytes: 512),
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
            authenticateStorageContinuationAuthority,
            authenticateEndpointRouteAuthority,
            authenticateEndpointRouteRelay,
            authenticateEndpointTypedActionChildReservation,
            authenticateEndpointTypedActionChildRelay,
            authenticateEndpointTypedActionChildImportAcknowledgment,
            authenticateEndpointTypedActionChildImportAbort);
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
    public async Task CancelledCrossSidecarPeerRelayConsumesReceivingSequenceWithoutTerminalImport()
    {
        static bool Authenticate(SidecarHostTerminalAuthority authority, string hash) =>
            authority.Proof == hash;

        static SidecarHostTerminalAuthority Sign(SidecarHostTerminalAuthority authority)
        {
            var hash = SidecarCapabilityTransportValidation.ComputeTerminalAuthorityBindingHash(authority);
            return authority with { CanonicalBindingHash = hash, Proof = hash };
        }

        var source = CreateFixture(
            moduleId: "source-module",
            graphId: "source-graph",
            authenticateHostTerminalAuthority: Authenticate);
        var target = CreateFixture(
            moduleId: "target-module",
            graphId: "target-graph",
            authenticateHostTerminalAuthority: Authenticate);
        var cross = CreateCrossRelay(source, target);
        var peer = CreateMirroredFixture(target, Authenticate);
        Assert.Equal(1, cross.Relay.PeerCall!.Sequence);

        var parentDescriptor = new SidecarActionDescriptorIdentity(
            new SharpClawActionKey("source.parent"),
            1,
            "source.category",
            "source.parent.input",
            "source.parent-schema",
            1,
            "source.parent.result",
            "source.parent-result-schema",
            1,
            "source.parent-descriptor");
        var parentTerminal = new SidecarActionTerminalRegistration(
            Guid.NewGuid(),
            parentDescriptor.InputTypeIdentity,
            parentDescriptor.InputSchemaVersion,
            parentDescriptor.ResultTypeIdentity,
            parentDescriptor.ResultSchemaVersion,
            parentDescriptor.DescriptorHash);
        var parentRequest = SidecarCapabilityTransportValidationRequest(
            cross.ParentCall,
            parentDescriptor,
            cross.ParentAction,
            cross.ParentContext);
        var terminalRequest = CreateTerminalRequest(
            source,
            parentRequest with { Terminal = parentTerminal },
            new ActionPipelineSnapshot("source-snapshot", []));
        var terminalAuthority = terminalRequest.Authority with
        {
            RootPeerCall = cross.Relay.PeerCall,
            CrossSidecarPeerRelayBindingHash =
                SidecarCapabilityTransportValidation.ComputeCrossSidecarPeerRelayBindingHash(cross.Relay),
        };
        terminalAuthority = terminalAuthority with
        {
            CancellationState = SidecarHostTerminalCancellationState.Cancelled,
            CancellationAt = source.Now,
        };
        terminalAuthority = terminalAuthority with
        {
            CanonicalBindingHash = SidecarCapabilityTransportValidation.ComputeTerminalAuthorityBindingHash(
                terminalAuthority),
        };
        terminalAuthority = terminalAuthority with { Proof = terminalAuthority.CanonicalBindingHash };
        Assert.Equal(cross.ParentCall.CallId, terminalAuthority.CallId);
        Assert.Equal(cross.Relay.PeerCall, terminalAuthority.RootPeerCall);
        Assert.Equal(
            SidecarCapabilityTransportValidation.ComputeCrossSidecarPeerRelayBindingHash(cross.Relay),
            terminalAuthority.CrossSidecarPeerRelayBindingHash);
        Assert.Equal(
            SidecarCapabilityTransportValidation.ComputeTerminalAuthorityBindingHash(terminalAuthority),
            terminalAuthority.CanonicalBindingHash);
        Assert.True(Authenticate(terminalAuthority, terminalAuthority.CanonicalBindingHash));

        var cancellation = new SidecarCrossSidecarActionEntryPeerCancellation(
            cross.Relay,
            terminalAuthority,
            source.Now);
        cancellation = SidecarCapabilityTransportCodec.Deserialize<SidecarCrossSidecarActionEntryPeerCancellation>(
            SidecarCapabilityTransportCodec.Serialize(cancellation));
        Assert.Equal(cancellation.Relay.PeerBindingGeneration, target.Session.BindingGeneration);
        Assert.Equal(cancellation.Relay.PeerCall, cancellation.Relay.Carrier.Authority.PeerCall);
        Assert.Equal(cancellation.Relay.Carrier.Authority.PeerBindingGeneration, target.Session.BindingGeneration);
        Assert.Equal(cancellation.Relay.Carrier.ExpiresAt, cancellation.TerminalAuthority.ExpiresAt);
        Assert.True(cancellation.IsWellFormed);
        var cancelledNormalRequest = terminalRequest with
        {
            Authority = terminalAuthority,
        };
        var normalRejected = SidecarCapabilityTransportValidation.ValidateActionTerminalRequest(
            parentRequest,
            cancelledNormalRequest,
            source.Binding,
            source.Now,
            Authenticate);
        Assert.False(normalRejected.Accepted);

        var rotatedPeer = CreateMirroredFixture(target, Authenticate);
        var rotatedBinding = CreateRotatedBinding(rotatedPeer, "cancelled-peer-rotation");
        rotatedPeer.BindingHashes.Add(rotatedBinding.Authentication.BindingHash);
        Assert.True(rotatedPeer.Session.RotateBinding(rotatedBinding, rotatedPeer.Now).Accepted);
        var rotatedRejected = rotatedPeer.Session.ConsumeCancelledCrossSidecarActionEntryPeerRelay(
            cancellation,
            source.Now,
            static (authority, hash) => authority.Proof == hash);
        Assert.False(rotatedRejected.Accepted);

        var disconnectedPeer = CreateMirroredFixture(target, Authenticate);
        disconnectedPeer.Session.Disconnect();
        var disconnectedRejected = disconnectedPeer.Session.ConsumeCancelledCrossSidecarActionEntryPeerRelay(
            cancellation,
            source.Now,
            static (authority, hash) => authority.Proof == hash);
        Assert.False(disconnectedRejected.Accepted);

        var peerCarrier = SidecarCrossSidecarActionEntryValidation.ValidatePeerCarrier(
            cancellation.Relay.Carrier,
            target.Binding,
            source.Now,
            static (authority, hash) => authority.Proof == hash);
        Assert.True(peerCarrier.Accepted, peerCarrier.Message);

        var invalidAttempts = new[]
        {
            cancellation with
            {
                TerminalAuthority = cancellation.TerminalAuthority with
                {
                    CallId = Guid.NewGuid(),
                },
            },
            cancellation with
            {
                Relay = cancellation.Relay with
                {
                    PeerBindingGeneration = cancellation.Relay.PeerBindingGeneration + 1,
                },
            },
            cancellation with
            {
                Relay = cancellation.Relay with
                {
                    Carrier = cancellation.Relay.Carrier with
                    {
                        Action = Payload(cancellation.Relay.Carrier.Action.TypeIdentity, new { value = 99 }),
                    },
                },
            },
            cancellation with
            {
                CancelledAt = cancellation.CancelledAt.AddSeconds(1),
            },
            cancellation with
            {
                TerminalAuthority = cancellation.TerminalAuthority with
                {
                    CancellationState = SidecarHostTerminalCancellationState.None,
                },
            },
            cancellation with
            {
                TerminalAuthority = Sign(cancellation.TerminalAuthority with
                {
                    IssuedAt = source.Now.AddMinutes(1),
                    CancellationAt = source.Now.AddMinutes(2),
                    ExpiresAt = source.Now.AddMinutes(3),
                }),
                CancelledAt = source.Now.AddMinutes(2),
            },
            cancellation with
            {
                TerminalAuthority = Sign(cancellation.TerminalAuthority with
                {
                    IssuedAt = source.Now.AddMinutes(-3),
                    CancellationAt = source.Now.AddMinutes(-2),
                    ExpiresAt = source.Now.AddMinutes(-1),
                }),
                CancelledAt = source.Now.AddMinutes(-2),
            },
            cancellation with
            {
                TerminalAuthority = Sign(cancellation.TerminalAuthority with
                {
                    ExpiresAt = source.Now.AddMinutes(1),
                    CancellationAt = source.Now.AddMinutes(2),
                }),
                CancelledAt = source.Now.AddMinutes(2),
            },
        };
        foreach (var invalid in invalidAttempts)
        {
            var rejected = peer.Session.ConsumeCancelledCrossSidecarActionEntryPeerRelay(
                invalid,
                source.Now,
                static (authority, hash) => authority.Proof == hash);
            Assert.False(rejected.Accepted);
        }

        var concurrent = await Task.WhenAll(
            Task.Run(() => peer.Session.ConsumeCancelledCrossSidecarActionEntryPeerRelay(
                cancellation,
                source.Now,
                static (authority, hash) => authority.Proof == hash)),
            Task.Run(() => peer.Session.ConsumeCancelledCrossSidecarActionEntryPeerRelay(
                cancellation,
                source.Now,
                static (authority, hash) => authority.Proof == hash)));
        Assert.Equal(1, concurrent.Count(result => result.Accepted));

        var replay = peer.Session.ConsumeCancelledCrossSidecarActionEntryPeerRelay(
            cancellation,
            source.Now,
            static (authority, hash) => authority.Proof == hash);
        Assert.False(replay.Accepted);
        Assert.Equal(SidecarCapabilityErrors.Replay, replay.Code);

        var changedRelay = cancellation with
        {
            Relay = cancellation.Relay with
            {
                Carrier = cancellation.Relay.Carrier with
                {
                    Action = Payload(cancellation.Relay.Carrier.Action.TypeIdentity, new { value = 99 }),
                },
            },
        };
        var changed = peer.Session.ConsumeCancelledCrossSidecarActionEntryPeerRelay(
            changedRelay,
            source.Now,
            static (authority, hash) => authority.Proof == hash);
        Assert.False(changed.Accepted);

        var nextCall = peer.Call with
        {
            Capability = SidecarCapabilityKind.Storage,
            CallId = Guid.NewGuid(),
            ReplayNonce = "after-cancelled-peer-relay",
            Sequence = cross.Relay.PeerCall!.Sequence + 1,
        };
        var nextPayload = Payload("storage.request", new { value = 4 });
        var next = peer.Session.BeginCall(
            nextCall,
            SidecarCapabilityKind.Storage,
            nextPayload,
            nextPayload.ByteLength,
            source.Now);
        Assert.True(next.Accepted, next.Message);
        Assert.True(peer.Session.CompleteCall(nextCall.CallId, 0).Accepted);
    }

    [Theory]
    [InlineData(4)]
    [InlineData(7)]
    public void CrossSidecarPeerRelayImportsTargetCarrierThroughTerminalExchange(int priorCalls)
    {
        var source = CreateFixture(maxInFlight: 4, maxCalls: 8, moduleId: "source-module", graphId: "source-graph");
        var hostTarget = CreateFixture(maxInFlight: 4, maxCalls: 8, moduleId: "target-module", graphId: "target-graph");
        var targetPeer = CreateMirroredFixture(
            hostTarget,
            static (authority, hash) => authority.Proof == hash,
            static (authority, hash) => hash == SidecarCapabilityTransportValidation.ComputeStorageContinuationBindingHash(authority));
        ConsumeStorageCalls(hostTarget, priorCalls, "peer-host-prior");
        ConsumeStorageCalls(targetPeer, priorCalls, "peer-module-prior");
        var parent = PrepareCrossParent(source, "peer-source.parent");
        var descriptor = new SidecarActionDescriptorIdentity(
            new SharpClawActionKey("peer-target.action"),
            1,
            "peer-target.category",
            "peer-target.input",
            "peer-target-input-schema",
            1,
            "peer-target.result",
            "peer-target-result-schema",
            1,
            "peer-target-descriptor");
        var entry = new SidecarModuleActionEntryDefinition(
            hostTarget.Binding.ModuleId,
            hostTarget.Binding.GraphId,
            descriptor,
            hostTarget.Binding.ModuleId,
            hostTarget.Binding.GraphId);
        var childRequest = new SidecarCrossSidecarActionEntryRequest(
            descriptor.Key,
            descriptor.Version,
            Payload(descriptor.InputTypeIdentity, new { value = 2 }),
            parent.Call.Deadline,
            source.Now.AddMinutes(2));

        var issue = source.Session.IssueCrossSidecarActionEntryRelay(
            parent.Call,
            childRequest,
            hostTarget.Session,
            entry,
            new ActionPipelineSnapshot("peer-target-snapshot", []),
            source.Now,
            static (_, hash) => hash,
            out var relay);
        Assert.True(issue.Accepted, issue.Message);
        Assert.NotNull(relay);
        Assert.NotNull(relay!.PeerCall);
        Assert.Equal(priorCalls + 1, relay.PeerCall!.Sequence);

        var terminal = new SidecarActionTerminalRegistration(
            Guid.NewGuid(),
            descriptor.InputTypeIdentity,
            descriptor.InputSchemaVersion,
            descriptor.ResultTypeIdentity,
            descriptor.ResultSchemaVersion,
            descriptor.DescriptorHash);
        var hostBegin = hostTarget.Session.BeginCrossSidecarActionEntryCall(
            relay.Carrier,
            terminal,
            relay.Carrier.Action.ByteLength,
            source.Now,
            out var hostContext,
            static (authority, hash) => authority.Proof == hash);
        Assert.True(hostBegin.Accepted, hostBegin.Message);
        Assert.NotNull(hostContext);

        var hostActionRequest = SidecarActionCapabilityRequest.HostEntry(
            relay.Carrier.Authority.TargetChildCall,
            descriptor,
            relay.Carrier.Action,
            new SidecarCancellationIdentity(
                hostTarget.Binding.CancellationId,
                "peer-target-cancellation",
                relay.Carrier.Authority.Deadline),
            relay.Carrier.Authority.Deadline,
            hostContext!,
            terminal);
        var hostReceipt = new SidecarTerminalReceipt(
            "peer-target-host-receipt",
            descriptor.Key,
            descriptor.Version,
            relay.Carrier.Authority.TargetChildCall.CallId,
            relay.Carrier.Authority.Attempt,
            "peer-target-host-scope",
            relay.Carrier.Action.ContentHash);
        var terminalRequest = CreateTerminalRequest(
            hostTarget,
            hostActionRequest,
            new ActionPipelineSnapshot("peer-target-snapshot", []),
            hostReceipt) with
        {
            CrossSidecarPeerRelay = relay,
            CrossSidecarActionRequest = childRequest,
        };
        var terminalAuthority = terminalRequest.Authority with
        {
            RootPeerCall = relay.PeerCall,
            CrossSidecarPeerRelayBindingHash =
                SidecarCapabilityTransportValidation.ComputeCrossSidecarPeerRelayBindingHash(relay),
        };
        terminalAuthority = terminalAuthority with
        {
            CanonicalBindingHash = SidecarCapabilityTransportValidation.ComputeTerminalAuthorityBindingHash(terminalAuthority),
            Proof = string.Empty,
        };
        terminalAuthority = terminalAuthority with { Proof = terminalAuthority.CanonicalBindingHash };
        terminalRequest = terminalRequest with { Authority = terminalAuthority };
        terminalRequest = SidecarCapabilityTransportCodec.Deserialize<SidecarActionTerminalTransportRequest>(
            SidecarCapabilityTransportCodec.Serialize(terminalRequest));

        var invalidRequests = new[]
        {
            terminalRequest with { CrossSidecarPeerRelay = null },
            terminalRequest with
            {
                Authority = terminalRequest.Authority with { RootPeerCall = relay.Carrier.Authority.TargetChildCall },
            },
            terminalRequest with
            {
                CrossSidecarPeerRelay = relay with { PeerBindingGeneration = relay.PeerBindingGeneration + 1 },
            },
            terminalRequest with
            {
                CrossSidecarActionRequest = childRequest with
                {
                    Action = Payload(descriptor.InputTypeIdentity, new { value = 99 }),
                },
            },
            terminalRequest with
            {
                Authority = terminalRequest.Authority with { Proof = "forged-peer-proof" },
            },
        };
        foreach (var (invalidRequest, index) in invalidRequests.Select((request, index) => (request, index)))
        {
            var invalidResult = targetPeer.Session.ImportCrossSidecarActionEntryPeerRelay(
                invalidRequest,
                source.Now,
                static (authority, hash) => authority.Proof == hash,
                out _);
            Assert.False(invalidResult.Accepted, $"Mutation index {index} was accepted: {invalidResult.Code}");
        }

        var import = targetPeer.Session.ImportCrossSidecarActionEntryPeerRelay(
            terminalRequest,
            source.Now,
            static (authority, hash) => authority.Proof == hash,
            out var importedCarrier);
        Assert.True(import.Accepted, import.Message);
        Assert.NotNull(importedCarrier);
        Assert.Equal(relay.Carrier.CarrierId, importedCarrier!.CarrierId);
        Assert.Equal(relay.PeerCall, importedCarrier.Authority.PeerCall);

        var peerBegin = targetPeer.Session.BeginCrossSidecarActionEntryCall(
            importedCarrier!,
            terminal,
            importedCarrier!.Action.ByteLength,
            source.Now,
            out _,
            static (authority, hash) => authority.Proof == hash);
        Assert.True(peerBegin.Accepted, peerBegin.Message);

        var storageCall = relay.PeerCall! with
        {
            Capability = SidecarCapabilityKind.Storage,
            CallId = Guid.NewGuid(),
            ReplayNonce = "peer-storage-after-action",
            Sequence = relay.PeerCall.Sequence + 1,
        };
        var storagePayload = Payload("peer-storage.request", new { value = 3 });
        Assert.Equal(priorCalls + 2, storageCall.Sequence);
        if (priorCalls < 7)
        {
            Assert.True(targetPeer.Session.BeginCall(
                storageCall,
                SidecarCapabilityKind.Storage,
                storagePayload,
                storagePayload.ByteLength,
                source.Now).Accepted);
            Assert.True(targetPeer.Session.CompleteCall(storageCall.CallId, 0).Accepted);
        }
        else
        {
            var peerReceipt = new SidecarTerminalReceipt(
                "peer-target-terminal-receipt",
                descriptor.Key,
                descriptor.Version,
                relay.PeerCall.CallId,
                relay.Carrier.Authority.Attempt,
                "peer-target-terminal-scope",
                relay.Carrier.Action.ContentHash);
            Assert.True(targetPeer.Session.RecordTerminal(
                relay.PeerCall.CallId,
                terminal.TerminalId,
                peerReceipt).Accepted);
            var storageRequest = SidecarStorageCapabilityRequest.Invoke(
                storageCall,
                targetPeer.Binding.ModuleId,
                "peer-storage/get",
                storagePayload,
                PayloadType("peer-storage.result"),
                new SidecarCancellationIdentity(
                    targetPeer.Binding.CancellationId,
                    "peer-storage-cancellation",
                    storageCall.Deadline),
                storageCall.Deadline);
            var storageIssue = source.Session.IssueHostEntryStorageContinuation(
                targetPeer.Session,
                parent.Call,
                relay.PeerCall,
                storageRequest,
                source.Now,
                (_, hash) => hash,
                out var storageAuthority);
            Assert.True(storageIssue.Accepted, storageIssue.Message);
            var wireStorageRequest = storageRequest with
            {
                HostEntryContinuationAuthority = SidecarCapabilityTransportCodec.Deserialize<SidecarHostEntryStorageContinuationAuthority>(
                    SidecarCapabilityTransportCodec.Serialize(storageAuthority)),
            };
            Assert.True(targetPeer.Session.ImportHostEntryStorageContinuationAuthority(
                wireStorageRequest.HostEntryContinuationAuthority!,
                source.Now).Accepted);
            Assert.True(targetPeer.Session.BeginStorageContinuationCall(
                wireStorageRequest,
                storagePayload.ByteLength,
                source.Now,
                out _).Accepted);
            Assert.True(targetPeer.Session.CompleteCall(storageCall.CallId, 0).Accepted);
        }
        Assert.False(targetPeer.Session.ImportCrossSidecarActionEntryPeerRelay(
            terminalRequest,
            source.Now,
            static (authority, hash) => authority.Proof == hash,
            out _).Accepted);
        Assert.True(targetPeer.Session.RevokeCrossSidecarActionEntry(
            relay.Carrier.CarrierId,
            source.Now).Accepted);
        Assert.True(hostTarget.Session.RevokeCrossSidecarActionEntry(
            relay.Carrier.CarrierId,
            source.Now).Accepted);
        Assert.True(source.Session.CompleteCall(parent.Call.CallId, 1).Accepted);
    }

    [Fact]
    public void CrossSidecarTargetCreatesStorageContinuationCarrierState()
    {
        var source = CreateFixture(maxInFlight: 4, maxCalls: 8);
        var target = CreateFixture(
            maxInFlight: 4,
            maxCalls: 8,
            authenticateStorageContinuationAuthority: (authority, hash) =>
                hash == SidecarCapabilityTransportValidation.ComputeStorageContinuationBindingHash(authority) &&
                source.Session.IsStorageContinuationAuthorityLive(authority, source.Now),
            moduleId: "module-b",
            graphId: "graph-b");
        ConsumeStorageCalls(target, 6, "cross-boundary");
        var targetParent = PrepareCrossParent(target, "target.root", sequence: 7);
        var cross = CreateCrossRelay(source, target);
        var terminal = new SidecarActionTerminalRegistration(
            Guid.NewGuid(),
            cross.Relay.Descriptor.InputTypeIdentity,
            cross.Relay.Descriptor.InputSchemaVersion,
            cross.Relay.Descriptor.ResultTypeIdentity,
            cross.Relay.Descriptor.ResultSchemaVersion,
            cross.Relay.Descriptor.DescriptorHash);

        var mutatedCarriers = new[]
        {
            cross.Relay.Carrier with
            {
                Authority = cross.Relay.Carrier.Authority with { RootBudgetId = Guid.NewGuid() },
            },
            cross.Relay.Carrier with
            {
                Authority = cross.Relay.Carrier.Authority with
                {
                    SourceParentCall = cross.Relay.Carrier.Authority.SourceParentCall with { CallId = Guid.NewGuid() },
                },
            },
            cross.Relay.Carrier with
            {
                Authority = cross.Relay.Carrier.Authority with
                {
                    TargetChildCall = cross.Relay.Carrier.Authority.TargetChildCall with { CallId = Guid.NewGuid() },
                },
            },
            cross.Relay.Carrier with
            {
                Authority = cross.Relay.Carrier.Authority with { Cancellation = cross.Relay.Carrier.Authority.Cancellation with { CancellationId = Guid.NewGuid() } },
            },
            cross.Relay.Carrier with
            {
                Authority = cross.Relay.Carrier.Authority with { Proof = "forged-proof" },
            },
            cross.Relay.Carrier with
            {
                Authority = cross.Relay.Carrier.Authority with { ExpiresAt = cross.Relay.Carrier.ExpiresAt.AddSeconds(1) },
                ExpiresAt = cross.Relay.Carrier.ExpiresAt.AddSeconds(1),
            },
            cross.Relay.Carrier with
            {
                Action = Payload(cross.Relay.Carrier.Action.TypeIdentity, new { value = 99 }),
            },
        };
        foreach (var mutatedCarrier in mutatedCarriers)
        {
            var mutation = target.Session.BeginCrossSidecarActionEntryCall(
                mutatedCarrier,
                terminal,
                mutatedCarrier.Action.ByteLength,
                cross.Now,
                out _,
                (authority, hash) => authority.Proof == hash);
            Assert.False(mutation.Accepted);
        }

        Assert.True(target.Session.BeginCrossSidecarActionEntryCall(
            cross.Relay.Carrier,
            terminal,
            cross.Relay.Carrier.Action.ByteLength,
            cross.Now,
            out var childContext,
            (authority, hash) => authority.Proof == hash).Accepted);
        Assert.NotNull(childContext);
        Assert.Equal(8, cross.Relay.Carrier.Authority.TargetChildCall.Sequence);
        Assert.True(target.Session.TryGetActiveHostActionEntryCarrier(
            cross.Relay.Carrier.CarrierId,
            out var targetCarrier));
        Assert.NotNull(targetCarrier);

        var childCall = cross.Relay.Carrier.Authority.TargetChildCall;
        var childReceipt = new SidecarTerminalReceipt(
            "cross-storage-child",
            cross.Relay.Descriptor.Key,
            cross.Relay.Descriptor.Version,
            childCall.CallId,
            cross.Relay.Carrier.Authority.Attempt,
            "cross-storage-scope",
            cross.Relay.Carrier.Action.ContentHash);
        Assert.True(target.Session.RecordTerminal(
            childCall.CallId,
            Guid.NewGuid(),
            childReceipt).Accepted);

        var storageCall = childCall with
        {
            Capability = SidecarCapabilityKind.Storage,
            CallId = Guid.NewGuid(),
            ReplayNonce = "cross-storage-continuation",
            Sequence = 9,
        };
        var storagePayload = Payload(
            "agent_job_imports.request",
            new { jobId = "cross-sidecar-job" });
        var storageRequest = SidecarStorageCapabilityRequest.Invoke(
            storageCall,
            target.Binding.ModuleId,
            "agent_job_imports/get",
            storagePayload,
            PayloadType("agent_job_imports.result"),
            new SidecarCancellationIdentity(
                target.Binding.CancellationId,
                "cross-storage-cancellation",
                storageCall.Deadline),
            storageCall.Deadline);
        var issue = source.Session.IssueHostEntryStorageContinuation(
            target.Session,
            cross.ParentCall,
            childCall,
            storageRequest,
            source.Now,
            (_, hash) => hash,
            out var authority);
        Assert.True(issue.Accepted, issue.Message);
        Assert.NotNull(authority);

        var wireRequest = storageRequest with
        {
            HostEntryContinuationAuthority = SidecarCapabilityTransportCodec.Deserialize<SidecarHostEntryStorageContinuationAuthority>(
                SidecarCapabilityTransportCodec.Serialize(authority)),
        };
        Assert.True(target.Session.ImportHostEntryStorageContinuationAuthority(
            wireRequest.HostEntryContinuationAuthority!,
            target.Now).Accepted);
        Assert.Equal(
            SidecarCapabilityErrors.InvalidBinding,
            target.Session.CompleteCall(childCall.CallId, 1).Code);
        Assert.True(target.Session.BeginStorageContinuationCall(
            wireRequest,
            storagePayload.ByteLength,
            target.Now,
            out var storageContext).Accepted);
        Assert.Equal(childContext!.CapabilityId, storageContext!.CapabilityId);
        Assert.Equal(
            SidecarCapabilityErrors.Replay,
            target.Session.BeginStorageContinuationCall(
                wireRequest,
                storagePayload.ByteLength,
                target.Now,
                out _).Code);
        Assert.True(target.Session.CompleteCall(storageCall.CallId, 0).Accepted);

        var childResult = Payload(cross.Relay.Descriptor.ResultTypeIdentity, new { ok = true });
        var childOutcome = new SidecarActionOutcomeEnvelope(
            ActionOutcomeKind.Completed,
            childResult,
            null,
            null,
            null,
            childReceipt,
            target.Binding.SafeFailure,
            1);
        var childExecution = new SidecarTerminalExecutionResult(childResult, null, true);
        var childResultIdentity = new SidecarActionResultIdentity(
            Guid.NewGuid(),
            childCall.CallId,
            cross.Relay.Descriptor.Key,
            cross.Relay.Descriptor.Version,
            childResult.TypeIdentity,
            childResult.ContentHash);
        Assert.True(target.Session.CompleteCrossSidecarActionEntry(
            cross.Relay.Carrier,
            childOutcome,
            childReceipt,
            childExecution,
            childResultIdentity,
            target.Binding.SafeFailure,
            target.Now,
            (_, hash) => hash,
            out _).Accepted);
        Assert.False(target.Session.TryGetActiveHostActionEntryCarrier(
            cross.Relay.Carrier.CarrierId,
            out _));
        Assert.True(target.Session.CompleteCall(targetParent.Call.CallId, 1).Accepted);
        Assert.True(source.Session.CompleteCall(cross.ParentCall.CallId, 1).Accepted);
    }

    [Fact]
    public void CrossSidecarStorageContinuationResolvesPeerParentToTargetChild()
    {
        static bool Authenticate(SidecarHostTerminalAuthority authority, string hash) =>
            authority.Proof == hash;

        var source = CreateFixture(
            moduleId: "source-module",
            graphId: "source-graph");
        var hostTarget = CreateFixture(
            maxInFlight: 4,
            maxCalls: 8,
            moduleId: "target-module",
            graphId: "target-graph",
            authenticateHostTerminalAuthority: Authenticate,
            authenticateStorageContinuationAuthority: (authority, hash) =>
                authority.Proof == hash &&
                hash == SidecarCapabilityTransportValidation.ComputeStorageContinuationBindingHash(authority));
        var targetPeer = CreateMirroredFixture(
            hostTarget,
            (authority, hash) => authority.Proof == hash,
            (authority, hash) =>
                authority.Proof == hash &&
                hash == SidecarCapabilityTransportValidation.ComputeStorageContinuationBindingHash(authority));
        ConsumeStorageCalls(hostTarget, 7, "cross-target-host-prior");
        ConsumeStorageCalls(targetPeer, 7, "cross-target-peer-prior");

        var cross = CreateCrossRelay(source, hostTarget);
        var hostActivation = cross.Now.AddSeconds(1);
        var peerImportTime = cross.Now.AddSeconds(2);
        var peerActivation = cross.Now.AddSeconds(3);
        var continuationIssued = cross.Now.AddSeconds(4);
        var peerContinuationImport = cross.Now.AddSeconds(5);
        var peerStorageBegin = cross.Now.AddSeconds(6);
        var hostImport = cross.Now.AddSeconds(7);
        var hostStorageBegin = cross.Now.AddSeconds(8);
        var descriptor = cross.Relay.Descriptor;
        var terminal = new SidecarActionTerminalRegistration(
            Guid.NewGuid(),
            descriptor.InputTypeIdentity,
            descriptor.InputSchemaVersion,
            descriptor.ResultTypeIdentity,
            descriptor.ResultSchemaVersion,
            descriptor.DescriptorHash);
        var hostBegin = hostTarget.Session.BeginCrossSidecarActionEntryCall(
            cross.Relay.Carrier,
            terminal,
            cross.Relay.Carrier.Action.ByteLength,
            hostActivation,
            out var hostContext,
            (authority, hash) => authority.Proof == hash);
        Assert.True(hostBegin.Accepted, hostBegin.Message);
        Assert.NotNull(hostContext);

        var hostActionRequest = SidecarActionCapabilityRequest.HostEntry(
            cross.Relay.Carrier.Authority.TargetChildCall,
            descriptor,
            cross.Relay.Carrier.Action,
            new SidecarCancellationIdentity(
                hostTarget.Binding.CancellationId,
                "cross-target-host-cancellation",
                cross.Relay.Carrier.Authority.Deadline),
            cross.Relay.Carrier.Authority.Deadline,
            hostContext!,
            terminal);
        var hostReceipt = new SidecarTerminalReceipt(
            "cross-target-host-receipt",
            descriptor.Key,
            descriptor.Version,
            cross.Relay.Carrier.Authority.TargetChildCall.CallId,
            cross.Relay.Carrier.Authority.Attempt,
            "cross-target-host-scope",
            cross.Relay.Carrier.Action.ContentHash);
        Assert.True(hostTarget.Session.RecordTerminal(
            cross.Relay.Carrier.Authority.TargetChildCall.CallId,
            terminal.TerminalId,
            hostReceipt).Accepted);

        var terminalRequest = CreateTerminalRequest(
            hostTarget,
            hostActionRequest,
            new ActionPipelineSnapshot("target-snapshot", []),
            hostReceipt) with
        {
            CrossSidecarPeerRelay = cross.Relay,
            CrossSidecarActionRequest = new SidecarCrossSidecarActionEntryRequest(
                descriptor.Key,
                descriptor.Version,
                cross.Relay.Carrier.Action,
                cross.Relay.Carrier.Authority.Deadline,
                cross.Now.AddMinutes(2)),
        };
        var terminalAuthority = terminalRequest.Authority with
        {
            RootPeerCall = cross.Relay.PeerCall,
            CrossSidecarPeerRelayBindingHash =
                SidecarCapabilityTransportValidation.ComputeCrossSidecarPeerRelayBindingHash(cross.Relay),
        };
        terminalAuthority = terminalAuthority with
        {
            CanonicalBindingHash =
                SidecarCapabilityTransportValidation.ComputeTerminalAuthorityBindingHash(terminalAuthority),
            Proof = string.Empty,
        };
        terminalAuthority = terminalAuthority with
        {
            Proof = terminalAuthority.CanonicalBindingHash,
        };
        terminalRequest = terminalRequest with { Authority = terminalAuthority };
        terminalRequest = SidecarCapabilityTransportCodec.Deserialize<SidecarActionTerminalTransportRequest>(
            SidecarCapabilityTransportCodec.Serialize(terminalRequest));
        Assert.NotNull(terminalRequest.Authority);
        Assert.Equal(terminalRequest.TerminalId, terminalRequest.Authority.TerminalId);
        Assert.Equal(cross.Relay.PeerCall, terminalRequest.Authority.RootPeerCall);
        Assert.Equal(
            SidecarCapabilityTransportValidation.ComputeCrossSidecarPeerRelayBindingHash(terminalRequest.CrossSidecarPeerRelay!),
            terminalRequest.Authority.CrossSidecarPeerRelayBindingHash);
        Assert.Equal(
            SidecarCapabilityTransportValidation.ComputeTerminalAuthorityBindingHash(terminalRequest.Authority),
            terminalRequest.Authority.CanonicalBindingHash);
        Assert.Equal(terminalAuthority.CanonicalBindingHash, terminalRequest.Authority.CanonicalBindingHash);
        Assert.Equal(terminalRequest.Authority.CanonicalBindingHash, terminalRequest.Authority.Proof);
        Assert.Equal(
            terminalRequest.Call,
            terminalRequest.CrossSidecarPeerRelay!.Carrier.Authority.TargetChildCall);

        var peerImport = targetPeer.Session.ImportCrossSidecarActionEntryPeerRelay(
            terminalRequest,
            peerImportTime,
            (authority, hash) => authority.Proof == hash,
            out var importedCarrier);
        Assert.True(peerImport.Accepted, peerImport.Message);
        Assert.NotNull(importedCarrier);
        var peerBegin = targetPeer.Session.BeginCrossSidecarActionEntryCall(
            importedCarrier!,
            terminal,
            importedCarrier!.Action.ByteLength,
            peerActivation,
            out _,
            (authority, hash) => authority.Proof == hash);
        Assert.True(peerBegin.Accepted, peerBegin.Message);
        var peerReceipt = hostReceipt with
        {
            ReceiptId = "cross-target-peer-receipt",
            CallId = cross.Relay.PeerCall!.CallId,
            IdempotencyScope = "cross-target-peer-scope",
        };
        Assert.True(targetPeer.Session.RecordTerminal(
            cross.Relay.PeerCall.CallId,
            terminal.TerminalId,
            peerReceipt).Accepted);

        var storageCall = cross.Relay.PeerCall with
        {
            Capability = SidecarCapabilityKind.Storage,
            CallId = Guid.NewGuid(),
            ReplayNonce = "cross-target-storage-continuation",
            Sequence = cross.Relay.PeerCall.Sequence + 1,
        };
        var storagePayload = Payload("cross-target-storage.request", new { value = 4 });
        var storageRequest = SidecarStorageCapabilityRequest.Invoke(
            storageCall,
            hostTarget.Binding.ModuleId,
            "cross-target-storage/get",
            storagePayload,
            PayloadType("cross-target-storage.result"),
            new SidecarCancellationIdentity(
                hostTarget.Binding.CancellationId,
                "cross-target-storage-cancellation",
                storageCall.Deadline),
            storageCall.Deadline);
        var issue = targetPeer.Session.IssueHostEntryStorageContinuation(
            targetPeer.Session,
            cross.Relay.PeerCall,
            cross.Relay.PeerCall,
            storageRequest,
            continuationIssued,
            (_, hash) => hash,
            out var authority);
        Assert.True(issue.Accepted, issue.Message);
        Assert.NotNull(authority);
        var wireAuthority = SidecarCapabilityTransportCodec.Deserialize<SidecarHostEntryStorageContinuationAuthority>(
            SidecarCapabilityTransportCodec.Serialize(authority));
        var targetChildCall = cross.Relay.Carrier.Authority.TargetChildCall;
        var wireRequest = storageRequest with { HostEntryContinuationAuthority = wireAuthority };
        Assert.True(targetPeer.Session.ImportHostEntryStorageContinuationAuthority(
            wireAuthority,
            peerContinuationImport).Accepted);
        var peerBlocked = targetPeer.Session.CompleteCall(cross.Relay.PeerCall!.CallId, 1);
        Assert.False(peerBlocked.Accepted);
        Assert.Equal(SidecarCapabilityErrors.InvalidBinding, peerBlocked.Code);
        Assert.True(targetPeer.Session.BeginStorageContinuationCall(
            wireRequest,
            storagePayload.ByteLength,
            peerStorageBegin,
            out _).Accepted);
        Assert.True(hostTarget.Session.ImportHostEntryStorageContinuationAuthority(
            wireAuthority,
            hostImport).Accepted);
        var hostBlocked = hostTarget.Session.CompleteCall(targetChildCall.CallId, 1);
        Assert.False(hostBlocked.Accepted);
        Assert.Equal(SidecarCapabilityErrors.InvalidBinding, hostBlocked.Code);
        Assert.True(hostTarget.Session.BeginStorageContinuationCall(
            wireRequest,
            storagePayload.ByteLength,
            hostStorageBegin,
            out _).Accepted);
        Assert.True(hostTarget.Session.CompleteCall(storageCall.CallId, 0).Accepted);
        Assert.False(targetPeer.Session.CompleteCall(cross.Relay.PeerCall.CallId, 1).Accepted);
        Assert.True(targetPeer.Session.CompleteCall(storageCall.CallId, 0).Accepted);
        Assert.True(targetPeer.Session.CompleteCall(cross.Relay.PeerCall.CallId, 1).Accepted);
        Assert.True(hostTarget.Session.CompleteCall(targetChildCall.CallId, 1).Accepted);
        Assert.False(targetPeer.Session.ImportHostEntryStorageContinuationAuthority(
            wireAuthority,
            peerStorageBegin).Accepted);
        Assert.False(hostTarget.Session.ImportHostEntryStorageContinuationAuthority(
            wireAuthority,
            hostStorageBegin).Accepted);

        Assert.True(targetPeer.Session.RevokeCrossSidecarActionEntry(
            cross.Relay.Carrier.CarrierId,
            hostStorageBegin).Accepted);
        Assert.True(hostTarget.Session.RevokeCrossSidecarActionEntry(
            cross.Relay.Carrier.CarrierId,
            hostStorageBegin).Accepted);
        Assert.False(hostTarget.Session.TryGetActiveHostActionEntryCarrier(
            cross.Relay.Carrier.CarrierId,
            out _));
        Assert.False(targetPeer.Session.TryGetActiveHostActionEntryCarrier(
            cross.Relay.Carrier.CarrierId,
            out _));
        var sourceRevocation = source.Session.RevokeCrossSidecarActionEntry(
            cross.Relay.Carrier.CarrierId,
            hostStorageBegin);
        Assert.False(sourceRevocation.Accepted);
        Assert.Equal(SidecarCapabilityErrors.Duplicate, sourceRevocation.Code);
        Assert.True(source.Session.CompleteCall(cross.ParentCall.CallId, 1).Accepted);
    }

    [Fact]
    public void CrossSidecarStorageContinuationRejectsMissingHostTerminalBeforeImport()
    {
        var attempt = PrepareHostReceiptContinuationCase(
            null,
            null,
            importPeerContinuation: false,
            recordHostReceipt: false);

        var import = attempt.HostTarget.Session.ImportHostEntryStorageContinuationAuthority(
            attempt.Authority,
            attempt.HostImportTime);
        Assert.False(import.Accepted);
        Assert.Equal(SidecarCapabilityErrors.SpoofedIdentity, import.Code);

        var begin = attempt.HostTarget.Session.BeginStorageContinuationCall(
            attempt.Request,
            attempt.Request.RequestPayload!.ByteLength,
            attempt.HostImportTime,
            out _);
        Assert.False(begin.Accepted);
        Assert.True(attempt.HostTarget.Session.RevokeCrossSidecarActionEntry(
            attempt.Authority.CarrierId,
            attempt.HostImportTime).Accepted);
        Assert.True(attempt.TargetPeer.Session.RevokeCrossSidecarActionEntry(
            attempt.Authority.CarrierId,
            attempt.PeerImportTime).Accepted);
        Assert.True(attempt.Source.Session.CompleteCall(
            attempt.SourceParentCall.CallId,
            1).Accepted);
    }

    [Fact]
    public void CrossSidecarStorageContinuationRejectsCompletedTargetBeforeImport()
    {
        var attempt = PrepareHostReceiptContinuationCase(null, null, importPeerContinuation: false);

        Assert.True(attempt.HostTarget.Session.CompleteCall(
            attempt.TargetChildCall.CallId,
            attempt.TargetAttempt).Accepted);
        var import = attempt.HostTarget.Session.ImportHostEntryStorageContinuationAuthority(
            attempt.Authority,
            attempt.HostImportTime);
        Assert.False(import.Accepted);
        var begin = attempt.HostTarget.Session.BeginStorageContinuationCall(
            attempt.Request,
            attempt.Request.RequestPayload!.ByteLength,
            attempt.HostImportTime,
            out _);
        Assert.False(begin.Accepted);
        Assert.True(attempt.HostTarget.Session.RevokeCrossSidecarActionEntry(
            attempt.Authority.CarrierId,
            attempt.HostImportTime).Accepted);
        Assert.True(attempt.TargetPeer.Session.RevokeCrossSidecarActionEntry(
            attempt.Authority.CarrierId,
            attempt.PeerImportTime).Accepted);
        Assert.True(attempt.Source.Session.CompleteCall(
            attempt.SourceParentCall.CallId,
            1).Accepted);
    }

    [Fact]
    public void CrossSidecarStorageContinuationRevocationBeforeBeginReleasesReservation()
    {
        var attempt = PrepareHostReceiptContinuationCase(null, null);
        Assert.True(attempt.HostTarget.Session.ImportHostEntryStorageContinuationAuthority(
            attempt.Authority,
            attempt.HostImportTime).Accepted);

        Assert.True(attempt.HostTarget.Session.RevokeCrossSidecarActionEntry(
            attempt.Authority.CarrierId,
            attempt.HostImportTime).Accepted);
        Assert.Equal(
            SidecarCapabilityErrors.Duplicate,
            attempt.HostTarget.Session.RevokeCrossSidecarActionEntry(
                attempt.Authority.CarrierId,
                attempt.HostImportTime).Code);
        Assert.True(attempt.TargetPeer.Session.RevokeCrossSidecarActionEntry(
            attempt.Authority.CarrierId,
            attempt.PeerImportTime).Accepted);
        Assert.Equal(
            SidecarCapabilityErrors.Duplicate,
            attempt.TargetPeer.Session.CompleteCall(
                attempt.Request.Call.CallId,
                0).Code);
        Assert.False(attempt.HostTarget.Session.BeginStorageContinuationCall(
            attempt.Request,
            attempt.Request.RequestPayload!.ByteLength,
            attempt.HostImportTime,
            out _).Accepted);
        Assert.False(attempt.HostTarget.Session.ImportHostEntryStorageContinuationAuthority(
            attempt.Authority,
            attempt.HostImportTime).Accepted);
        Assert.False(attempt.TargetPeer.Session.ImportHostEntryStorageContinuationAuthority(
            attempt.Authority,
            attempt.PeerImportTime).Accepted);
        Assert.False(attempt.HostTarget.Session.CompleteCall(
            attempt.TargetChildCall.CallId,
            attempt.TargetAttempt).Accepted);
        Assert.True(attempt.Source.Session.CompleteCall(
            attempt.SourceParentCall.CallId,
            1).Accepted);
    }

    [Fact]
    public void CrossSidecarStorageContinuationRevocationAfterBeginAbortsStorage()
    {
        var attempt = PrepareHostReceiptContinuationCase(null, null);
        Assert.True(attempt.HostTarget.Session.ImportHostEntryStorageContinuationAuthority(
            attempt.Authority,
            attempt.HostImportTime).Accepted);
        Assert.True(attempt.HostTarget.Session.BeginStorageContinuationCall(
            attempt.Request,
            attempt.Request.RequestPayload!.ByteLength,
            attempt.HostImportTime,
            out _).Accepted);

        Assert.True(attempt.HostTarget.Session.RevokeCrossSidecarActionEntry(
            attempt.Authority.CarrierId,
            attempt.HostImportTime).Accepted);
        Assert.Equal(
            SidecarCapabilityErrors.Duplicate,
            attempt.HostTarget.Session.CompleteCall(
                attempt.Request.Call.CallId,
                0).Code);
        Assert.True(attempt.TargetPeer.Session.RevokeCrossSidecarActionEntry(
            attempt.Authority.CarrierId,
            attempt.PeerImportTime).Accepted);
        Assert.Equal(
            SidecarCapabilityErrors.Duplicate,
            attempt.TargetPeer.Session.CompleteCall(
                attempt.Request.Call.CallId,
                0).Code);
        Assert.False(attempt.HostTarget.Session.BeginStorageContinuationCall(
            attempt.Request,
            attempt.Request.RequestPayload!.ByteLength,
            attempt.HostImportTime,
            out _).Accepted);
        Assert.False(attempt.HostTarget.Session.ImportHostEntryStorageContinuationAuthority(
            attempt.Authority,
            attempt.HostImportTime).Accepted);
        Assert.False(attempt.TargetPeer.Session.ImportHostEntryStorageContinuationAuthority(
            attempt.Authority,
            attempt.PeerImportTime).Accepted);
        Assert.False(attempt.HostTarget.Session.CompleteCall(
            attempt.TargetChildCall.CallId,
            attempt.TargetAttempt).Accepted);
        Assert.True(attempt.Source.Session.CompleteCall(
            attempt.SourceParentCall.CallId,
            1).Accepted);
    }

    [Fact]
    public void CrossSidecarStorageContinuationInvalidCompletionReleasesParent()
    {
        var attempt = PrepareHostReceiptContinuationCase(null, null);
        Assert.True(attempt.HostTarget.Session.ImportHostEntryStorageContinuationAuthority(
            attempt.Authority,
            attempt.HostImportTime).Accepted);
        Assert.True(attempt.HostTarget.Session.BeginStorageContinuationCall(
            attempt.Request,
            attempt.Request.RequestPayload!.ByteLength,
            attempt.HostImportTime,
            out _).Accepted);

        var completion = attempt.HostTarget.Session.CompleteCall(
            attempt.Request.Call.CallId,
            1);
        Assert.Equal(SidecarCapabilityErrors.InvalidBinding, completion.Code);
        Assert.Equal(
            "Storage calls cannot complete with a terminal callback.",
            completion.Message);
        Assert.False(attempt.HostTarget.Session.BeginStorageContinuationCall(
            attempt.Request,
            attempt.Request.RequestPayload!.ByteLength,
            attempt.HostImportTime,
            out _).Accepted);
        Assert.False(attempt.HostTarget.Session.ImportHostEntryStorageContinuationAuthority(
            attempt.Authority,
            attempt.HostImportTime).Accepted);
        Assert.True(attempt.TargetPeer.Session.CompleteCall(
            attempt.Request.Call.CallId,
            0).Accepted);
        Assert.True(attempt.TargetPeer.Session.CompleteCall(
            attempt.Authority.ParentCall.CallId,
            1).Accepted);
        Assert.True(attempt.HostTarget.Session.RevokeCrossSidecarActionEntry(
            attempt.Authority.CarrierId,
            attempt.HostImportTime).Accepted);
        Assert.True(attempt.TargetPeer.Session.RevokeCrossSidecarActionEntry(
            attempt.Authority.CarrierId,
            attempt.PeerImportTime).Accepted);
        Assert.Equal(
            SidecarCapabilityErrors.Replay,
            attempt.HostTarget.Session.ImportHostEntryStorageContinuationAuthority(
                attempt.Authority,
                attempt.HostImportTime).Code);
        Assert.False(attempt.HostTarget.Session.CompleteCall(
            attempt.TargetChildCall.CallId,
            attempt.TargetAttempt).Accepted);
        Assert.True(attempt.Source.Session.CompleteCall(
            attempt.SourceParentCall.CallId,
            1).Accepted);
    }

    [Fact]
    public void CrossSidecarStorageContinuationHostDisconnectDrainsPeerCleanup()
    {
        var attempt = PrepareHostReceiptContinuationCase(null, null);
        Assert.True(attempt.HostTarget.Session.ImportHostEntryStorageContinuationAuthority(
            attempt.Authority,
            attempt.HostImportTime).Accepted);
        Assert.True(attempt.HostTarget.Session.BeginStorageContinuationCall(
            attempt.Request,
            attempt.Request.RequestPayload!.ByteLength,
            attempt.HostImportTime,
            out _).Accepted);

        attempt.HostTarget.Session.Disconnect();
        attempt.TargetPeer.Session.Disconnect();
        Assert.False(attempt.HostTarget.Session.BeginStorageContinuationCall(
                attempt.Request,
                attempt.Request.RequestPayload!.ByteLength,
                attempt.HostImportTime,
                out _).Accepted);
        Assert.False(attempt.TargetPeer.Session.BeginStorageContinuationCall(
            attempt.Request,
            attempt.Request.RequestPayload!.ByteLength,
            attempt.PeerImportTime,
            out _).Accepted);
        Assert.True(attempt.Source.Session.CompleteCall(
            attempt.SourceParentCall.CallId,
            1).Accepted);
    }

    [Fact]
    public void CrossSidecarStorageContinuationRotationSucceedsAfterCleanup()
    {
        var attempt = PrepareHostReceiptContinuationCase(null, null);
        Assert.True(attempt.HostTarget.Session.ImportHostEntryStorageContinuationAuthority(
            attempt.Authority,
            attempt.HostImportTime).Accepted);
        Assert.True(attempt.HostTarget.Session.BeginStorageContinuationCall(
            attempt.Request,
            attempt.Request.RequestPayload!.ByteLength,
            attempt.HostImportTime,
            out _).Accepted);

        var activeRotation = CreateRotatedBinding(attempt.HostTarget, "lifecycle-active-rotation");
        attempt.HostTarget.BindingHashes.Add(activeRotation.Authentication.BindingHash);
        Assert.Equal(
            SidecarCapabilityErrors.InvalidBinding,
            attempt.HostTarget.Session.RotateBinding(
                activeRotation,
                attempt.HostImportTime).Code);

        Assert.True(attempt.HostTarget.Session.CompleteCall(
            attempt.Request.Call.CallId,
            0).Accepted);
        Assert.True(attempt.TargetPeer.Session.CompleteCall(
            attempt.Request.Call.CallId,
            0).Accepted);
        Assert.True(attempt.TargetPeer.Session.CompleteCall(
            attempt.Authority.ParentCall.CallId,
            1).Accepted);

        Assert.True(attempt.HostTarget.Session.RevokeCrossSidecarActionEntry(
            attempt.Authority.CarrierId,
            attempt.HostImportTime).Accepted);
        Assert.True(attempt.TargetPeer.Session.RevokeCrossSidecarActionEntry(
            attempt.Authority.CarrierId,
            attempt.HostImportTime).Accepted);
        Assert.False(attempt.HostTarget.Session.CompleteCall(
            attempt.TargetChildCall.CallId,
            attempt.TargetAttempt).Accepted);
        Assert.True(attempt.Source.Session.CompleteCall(
            attempt.SourceParentCall.CallId,
            1).Accepted);
        var rotated = CreateRotatedBinding(attempt.HostTarget, "lifecycle-clean-rotation");
        attempt.HostTarget.BindingHashes.Add(rotated.Authentication.BindingHash);
        Assert.True(attempt.HostTarget.Session.RotateBinding(
            rotated,
            attempt.HostImportTime).Accepted);
        Assert.False(attempt.HostTarget.Session.ImportHostEntryStorageContinuationAuthority(
            attempt.Authority,
            attempt.HostImportTime).Accepted);
    }

    [Theory]
    [InlineData("key")]
    [InlineData("version")]
    [InlineData("attempt")]
    [InlineData("content")]
    public void CrossSidecarStorageContinuationRejectsMismatchedHostReceipt(string mutation)
    {
        static SidecarTerminalReceipt Mutate(
            SidecarTerminalReceipt receipt,
            string mutation) => mutation switch
            {
                "key" => receipt with { ActionKey = new SharpClawActionKey("wrong.receipt.key") },
                "version" => receipt with { ActionVersion = receipt.ActionVersion + 1 },
                "attempt" => receipt with { Attempt = receipt.Attempt + 1 },
                "content" => receipt with { ContentHash = "wrong-receipt-content" },
                _ => throw new ArgumentOutOfRangeException(nameof(mutation)),
            };

        var attempt = PrepareHostReceiptContinuationCase(
            receipt => Mutate(receipt, mutation));
        var wireAuthority = SidecarCapabilityTransportCodec.Deserialize<SidecarHostEntryStorageContinuationAuthority>(
            SidecarCapabilityTransportCodec.Serialize(attempt.Authority));
        var rejected = attempt.HostTarget.Session.ImportHostEntryStorageContinuationAuthority(
            wireAuthority,
            attempt.HostImportTime);

        Assert.False(rejected.Accepted);
        Assert.Equal(SidecarCapabilityErrors.SpoofedIdentity, rejected.Code);
        var begin = attempt.HostTarget.Session.BeginStorageContinuationCall(
            attempt.Request,
            attempt.Request.RequestPayload!.ByteLength,
            attempt.HostImportTime,
            out _);
        Assert.False(begin.Accepted);
        Assert.True(attempt.HostTarget.Session.CompleteCall(
            attempt.TargetChildCall.CallId,
            attempt.TargetAttempt).Accepted);
    }

    [Theory]
    [InlineData("key")]
    [InlineData("version")]
    [InlineData("attempt")]
    [InlineData("content")]
    public void CrossSidecarStorageContinuationRejectsMismatchedPeerReceipt(string mutation)
    {
        static SidecarTerminalReceipt Mutate(
            SidecarTerminalReceipt receipt,
            string mutation) => mutation switch
            {
                "key" => receipt with { ActionKey = new SharpClawActionKey("wrong.peer.receipt.key") },
                "version" => receipt with { ActionVersion = receipt.ActionVersion + 1 },
                "attempt" => receipt with { Attempt = receipt.Attempt + 1 },
                "content" => receipt with { ContentHash = "wrong-peer-receipt-content" },
                _ => throw new ArgumentOutOfRangeException(nameof(mutation)),
            };

        var attempt = PrepareHostReceiptContinuationCase(
            null,
            receipt => Mutate(receipt, mutation),
            importPeerContinuation: false);
        var rejected = attempt.TargetPeer.Session.ImportHostEntryStorageContinuationAuthority(
            attempt.Authority,
            attempt.PeerImportTime);

        Assert.False(rejected.Accepted);
        Assert.Equal(SidecarCapabilityErrors.SpoofedIdentity, rejected.Code);
        var begin = attempt.TargetPeer.Session.BeginStorageContinuationCall(
            attempt.Request,
            attempt.Request.RequestPayload!.ByteLength,
            attempt.PeerImportTime,
            out _);
        Assert.False(begin.Accepted);
        Assert.True(attempt.TargetPeer.Session.CompleteCall(
            attempt.Authority.ParentCall.CallId,
            1).Accepted);
    }

    [Theory]
    [InlineData("parent-call")]
    [InlineData("carrier")]
    [InlineData("carrier-capability")]
    [InlineData("context-capability")]
    [InlineData("root")]
    [InlineData("target-generation")]
    [InlineData("issuer-generation")]
    [InlineData("issuer-session")]
    [InlineData("proof")]
    public void CrossSidecarStorageContinuationRejectsStructuralAuthorityMutation(string mutation)
    {
        var attempt = PrepareHostReceiptContinuationCase(
            null,
            null,
            importPeerContinuation: false);
        var mutated = mutation switch
        {
            "parent-call" => attempt.Authority with
            {
                ParentCall = attempt.Authority.ParentCall with { CallId = Guid.NewGuid() },
            },
            "carrier" => attempt.Authority with { CarrierId = Guid.NewGuid() },
            "carrier-capability" => attempt.Authority with
            {
                CarrierAuthority = attempt.Authority.CarrierAuthority with { CapabilityId = Guid.NewGuid() },
            },
            "context-capability" => attempt.Authority with
            {
                ParentContext = attempt.Authority.ParentContext with { CapabilityId = Guid.NewGuid() },
            },
            "root" => attempt.Authority with { RootBudgetId = Guid.NewGuid() },
            "target-generation" => attempt.Authority with
            {
                TargetBindingGeneration = attempt.Authority.TargetBindingGeneration + 1,
            },
            "issuer-generation" => attempt.Authority with
            {
                IssuerBindingGeneration = attempt.Authority.IssuerBindingGeneration + 1,
            },
            "issuer-session" => attempt.Authority with { IssuerSessionId = Guid.NewGuid() },
            "proof" => attempt.Authority with { Proof = "forged-storage-proof" },
            _ => throw new ArgumentOutOfRangeException(nameof(mutation)),
        };
        if (mutation is not "proof")
        {
            mutated = mutated with
            {
                CanonicalBindingHash =
                    SidecarCapabilityTransportValidation.ComputeStorageContinuationBindingHash(mutated),
                Proof = string.Empty,
            };
            mutated = mutated with { Proof = mutated.CanonicalBindingHash };
        }
        mutated = SidecarCapabilityTransportCodec.Deserialize<SidecarHostEntryStorageContinuationAuthority>(
            SidecarCapabilityTransportCodec.Serialize(mutated));
        var invalidRequest = attempt.Request with { HostEntryContinuationAuthority = mutated };
        var rejected = attempt.HostTarget.Session.ImportHostEntryStorageContinuationAuthority(
            mutated,
            attempt.HostImportTime);
        Assert.False(rejected.Accepted);
        Assert.Equal(SidecarCapabilityErrors.SpoofedIdentity, rejected.Code);
        Assert.False(attempt.HostTarget.Session.BeginStorageContinuationCall(
            invalidRequest,
            invalidRequest.RequestPayload!.ByteLength,
            attempt.HostImportTime,
            out _).Accepted);

        var validAuthority = SidecarCapabilityTransportCodec.Deserialize<SidecarHostEntryStorageContinuationAuthority>(
            SidecarCapabilityTransportCodec.Serialize(attempt.Authority));
        var validRequest = attempt.Request with { HostEntryContinuationAuthority = validAuthority };
        var validPeerImport = attempt.TargetPeer.Session.ImportHostEntryStorageContinuationAuthority(
            validAuthority,
            attempt.PeerImportTime);
        Assert.True(validPeerImport.Accepted, validPeerImport.Message);
        Assert.True(attempt.TargetPeer.Session.BeginStorageContinuationCall(
            validRequest,
            validRequest.RequestPayload!.ByteLength,
            attempt.PeerImportTime,
            out _).Accepted);
        var validHostImport = attempt.HostTarget.Session.ImportHostEntryStorageContinuationAuthority(
            validAuthority,
            attempt.HostImportTime);
        Assert.True(validHostImport.Accepted, validHostImport.Message);
        Assert.True(attempt.HostTarget.Session.BeginStorageContinuationCall(
            validRequest,
            validRequest.RequestPayload!.ByteLength,
            attempt.HostImportTime,
            out _).Accepted);
        Assert.True(attempt.HostTarget.Session.CompleteCall(validRequest.Call.CallId, 0).Accepted);
        Assert.True(attempt.TargetPeer.Session.CompleteCall(validRequest.Call.CallId, 0).Accepted);
        Assert.True(attempt.TargetPeer.Session.CompleteCall(
            attempt.Authority.ParentCall.CallId,
            1).Accepted);
        Assert.True(attempt.HostTarget.Session.CompleteCall(
            attempt.TargetChildCall.CallId,
            attempt.TargetAttempt).Accepted);
    }

    [Theory]
    [InlineData("carrier-issued-before-relay", "sidecar_spoofed_identity")]
    [InlineData("carrier-issued-after-continuation", "sidecar_spoofed_identity")]
    [InlineData("carrier-expiry", "sidecar_spoofed_identity")]
    [InlineData("continuation-issued-after-import", "sidecar_expired")]
    [InlineData("continuation-expiry-after-storage", "sidecar_expired")]
    [InlineData("storage-deadline-after-parent", "sidecar_expired")]
    [InlineData("storage-deadline-after-context", "sidecar_expired")]
    [InlineData("storage-sequence", "sidecar_concurrency_limit")]
    [InlineData("storage-cancellation", "sidecar_spoofed_identity")]
    [InlineData("cancellation-expiry-before-storage", "sidecar_expired")]
    public void CrossSidecarStorageContinuationRejectsAuthorityDerivedRequestMutation(
        string mutation,
        string expectedCode)
    {
        var attempt = PrepareHostReceiptContinuationCase(
            null,
            null,
            importPeerContinuation: false);
        var mutated = mutation switch
        {
            "carrier-issued-before-relay" => attempt.Authority with
            {
                CarrierAuthority = attempt.Authority.CarrierAuthority with
                {
                    IssuedAt = attempt.SignedCarrierIssuedAt.AddSeconds(-1),
                },
            },
            "carrier-issued-after-continuation" => attempt.Authority with
            {
                CarrierAuthority = attempt.Authority.CarrierAuthority with
                {
                    IssuedAt = attempt.ContinuationIssuedAt.AddSeconds(1),
                },
            },
            "carrier-expiry" => attempt.Authority with
            {
                CarrierAuthority = attempt.Authority.CarrierAuthority with
                {
                    ExpiresAt = attempt.Authority.CarrierAuthority.ExpiresAt.AddSeconds(1),
                },
            },
            "continuation-issued-after-import" => attempt.Authority with
            {
                IssuedAt = attempt.HostImportTime.AddSeconds(1),
            },
            "continuation-expiry-after-storage" => attempt.Authority with
            {
                ExpiresAt = attempt.Authority.StorageCall.Deadline.AddSeconds(1),
            },
            "storage-deadline-after-parent" => attempt.Authority with
            {
                StorageCall = attempt.Authority.StorageCall with
                {
                    Deadline = attempt.Authority.ParentCall.Deadline.AddSeconds(1),
                },
            },
            "storage-deadline-after-context" => CreateAuthorityWithShorterParentContext(attempt),
            "storage-sequence" => attempt.Authority with
            {
                StorageCall = attempt.Authority.StorageCall with
                {
                    Sequence = attempt.Authority.StorageCall.Sequence + 1,
                },
            },
            "storage-cancellation" =>
                CreateAuthorityWithStorageCancellationMutation(attempt),
            "cancellation-expiry-before-storage" => attempt.Authority with
            {
                Cancellation = attempt.Authority.Cancellation with
                {
                    ExpiresAt = attempt.ContinuationIssuedAt.AddSeconds(1),
                },
            },
            _ => throw new ArgumentOutOfRangeException(nameof(mutation)),
        };
        mutated = mutated with
        {
            CanonicalBindingHash =
                SidecarCapabilityTransportValidation.ComputeStorageContinuationBindingHash(mutated),
            Proof = string.Empty,
        };
        mutated = mutated with { Proof = mutated.CanonicalBindingHash };
        mutated = SidecarCapabilityTransportCodec.Deserialize<SidecarHostEntryStorageContinuationAuthority>(
            SidecarCapabilityTransportCodec.Serialize(mutated));

        var invalidRequest = attempt.Request with { HostEntryContinuationAuthority = mutated };
        var rejected = attempt.HostTarget.Session.ImportHostEntryStorageContinuationAuthority(
            mutated,
            attempt.HostImportTime);
        Assert.False(rejected.Accepted);
        Assert.Equal(expectedCode, rejected.Code);
        var begin = attempt.HostTarget.Session.BeginStorageContinuationCall(
            invalidRequest,
            invalidRequest.RequestPayload!.ByteLength,
            attempt.HostImportTime,
            out _);
        Assert.False(begin.Accepted);

        var validAuthority = SidecarCapabilityTransportCodec.Deserialize<SidecarHostEntryStorageContinuationAuthority>(
            SidecarCapabilityTransportCodec.Serialize(attempt.Authority));
        var validRequest = attempt.Request with { HostEntryContinuationAuthority = validAuthority };
        var validPeerImport = attempt.TargetPeer.Session.ImportHostEntryStorageContinuationAuthority(
            validAuthority,
            attempt.PeerImportTime);
        Assert.True(validPeerImport.Accepted, validPeerImport.Message);
        Assert.True(attempt.TargetPeer.Session.BeginStorageContinuationCall(
            validRequest,
            validRequest.RequestPayload!.ByteLength,
            attempt.PeerImportTime,
            out _).Accepted);
        var validHostImport = attempt.HostTarget.Session.ImportHostEntryStorageContinuationAuthority(
            validAuthority,
            attempt.HostImportTime);
        Assert.True(validHostImport.Accepted, validHostImport.Message);
        Assert.True(attempt.HostTarget.Session.BeginStorageContinuationCall(
            validRequest,
            validRequest.RequestPayload!.ByteLength,
            attempt.HostImportTime,
            out _).Accepted);
        Assert.True(attempt.TargetPeer.Session.CompleteCall(validRequest.Call.CallId, 0).Accepted);
        Assert.True(attempt.HostTarget.Session.CompleteCall(validRequest.Call.CallId, 0).Accepted);
        Assert.True(attempt.TargetPeer.Session.CompleteCall(
            attempt.Authority.ParentCall.CallId,
            1).Accepted);
        Assert.True(attempt.HostTarget.Session.CompleteCall(
            attempt.TargetChildCall.CallId,
            attempt.TargetAttempt).Accepted);
    }

    private static SidecarHostEntryStorageContinuationAuthority CreateAuthorityWithStorageCancellationMutation(
        HostReceiptContinuationCase attempt)
    {
        var cancellationId = Guid.NewGuid();
        return attempt.Authority with
        {
            StorageCall = attempt.Authority.StorageCall with { CancellationId = cancellationId },
            Cancellation = attempt.Authority.Cancellation with { CancellationId = cancellationId },
        };
    }

    private static SidecarHostEntryStorageContinuationAuthority CreateAuthorityWithShorterParentContext(
        HostReceiptContinuationCase attempt)
    {
        var contextDeadline = attempt.Authority.ParentCall.Deadline.AddSeconds(-2);
        return attempt.Authority with
        {
            ParentContext = attempt.Authority.ParentContext with { Deadline = contextDeadline },
            StorageCall = attempt.Authority.StorageCall with
            {
                Deadline = contextDeadline.AddSeconds(1),
            },
        };
    }

    [Fact]
    public void CrossSidecarReceivingRootReservationsRemainConsumedAfterCompletionAndRevoke()
    {
        var target = CreateFixture(
            maxInFlight: 4,
            maxCalls: 8,
            moduleId: "target-module",
            graphId: "target-graph");
        ConsumeStorageCalls(target, 8, "cross-root-budget");

        var sourceOne = CreateFixture(moduleId: "source-one", graphId: "source-one-graph");
        var sourceTwo = CreateFixture(moduleId: "source-two", graphId: "source-two-graph");
        var sourceThree = CreateFixture(moduleId: "source-three", graphId: "source-three-graph");
        var sourceFour = CreateFixture(moduleId: "source-four", graphId: "source-four-graph");
        var first = CreateCrossRelayAttempt(sourceOne, target, _ => (_, hash) => hash);
        var second = CreateCrossRelayAttempt(sourceTwo, target, _ => (_, hash) => hash);
        Assert.True(first.Result.Accepted, first.Result.Message);
        Assert.True(second.Result.Accepted, second.Result.Message);

        var rejectedBeforeCleanup = CreateCrossRelayAttempt(sourceThree, target, _ => (_, hash) => hash);
        Assert.Equal(
            SidecarCapabilityErrors.ConcurrencyLimit,
            rejectedBeforeCleanup.Result.Code);
        Assert.True(sourceThree.Session.CompleteCall(rejectedBeforeCleanup.ParentCall.CallId, 1).Accepted);

        Assert.True(target.Session.RevokeCrossSidecarActionEntry(
            first.Relay!.Carrier.CarrierId,
            target.Now).Accepted);

        var terminal = new SidecarActionTerminalRegistration(
            Guid.NewGuid(),
            second.Relay!.Descriptor.InputTypeIdentity,
            second.Relay.Descriptor.InputSchemaVersion,
            second.Relay.Descriptor.ResultTypeIdentity,
            second.Relay.Descriptor.ResultSchemaVersion,
            second.Relay.Descriptor.DescriptorHash);
        Assert.True(target.Session.BeginCrossSidecarActionEntryCall(
            second.Relay.Carrier,
            terminal,
            second.Relay.Carrier.Action.ByteLength,
            target.Now,
            out _,
            (authority, hash) => authority.Proof == hash).Accepted);
        var receipt = new SidecarTerminalReceipt(
            "cross-root-complete",
            second.Relay.Descriptor.Key,
            second.Relay.Descriptor.Version,
            second.Relay.Carrier.Authority.TargetChildCall.CallId,
            second.Relay.Carrier.Authority.Attempt,
            "cross-root-scope",
            second.Relay.Carrier.Action.ContentHash);
        Assert.True(target.Session.RecordTerminal(
            second.Relay.Carrier.Authority.TargetChildCall.CallId,
            terminal.TerminalId,
            receipt).Accepted);
        var result = Payload(second.Relay.Descriptor.ResultTypeIdentity, new { value = 1 });
        var outcome = new SidecarActionOutcomeEnvelope(
            ActionOutcomeKind.Completed,
            result,
            null,
            null,
            null,
            receipt,
            target.Binding.SafeFailure,
            1);
        var execution = new SidecarTerminalExecutionResult(result, null, true);
        var resultIdentity = new SidecarActionResultIdentity(
            Guid.NewGuid(),
            second.Relay.Carrier.Authority.TargetChildCall.CallId,
            second.Relay.Descriptor.Key,
            second.Relay.Descriptor.Version,
            result.TypeIdentity,
            result.ContentHash);
        Assert.True(target.Session.CompleteCrossSidecarActionEntry(
            second.Relay.Carrier,
            outcome,
            receipt,
            execution,
            resultIdentity,
            target.Binding.SafeFailure,
            target.Now,
            (_, hash) => hash,
            out _).Accepted);

        var rejectedAfterCleanup = CreateCrossRelayAttempt(sourceFour, target, _ => (_, hash) => hash);
        Assert.Equal(
            SidecarCapabilityErrors.ConcurrencyLimit,
            rejectedAfterCleanup.Result.Code);
        Assert.True(sourceFour.Session.CompleteCall(rejectedAfterCleanup.ParentCall.CallId, 1).Accepted);
    }

    [Fact]
    public void CrossSidecarReceivingRootReservationsRemainConsumedAfterExpiryAndPeerCleanup()
    {
        var target = CreateFixture(
            maxInFlight: 4,
            maxCalls: 8,
            moduleId: "target-expiry-module",
            graphId: "target-expiry-graph");
        ConsumeStorageCalls(target, 8, "cross-root-expiry");

        var sourceOne = CreateFixture(moduleId: "expiry-source-one", graphId: "expiry-source-one-graph");
        var sourceTwo = CreateFixture(moduleId: "expiry-source-two", graphId: "expiry-source-two-graph");
        var sourceThree = CreateFixture(moduleId: "expiry-source-three", graphId: "expiry-source-three-graph");
        var first = CreateCrossRelayAttempt(sourceOne, target, _ => (_, hash) => hash);
        var second = CreateCrossRelayAttempt(sourceTwo, target, _ => (_, hash) => hash);
        Assert.True(first.Result.Accepted, first.Result.Message);
        Assert.True(second.Result.Accepted, second.Result.Message);

        var expiry = second.Relay!.Carrier.ExpiresAt.AddSeconds(1);
        Assert.Equal(2, target.Session.SweepExpiredHostActionEntryCarriers(expiry));
        Assert.True(sourceOne.Session.CompleteCall(first.ParentCall.CallId, 1).Accepted);
        Assert.True(sourceTwo.Session.CompleteCall(second.ParentCall.CallId, 1).Accepted);

        var rejected = CreateCrossRelayAttempt(sourceThree, target, _ => (_, hash) => hash);
        Assert.Equal(SidecarCapabilityErrors.ConcurrencyLimit, rejected.Result.Code);
        Assert.True(sourceThree.Session.CompleteCall(rejected.ParentCall.CallId, 1).Accepted);
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
        PrepareCrossParent(Fixture fixture, string key, long sequence = 1)
    {
        var call = fixture.Call with
        {
            Capability = SidecarCapabilityKind.Action,
            CallId = Guid.NewGuid(),
            ReplayNonce = $"{key}-nonce",
            Sequence = sequence,
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
        return new CrossRelayFixture(
            parent.Call,
            relay!,
            target.Session,
            target.Binding,
            source.Now,
            parent.Context,
            parent.Action);
    }

    private static HostReceiptContinuationCase PrepareHostReceiptContinuationCase(
        Func<SidecarTerminalReceipt, SidecarTerminalReceipt>? mutateHostReceipt,
        Func<SidecarTerminalReceipt, SidecarTerminalReceipt>? mutatePeerReceipt = null,
        bool importPeerContinuation = true,
        bool recordHostReceipt = true)
    {
        var source = CreateFixture(
            moduleId: "source-module",
            graphId: "source-graph");
        var hostTarget = CreateFixture(
            maxInFlight: 4,
            maxCalls: 8,
            moduleId: "target-module",
            graphId: "target-graph",
            authenticateHostTerminalAuthority: static (authority, hash) => authority.Proof == hash,
            authenticateStorageContinuationAuthority: static (authority, hash) =>
                authority.Proof == hash &&
                hash == SidecarCapabilityTransportValidation.ComputeStorageContinuationBindingHash(authority));
        var targetPeer = CreateMirroredFixture(
            hostTarget,
            static (authority, hash) => authority.Proof == hash,
            static (authority, hash) =>
                authority.Proof == hash &&
                hash == SidecarCapabilityTransportValidation.ComputeStorageContinuationBindingHash(authority));
        ConsumeStorageCalls(hostTarget, 7, "receipt-host-prior");
        ConsumeStorageCalls(targetPeer, 7, "receipt-peer-prior");

        var cross = CreateCrossRelay(source, hostTarget);
        var hostActivation = cross.Now.AddSeconds(1);
        var peerImportTime = cross.Now.AddSeconds(2);
        var peerActivation = cross.Now.AddSeconds(3);
        var continuationIssued = cross.Now.AddSeconds(4);
        var peerContinuationImport = cross.Now.AddSeconds(5);
        var peerStorageBegin = cross.Now.AddSeconds(6);
        var hostImport = cross.Now.AddSeconds(7);
        var descriptor = cross.Relay.Descriptor;
        var terminal = new SidecarActionTerminalRegistration(
            Guid.NewGuid(),
            descriptor.InputTypeIdentity,
            descriptor.InputSchemaVersion,
            descriptor.ResultTypeIdentity,
            descriptor.ResultSchemaVersion,
            descriptor.DescriptorHash);
        Assert.True(hostTarget.Session.BeginCrossSidecarActionEntryCall(
            cross.Relay.Carrier,
            terminal,
            cross.Relay.Carrier.Action.ByteLength,
            hostActivation,
            out var hostContext,
            static (authority, hash) => authority.Proof == hash).Accepted);
        Assert.NotNull(hostContext);

        var hostActionRequest = SidecarActionCapabilityRequest.HostEntry(
            cross.Relay.Carrier.Authority.TargetChildCall,
            descriptor,
            cross.Relay.Carrier.Action,
            new SidecarCancellationIdentity(
                hostTarget.Binding.CancellationId,
                "receipt-host-cancellation",
                cross.Relay.Carrier.Authority.Deadline),
            cross.Relay.Carrier.Authority.Deadline,
            hostContext!,
            terminal);
        var hostReceipt = new SidecarTerminalReceipt(
            "receipt-host",
            descriptor.Key,
            descriptor.Version,
            cross.Relay.Carrier.Authority.TargetChildCall.CallId,
            cross.Relay.Carrier.Authority.Attempt,
            "receipt-host-scope",
            cross.Relay.Carrier.Action.ContentHash);
        var storedHostReceipt = mutateHostReceipt is null
            ? hostReceipt
            : mutateHostReceipt(hostReceipt);
        if (recordHostReceipt)
        {
            Assert.True(hostTarget.Session.RecordTerminal(
                cross.Relay.Carrier.Authority.TargetChildCall.CallId,
                terminal.TerminalId,
                storedHostReceipt).Accepted);
        }

        var terminalRequest = CreateTerminalRequest(
            hostTarget,
            hostActionRequest,
            new ActionPipelineSnapshot("receipt-snapshot", []),
            hostReceipt) with
        {
            CrossSidecarPeerRelay = cross.Relay,
            CrossSidecarActionRequest = new SidecarCrossSidecarActionEntryRequest(
                descriptor.Key,
                descriptor.Version,
                cross.Relay.Carrier.Action,
                cross.Relay.Carrier.Authority.Deadline,
                cross.Now.AddMinutes(2)),
        };
        terminalRequest = terminalRequest with
        {
            Authority = terminalRequest.Authority with
            {
                RootPeerCall = cross.Relay.PeerCall,
                CrossSidecarPeerRelayBindingHash =
                    SidecarCapabilityTransportValidation.ComputeCrossSidecarPeerRelayBindingHash(cross.Relay),
            },
        };
        terminalRequest = terminalRequest with
        {
            Authority = terminalRequest.Authority with
            {
                CanonicalBindingHash =
                    SidecarCapabilityTransportValidation.ComputeTerminalAuthorityBindingHash(terminalRequest.Authority),
                Proof = string.Empty,
            },
        };
        terminalRequest = terminalRequest with
        {
            Authority = terminalRequest.Authority with
            {
                Proof = terminalRequest.Authority.CanonicalBindingHash,
            },
        };
        terminalRequest = SidecarCapabilityTransportCodec.Deserialize<SidecarActionTerminalTransportRequest>(
            SidecarCapabilityTransportCodec.Serialize(terminalRequest));

        var peerImport = targetPeer.Session.ImportCrossSidecarActionEntryPeerRelay(
            terminalRequest,
            peerImportTime,
            static (authority, hash) => authority.Proof == hash,
            out var importedCarrier);
        Assert.True(peerImport.Accepted, peerImport.Message);
        Assert.NotNull(importedCarrier);
        Assert.True(targetPeer.Session.BeginCrossSidecarActionEntryCall(
            importedCarrier!,
            terminal,
            importedCarrier!.Action.ByteLength,
            peerActivation,
            out _,
            static (authority, hash) => authority.Proof == hash).Accepted);
        var peerReceipt = new SidecarTerminalReceipt(
            "receipt-peer",
            descriptor.Key,
            descriptor.Version,
            cross.Relay.PeerCall!.CallId,
            cross.Relay.Carrier.Authority.Attempt,
            "receipt-peer-scope",
            cross.Relay.Carrier.Action.ContentHash);
        Assert.True(targetPeer.Session.RecordTerminal(
            cross.Relay.PeerCall.CallId,
            terminal.TerminalId,
            mutatePeerReceipt is null ? peerReceipt : mutatePeerReceipt(peerReceipt)).Accepted);

        var storageCall = cross.Relay.PeerCall with
        {
            Capability = SidecarCapabilityKind.Storage,
            CallId = Guid.NewGuid(),
            ReplayNonce = "receipt-storage-continuation",
            Sequence = cross.Relay.PeerCall.Sequence + 1,
        };
        var storagePayload = Payload("receipt-storage.request", new { value = 4 });
        var storageRequest = SidecarStorageCapabilityRequest.Invoke(
            storageCall,
            hostTarget.Binding.ModuleId,
            "receipt-storage/get",
            storagePayload,
            PayloadType("receipt-storage.result"),
            new SidecarCancellationIdentity(
                hostTarget.Binding.CancellationId,
                "receipt-storage-cancellation",
                storageCall.Deadline),
            storageCall.Deadline);
        var issue = targetPeer.Session.IssueHostEntryStorageContinuation(
            targetPeer.Session,
            cross.Relay.PeerCall,
            cross.Relay.PeerCall,
            storageRequest,
            continuationIssued,
            static (_, hash) => hash,
            out var authority);
        Assert.True(issue.Accepted, issue.Message);
        Assert.NotNull(authority);
        var wireAuthority = SidecarCapabilityTransportCodec.Deserialize<SidecarHostEntryStorageContinuationAuthority>(
            SidecarCapabilityTransportCodec.Serialize(authority));
        var wireRequest = storageRequest with { HostEntryContinuationAuthority = wireAuthority };
        if (importPeerContinuation)
        {
            Assert.True(targetPeer.Session.ImportHostEntryStorageContinuationAuthority(
                wireAuthority,
                peerContinuationImport).Accepted);
            Assert.True(targetPeer.Session.BeginStorageContinuationCall(
                wireRequest,
                storagePayload.ByteLength,
                peerStorageBegin,
                out _).Accepted);
        }

        return new HostReceiptContinuationCase(
            source,
            cross.ParentCall,
            hostTarget,
            targetPeer,
            wireRequest,
            wireAuthority,
            hostImport,
            peerContinuationImport,
            cross.Relay.Carrier.Authority.IssuedAt,
            continuationIssued,
            cross.Relay.Carrier.Authority.TargetChildCall,
            cross.Relay.Carrier.Authority.Attempt);
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

    private static void ConsumeStorageCalls(
        Fixture fixture,
        int count,
        string noncePrefix,
        long startingSequence = 1)
    {
        for (var index = 0; index < count; index++)
        {
            var call = fixture.Call with
            {
                CallId = Guid.NewGuid(),
                ReplayNonce = $"{noncePrefix}-{index}",
                Sequence = startingSequence + index,
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
        bool bindPayload = false,
        Guid? conversationId = null,
        ExtensionFeatureSet? features = null)
    {
        var request = new HostActionEntryContextRequest(
            ingress,
            Guid.NewGuid(),
            fixture.Binding.RequestId,
            fixture.Binding.CancellationId,
            caller,
            features ?? ExtensionFeatureSet.Empty,
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
                    HostActionEntryIngress.Tool => new HostActionEntryIngressBinding(
                        ingress,
                        "clock_now",
                        conversationId?.ToString("D")),
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
        HostActionEntryRequestContext context,
        SidecarCapabilityCallIdentity? endpointCall = null)
    {
        if (context.Ingress == HostActionEntryIngress.Endpoint)
        {
            if (endpointCall is null)
                throw new ArgumentException("Endpoint activation requires its route call.", nameof(endpointCall));

            var routeRequest = EndpointRouteRequest(
                fixture,
                context,
                HostEndpointTransport.Http);
            var routeIssue = fixture.Session.IssueHostEndpointRouteAuthority(
                routeRequest,
                endpointCall,
                fixture.Now,
                HostEndpointRouteAuthorityValidator.ComputeBindingHash,
                out var routeAuthority);
            Assert.True(routeIssue.Accepted, routeIssue.Message);
            Assert.NotNull(routeAuthority);

            var routeCarrier = new HostActionEntryCarrierIdentity(
                HostActionEntryIngress.Endpoint,
                context.InvocationId,
                context.Contribution!.IngressBinding);
            var routeAdmission = fixture.Session.BeginHostEndpointRouteCarrier(
                routeRequest,
                routeAuthority!,
                routeCarrier,
                fixture.Now,
                out var routeCarrierAuthority);
            Assert.True(routeAdmission.Accepted, routeAdmission.Message);
            Assert.NotNull(routeCarrierAuthority);
            return routeCarrierAuthority!;
        }

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

    private static HostEndpointRouteRequest EndpointRouteRequest(
        Fixture fixture,
        HostActionEntryRequestContext context,
        HostEndpointTransport transport) =>
        new(
            new HostEndpointInvocation(context.InvocationId, "/demo", context),
            new HostEndpointRouteIdentity(
                "/demo",
                transport == HostEndpointTransport.Http ? "/api/items" : "/socket",
                transport == HostEndpointTransport.Http ? "POST" : "GET",
                transport),
            new Dictionary<string, string[]>(StringComparer.Ordinal)
            {
                ["x-request"] = ["one", "two"],
                ["x-empty"] = [],
            },
            new Dictionary<string, string[]>(StringComparer.Ordinal)
            {
                ["tag"] = ["one", "two"],
            },
            [0, 255, 1, 2])
        {
            RouteValues = new Dictionary<string, string[]>(StringComparer.Ordinal)
            {
                ["id"] = ["71e8f8f6-b8f3-4aaf-bcc1-c0879b0f0eb2"],
            },
        };

    private static HostEndpointRouteRequest MalformedEndpointRouteRequest(
        HostEndpointRouteRequest request,
        string mutation) => mutation switch
        {
            "invocation" => request with
            {
                Invocation = request.Invocation with { Endpoint = null! },
            },
            "route" => request with { Route = null! },
            "route-values" => request with { RouteValues = null! },
            "headers" => request with { Headers = null! },
            "query" => request with { Query = null! },
            "metadata-array" => request with
            {
                Headers = new Dictionary<string, string[]>(StringComparer.Ordinal)
                {
                    ["x-request"] = null!,
                },
            },
            "metadata-value" => request with
            {
                Headers = new Dictionary<string, string[]>(StringComparer.Ordinal)
                {
                    ["x-request"] = [null!],
                },
            },
            "body" => request with { Body = null! },
            _ => throw new ArgumentOutOfRangeException(nameof(mutation)),
        };

    private static HostEndpointRouteAuthority ResignEndpointAuthority(
        HostEndpointRouteAuthority authority)
    {
        var hash = HostEndpointRouteAuthorityValidator.ComputeBindingHash(authority);
        return authority with { CanonicalBindingHash = hash, Proof = hash };
    }

    private static string KeyedEndpointProof(string domain, string hash)
    {
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes("endpoint-route-relay-test-key"));
        return Convert.ToHexString(hmac.ComputeHash(Encoding.UTF8.GetBytes($"{domain}:{hash}")));
    }

    private static string IssueEndpointChildImportAcknowledgment(
        SidecarEndpointTypedActionChildImportAcknowledgment acknowledgment) =>
        KeyedEndpointProof(
            "child-import",
            SidecarEndpointTypedActionChildValidation.ComputeImportAcknowledgmentHash(acknowledgment));

    private static string IssueEndpointChildImportAbort(
        SidecarEndpointTypedActionChildImportAbort abort) =>
        KeyedEndpointProof(
            "child-import-abort",
            SidecarEndpointTypedActionChildValidation.ComputeImportAbortHash(abort));

    private static SidecarEndpointTypedActionChildImportAcknowledgment
        MutateEndpointChildImportAcknowledgment(
            SidecarEndpointTypedActionChildImportAcknowledgment acknowledgment,
            string mutation)
    {
        var changedId = Guid.Parse("ffffffff-ffff-ffff-ffff-fffffffffff1");
        var relay = acknowledgment.Relay;
        var reservation = relay.ReceivingReservation;
        var child = reservation.Child;
        switch (mutation)
        {
            case "relay-hash":
                relay = relay with { CanonicalBindingHash = "changed-relay-hash" };
                break;
            case "reservation":
                relay = relay with
                {
                    ReceivingReservation = reservation with { ReservationId = changedId },
                };
                break;
            case "child-call":
                relay = relay with
                {
                    ReceivingReservation = reservation with
                    {
                        Child = child with
                        {
                            Call = child.Call with { CallId = changedId },
                        },
                    },
                };
                break;
            case "parent":
                relay = relay with
                {
                    SourceParentCall = relay.SourceParentCall with { CallId = changedId },
                };
                break;
            case "binding":
                acknowledgment = acknowledgment with
                {
                    ReceivingBindingHash = "changed-receiving-binding-hash",
                };
                break;
            case "generation":
                acknowledgment = acknowledgment with
                {
                    SourceBindingGeneration = acknowledgment.SourceBindingGeneration + 1,
                };
                break;
            case "deadline":
                relay = relay with
                {
                    SourceParentCall = relay.SourceParentCall with
                    {
                        Deadline = relay.SourceParentCall.Deadline.AddSeconds(-1),
                    },
                };
                break;
            case "cancellation":
                relay = relay with
                {
                    ReceivingReservation = reservation with
                    {
                        Child = child with
                        {
                            Call = child.Call with { CancellationId = changedId },
                        },
                    },
                };
                break;
            case "proof":
                return acknowledgment with { Proof = "forged-child-import-proof" };
            case "expiry":
                acknowledgment = acknowledgment with
                {
                    ExpiresAt = acknowledgment.ExpiresAt.AddSeconds(1),
                };
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(mutation));
        }

        var resigned = acknowledgment with { Relay = relay };
        var hash = SidecarEndpointTypedActionChildValidation.ComputeImportAcknowledgmentHash(resigned);
        return resigned with
        {
            CanonicalBindingHash = hash,
            Proof = KeyedEndpointProof("child-import", hash),
        };
    }

    private static SidecarHostEndpointRouteRelay ResignEndpointRelay(
        SidecarHostEndpointRouteRelay relay)
    {
        var hash = SidecarCapabilityTransportValidation.ComputeEndpointRouteRelayBindingHash(relay);
        return relay with
        {
            CanonicalBindingHash = hash,
            Proof = KeyedEndpointProof("relay", hash),
        };
    }

    private static SidecarCapabilitySessionBinding CreateRotatedBinding(
        Fixture fixture,
        string nonce,
        int? actionResultBytes = null,
        DateTimeOffset? minimumExpiry = null)
    {
        var expiry = fixture.Binding.ExpiresAt.AddMinutes(1);
        if (minimumExpiry is { } requiredExpiry && expiry < requiredExpiry)
            expiry = requiredExpiry;
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

    private static SidecarSerializedPayload EndpointInvocationPayload(
        string typeIdentity,
        HostEndpointInvocation invocation)
    {
        var encoded = SidecarCapabilityTransportCodec.Serialize(invocation);
        using var document = JsonDocument.Parse(encoded);
        var canonicalBytes = SidecarCapabilityTransportCodec.Serialize(document.RootElement);
        return new SidecarSerializedPayload(
            typeIdentity,
            1,
            SidecarCapabilityTransportCodec.ComputeSha256(canonicalBytes),
            document.RootElement.Clone(),
            canonicalBytes.Length);
    }

    private static void CleanupEndpointTypedActionChildParents(
        EndpointTypedActionChildCase test)
    {
        Assert.True(test.Receiving.Session.CompleteCall(
            test.ReceivingParent.Call.CallId,
            0).Accepted);
        Assert.True(test.Receiving.Session.CompleteHostActionEntryCarrier(
            test.ReceivingParent.Carrier,
            HostActionEntryCarrierCompletionKind.Succeeded,
            test.Receiving.Now).Accepted);
        Assert.True(test.Source.Session.CompleteHostEndpointRouteRelay(
            test.RouteRelay,
            test.Source.Now).Accepted);
        var cleanupSourceParentCompletion = test.Source.Session.CompleteCall(
            test.SourceParent.Call.CallId,
            0);
        Assert.True(
            cleanupSourceParentCompletion.Accepted,
            $"{cleanupSourceParentCompletion.Code}: {cleanupSourceParentCompletion.Message}");
        Assert.Equal(
            SidecarCapabilityErrors.Replay,
            test.Source.Session.CompleteHostActionEntryCarrier(
                test.SourceParent.Carrier,
                HostActionEntryCarrierCompletionKind.Succeeded,
                test.Source.Now).Code);
    }

    private static void SweepEndpointTypedActionChildOutcome(
        EndpointTypedActionChildCase test,
        DateTimeOffset now,
        bool sweepSourceFirst)
    {
        if (sweepSourceFirst)
        {
            test.Source.Session.SweepExpiredHostActionEntryCarriers(now);
            test.Receiving.Session.SweepExpiredHostActionEntryCarriers(now);
            return;
        }

        test.Receiving.Session.SweepExpiredHostActionEntryCarriers(now);
        test.Source.Session.SweepExpiredHostActionEntryCarriers(now);
    }

    private static EndpointTypedActionChildCase CompleteAndRotateAfterEndpointTypedActionChildOutcome(
        EndpointTypedActionChildCase test,
        DateTimeOffset now,
        string key)
    {
        Assert.True(test.Receiving.Session.CompleteCall(
            test.ReceivingParent.Call.CallId,
            0).Accepted);
        Assert.Equal(
            SidecarCapabilityErrors.Replay,
            test.Receiving.Session.CompleteHostActionEntryCarrier(
                test.ReceivingParent.Carrier,
                HostActionEntryCarrierCompletionKind.Succeeded,
                now).Code);
        Assert.Equal(
            SidecarCapabilityErrors.Replay,
            test.Source.Session.CompleteHostEndpointRouteRelay(
                test.RouteRelay,
                now).Code);
        Assert.True(test.Source.Session.CompleteCall(
            test.SourceParent.Call.CallId,
            0).Accepted);
        Assert.Equal(
            SidecarCapabilityErrors.Replay,
            test.Source.Session.CompleteHostActionEntryCarrier(
                test.SourceParent.Carrier,
                HostActionEntryCarrierCompletionKind.Succeeded,
                now).Code);

        var minimumExpiry = now.AddMinutes(2);
        var sourceBinding = CreateRotatedBinding(
            test.Source,
            $"{key}-source-rotation",
            minimumExpiry: minimumExpiry);
        test.Source.BindingHashes.Add(sourceBinding.Authentication.BindingHash);
        var sourceRotation = test.Source.Session.RotateBinding(sourceBinding, now);
        Assert.True(
            sourceRotation.Accepted,
            $"{sourceRotation.Code}: {sourceRotation.Message}");

        var receivingBinding = CreateRotatedBinding(
            test.Receiving,
            $"{key}-receiving-rotation",
            minimumExpiry: minimumExpiry);
        test.Receiving.BindingHashes.Add(receivingBinding.Authentication.BindingHash);
        var receivingRotation = test.Receiving.Session.RotateBinding(receivingBinding, now);
        Assert.True(
            receivingRotation.Accepted,
            $"{receivingRotation.Code}: {receivingRotation.Message}");

        return test with
        {
            Source = WithRotatedBinding(test.Source, sourceBinding, now),
            Receiving = WithRotatedBinding(test.Receiving, receivingBinding, now),
        };
    }

    private static Fixture WithRotatedBinding(
        Fixture fixture,
        SidecarCapabilitySessionBinding binding,
        DateTimeOffset now) =>
        fixture with
        {
            Now = now,
            Binding = binding,
            Call = fixture.Call with
            {
                ModuleId = binding.ModuleId,
                GraphId = binding.GraphId,
                SessionId = binding.SessionId,
                RequestId = binding.RequestId,
                CancellationId = binding.CancellationId,
                Deadline = now.AddMinutes(1),
            },
        };

    private static SidecarEndpointTypedActionChildImportAbort
        AbortUnimportedEndpointTypedActionChild(
        EndpointTypedActionChildCase test,
        DateTimeOffset now)
    {
        var issue = test.Source.Session.IssueHostEndpointTypedActionChildImportAbort(
            test.WireRelay,
            now,
            IssueEndpointChildImportAbort,
            out var abort);
        Assert.True(issue.Accepted, issue.Message);
        Assert.NotNull(abort);

        var wireAbort = SidecarCapabilityTransportCodec.Deserialize<
            SidecarEndpointTypedActionChildImportAbort>(
            SidecarCapabilityTransportCodec.Serialize(abort!));
        var consume = test.Receiving.Session.ConsumeHostEndpointTypedActionChildImportAbort(
            wireAbort,
            now);
        Assert.True(consume.Accepted, consume.Message);

        var complete = test.Source.Session.CompleteHostEndpointTypedActionChildImportAbort(
            wireAbort,
            now);
        Assert.True(complete.Accepted, complete.Message);
        return wireAbort;
    }

    private static void CompleteNextNormalRootRelay(
        Fixture source,
        Fixture receiving,
        HostEndpointTransport transport,
        string key,
        long sequence = 3)
    {
        var descriptor = NestedDescriptor(
            $"{key}.{transport}.root",
            typeof(string).AssemblyQualifiedName!);
        var action = Payload(descriptor.InputTypeIdentity, $"{key}-{transport}");
        var context = IssueContext(
            source,
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
        var sourceCarrier = ActivateContext(source, context);
        var sourceCall = ActionCall(source, sequence, $"{key}-source");
        var peerCall = sourceCall with
        {
            SessionId = receiving.Binding.SessionId,
            RequestId = receiving.Binding.RequestId,
            CancellationId = receiving.Binding.CancellationId,
            ModuleId = receiving.Binding.ModuleId,
            GraphId = receiving.Binding.GraphId,
            ReplayNonce = $"{key}-peer",
        };
        var sourceBegin = source.Session.BeginCall(
            sourceCall,
            SidecarCapabilityKind.Action,
            action,
            action.ByteLength,
            source.Now,
            context);
        Assert.True(
            sourceBegin.Accepted,
            $"{sourceBegin.Code}: {sourceBegin.Message}; sequence={source.Session.LastSequence}");
        var terminal = new SidecarActionTerminalRegistration(
            Guid.NewGuid(),
            descriptor.InputTypeIdentity,
            descriptor.InputSchemaVersion,
            descriptor.ResultTypeIdentity,
            descriptor.ResultSchemaVersion,
            descriptor.DescriptorHash);
        var receipt = new SidecarTerminalReceipt(
            $"{key}-source-receipt",
            descriptor.Key,
            descriptor.Version,
            sourceCall.CallId,
            1,
            $"{key}-source-scope",
            action.ContentHash);
        Assert.True(source.Session.RecordTerminal(
            sourceCall.CallId,
            terminal.TerminalId,
            receipt).Accepted);
        var request = SidecarActionCapabilityRequest.HostEntry(
            sourceCall,
            descriptor,
            action,
            Cancellation(source),
            sourceCall.Deadline,
            context,
            terminal);
        var authority = CreateTerminalRequest(
            source,
            request,
            new ActionPipelineSnapshot($"{key}-snapshot", []),
            receipt).Authority with
        {
            RootPeerCall = peerCall,
            ReceivingRootBudgetId = sourceCarrier.CapabilityId,
            ReceivingPeerBindingGeneration = receiving.Session.BindingGeneration,
        };
        authority = authority with
        {
            CanonicalBindingHash = SidecarCapabilityTransportValidation.ComputeTerminalAuthorityBindingHash(
                authority),
            Proof = string.Empty,
        };
        authority = authority with { Proof = authority.CanonicalBindingHash };

        var rootRelayIssue = source.Session.IssueHostActionEntryPeerRootRelay(
            sourceCall,
            peerCall,
            descriptor,
            action,
            terminal,
            new ActionPipelineSnapshot($"{key}-snapshot", []),
            receiving.Session,
            authority,
            source.Now,
            out var issuedRelay);
        Assert.True(
            rootRelayIssue.Accepted,
            $"{rootRelayIssue.Code}: {rootRelayIssue.Message}; source-sequence={source.Session.LastSequence}; receiving-sequence={receiving.Session.LastSequence}");
        Assert.NotNull(issuedRelay);
        var wireRelay = SidecarCapabilityTransportCodec.Deserialize<SidecarHostActionEntryRootRelay>(
            SidecarCapabilityTransportCodec.Serialize(issuedRelay!));
        Assert.True(receiving.Session.ImportHostActionEntryPeerRootRelay(
            wireRelay,
            receiving.Now,
            out var receivingContext).Accepted);
        Assert.NotNull(receivingContext);
        var receivingRequest = SidecarActionCapabilityRequest.HostEntry(
            peerCall,
            descriptor,
            action,
            Cancellation(receiving),
            peerCall.Deadline,
            receivingContext,
            terminal);
        Assert.True(receiving.Session.BeginActionCall(
            receivingRequest,
            action.ByteLength,
            receiving.Now,
            out var terminalContext).Accepted);
        Assert.NotNull(terminalContext);
        Assert.True(receiving.Session.TryGetActiveHostActionEntryCarrier(
            terminalContext!.CapabilityId,
            out var receivingCarrier));
        Assert.NotNull(receivingCarrier);
        var receivingReceipt = receipt with
        {
            ReceiptId = $"{key}-peer-receipt",
            CallId = peerCall.CallId,
            IdempotencyScope = $"{key}-peer-scope",
        };
        Assert.True(receiving.Session.RecordTerminal(
            peerCall.CallId,
            terminal.TerminalId,
            receivingReceipt).Accepted);
        Assert.True(receiving.Session.CompleteCall(peerCall.CallId, 1).Accepted);
        Assert.True(receiving.Session.CompleteHostActionEntryCarrier(
            receivingCarrier!,
            HostActionEntryCarrierCompletionKind.Succeeded,
            receiving.Now).Accepted);
        Assert.True(source.Session.CompleteCall(sourceCall.CallId, 1).Accepted);
        Assert.True(source.Session.CompleteHostActionEntryCarrier(
            sourceCarrier,
            HostActionEntryCarrierCompletionKind.Succeeded,
            source.Now).Accepted);

        var sourceRotated = CreateRotatedBinding(source, $"{key}-source-rotation");
        source.BindingHashes.Add(sourceRotated.Authentication.BindingHash);
        var sourceRotation = source.Session.RotateBinding(sourceRotated, source.Now);
        Assert.True(
            sourceRotation.Accepted,
            $"{sourceRotation.Code}: {sourceRotation.Message}; issued-contexts={source.Session.IssuedHostActionEntryContextCount}; active-carriers={source.Session.ActiveHostActionEntryCarrierCount}; sequence={source.Session.LastSequence}");
        var receivingRotated = CreateRotatedBinding(receiving, $"{key}-receiving-rotation");
        receiving.BindingHashes.Add(receivingRotated.Authentication.BindingHash);
        Assert.True(receiving.Session.RotateBinding(receivingRotated, receiving.Now).Accepted);
    }

    private static EndpointTypedActionChildReservationCase CreateEndpointTypedActionChildReservationOnlyCase(
        HostEndpointTransport transport)
    {
        static bool AuthenticateHostTerminal(SidecarHostTerminalAuthority authority, string hash) =>
            authority.Proof == hash;
        static bool AuthenticateRoute(HostEndpointRouteAuthority authority, string hash) =>
            authority.Proof == KeyedEndpointProof("route", hash);
        static bool AuthenticateRelay(SidecarHostEndpointRouteRelay relay, string hash) =>
            relay.Proof == KeyedEndpointProof("relay", hash);

        var source = CreateFixture(
            maxInFlight: 3,
            actionInputBytes: 4096,
            protocolMessageBytes: 65536,
            authenticateHostTerminalAuthority: AuthenticateHostTerminal,
            authenticateEndpointRouteAuthority: AuthenticateRoute);
        var receiving = CreateMirroredFixture(
            source,
            maxInFlight: 3,
            actionInputBytes: 4096,
            protocolMessageBytes: 65536,
            authenticateHostTerminalAuthority: AuthenticateHostTerminal,
            authenticateEndpointRouteAuthority: AuthenticateRoute,
            authenticateEndpointRouteRelay: AuthenticateRelay);
        var sourceContext = IssueContext(
            source,
            new RequestPrincipal(
                "endpoint-user",
                Roles: new HashSet<string>(["reader"], StringComparer.Ordinal)),
            HostActionEntryIngress.Endpoint,
            lineage: new HostActionEntryLineage(
                new SharpClawActionKey("endpoint.invoke"),
                1,
                "endpoint-invoke-descriptor",
                typeof(HostEndpointInvocation).AssemblyQualifiedName!,
                1,
                "endpoint-invoke-schema",
                null,
                null));
        var request = EndpointRouteRequest(source, sourceContext, transport);
        var sourceCall = ActionCall(source, 1, "endpoint-child-pre-relay-source");
        var receivingCall = ActionCall(receiving, 1, "endpoint-child-pre-relay-receiving");
        var routeReservationResult = receiving.Session.IssueHostEndpointRouteReservation(
            request,
            receivingCall,
            receiving.Now,
            reservation => KeyedEndpointProof(
                "reservation",
                SidecarCapabilityTransportValidation.ComputeEndpointRouteReservationBindingHash(
                    reservation)),
            out var routeReservation);
        Assert.True(routeReservationResult.Accepted, routeReservationResult.Message);
        Assert.NotNull(routeReservation);
        var wireRouteReservation = SidecarCapabilityTransportCodec.Deserialize<
            SidecarHostEndpointRouteReservation>(
            SidecarCapabilityTransportCodec.Serialize(routeReservation));
        var routeRelayResult = source.Session.IssueHostEndpointRouteRelay(
            request,
            sourceCall,
            wireRouteReservation,
            source.Now,
            authority => KeyedEndpointProof(
                "route",
                HostEndpointRouteAuthorityValidator.ComputeBindingHash(authority)),
            (candidate, hash) => candidate.Proof == KeyedEndpointProof("reservation", hash),
            (candidate, hash) => KeyedEndpointProof("relay", hash),
            out var routeRelay);
        Assert.True(routeRelayResult.Accepted, routeRelayResult.Message);
        Assert.NotNull(routeRelay);
        var wireRouteRelay = SidecarCapabilityTransportCodec.Deserialize<
            SidecarHostEndpointRouteRelay>(
            SidecarCapabilityTransportCodec.Serialize(routeRelay));

        var sourceCarrier = new HostActionEntryCarrierIdentity(
            HostActionEntryIngress.Endpoint,
            sourceContext.InvocationId,
            sourceContext.Contribution!.IngressBinding);
        var sourceCarrierResult = source.Session.BeginHostEndpointRouteCarrier(
            request,
            routeRelay!.Authority,
            sourceCarrier,
            source.Now,
            out var sourceCarrierAuthority);
        Assert.True(sourceCarrierResult.Accepted, sourceCarrierResult.Message);
        Assert.NotNull(sourceCarrierAuthority);
        var sourcePayload = EndpointInvocationPayload(
            typeof(HostEndpointInvocation).AssemblyQualifiedName!,
            request.Invocation);
        Assert.True(source.Session.BeginCall(
            sourceCall,
            SidecarCapabilityKind.Action,
            sourcePayload,
            sourcePayload.ByteLength,
            source.Now,
            sourceContext).Accepted);
        Assert.True(source.Session.TryGetActiveHostActionEntryContext(
            sourceContext.CapabilityId,
            out var activeSourceContext));
        Assert.NotNull(activeSourceContext);

        var routeImportResult = receiving.Session.ImportHostEndpointRouteRelay(
            wireRouteRelay,
            receiving.Now,
            out var receivingContext);
        Assert.True(routeImportResult.Accepted, routeImportResult.Message);
        Assert.NotNull(receivingContext);
        var receivingPayload = EndpointInvocationPayload(
            typeof(HostEndpointInvocation).AssemblyQualifiedName!,
            wireRouteRelay.Request.Invocation);
        Assert.True(receiving.Session.BeginCall(
            receivingCall,
            SidecarCapabilityKind.Action,
            receivingPayload,
            receivingPayload.ByteLength,
            receiving.Now,
            receivingContext).Accepted);
        Assert.True(receiving.Session.TryGetActiveHostActionEntryCarrier(
            receivingContext!.CapabilityId,
            out var receivingCarrier));
        Assert.NotNull(receivingCarrier);

        var sourceParent = new EndpointTypedActionChildParent(
            request,
            sourceCall,
            routeRelay.Authority,
            sourceCarrierAuthority!,
            activeSourceContext!);
        var receivingParent = new EndpointTypedActionChildParent(
            request,
            receivingCall,
            wireRouteRelay.Authority,
            receivingCarrier!,
            receivingContext);
        var descriptor = NestedDescriptor(
            "endpoint.typed.pre-relay-child",
            typeof(string).AssemblyQualifiedName!);
        var action = Payload(descriptor.InputTypeIdentity, "pre-relay-child");
        var childCall = sourceCall with
        {
            CallId = Guid.NewGuid(),
            ReplayNonce = "endpoint-pre-relay-child",
            Sequence = source.Session.LastSequence + 1,
            Deadline = source.Now.AddSeconds(30),
        };
        var reservationResult = source.Session.IssueHostEndpointTypedActionChildReservation(
            sourceParent.Call,
            sourceParent.ActiveContext,
            childCall,
            descriptor,
            action,
            source.Now,
            candidate => KeyedEndpointProof(
                "child-reservation",
                SidecarEndpointTypedActionChildValidation.ComputeReservationHash(candidate)),
            out var reservation);
        Assert.True(reservationResult.Accepted, reservationResult.Message);
        Assert.NotNull(reservation);
        return new EndpointTypedActionChildReservationCase(
            source,
            receiving,
            sourceParent,
            receivingParent,
            childCall,
            action,
            routeRelay,
            reservation!);
    }

    private static EndpointTypedActionChildCase CreateEndpointTypedActionChildCase(
        HostEndpointTransport transport,
        int maxInFlight = 2,
        int maxCalls = 4)
    {
        static bool AuthenticateHostTerminal(SidecarHostTerminalAuthority authority, string hash) =>
            authority.Proof == hash;
        static bool AuthenticateRoute(HostEndpointRouteAuthority authority, string hash) =>
            authority.Proof == KeyedEndpointProof("route", hash);
        static bool AuthenticateRelay(SidecarHostEndpointRouteRelay relay, string hash) =>
            relay.Proof == KeyedEndpointProof("relay", hash);
        static bool AuthenticateReservation(
            SidecarEndpointTypedActionChildReservation reservation,
            string hash) =>
            reservation.Proof == KeyedEndpointProof("child-reservation", hash);
        static bool AuthenticateChildRelay(
            SidecarEndpointTypedActionChildRelay relay,
            string hash) =>
            relay.Proof == KeyedEndpointProof("child-relay", hash);
        static bool AuthenticateImportAcknowledgment(
            SidecarEndpointTypedActionChildImportAcknowledgment acknowledgment,
            string hash) =>
            acknowledgment.Proof == KeyedEndpointProof("child-import", hash);
        static bool AuthenticateImportAbort(
            SidecarEndpointTypedActionChildImportAbort abort,
            string hash) =>
            abort.Proof == KeyedEndpointProof("child-import-abort", hash);

        var source = CreateFixture(
            maxInFlight: maxInFlight,
            maxCalls: maxCalls,
            actionInputBytes: 4096,
            protocolMessageBytes: 65536,
            authenticateHostTerminalAuthority: AuthenticateHostTerminal,
            authenticateEndpointRouteAuthority: AuthenticateRoute,
            authenticateEndpointTypedActionChildReservation: AuthenticateReservation,
            authenticateEndpointTypedActionChildRelay: AuthenticateChildRelay);
        var receiving = CreateMirroredFixture(
            source,
            maxInFlight: maxInFlight,
            maxCalls: maxCalls,
            actionInputBytes: 4096,
            protocolMessageBytes: 65536,
            authenticateHostTerminalAuthority: AuthenticateHostTerminal,
            authenticateEndpointRouteAuthority: AuthenticateRoute,
            authenticateEndpointRouteRelay: AuthenticateRelay,
            authenticateEndpointTypedActionChildReservation: AuthenticateReservation,
            authenticateEndpointTypedActionChildRelay: AuthenticateChildRelay,
            authenticateEndpointTypedActionChildImportAcknowledgment: AuthenticateImportAcknowledgment,
            authenticateEndpointTypedActionChildImportAbort: AuthenticateImportAbort);

        var sourceContext = IssueContext(
            source,
            new RequestPrincipal(
                "endpoint-user",
                Roles: new HashSet<string>(["reader"], StringComparer.Ordinal)),
            HostActionEntryIngress.Endpoint,
            lineage: new HostActionEntryLineage(
                new SharpClawActionKey("endpoint.invoke"),
                1,
                "endpoint-invoke-descriptor",
                typeof(HostEndpointInvocation).AssemblyQualifiedName!,
                1,
                "endpoint-invoke-schema",
                null,
                null));
        var request = EndpointRouteRequest(source, sourceContext, transport);
        var sourceCall = ActionCall(source, 1, "endpoint-child-source");
        var receivingCall = ActionCall(receiving, 1, "endpoint-child-receiving");
        var routeReservationResult = receiving.Session.IssueHostEndpointRouteReservation(
            request,
            receivingCall,
            receiving.Now,
            reservation => KeyedEndpointProof(
                "reservation",
                SidecarCapabilityTransportValidation.ComputeEndpointRouteReservationBindingHash(
                    reservation)),
            out var routeReservation);
        Assert.True(routeReservationResult.Accepted, routeReservationResult.Message);
        Assert.NotNull(routeReservation);
        var wireRouteReservation = SidecarCapabilityTransportCodec.Deserialize<
            SidecarHostEndpointRouteReservation>(
            SidecarCapabilityTransportCodec.Serialize(routeReservation));
        var routeRelayResult = source.Session.IssueHostEndpointRouteRelay(
            request,
            sourceCall,
            wireRouteReservation,
            source.Now,
            authority => KeyedEndpointProof(
                "route",
                HostEndpointRouteAuthorityValidator.ComputeBindingHash(authority)),
            (candidate, hash) => candidate.Proof == KeyedEndpointProof("reservation", hash),
            (candidate, hash) => KeyedEndpointProof("relay", hash),
            out var routeRelay);
        Assert.True(routeRelayResult.Accepted, routeRelayResult.Message);
        Assert.NotNull(routeRelay);
        var wireRouteRelay = SidecarCapabilityTransportCodec.Deserialize<
            SidecarHostEndpointRouteRelay>(
            SidecarCapabilityTransportCodec.Serialize(routeRelay));

        var sourceCarrier = new HostActionEntryCarrierIdentity(
            HostActionEntryIngress.Endpoint,
            sourceContext.InvocationId,
            sourceContext.Contribution!.IngressBinding);
        var sourceCarrierResult = source.Session.BeginHostEndpointRouteCarrier(
            request,
            routeRelay!.Authority,
            sourceCarrier,
            source.Now,
            out var sourceCarrierAuthority);
        Assert.True(sourceCarrierResult.Accepted, sourceCarrierResult.Message);
        Assert.NotNull(sourceCarrierAuthority);
        var sourcePayload = EndpointInvocationPayload(
            typeof(HostEndpointInvocation).AssemblyQualifiedName!,
            request.Invocation);
        Assert.True(source.Session.BeginCall(
            sourceCall,
            SidecarCapabilityKind.Action,
            sourcePayload,
            sourcePayload.ByteLength,
            source.Now,
            sourceContext).Accepted);
        Assert.True(source.Session.TryGetActiveHostActionEntryContext(
            sourceContext.CapabilityId,
            out var activeSourceContext));
        Assert.NotNull(activeSourceContext);

        var routeImportResult = receiving.Session.ImportHostEndpointRouteRelay(
            wireRouteRelay,
            receiving.Now,
            out var receivingContext);
        Assert.True(routeImportResult.Accepted, routeImportResult.Message);
        Assert.NotNull(receivingContext);
        var receivingPayload = EndpointInvocationPayload(
            typeof(HostEndpointInvocation).AssemblyQualifiedName!,
            wireRouteRelay.Request.Invocation);
        Assert.True(receiving.Session.BeginCall(
            receivingCall,
            SidecarCapabilityKind.Action,
            receivingPayload,
            receivingPayload.ByteLength,
            receiving.Now,
            receivingContext).Accepted);
        Assert.True(receiving.Session.TryGetActiveHostActionEntryCarrier(
            receivingContext!.CapabilityId,
            out var receivingCarrier));
        Assert.NotNull(receivingCarrier);
        var sourceParent = new EndpointTypedActionChildParent(
            request,
            sourceCall,
            routeRelay.Authority,
            sourceCarrierAuthority!,
            activeSourceContext!);
        var receivingParent = new EndpointTypedActionChildParent(
            request,
            receivingCall,
            wireRouteRelay.Authority,
            receivingCarrier!,
            receivingContext);

        var descriptor = NestedDescriptor(
            "endpoint.typed.child",
            typeof(string).AssemblyQualifiedName!);
        var action = Payload(descriptor.InputTypeIdentity, "typed-child");
        var childCall = sourceParent.Call with
        {
            CallId = Guid.NewGuid(),
            ReplayNonce = "endpoint-typed-child",
            Sequence = source.Session.LastSequence + 1,
            Deadline = source.Now.AddSeconds(30),
        };
        var reservationResult = source.Session.IssueHostEndpointTypedActionChildReservation(
            sourceParent.Call,
            sourceParent.ActiveContext,
            childCall,
            descriptor,
            action,
            source.Now,
            candidate => KeyedEndpointProof(
                "child-reservation",
                SidecarEndpointTypedActionChildValidation.ComputeReservationHash(candidate)),
            out var reservation);
        Assert.True(reservationResult.Accepted, reservationResult.Message);
        Assert.NotNull(reservation);
        var wireReservation = SidecarCapabilityTransportCodec.Deserialize<
            SidecarEndpointTypedActionChildReservation>(
            SidecarCapabilityTransportCodec.Serialize(reservation));

        var relayResult = receiving.Session.IssueHostEndpointTypedActionChildRelay(
            receivingParent.Authority,
            receivingParent.Call,
            receivingParent.ActiveContext,
            wireReservation,
            receiving.Now,
            (candidate, hash) => candidate.Proof == KeyedEndpointProof("child-reservation", hash),
            candidate => KeyedEndpointProof(
                "child-relay",
                SidecarEndpointTypedActionChildValidation.ComputeRelayHash(candidate)),
            out var relay);
        Assert.True(relayResult.Accepted, relayResult.Message);
        Assert.NotNull(relay);
        var wireRelay = SidecarCapabilityTransportCodec.Deserialize<SidecarEndpointTypedActionChildRelay>(
            SidecarCapabilityTransportCodec.Serialize(relay));

        return new EndpointTypedActionChildCase(
            source,
            receiving,
            sourceParent,
            receivingParent,
            childCall,
            action,
            routeRelay,
            relay!,
            wireRelay);
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

    private sealed record EndpointTypedActionChildParent(
        HostEndpointRouteRequest Request,
        SidecarCapabilityCallIdentity Call,
        HostEndpointRouteAuthority Authority,
        HostActionEntryCarrierAuthority Carrier,
        HostActionEntryRequestContext ActiveContext);

    private sealed record EndpointTypedActionChildCase(
        Fixture Source,
        Fixture Receiving,
        EndpointTypedActionChildParent SourceParent,
        EndpointTypedActionChildParent ReceivingParent,
        SidecarCapabilityCallIdentity ChildCall,
        SidecarSerializedPayload ChildAction,
        SidecarHostEndpointRouteRelay RouteRelay,
        SidecarEndpointTypedActionChildRelay Relay,
        SidecarEndpointTypedActionChildRelay WireRelay);

    private sealed record EndpointTypedActionChildReservationCase(
        Fixture Source,
        Fixture Receiving,
        EndpointTypedActionChildParent SourceParent,
        EndpointTypedActionChildParent ReceivingParent,
        SidecarCapabilityCallIdentity ChildCall,
        SidecarSerializedPayload ChildAction,
        SidecarHostEndpointRouteRelay RouteRelay,
        SidecarEndpointTypedActionChildReservation Reservation);

    private sealed record Fixture(
        DateTimeOffset Now,
        SidecarCapabilitySessionBinding Binding,
        SidecarCapabilitySession Session,
        SidecarCapabilityCallIdentity Call,
        SidecarSafeFailureIdentity SafeFailure,
        HashSet<string> Nonces,
        HashSet<string> BindingHashes);

    private sealed record EndpointRelayInputs(
        Fixture Source,
        Fixture Receiving,
        HostEndpointRouteRequest Request,
        SidecarCapabilityCallIdentity SourceCall,
        SidecarCapabilityCallIdentity ReceivingCall);

    private sealed record EndpointRelayFixture(
        EndpointRelayInputs Inputs,
        SidecarHostEndpointRouteRelay Relay);

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
        DateTimeOffset Now,
        HostActionEntryRequestContext ParentContext,
        SidecarSerializedPayload ParentAction);

    private sealed record CrossRelayAttempt(
        SidecarCapabilityValidationResult Result,
        SidecarCapabilityCallIdentity ParentCall,
        SidecarCrossSidecarActionEntryRelay? Relay,
        SidecarCapabilitySession TargetSession,
        SidecarCapabilitySessionBinding TargetBinding,
        DateTimeOffset Now);

    private sealed record HostReceiptContinuationCase(
        Fixture Source,
        SidecarCapabilityCallIdentity SourceParentCall,
        Fixture HostTarget,
        Fixture TargetPeer,
        SidecarStorageCapabilityRequest Request,
        SidecarHostEntryStorageContinuationAuthority Authority,
        DateTimeOffset HostImportTime,
        DateTimeOffset PeerImportTime,
        DateTimeOffset SignedCarrierIssuedAt,
        DateTimeOffset ContinuationIssuedAt,
        SidecarCapabilityCallIdentity TargetChildCall,
        int TargetAttempt);

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

internal static class EndpointRouteRelayTestExtensions
{
    public static SidecarCapabilityValidationResult IssueHostEndpointRouteRelay(
        this SidecarCapabilitySession source,
        HostEndpointRouteRequest request,
        SidecarCapabilityCallIdentity sourceCall,
        SidecarCapabilityCallIdentity receivingParentCall,
        SidecarCapabilitySession receivingSession,
        DateTimeOffset now,
        Func<HostEndpointRouteAuthority, string> issueRouteAuthorityProof,
        Func<SidecarHostEndpointRouteRelay, string, string> issueProof,
        out SidecarHostEndpointRouteRelay? relay)
    {
        var reservationResult = receivingSession.IssueHostEndpointRouteReservation(
            request,
            receivingParentCall,
            now,
            reservation => KeyedEndpointProof(
                "reservation",
                SidecarCapabilityTransportValidation.ComputeEndpointRouteReservationBindingHash(reservation)),
            out var reservation);
        if (!reservationResult.Accepted || reservation is null)
        {
            relay = null;
            return reservationResult;
        }

        var wireReservation = SidecarCapabilityTransportCodec.Deserialize<SidecarHostEndpointRouteReservation>(
            SidecarCapabilityTransportCodec.Serialize(reservation));
        var result = source.IssueHostEndpointRouteRelay(
            request,
            sourceCall,
            wireReservation,
            now,
            issueRouteAuthorityProof,
            (candidate, hash) => candidate.Proof == KeyedEndpointProof("reservation", hash),
            issueProof,
            out relay);
        if (!result.Accepted)
            receivingSession.ReleaseHostEndpointRouteReservation(wireReservation, now);
        return result;
    }

    private static string KeyedEndpointProof(string domain, string hash)
    {
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes("endpoint-route-relay-test-key"));
        return Convert.ToHexString(hmac.ComputeHash(Encoding.UTF8.GetBytes($"{domain}:{hash}")));
    }
}
