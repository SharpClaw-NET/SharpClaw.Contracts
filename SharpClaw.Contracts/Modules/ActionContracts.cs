using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text.Json;

namespace SharpClaw.Contracts.Modules;

[Flags]
public enum ActionInterceptionCapabilities
{
    Inspect = 1 << 0,
    ReplaceInput = 1 << 1,
    Cancel = 1 << 2,
    ReplaceResult = 1 << 3,
    Defer = 1 << 4,
    Repeat = 1 << 5,
    Wrap = 1 << 6,
    Observe = 1 << 7,
    PublishEvents = 1 << 8,
}

public enum ActionRepeatKind
{
    None,
    ConflictOnly,
    Idempotent,
    Receipted,
}

public sealed record ActionRepeatPolicy(
    ActionRepeatKind Kind,
    int MaximumAttempts,
    TimeSpan MinimumBackoff,
    string IdempotencyScope);

public sealed record ActionContinuationPolicy(
    TimeSpan MaximumLifetime,
    bool Durable,
    bool SingleClaim);

public sealed record ActionDescriptor<TAction, TResult>(
    SharpClawActionKey Key,
    int Version,
    string Category,
    ActionInterceptionCapabilities Capabilities,
    bool ContainsSensitiveData,
    bool HasIrreversibleEffects,
    ActionRepeatPolicy RepeatPolicy,
    ActionContinuationPolicy? ContinuationPolicy,
    TimeSpan DefaultTimeout)
{
    public ContractVersionRange ProtocolVersionRange { get; init; } =
        ContractVersionRange.Exact(1);

    public IReadOnlyList<ActionSafePoint> SafePoints { get; init; } = [];

    public JsonSchemaReference? InputSchema { get; init; }

    public JsonSchemaReference? ResultSchema { get; init; }
}

public enum ActionOutcomeKind
{
    Completed,
    Cancelled,
    Deferred,
    Failed,
    Uncertain,
}

public enum ActionExecutionStage
{
    BeforeContinuation,
    ContinuationRunning,
    TerminalReturned,
    Committed,
    AfterContinuation,
}

public sealed record ActionRecoveryReference(
    Guid RecoveryId,
    SharpClawActionKey ActionKey,
    int ActionVersion,
    Guid IdempotencyKey);

public sealed record ActionUncertainty(
    string Code,
    string Message,
    ActionExecutionStage Stage,
    string? ReceiptReference,
    ActionRecoveryReference Recovery,
    DateTimeOffset RecordedAt)
{
    public bool AutomaticRepeatAllowed => false;
}

public interface IActionOutcome<out TResult>
{
    ActionOutcomeKind Kind { get; }
    TResult? Result { get; }
    ContinuationToken? Continuation { get; }
    ExecutionError? Error { get; }
    ActionUncertainty? Uncertainty { get; }
}

public sealed record ActionReplacement<TAction>(TAction Value, string Reason);

public sealed record ActionRepeatRequest<TAction>(
    TAction Value,
    string Reason,
    TimeSpan? Backoff = null);

public sealed record ActionDeferRequest(
    DateTimeOffset ExpiresAt,
    string Reason);

public interface IActionControl<TAction, TResult>
{
    ValueTask<IActionOutcome<TResult>> ProceedAsync(CancellationToken ct);

    ValueTask<IActionOutcome<TResult>> ProceedWithInputAsync(
        ActionReplacement<TAction> replacement,
        CancellationToken ct);

    IActionOutcome<TResult> ReplaceResult(TResult result, string reason);
    IActionOutcome<TResult> Cancel(string code, string message);
    IActionOutcome<TResult> Fail(ExecutionError error);

    ValueTask<IActionOutcome<TResult>> DeferAsync(
        ActionDeferRequest request,
        CancellationToken ct);

    ValueTask<IActionOutcome<TResult>> RepeatAsync(
        ActionRepeatRequest<TAction> request,
        CancellationToken ct);
}

public interface IActionInterceptor<TAction, TResult>
{
    ValueTask<IActionOutcome<TResult>> InvokeAsync(
        ActionContext<TAction> context,
        IActionControl<TAction, TResult> control,
        CancellationToken ct);
}

public abstract record BeforeActionDecision<TAction>
{
    public sealed record Continue : BeforeActionDecision<TAction>;
    public sealed record Replace(ActionReplacement<TAction> Replacement) : BeforeActionDecision<TAction>;
    public sealed record Cancel(string Code, string Message) : BeforeActionDecision<TAction>;
}

public interface IBeforeAction<TAction>
{
    ValueTask<BeforeActionDecision<TAction>> BeforeAsync(
        ActionContext<TAction> context,
        CancellationToken ct);
}

public interface IAfterAction<TAction, TResult>
{
    ValueTask<IActionOutcome<TResult>> AfterAsync(
        ActionContext<TAction> context,
        IActionOutcome<TResult> outcome,
        IActionControl<TAction, TResult> control,
        CancellationToken ct);
}

public interface IActionFaultHandler<TAction, TResult>
{
    ValueTask<IActionOutcome<TResult>> OnFaultAsync(
        ActionContext<TAction> context,
        Exception exception,
        IActionControl<TAction, TResult> control,
        CancellationToken ct);
}

public interface IActionCancellationListener<TAction>
{
    ValueTask OnCancelledAsync(
        ActionContext<TAction> context,
        CancellationToken ct);
}

public sealed record ActionContext<TAction>(
    Guid InvocationId,
    Guid? ParentInvocationId,
    Guid TraceId,
    Guid IdempotencyKey,
    int Depth,
    int Attempt,
    DateTimeOffset Deadline,
    SharpClawActionKey ActionKey,
    string OwnerModuleId,
    RequestPrincipal Caller,
    TAction Action,
    ExtensionFeatureSet Features,
    ActionPipelineSnapshot Snapshot)
{
    public IHostActionEntry? HostActionEntry { get; init; }
}

public sealed record HostActionEntryValidationResult(
    bool Accepted,
    string Code,
    string Message)
{
    public static HostActionEntryValidationResult Accept() =>
        new(true, "accepted", "Accepted.");

    public static HostActionEntryValidationResult Reject(string code, string message) =>
        new(false, code, message);
}

public enum HostActionEntryIngress
{
    Endpoint,
    Cli,
    Tool,
    CrossModule,
}

public sealed record HostActionEntryLineage(
    SharpClawActionKey ActionKey,
    int ActionVersion,
    string DescriptorHash,
    string InputTypeIdentity,
    int InputSchemaVersion,
    string InputSchemaHash,
    string? PayloadContentHash,
    int? PayloadByteLength)
{
    public bool IsDescriptorWellFormed =>
        !string.IsNullOrWhiteSpace(ActionKey.Value) &&
        ActionVersion >= 1 &&
        !string.IsNullOrWhiteSpace(DescriptorHash) &&
        !string.IsNullOrWhiteSpace(InputTypeIdentity) &&
        InputSchemaVersion >= 1 &&
        !string.IsNullOrWhiteSpace(InputSchemaHash);

    public bool IsPayloadBound =>
        !string.IsNullOrWhiteSpace(PayloadContentHash) &&
        PayloadByteLength is > 0;

    public bool IsWellFormed =>
        IsDescriptorWellFormed &&
        ((PayloadContentHash is null && PayloadByteLength is null) || IsPayloadBound);
}

public sealed record HostActionEntryIngressBinding(
    HostActionEntryIngress Ingress,
    string PrimaryIdentity,
    string? SecondaryIdentity = null)
{
    public bool IsWellFormed =>
        Enum.IsDefined(Ingress) &&
        !string.IsNullOrWhiteSpace(PrimaryIdentity) &&
        Ingress switch
        {
            HostActionEntryIngress.CrossModule =>
                !string.IsNullOrWhiteSpace(SecondaryIdentity) &&
                !string.Equals(PrimaryIdentity, SecondaryIdentity, StringComparison.Ordinal),
            HostActionEntryIngress.Tool =>
                SecondaryIdentity is null || IsCanonicalConversationIdentity(SecondaryIdentity),
            _ => SecondaryIdentity is null,
        };

    private static bool IsCanonicalConversationIdentity(string value) =>
        Guid.TryParseExact(value, "D", out var conversationId) &&
        conversationId != Guid.Empty &&
        string.Equals(value, conversationId.ToString("D"), StringComparison.Ordinal);
}

public sealed record HostActionEntryContribution(
    HostActionEntryIngressBinding IngressBinding,
    HostActionEntryLineage Lineage)
{
    public bool IsWellFormed =>
        IngressBinding is not null &&
        IngressBinding.IsWellFormed &&
        Lineage is not null &&
        Lineage.IsWellFormed;
}

public sealed record HostActionEntryContextRequest(
    HostActionEntryIngress Ingress,
    Guid InvocationId,
    Guid RequestId,
    Guid CancellationId,
    RequestPrincipal Caller,
    ExtensionFeatureSet Features,
    Guid TraceId,
    Guid IdempotencyKey,
    DateTimeOffset Deadline,
    DateTimeOffset ExpiresAt)
{
    public HostActionEntryContribution? Contribution { get; init; }
    public Guid? ParentInvocationId { get; init; }
    public int Depth { get; init; }
    public int Attempt { get; init; } = 1;

    public bool IsWellFormed(DateTimeOffset now) =>
        Enum.IsDefined(Ingress) &&
        InvocationId != Guid.Empty &&
        RequestId != Guid.Empty &&
        CancellationId != Guid.Empty &&
        Caller is not null &&
        !string.IsNullOrWhiteSpace(Caller.SubjectId) &&
        Features is not null &&
        Features.Items is not null &&
        TraceId != Guid.Empty &&
        IdempotencyKey != Guid.Empty &&
        Depth >= 0 &&
        Attempt >= 1 &&
        Deadline > now &&
        ExpiresAt >= Deadline &&
        Contribution is not null &&
        Contribution.IsWellFormed &&
        Contribution.IngressBinding.Ingress == Ingress &&
        !Contribution.Lineage.IsPayloadBound;
}

public sealed record HostEndpointInvocation(
    Guid InvocationId,
    string Endpoint,
    HostActionEntryRequestContext HostActionContext)
{
    public bool IsWellFormed(DateTimeOffset now) =>
        InvocationId != Guid.Empty &&
        !string.IsNullOrWhiteSpace(Endpoint) &&
        HostActionContext is not null &&
        HostActionContext.Ingress == HostActionEntryIngress.Endpoint &&
        HostActionContext.InvocationId == InvocationId &&
        HostActionContext.Contribution?.IngressBinding.Ingress == HostActionEntryIngress.Endpoint &&
        string.Equals(HostActionContext.Contribution.IngressBinding.PrimaryIdentity, Endpoint, StringComparison.Ordinal) &&
        HostActionContext.IsWellFormed(now);
}

public enum HostEndpointTransport
{
    Http,
    WebSocket,
}

public sealed record HostEndpointRouteIdentity(
    string HandlerIdentity,
    string Path,
    string Method,
    HostEndpointTransport Transport)
{
    public bool IsWellFormed =>
        !string.IsNullOrWhiteSpace(HandlerIdentity) &&
        HandlerIdentity == HandlerIdentity.Trim() &&
        HandlerIdentity.Length <= 512 &&
        IsCanonicalPath(Path) &&
        Path.Length <= 512 &&
        IsCanonicalMethod(Method) &&
        Method.Length <= 16 &&
        Enum.IsDefined(Transport);

    private static bool IsCanonicalPath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) ||
            path != path.Trim() ||
            !path.StartsWith("/", StringComparison.Ordinal) ||
            path.Contains("//", StringComparison.Ordinal) ||
            path.Contains('?', StringComparison.Ordinal) ||
            path.Contains('#', StringComparison.Ordinal) ||
            path.Contains('\\', StringComparison.Ordinal) ||
            path.Contains('%', StringComparison.Ordinal) ||
            path.Any(character => char.IsControl(character) || char.IsWhiteSpace(character)) ||
            path.Split('/').Any(segment => segment is "." or ".."))
        {
            return false;
        }

        try
        {
            return string.Equals(
                path,
                Uri.UnescapeDataString(path),
                StringComparison.Ordinal);
        }
        catch
        {
            return false;
        }
    }

    private static bool IsCanonicalMethod(string? method) =>
        !string.IsNullOrWhiteSpace(method) &&
        method == method.Trim() &&
        method.All(character => character is >= 'A' and <= 'Z');
}

public sealed record HostEndpointRouteRequest(
    HostEndpointInvocation Invocation,
    HostEndpointRouteIdentity Route,
    IReadOnlyDictionary<string, string[]> Headers,
    IReadOnlyDictionary<string, string[]> Query,
    byte[] Body)
{
    public IReadOnlyDictionary<string, string[]> RouteValues { get; init; } =
        ImmutableDictionary<string, string[]>.Empty;

    public string ContentHash =>
        Body is null ? string.Empty : Convert.ToHexString(SHA256.HashData(Body));

    public int ContentByteLength => Body?.Length ?? -1;

    public string InvocationContentHash =>
        Invocation is null
            ? string.Empty
            : SidecarCapabilityTransportCodec.ComputeSha256(
                CanonicalInvocationBytes(Invocation));

    public int InvocationByteLength =>
        Invocation is null
            ? -1
            : CanonicalInvocationBytes(Invocation).Length;

    public bool IsWellFormed(DateTimeOffset now)
    {
        try
        {
            return Invocation is not null &&
                Invocation.IsWellFormed(now) &&
                Route is not null &&
                Route.IsWellFormed &&
                string.Equals(Route.HandlerIdentity, Invocation.Endpoint, StringComparison.Ordinal) &&
                HostEndpointRouteAuthorityValidator.IsRouteValueMetadataWellFormed(RouteValues) &&
                HostEndpointRouteAuthorityValidator.IsHeaderMetadataWellFormed(Headers) &&
                HostEndpointRouteAuthorityValidator.IsQueryMetadataWellFormed(Query) &&
                Body is not null;
        }
        catch
        {
            return false;
        }
    }

    private static byte[] CanonicalInvocationBytes(HostEndpointInvocation invocation)
    {
        var encoded = SidecarCapabilityTransportCodec.Serialize(invocation);
        using var document = JsonDocument.Parse(encoded);
        return SidecarCapabilityTransportCodec.Serialize(document.RootElement);
    }
}

public sealed record HostEndpointRouteAuthority(
    Guid AuthorityId,
    SidecarCapabilityCallIdentity Call,
    Guid InvocationId,
    HostEndpointRouteIdentity Route,
    IReadOnlyDictionary<string, string[]> Headers,
    IReadOnlyDictionary<string, string[]> Query,
    string RequestContentHash,
    int RequestContentByteLength,
    HostActionEntryRequestContext HostActionContext,
    DateTimeOffset IssuedAt,
    DateTimeOffset ExpiresAt,
    string CanonicalBindingHash,
    string Proof)
{
    public IReadOnlyDictionary<string, string[]> RouteValues { get; init; } =
        ImmutableDictionary<string, string[]>.Empty;

    public string InvocationContentHash { get; init; } = string.Empty;

    public int InvocationByteLength { get; init; } = -1;

    public bool IsWellFormed =>
        AuthorityId != Guid.Empty &&
        Call is not null &&
        Call.IsValid &&
        InvocationId != Guid.Empty &&
        Route is not null &&
        Route.IsWellFormed &&
        HostEndpointRouteAuthorityValidator.IsRouteValueMetadataWellFormed(RouteValues) &&
        HostEndpointRouteAuthorityValidator.IsHeaderMetadataWellFormed(Headers) &&
        HostEndpointRouteAuthorityValidator.IsQueryMetadataWellFormed(Query) &&
        !string.IsNullOrWhiteSpace(RequestContentHash) &&
        RequestContentByteLength >= 0 &&
        !string.IsNullOrWhiteSpace(InvocationContentHash) &&
        InvocationByteLength >= 0 &&
        HostActionContext is not null &&
        IssuedAt <= ExpiresAt &&
        !string.IsNullOrWhiteSpace(CanonicalBindingHash) &&
        !string.IsNullOrWhiteSpace(Proof);
}

public static class HostEndpointRouteAuthorityValidator
{
    public static string ComputeBindingHash(HostEndpointRouteAuthority authority)
    {
        ArgumentNullException.ThrowIfNull(authority);
        var canonical = new
        {
            Call = Convert.ToBase64String(SidecarCapabilityTransportCodec.Serialize(authority.Call)),
            authority.InvocationId,
            Route = Convert.ToBase64String(SidecarCapabilityTransportCodec.Serialize(authority.Route)),
            RouteValues = Convert.ToBase64String(
                SerializeMetadata(authority.RouteValues, caseInsensitiveKeys: false)),
            Headers = Convert.ToBase64String(SerializeMetadata(authority.Headers, caseInsensitiveKeys: true)),
            Query = Convert.ToBase64String(SerializeMetadata(authority.Query, caseInsensitiveKeys: false)),
            authority.RequestContentHash,
            authority.RequestContentByteLength,
            authority.AuthorityId,
            authority.InvocationContentHash,
            authority.InvocationByteLength,
            HostActionContextBindingHash =
                SidecarCapabilityTransportValidation.ComputeHostActionEntryContextBindingHash(
                    authority.HostActionContext),
            authority.IssuedAt,
            authority.ExpiresAt,
        };
        return SidecarCapabilityTransportCodec.ComputeSha256(
            SidecarCapabilityTransportCodec.Serialize(canonical));
    }

    public static SidecarCapabilityValidationResult Validate(
        HostEndpointRouteRequest request,
        HostEndpointRouteAuthority authority,
        DateTimeOffset now,
        Func<HostEndpointRouteAuthority, string, bool> authenticateAuthority)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(authority);
        ArgumentNullException.ThrowIfNull(authenticateAuthority);

        if (!request.IsWellFormed(now) ||
            !authority.IsWellFormed ||
            !authority.HostActionContext.IsWellFormed(now))
            return SidecarCapabilityValidationResult.Reject(
                SidecarCapabilityErrors.InvalidBinding,
                "The endpoint route authority is incomplete.");

        if (authority.IssuedAt > now ||
            authority.ExpiresAt <= now ||
            authority.ExpiresAt > authority.Call.Deadline ||
            authority.ExpiresAt > authority.HostActionContext.Deadline ||
            authority.ExpiresAt > authority.HostActionContext.ExpiresAt)
        {
            return SidecarCapabilityValidationResult.Reject(
                SidecarCapabilityErrors.Expired,
                "The endpoint route authority is outside its signed lifetime.");
        }

        if (!string.Equals(
                authority.CanonicalBindingHash,
                ComputeBindingHash(authority),
                StringComparison.OrdinalIgnoreCase))
        {
            return SidecarCapabilityValidationResult.Reject(
                SidecarCapabilityErrors.SpoofedIdentity,
                "The endpoint route authority binding is invalid.");
        }

        if (authority.InvocationId != request.Invocation.InvocationId ||
            !SameRoute(authority.Route, request.Route) ||
            !SameMetadata(
                authority.RouteValues,
                request.RouteValues,
                caseInsensitiveKeys: false) ||
            !SameMetadata(authority.Headers, request.Headers, caseInsensitiveKeys: true) ||
            !SameMetadata(authority.Query, request.Query, caseInsensitiveKeys: false) ||
            !string.Equals(
                authority.RequestContentHash,
                request.ContentHash,
                StringComparison.OrdinalIgnoreCase) ||
            authority.RequestContentByteLength != request.ContentByteLength ||
            !string.Equals(
                authority.InvocationContentHash,
                request.InvocationContentHash,
                StringComparison.OrdinalIgnoreCase) ||
            authority.InvocationByteLength != request.InvocationByteLength ||
            !string.Equals(
                SidecarCapabilityTransportValidation.ComputeHostActionEntryContextBindingHash(
                    authority.HostActionContext),
                SidecarCapabilityTransportValidation.ComputeHostActionEntryContextBindingHash(
                    request.Invocation.HostActionContext),
                StringComparison.OrdinalIgnoreCase))
        {
            return SidecarCapabilityValidationResult.Reject(
                SidecarCapabilityErrors.SpoofedIdentity,
                "The endpoint route request does not match its authority.");
        }

        bool authenticated;
        try
        {
            authenticated = authenticateAuthority(authority, authority.CanonicalBindingHash);
        }
        catch
        {
            authenticated = false;
        }

        return authenticated
            ? SidecarCapabilityValidationResult.Accept()
            : SidecarCapabilityValidationResult.Reject(
                SidecarCapabilityErrors.Unauthenticated,
                "The host did not authenticate the endpoint route authority.");
    }

    internal static bool IsHeaderMetadataWellFormed(
        IReadOnlyDictionary<string, string[]>? metadata) =>
        IsMetadataWellFormed(
            metadata,
            StringComparer.OrdinalIgnoreCase,
            validateHeaderNames: true,
            validateHeaderValues: true);

    internal static bool IsQueryMetadataWellFormed(
        IReadOnlyDictionary<string, string[]>? metadata) =>
        IsMetadataWellFormed(
            metadata,
            StringComparer.Ordinal,
            validateHeaderNames: false,
            validateHeaderValues: false);

    internal static bool IsRouteValueMetadataWellFormed(
        IReadOnlyDictionary<string, string[]>? metadata) =>
        IsMetadataWellFormed(
            metadata,
            StringComparer.Ordinal,
            validateHeaderNames: false,
            validateHeaderValues: false) &&
        metadata!.All(pair =>
            pair.Key == pair.Key.Trim() &&
            pair.Value.Length == 1 &&
            pair.Value[0] == pair.Value[0].Trim());

    private static bool IsMetadataWellFormed(
        IReadOnlyDictionary<string, string[]>? metadata,
        StringComparer keyComparer,
        bool validateHeaderNames,
        bool validateHeaderValues)
    {
        if (metadata is null)
            return false;

        var keys = new HashSet<string>(keyComparer);
        foreach (var pair in metadata)
        {
            if (string.IsNullOrWhiteSpace(pair.Key) ||
                (validateHeaderNames && !IsHttpToken(pair.Key)) ||
                pair.Value is null ||
                !keys.Add(pair.Key) ||
                pair.Value.Any(value =>
                    value is null ||
                    (validateHeaderValues &&
                     value.Any(character =>
                         char.IsControl(character) ||
                         character is '\r' or '\n' or '\0'))))
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsHttpToken(string value) =>
        value.All(character =>
            character is >= 'A' and <= 'Z' ||
            character is >= 'a' and <= 'z' ||
            character is >= '0' and <= '9' ||
            "!#$%&'*+-.^_`|~".IndexOf(character) >= 0);

    internal static bool IsWithinLimits(
        HostEndpointRouteRequest request,
        SidecarPayloadLimits limits)
    {
        if (request is null || limits is null || !limits.IsValid ||
            request.Body is null ||
            request.Body.Length > limits.ActionInputBytes ||
            !IsMetadataWithinLimits(request.RouteValues) ||
            !IsMetadataWithinLimits(request.Headers) ||
            !IsMetadataWithinLimits(request.Query))
            return false;

        try
        {
            return SidecarCapabilityTransportCodec.Serialize(request).Length <=
                limits.ProtocolMessageBytes;
        }
        catch
        {
            return false;
        }
    }

    private static bool IsMetadataWithinLimits(
        IReadOnlyDictionary<string, string[]>? metadata) =>
        metadata is not null &&
        metadata.Count <= 128 &&
        metadata.All(pair =>
            pair.Key is not null &&
            pair.Value is not null &&
            pair.Key.Length <= 256 &&
            pair.Value.Length <= 64 &&
            pair.Value.All(value => value is not null && value.Length <= 8192));

    private static bool SameRoute(
        HostEndpointRouteIdentity left,
        HostEndpointRouteIdentity right) =>
        left == right;

    private static bool SameMetadata(
        IReadOnlyDictionary<string, string[]> left,
        IReadOnlyDictionary<string, string[]> right,
        bool caseInsensitiveKeys) =>
        string.Equals(
            Convert.ToBase64String(SerializeMetadata(left, caseInsensitiveKeys)),
            Convert.ToBase64String(SerializeMetadata(right, caseInsensitiveKeys)),
            StringComparison.Ordinal);

    private static byte[] SerializeMetadata(
        IReadOnlyDictionary<string, string[]> metadata,
        bool caseInsensitiveKeys)
    {
        var ordered = metadata
            .Select(pair => new
            {
                Key = caseInsensitiveKeys ? pair.Key.ToUpperInvariant() : pair.Key,
                Values = pair.Value,
            })
            .OrderBy(pair => pair.Key, StringComparer.Ordinal)
            .ToArray();
        return SidecarCapabilityTransportCodec.Serialize(ordered);
    }
}

public sealed record CrossModuleActionInvocation(
    Guid InvocationId,
    string SourceModuleId,
    string TargetModuleId,
    HostActionEntryRequestContext HostActionContext)
{
    public bool IsWellFormed(DateTimeOffset now) =>
        InvocationId != Guid.Empty &&
        !string.IsNullOrWhiteSpace(SourceModuleId) &&
        !string.IsNullOrWhiteSpace(TargetModuleId) &&
        !string.Equals(SourceModuleId, TargetModuleId, StringComparison.Ordinal) &&
        HostActionContext is not null &&
        HostActionContext.Ingress == HostActionEntryIngress.CrossModule &&
        HostActionContext.InvocationId == InvocationId &&
        HostActionContext.Contribution?.IngressBinding.Ingress == HostActionEntryIngress.CrossModule &&
        string.Equals(HostActionContext.Contribution.IngressBinding.PrimaryIdentity, SourceModuleId, StringComparison.Ordinal) &&
        string.Equals(HostActionContext.Contribution.IngressBinding.SecondaryIdentity, TargetModuleId, StringComparison.Ordinal) &&
        HostActionContext.IsWellFormed(now);
}

/// <summary>Host-issued authority for one typed module action entry.</summary>
public sealed record HostActionEntryAuthority(
    string ModuleId,
    string GraphId,
    Guid SessionId,
    Guid RequestId,
    Guid CancellationId,
    Guid CallId,
    string ReplayNonce,
    long Sequence,
    RequestPrincipal Caller,
    ExtensionFeatureSet Features,
    Guid TraceId,
    Guid IdempotencyKey,
    SharpClawActionKey ActionKey,
    int ActionVersion,
    string Category,
    string InputTypeIdentity,
    string ResultTypeIdentity,
    string DescriptorHash,
    string InputSchemaHash,
    int InputSchemaVersion,
    string ResultSchemaHash,
    int ResultSchemaVersion,
    string ActionContentHash,
    int ActionByteLength,
    DateTimeOffset Deadline,
    DateTimeOffset IssuedAt,
    DateTimeOffset ExpiresAt,
    string Proof)
{
    public HostActionEntryIngress Ingress { get; init; }
    public Guid InvocationId { get; init; }
    public Guid? ParentInvocationId { get; init; }
    public int Depth { get; init; }
    public int Attempt { get; init; } = 1;
    public Guid CapabilityId { get; init; }
    public string CapabilityHandleHash { get; init; } = string.Empty;

    public bool IsValid =>
        !string.IsNullOrWhiteSpace(ModuleId) &&
        !string.IsNullOrWhiteSpace(GraphId) &&
        SessionId != Guid.Empty &&
        RequestId != Guid.Empty &&
        CancellationId != Guid.Empty &&
        CallId != Guid.Empty &&
        !string.IsNullOrWhiteSpace(ReplayNonce) &&
        Sequence > 0 &&
        Caller is not null &&
        !string.IsNullOrWhiteSpace(Caller.SubjectId) &&
        Features is not null &&
        Features.Items is not null &&
        TraceId != Guid.Empty &&
        IdempotencyKey != Guid.Empty &&
        !string.IsNullOrWhiteSpace(ActionKey.Value) &&
        ActionVersion >= 1 &&
        !string.IsNullOrWhiteSpace(Category) &&
        !string.IsNullOrWhiteSpace(InputTypeIdentity) &&
        !string.IsNullOrWhiteSpace(ResultTypeIdentity) &&
        !string.IsNullOrWhiteSpace(DescriptorHash) &&
        !string.IsNullOrWhiteSpace(InputSchemaHash) &&
        InputSchemaVersion >= 1 &&
        !string.IsNullOrWhiteSpace(ResultSchemaHash) &&
        ResultSchemaVersion >= 1 &&
        !string.IsNullOrWhiteSpace(ActionContentHash) &&
        ActionByteLength > 0 &&
        Enum.IsDefined(Ingress) &&
        InvocationId != Guid.Empty &&
        Depth >= 0 &&
        Attempt >= 1 &&
        CapabilityId != Guid.Empty &&
        !string.IsNullOrWhiteSpace(CapabilityHandleHash) &&
        !string.IsNullOrWhiteSpace(Proof);
}

/// <summary>Host-issued context capability for one typed module action entry.</summary>
public sealed record HostActionEntryRequestContext(
    Guid CapabilityId,
    string CapabilityHandle,
    HostActionEntryIngress Ingress,
    Guid InvocationId,
    Guid RequestId,
    Guid CancellationId,
    RequestPrincipal Caller,
    ExtensionFeatureSet Features,
    Guid TraceId,
    Guid IdempotencyKey,
    DateTimeOffset Deadline,
    DateTimeOffset ExpiresAt)
{
    public HostActionEntryContribution? Contribution { get; init; }
    public Guid? ParentInvocationId { get; init; }
    public int Depth { get; init; }
    public int Attempt { get; init; } = 1;

    public bool IsWellFormed(DateTimeOffset now) =>
        CapabilityId != Guid.Empty &&
        !string.IsNullOrWhiteSpace(CapabilityHandle) &&
        Enum.IsDefined(Ingress) &&
        InvocationId != Guid.Empty &&
        RequestId != Guid.Empty &&
        CancellationId != Guid.Empty &&
        Caller is not null &&
        !string.IsNullOrWhiteSpace(Caller.SubjectId) &&
        Features is not null &&
        Features.Items is not null &&
        TraceId != Guid.Empty &&
        IdempotencyKey != Guid.Empty &&
        Depth >= 0 &&
        Attempt >= 1 &&
        Deadline > now &&
        ExpiresAt >= Deadline &&
        Contribution is not null &&
        Contribution.IsWellFormed;
}

public enum HostActionEntryCarrierCompletionKind
{
    Succeeded,
    Failed,
    Cancelled,
}

public sealed record HostActionEntryCarrierIdentity(
    HostActionEntryIngress Ingress,
    Guid InvocationId,
    HostActionEntryIngressBinding Contribution)
{
    public bool IsWellFormed =>
        Enum.IsDefined(Ingress) &&
        InvocationId != Guid.Empty &&
        Contribution is not null &&
        Contribution.IsWellFormed &&
        Contribution.Ingress == Ingress;
}

public sealed record HostActionEntryCarrierAuthority(
    string ModuleId,
    string GraphId,
    Guid SessionId,
    Guid RequestId,
    Guid CancellationId,
    Guid CapabilityId,
    HostActionEntryCarrierIdentity Carrier,
    long BindingGeneration,
    DateTimeOffset IssuedAt,
    DateTimeOffset ExpiresAt,
    string CapabilityHandleHash)
{
    public bool IsValid =>
        !string.IsNullOrWhiteSpace(ModuleId) &&
        !string.IsNullOrWhiteSpace(GraphId) &&
        SessionId != Guid.Empty &&
        RequestId != Guid.Empty &&
        CancellationId != Guid.Empty &&
        CapabilityId != Guid.Empty &&
        Carrier is not null &&
        Carrier.IsWellFormed &&
        BindingGeneration > 0 &&
        ExpiresAt >= IssuedAt &&
        !string.IsNullOrWhiteSpace(CapabilityHandleHash);
}

public sealed record HostActionEntryRequest<TAction, TResult>(
    ActionDescriptor<TAction, TResult> Descriptor,
    TAction Action,
    HostActionEntryRequestContext Context)
{
    public RequestPrincipal Caller => Context.Caller;
    public ExtensionFeatureSet Features => Context.Features;
    public Guid TraceId => Context.TraceId;
    public Guid IdempotencyKey => Context.IdempotencyKey;
    public DateTimeOffset Deadline => Context.Deadline;

    public bool IsWellFormed(DateTimeOffset now) =>
        Descriptor is not null &&
        Descriptor.Version >= 1 &&
        !string.IsNullOrWhiteSpace(Descriptor.Key.Value) &&
        Context is not null &&
        Context.IsWellFormed(now);
}

public sealed record HostActionEntryNestedRequest<TParentAction, TAction, TResult>(
    SharpClawActionKey ActionKey,
    int ActionVersion,
    TAction Action,
    ActionContext<TParentAction> ParentContext)
{
    public bool IsWellFormed(DateTimeOffset now) =>
        !string.IsNullOrWhiteSpace(ActionKey.Value) &&
        ActionVersion >= 1 &&
        ParentContext is not null &&
        ParentContext.HostActionEntry is not null &&
        ParentContext.InvocationId != Guid.Empty &&
        ParentContext.TraceId != Guid.Empty &&
        ParentContext.IdempotencyKey != Guid.Empty &&
        ParentContext.Depth >= 0 &&
        ParentContext.Attempt >= 1 &&
        ParentContext.Deadline > now;
}

/// <summary>Host-only transport envelope after authority issuance.</summary>
public sealed record HostActionEntryTransportRequest<TAction, TResult>(
    HostActionEntryRequest<TAction, TResult> Request,
    HostActionEntryAuthority Authority)
{
    public HostActionEntryValidationResult Validate(
        DateTimeOffset now,
        Func<HostActionEntryAuthority, bool> authenticateAuthority) =>
        HostActionEntryAuthorityValidator.Validate(Request, Authority, now, authenticateAuthority);
}

public static class HostActionEntryAuthorityValidator
{
    public static HostActionEntryValidationResult Validate<TAction, TResult>(
        HostActionEntryRequest<TAction, TResult> request,
        HostActionEntryAuthority authority,
        DateTimeOffset now,
        Func<HostActionEntryAuthority, bool> authenticateAuthority)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(authenticateAuthority);

        if (authority is null || !authority.IsValid)
            return HostActionEntryValidationResult.Reject(
                "host_action_invalid_authority",
                "The host action entry authority is incomplete.");

        if (authority.IssuedAt > now || authority.ExpiresAt <= now ||
            authority.Deadline <= now || authority.Deadline > authority.ExpiresAt)
        {
            return HostActionEntryValidationResult.Reject(
                "host_action_expired",
                "The host action entry authority is expired or outside its deadline.");
        }

        if (!authenticateAuthority(authority))
            return HostActionEntryValidationResult.Reject(
                "host_action_unauthenticated",
                "The host action entry authority proof was not accepted.");

        if (!request.IsWellFormed(now))
        {
            return HostActionEntryValidationResult.Reject(
                "host_action_invalid_request",
                "The host action entry request is incomplete.");
        }

        var inputTypeIdentity = TypeIdentity<TAction>();
        var resultTypeIdentity = TypeIdentity<TResult>();
        var descriptorHash = ComputeDescriptorHash(request.Descriptor);
        if (request.Descriptor.InputSchema is null || request.Descriptor.ResultSchema is null ||
            string.IsNullOrWhiteSpace(request.Descriptor.InputSchema.ContentHash) ||
            string.IsNullOrWhiteSpace(request.Descriptor.ResultSchema.ContentHash) ||
            request.Descriptor.InputSchema.Version < 1 ||
            request.Descriptor.ResultSchema.Version < 1)
        {
            return HostActionEntryValidationResult.Reject(
                "host_action_missing_schema",
                "The host action descriptor does not contain complete schema authority.");
        }

        var actionBytes = SidecarCapabilityTransportCodec.Serialize(request.Action);
        var actionContentHash = Convert.ToHexString(SHA256.HashData(actionBytes));
        if (!string.Equals(authority.ActionKey.Value, request.Descriptor.Key.Value, StringComparison.Ordinal) ||
            authority.ActionVersion != request.Descriptor.Version ||
            !string.Equals(authority.Category, request.Descriptor.Category, StringComparison.Ordinal) ||
            !string.Equals(authority.InputTypeIdentity, inputTypeIdentity, StringComparison.Ordinal) ||
            !string.Equals(authority.ResultTypeIdentity, resultTypeIdentity, StringComparison.Ordinal) ||
            !string.Equals(authority.DescriptorHash, descriptorHash, StringComparison.Ordinal) ||
            !string.Equals(authority.InputSchemaHash, request.Descriptor.InputSchema.ContentHash, StringComparison.Ordinal) ||
            authority.InputSchemaVersion != request.Descriptor.InputSchema.Version ||
            !string.Equals(authority.ResultSchemaHash, request.Descriptor.ResultSchema.ContentHash, StringComparison.Ordinal) ||
            authority.ResultSchemaVersion != request.Descriptor.ResultSchema.Version ||
            !string.Equals(authority.ActionContentHash, actionContentHash, StringComparison.Ordinal) ||
            authority.ActionByteLength != actionBytes.Length ||
            !SameContext(authority, request.Context) ||
            !MatchesDescriptorLineage(request.Context.Contribution?.Lineage, request.Descriptor) ||
            !string.Equals(authority.CapabilityHandleHash,
                ComputeCapabilityHandleHash(request.Context.CapabilityHandle),
                StringComparison.OrdinalIgnoreCase))
        {
            return HostActionEntryValidationResult.Reject(
                "host_action_spoofed_authority",
                "The host action entry request does not match its host-issued authority.");
        }

        return HostActionEntryValidationResult.Accept();
    }

    public static bool MatchesRequestContext<TAction, TResult>(
        HostActionEntryRequest<TAction, TResult> request,
        HostActionEntryRequestContext context) =>
        request is not null &&
        context is not null &&
        request.Context is not null &&
        SameContext(request.Context, context);

    public static bool MatchesAuthorityContext(
        HostActionEntryAuthority authority,
        HostActionEntryRequestContext context) =>
        authority is not null &&
        context is not null &&
        authority.RequestId == context.RequestId &&
        SameContext(authority, context);

    public static string ComputeCapabilityHandleHash(string capabilityHandle) =>
        Convert.ToHexString(SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes(capabilityHandle)));

    public static bool MatchesLineage<TAction, TResult>(
        HostActionEntryLineage? lineage,
        ActionDescriptor<TAction, TResult> descriptor,
        TAction action)
    {
        if (!MatchesDescriptorLineage(lineage, descriptor) ||
            lineage is null || !lineage.IsPayloadBound)
            return false;

        var actionBytes = SidecarCapabilityTransportCodec.Serialize(action);
        var actionHash = Convert.ToHexString(SHA256.HashData(actionBytes));
        return string.Equals(lineage.PayloadContentHash, actionHash, StringComparison.OrdinalIgnoreCase) &&
               lineage.PayloadByteLength == actionBytes.Length;
    }

    public static bool MatchesDescriptorLineage<TAction, TResult>(
        HostActionEntryLineage? lineage,
        ActionDescriptor<TAction, TResult> descriptor)
    {
        if (lineage is null || !lineage.IsDescriptorWellFormed ||
            descriptor.InputSchema is null || descriptor.ResultSchema is null)
            return false;

        return string.Equals(lineage.ActionKey.Value, descriptor.Key.Value, StringComparison.Ordinal) &&
               lineage.ActionVersion == descriptor.Version &&
               string.Equals(lineage.DescriptorHash, ComputeDescriptorHash(descriptor), StringComparison.Ordinal) &&
               string.Equals(lineage.InputTypeIdentity, TypeIdentity<TAction>(), StringComparison.Ordinal) &&
               lineage.InputSchemaVersion == descriptor.InputSchema.Version &&
               string.Equals(lineage.InputSchemaHash, descriptor.InputSchema.ContentHash, StringComparison.Ordinal);
    }

    public static bool SameContext(
        HostActionEntryRequestContext left,
        HostActionEntryRequestContext right) =>
        left.CapabilityId == right.CapabilityId &&
        string.Equals(left.CapabilityHandle, right.CapabilityHandle, StringComparison.Ordinal) &&
        left.Ingress == right.Ingress &&
        left.InvocationId == right.InvocationId &&
        left.RequestId == right.RequestId &&
        left.CancellationId == right.CancellationId &&
        SamePrincipal(left.Caller, right.Caller) &&
        SameFeatures(left.Features, right.Features) &&
        left.TraceId == right.TraceId &&
        left.IdempotencyKey == right.IdempotencyKey &&
        left.ParentInvocationId == right.ParentInvocationId &&
        left.Depth == right.Depth &&
        left.Attempt == right.Attempt &&
        left.Deadline == right.Deadline &&
        left.ExpiresAt == right.ExpiresAt &&
        SameContribution(left.Contribution, right.Contribution, includePayload: true);

    public static bool SameContextIgnoringPayload(
        HostActionEntryRequestContext left,
        HostActionEntryRequestContext right) =>
        left.CapabilityId == right.CapabilityId &&
        string.Equals(left.CapabilityHandle, right.CapabilityHandle, StringComparison.Ordinal) &&
        left.Ingress == right.Ingress &&
        left.InvocationId == right.InvocationId &&
        left.RequestId == right.RequestId &&
        left.CancellationId == right.CancellationId &&
        SamePrincipal(left.Caller, right.Caller) &&
        SameFeatures(left.Features, right.Features) &&
        left.TraceId == right.TraceId &&
        left.IdempotencyKey == right.IdempotencyKey &&
        left.ParentInvocationId == right.ParentInvocationId &&
        left.Depth == right.Depth &&
        left.Attempt == right.Attempt &&
        left.Deadline == right.Deadline &&
        left.ExpiresAt == right.ExpiresAt &&
        SameContribution(left.Contribution, right.Contribution, includePayload: false);

    private static bool SameLineage(
        HostActionEntryLineage? left,
        HostActionEntryLineage? right) =>
        left is not null &&
        right is not null &&
        SameLineage(left, right, includePayload: true);

    private static bool SameLineage(
        HostActionEntryLineage? left,
        HostActionEntryLineage? right,
        bool includePayload) =>
        left is not null &&
        right is not null &&
        left.ActionKey.Value == right.ActionKey.Value &&
        left.ActionVersion == right.ActionVersion &&
        string.Equals(left.DescriptorHash, right.DescriptorHash, StringComparison.Ordinal) &&
        string.Equals(left.InputTypeIdentity, right.InputTypeIdentity, StringComparison.Ordinal) &&
        left.InputSchemaVersion == right.InputSchemaVersion &&
        string.Equals(left.InputSchemaHash, right.InputSchemaHash, StringComparison.Ordinal) &&
        (!includePayload ||
         (string.Equals(left.PayloadContentHash, right.PayloadContentHash, StringComparison.OrdinalIgnoreCase) &&
          left.PayloadByteLength == right.PayloadByteLength));

    private static bool SameContribution(
        HostActionEntryContribution? left,
        HostActionEntryContribution? right,
        bool includePayload) =>
        left is not null &&
        right is not null &&
        left.IngressBinding.Ingress == right.IngressBinding.Ingress &&
        string.Equals(left.IngressBinding.PrimaryIdentity, right.IngressBinding.PrimaryIdentity, StringComparison.Ordinal) &&
        string.Equals(left.IngressBinding.SecondaryIdentity, right.IngressBinding.SecondaryIdentity, StringComparison.Ordinal) &&
        SameLineage(left.Lineage, right.Lineage, includePayload);

    private static bool SameContext(
        HostActionEntryAuthority authority,
        HostActionEntryRequestContext context) =>
        authority.Ingress == context.Ingress &&
        authority.InvocationId == context.InvocationId &&
        authority.ParentInvocationId == context.ParentInvocationId &&
        authority.Depth == context.Depth &&
        authority.Attempt == context.Attempt &&
        authority.RequestId == context.RequestId &&
        authority.CancellationId == context.CancellationId &&
        SamePrincipal(authority.Caller, context.Caller) &&
        SameFeatures(authority.Features, context.Features) &&
        authority.TraceId == context.TraceId &&
        authority.IdempotencyKey == context.IdempotencyKey &&
        authority.Deadline == context.Deadline &&
        authority.ExpiresAt == context.ExpiresAt;

    public static string ComputeDescriptorHash<TAction, TResult>(
        ActionDescriptor<TAction, TResult> descriptor)
    {
        ArgumentNullException.ThrowIfNull(descriptor);
        var canonical = new
        {
            Key = descriptor.Key.Value,
            descriptor.Version,
            descriptor.Category,
            Capabilities = (int)descriptor.Capabilities,
            descriptor.ContainsSensitiveData,
            descriptor.HasIrreversibleEffects,
            Repeat = new
            {
                Kind = descriptor.RepeatPolicy.Kind.ToString(),
                descriptor.RepeatPolicy.MaximumAttempts,
                MinimumBackoffTicks = descriptor.RepeatPolicy.MinimumBackoff.Ticks,
                descriptor.RepeatPolicy.IdempotencyScope,
            },
            Continuation = descriptor.ContinuationPolicy is null
                ? null
                : new
                {
                    MaximumLifetimeTicks = descriptor.ContinuationPolicy.MaximumLifetime.Ticks,
                    descriptor.ContinuationPolicy.Durable,
                    descriptor.ContinuationPolicy.SingleClaim,
                },
            DefaultTimeoutTicks = descriptor.DefaultTimeout.Ticks,
            ProtocolMinimum = descriptor.ProtocolVersionRange.Minimum,
            ProtocolMaximum = descriptor.ProtocolVersionRange.Maximum,
            SafePoints = descriptor.SafePoints.Select(point => point.ToString()).ToArray(),
            InputSchema = descriptor.InputSchema is null
                ? null
                : new
                {
                    descriptor.InputSchema.ContractName,
                    descriptor.InputSchema.Version,
                    descriptor.InputSchema.ContentHash,
                },
            ResultSchema = descriptor.ResultSchema is null
                ? null
                : new
                {
                    descriptor.ResultSchema.ContractName,
                    descriptor.ResultSchema.Version,
                    descriptor.ResultSchema.ContentHash,
                },
            InputTypeIdentity = TypeIdentity<TAction>(),
            ResultTypeIdentity = TypeIdentity<TResult>(),
        };
        return Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(canonical)));
    }

    /// <summary>Computes the typed descriptor hash from neutral sidecar metadata.</summary>
    public static string ComputeDescriptorHash(
        SidecarActionDefinition definition,
        SidecarActionDescriptorIdentity identity)
    {
        ArgumentNullException.ThrowIfNull(definition);
        ArgumentNullException.ThrowIfNull(identity);
        var canonical = new
        {
            Key = definition.ActionKey.Value,
            definition.Version,
            definition.Category,
            Capabilities = (int)definition.Capabilities,
            definition.ContainsSensitiveData,
            definition.HasIrreversibleEffects,
            Repeat = new
            {
                Kind = definition.RepeatPolicy.Kind.ToString(),
                definition.RepeatPolicy.MaximumAttempts,
                MinimumBackoffTicks = definition.RepeatPolicy.MinimumBackoff.Ticks,
                definition.RepeatPolicy.IdempotencyScope,
            },
            Continuation = definition.ContinuationPolicy is null
                ? null
                : new
                {
                    MaximumLifetimeTicks = definition.ContinuationPolicy.MaximumLifetime.Ticks,
                    definition.ContinuationPolicy.Durable,
                    definition.ContinuationPolicy.SingleClaim,
                },
            DefaultTimeoutTicks = definition.DefaultTimeout.Ticks,
            ProtocolMinimum = definition.ProtocolVersionRange.Minimum,
            ProtocolMaximum = definition.ProtocolVersionRange.Maximum,
            SafePoints = definition.SafePoints.Select(point => point.ToString()).ToArray(),
            InputSchema = new
            {
                definition.InputSchema.ContractName,
                definition.InputSchema.Version,
                definition.InputSchema.ContentHash,
            },
            ResultSchema = new
            {
                definition.ResultSchema.ContractName,
                definition.ResultSchema.Version,
                definition.ResultSchema.ContentHash,
            },
            identity.InputTypeIdentity,
            identity.ResultTypeIdentity,
        };
        return Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(canonical)));
    }

    public static string ComputeAuthorityHash(HostActionEntryAuthority authority)
    {
        ArgumentNullException.ThrowIfNull(authority);
        var canonical = new
        {
            authority.ModuleId,
            authority.GraphId,
            authority.SessionId,
            authority.RequestId,
            authority.CancellationId,
            authority.CallId,
            authority.ReplayNonce,
            authority.Sequence,
            Caller = new
            {
                authority.Caller.SubjectId,
                authority.Caller.DisplayName,
                Roles = authority.Caller.Roles?.Order(StringComparer.Ordinal).ToArray(),
                authority.Caller.IsAuthenticated,
            },
            Features = authority.Features.Items.Select(feature => new
            {
                feature.ContractName,
                feature.SchemaVersion,
                feature.OwnerModuleId,
                feature.MaxBytes,
                Value = feature.Value.GetRawText(),
            }).ToArray(),
            authority.TraceId,
            authority.IdempotencyKey,
            ActionKey = authority.ActionKey.Value,
            authority.ActionVersion,
            authority.Category,
            authority.InputTypeIdentity,
            authority.ResultTypeIdentity,
            authority.DescriptorHash,
            authority.InputSchemaHash,
            authority.InputSchemaVersion,
            authority.ResultSchemaHash,
            authority.ResultSchemaVersion,
            authority.ActionContentHash,
            authority.ActionByteLength,
            authority.Deadline,
            authority.IssuedAt,
            authority.ExpiresAt,
            authority.Ingress,
            authority.InvocationId,
            authority.ParentInvocationId,
            authority.Depth,
            authority.Attempt,
            authority.CapabilityId,
            authority.CapabilityHandleHash,
        };
        return Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(canonical)));
    }

    private static string TypeIdentity<T>() =>
        typeof(T).AssemblyQualifiedName ?? typeof(T).FullName ?? typeof(T).Name;

    private static bool SamePrincipal(RequestPrincipal left, RequestPrincipal right) =>
        string.Equals(left.SubjectId, right.SubjectId, StringComparison.Ordinal) &&
        string.Equals(left.DisplayName, right.DisplayName, StringComparison.Ordinal) &&
        left.IsAuthenticated == right.IsAuthenticated &&
        SameSets(left.Roles, right.Roles);

    private static bool SameSets(IReadOnlySet<string>? left, IReadOnlySet<string>? right)
    {
        if (left is null || right is null)
            return left is null && right is null;

        if (left.Count != right.Count)
            return false;

        foreach (var leftRole in left)
        {
            if (leftRole is null ||
                !right.Any(rightRole =>
                    rightRole is not null &&
                    string.Equals(leftRole, rightRole, StringComparison.Ordinal)))
            {
                return false;
            }
        }

        return true;
    }

    private static bool SameFeatures(ExtensionFeatureSet left, ExtensionFeatureSet right) =>
        left.Items.Count == right.Items.Count &&
        left.Items.Zip(right.Items).All(pair =>
            string.Equals(pair.First.ContractName, pair.Second.ContractName, StringComparison.Ordinal) &&
            pair.First.SchemaVersion == pair.Second.SchemaVersion &&
            string.Equals(pair.First.OwnerModuleId, pair.Second.OwnerModuleId, StringComparison.Ordinal) &&
            pair.First.MaxBytes == pair.Second.MaxBytes &&
            string.Equals(pair.First.Value.GetRawText(), pair.Second.Value.GetRawText(), StringComparison.Ordinal));
}

/// <summary>Read-only terminal callback for one host-owned typed action entry.</summary>
public interface IHostActionEntryTerminal<TAction, TResult>
{
    Guid TerminalId { get; }

    ValueTask<TResult> InvokeAsync(
        ActionContext<TAction> context,
        CancellationToken cancellationToken = default);
}

/// <summary>Host-owned entry for typed module action calls.</summary>
/// <remarks>
/// Implementations resolve the authorized descriptor and pipeline snapshot from host state.
/// They must not use caller-supplied descriptor capabilities as authorization.
/// They must validate the request authority before resolving the descriptor or snapshot.
/// </remarks>
public interface IHostActionEntry
{
    ValueTask<IActionOutcome<TResult>> InvokeAsync<TAction, TResult>(
        HostActionEntryRequest<TAction, TResult> request,
        IHostActionEntryTerminal<TAction, TResult> terminal,
        CancellationToken cancellationToken = default);

    ValueTask<IActionOutcome<TResult>> InvokeNestedAsync<TParentAction, TAction, TResult>(
        HostActionEntryNestedRequest<TParentAction, TAction, TResult> request,
        IHostActionEntryTerminal<TAction, TResult> terminal,
        CancellationToken cancellationToken = default);
}

/// <summary>Authenticated authority for one external module action dispatch.</summary>
public sealed record SidecarExternalActionDispatchAuthority(
    string ModuleId,
    string GraphId,
    SidecarCapabilityCallIdentity Call,
    SidecarActionDescriptorIdentity Descriptor,
    SidecarSerializedPayload Action,
    SidecarActionTerminalRegistration Terminal,
    HostActionEntryRequestContext InitiatingHostContext,
    SidecarActionEffectiveHostEntryContext EffectiveHostEntry)
{
    public bool IsWellFormed =>
        !string.IsNullOrWhiteSpace(ModuleId) &&
        !string.IsNullOrWhiteSpace(GraphId) &&
        Call is not null &&
        Call.IsValid &&
        Call.Capability == SidecarCapabilityKind.Action &&
        Descriptor is not null &&
        Descriptor.IsWellFormed &&
        Action is not null &&
        Action.IsValid &&
        Terminal is not null &&
        Terminal.IsWellFormed &&
        InitiatingHostContext is not null &&
        EffectiveHostEntry is not null &&
        EffectiveHostEntry.IsWellFormed;
}

/// <summary>Trusted host or session authority for one external action dispatch.</summary>
public interface ISidecarExternalActionDispatchAuthorityVerifier
{
    SidecarCapabilityValidationResult ValidateAndConsume(
        SidecarExternalActionDispatchAuthority authority,
        DateTimeOffset now);
}

public static class SidecarExternalActionDispatchAuthorityValidator
{
    public static SidecarCapabilityValidationResult Validate<TAction, TResult>(
        SidecarExternalActionDispatchAuthority authority,
        ActionDescriptor<TAction, TResult> descriptor,
        TAction action,
        ActionPipelineSnapshot snapshot,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(authority);
        ArgumentNullException.ThrowIfNull(descriptor);
        ArgumentNullException.ThrowIfNull(snapshot);

        var expectedDescriptor = CreateDescriptorIdentity<TAction, TResult>(descriptor);
        byte[] actionBytes;
        try
        {
            actionBytes = SidecarCapabilityTransportCodec.Serialize(action);
        }
        catch (Exception exception) when (exception is JsonException or NotSupportedException)
        {
            return Reject("sidecar_external_invalid_payload", "The external action payload is not canonical.");
        }

        return ValidateCore(
            authority,
            expectedDescriptor,
            actionBytes,
            snapshot,
            now);
    }

    /// <summary>Validates one serialized external action against exact sidecar metadata.</summary>
    public static SidecarCapabilityValidationResult ValidateSerialized(
        SidecarExternalActionDispatchAuthority authority,
        SidecarActionDefinition definition,
        SidecarActionDescriptorIdentity descriptor,
        JsonElement action,
        ActionPipelineSnapshot snapshot,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(authority);
        ArgumentNullException.ThrowIfNull(definition);
        ArgumentNullException.ThrowIfNull(descriptor);
        ArgumentNullException.ThrowIfNull(snapshot);

        if (!DescriptorMatchesDefinition(descriptor, definition))
        {
            return Reject(
                "sidecar_external_invalid_descriptor",
                "The serialized external action descriptor is incomplete or inconsistent.");
        }

        byte[] actionBytes;
        try
        {
            actionBytes = SidecarCapabilityTransportCodec.Serialize(action);
        }
        catch (Exception exception) when (exception is JsonException or NotSupportedException)
        {
            return Reject("sidecar_external_invalid_payload", "The external action payload is not canonical.");
        }

        return ValidateCore(
            authority,
            descriptor,
            actionBytes,
            snapshot,
            now);
    }

    private static SidecarCapabilityValidationResult ValidateCore(
        SidecarExternalActionDispatchAuthority authority,
        SidecarActionDescriptorIdentity expectedDescriptor,
        byte[] actionBytes,
        ActionPipelineSnapshot snapshot,
        DateTimeOffset now)
    {
        if (!authority.IsWellFormed)
            return Reject("sidecar_external_invalid_authority", "The external action authority is incomplete.");

        var effective = authority.EffectiveHostEntry.EffectiveContext;
        var hostAuthority = authority.EffectiveHostEntry.Authority;
        if (!SameDescriptor(authority.Descriptor, expectedDescriptor) ||
            !SameDescriptor(effective.Descriptor, expectedDescriptor) ||
            !SamePayload(
                authority.Action,
                actionBytes,
                expectedDescriptor.InputTypeIdentity,
                expectedDescriptor.InputSchemaVersion) ||
            !SamePayload(
                effective.EffectiveAction,
                actionBytes,
                expectedDescriptor.InputTypeIdentity,
                expectedDescriptor.InputSchemaVersion) ||
            !string.Equals(authority.ModuleId, authority.Call.ModuleId, StringComparison.Ordinal) ||
            !string.Equals(authority.GraphId, authority.Call.GraphId, StringComparison.Ordinal) ||
            !string.Equals(authority.ModuleId, hostAuthority.ModuleId, StringComparison.Ordinal) ||
            !string.Equals(authority.GraphId, hostAuthority.GraphId, StringComparison.Ordinal) ||
            effective.Call != authority.Call ||
            hostAuthority.SessionId != authority.Call.SessionId ||
            hostAuthority.RequestId != authority.Call.RequestId ||
            hostAuthority.CancellationId != authority.Call.CancellationId ||
            hostAuthority.CallId != authority.Call.CallId ||
            hostAuthority.Invocation != effective.Invocation ||
            hostAuthority.ActionKey != expectedDescriptor.Key ||
            hostAuthority.ActionVersion != expectedDescriptor.Version ||
            hostAuthority.TerminalId != authority.Terminal.TerminalId ||
            authority.Terminal.ActionTypeIdentity != expectedDescriptor.InputTypeIdentity ||
            authority.Terminal.ActionSchemaVersion != expectedDescriptor.InputSchemaVersion ||
            authority.Terminal.ResultTypeIdentity != expectedDescriptor.ResultTypeIdentity ||
            authority.Terminal.ResultSchemaVersion != expectedDescriptor.ResultSchemaVersion ||
            !string.Equals(authority.Terminal.DescriptorHash, expectedDescriptor.DescriptorHash, StringComparison.Ordinal) ||
            !string.Equals(
                SidecarCapabilityTransportValidation.ComputeSnapshotHash(effective.Snapshot),
                SidecarCapabilityTransportValidation.ComputeSnapshotHash(snapshot),
                StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(
                hostAuthority.SnapshotContentHash,
                SidecarCapabilityTransportValidation.ComputeSnapshotHash(snapshot),
                StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(
                hostAuthority.HostContextBindingHash,
                SidecarCapabilityTransportValidation.ComputeHostActionEntryContextBindingHash(
                    authority.InitiatingHostContext),
                StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(
                hostAuthority.CanonicalBindingHash,
                SidecarCapabilityTransportValidation.ComputeTerminalAuthorityBindingHash(hostAuthority),
                StringComparison.OrdinalIgnoreCase) ||
            string.IsNullOrWhiteSpace(hostAuthority.Proof))
        {
            return Reject(
                "sidecar_external_spoofed_authority",
                "The external action authority does not match the descriptor, payload, terminal, or snapshot.");
        }

        if (now >= effective.Deadline ||
            now >= hostAuthority.ExpiresAt ||
            authority.Call.Deadline != effective.Deadline ||
            authority.Call.CancellationId != effective.Cancellation.CancellationId ||
            effective.Cancellation.ExpiresAt < effective.Deadline ||
            effective.InvocationId != authority.InitiatingHostContext.InvocationId ||
            effective.ParentInvocationId != authority.InitiatingHostContext.ParentInvocationId ||
            effective.Depth != authority.InitiatingHostContext.Depth ||
            effective.Attempt != authority.InitiatingHostContext.Attempt ||
            effective.TraceId != authority.InitiatingHostContext.TraceId ||
            effective.IdempotencyKey != authority.InitiatingHostContext.IdempotencyKey ||
            effective.Deadline != authority.InitiatingHostContext.Deadline ||
            !SameCanonical(effective.Caller, authority.InitiatingHostContext.Caller) ||
            !SameCanonical(effective.Features, authority.InitiatingHostContext.Features))
        {
            return Reject(
                "sidecar_external_expired_authority",
                "The external action authority is expired or has a changed host context.");
        }

        return SidecarCapabilityValidationResult.Accept();
    }

    /// <summary>Gets whether one transport identity matches its complete discovered definition.</summary>
    public static bool DescriptorMatchesDefinition(
        SidecarActionDescriptorIdentity descriptor,
        SidecarActionDefinition definition)
    {
        ArgumentNullException.ThrowIfNull(descriptor);
        ArgumentNullException.ThrowIfNull(definition);
        return descriptor.IsWellFormed &&
            definition.ActionKey == descriptor.Key &&
            definition.Version == descriptor.Version &&
            string.Equals(definition.Category, descriptor.Category, StringComparison.Ordinal) &&
            definition.DefaultTimeout > TimeSpan.Zero &&
            definition.InputSchema.Version == descriptor.InputSchemaVersion &&
            string.Equals(
                definition.InputSchema.ContentHash,
                descriptor.InputSchemaHash,
                StringComparison.Ordinal) &&
            definition.ResultSchema.Version == descriptor.ResultSchemaVersion &&
            string.Equals(
                definition.ResultSchema.ContentHash,
                descriptor.ResultSchemaHash,
                StringComparison.Ordinal) &&
            string.Equals(
                HostActionEntryAuthorityValidator.ComputeDescriptorHash(definition, descriptor),
                descriptor.DescriptorHash,
                StringComparison.Ordinal);
    }

    private static SidecarActionDescriptorIdentity CreateDescriptorIdentity<TAction, TResult>(
        ActionDescriptor<TAction, TResult> descriptor) =>
        new(
            descriptor.Key,
            descriptor.Version,
            descriptor.Category,
            TypeIdentity<TAction>(),
            descriptor.InputSchema?.ContentHash ?? string.Empty,
            descriptor.InputSchema?.Version ?? 0,
            TypeIdentity<TResult>(),
            descriptor.ResultSchema?.ContentHash ?? string.Empty,
            descriptor.ResultSchema?.Version ?? 0,
            HostActionEntryAuthorityValidator.ComputeDescriptorHash(descriptor));

    private static bool SameDescriptor(
        SidecarActionDescriptorIdentity left,
        SidecarActionDescriptorIdentity right) =>
        left.Key == right.Key &&
        left.Version == right.Version &&
        string.Equals(left.Category, right.Category, StringComparison.Ordinal) &&
        string.Equals(left.InputTypeIdentity, right.InputTypeIdentity, StringComparison.Ordinal) &&
        string.Equals(left.InputSchemaHash, right.InputSchemaHash, StringComparison.Ordinal) &&
        left.InputSchemaVersion == right.InputSchemaVersion &&
        string.Equals(left.ResultTypeIdentity, right.ResultTypeIdentity, StringComparison.Ordinal) &&
        string.Equals(left.ResultSchemaHash, right.ResultSchemaHash, StringComparison.Ordinal) &&
        left.ResultSchemaVersion == right.ResultSchemaVersion &&
        string.Equals(left.DescriptorHash, right.DescriptorHash, StringComparison.Ordinal);

    private static bool SamePayload(
        SidecarSerializedPayload left,
        ReadOnlySpan<byte> rightBytes,
        string rightTypeIdentity,
        int rightSchemaVersion) =>
        string.Equals(left.TypeIdentity, rightTypeIdentity, StringComparison.Ordinal) &&
        left.SchemaVersion == rightSchemaVersion &&
        string.Equals(
            left.ContentHash,
            SidecarCapabilityTransportCodec.ComputeSha256(rightBytes),
            StringComparison.OrdinalIgnoreCase) &&
        left.ByteLength == rightBytes.Length;

    private static bool SameCanonical<T>(T left, T right) =>
        string.Equals(
            SidecarCapabilityTransportCodec.ComputeSha256(
                SidecarCapabilityTransportCodec.Serialize(left)),
            SidecarCapabilityTransportCodec.ComputeSha256(
                SidecarCapabilityTransportCodec.Serialize(right)),
            StringComparison.OrdinalIgnoreCase);

    private static string TypeIdentity<T>() =>
        typeof(T).AssemblyQualifiedName ?? typeof(T).FullName ?? typeof(T).Name;

    private static SidecarCapabilityValidationResult Reject(string code, string message) =>
        SidecarCapabilityValidationResult.Reject(code, message);
}

public interface IActionDispatcher
{
    ValueTask<IActionOutcome<TResult>> RunAsync<TAction, TResult>(
        ActionDescriptor<TAction, TResult> descriptor,
        TAction action,
        Func<ActionContext<TAction>, CancellationToken, ValueTask<TResult>> terminal,
        ActionPipelineSnapshot snapshot,
        CancellationToken ct);

    ValueTask<IActionOutcome<TResult>> RunExternalAsync<TAction, TResult>(
        ActionDescriptor<TAction, TResult> descriptor,
        TAction action,
        Func<ActionContext<TAction>, CancellationToken, ValueTask<TResult>> terminal,
        ActionPipelineSnapshot snapshot,
        SidecarExternalActionDispatchAuthority authority,
        CancellationToken ct);

    /// <summary>Runs one external action without loading its optional CLR contract types.</summary>
    ValueTask<IActionOutcome<JsonElement>> RunExternalSerializedAsync(
        SidecarActionDefinition definition,
        SidecarActionDescriptorIdentity descriptor,
        JsonElement action,
        Func<ActionContext<JsonElement>, CancellationToken, ValueTask<JsonElement>> terminal,
        ActionPipelineSnapshot snapshot,
        SidecarExternalActionDispatchAuthority authority,
        CancellationToken ct);

    ValueTask<TResult> RunRequiredAsync<TAction, TResult>(
        ActionDescriptor<TAction, TResult> descriptor,
        TAction action,
        Func<ActionContext<TAction>, CancellationToken, ValueTask<TResult>> terminal,
        ActionPipelineSnapshot snapshot,
        CancellationToken ct);

    ValueTask<TResult> RunExternalRequiredAsync<TAction, TResult>(
        ActionDescriptor<TAction, TResult> descriptor,
        TAction action,
        Func<ActionContext<TAction>, CancellationToken, ValueTask<TResult>> terminal,
        ActionPipelineSnapshot snapshot,
        SidecarExternalActionDispatchAuthority authority,
        CancellationToken ct);
}

public sealed class ActionOutcomeUncertainException : Exception
{
    public ActionOutcomeUncertainException(ActionUncertainty uncertainty)
        : base(uncertainty.Message)
    {
        Uncertainty = uncertainty;
    }

    public ActionUncertainty Uncertainty { get; }

    public bool IsRetryable => false;
}
