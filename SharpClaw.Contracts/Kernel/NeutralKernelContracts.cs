using System.Text.Json;

namespace SharpClaw.Contracts.Kernel;

/// <summary>Identifies one versioned action in the SharpClaw dispatcher.</summary>
public readonly record struct SharpClawActionKey(string Value)
{
    public override string ToString() => Value;
}

/// <summary>Identifies one versioned event in the SharpClaw dispatcher.</summary>
public readonly record struct SharpClawEventKey(string Value)
{
    public override string ToString() => Value;
}

/// <summary>Describes the supported versions for a contract or protocol.</summary>
public sealed record ContractVersionRange
{
    public int Minimum { get; }
    public int Maximum { get; }

    public ContractVersionRange(int minimum, int maximum)
    {
        if (minimum < 1)
            throw new ArgumentOutOfRangeException(nameof(minimum));

        if (maximum < minimum)
            throw new ArgumentOutOfRangeException(nameof(maximum));

        Minimum = minimum;
        Maximum = maximum;
    }

    public bool Contains(int version) => version >= Minimum && version <= Maximum;

    public int? Negotiate(ContractVersionRange other)
    {
        ArgumentNullException.ThrowIfNull(other);
        var maximum = Math.Min(Maximum, other.Maximum);
        var minimum = Math.Max(Minimum, other.Minimum);
        return minimum <= maximum ? maximum : null;
    }

    public static ContractVersionRange Exact(int version) => new(version, version);
}

/// <summary>Negotiates one sidecar protocol version range.</summary>
public sealed record ProtocolVersionNegotiation(
    int MinimumVersion,
    int MaximumVersion)
{
    public int? Select(ProtocolVersionNegotiation other)
    {
        ArgumentNullException.ThrowIfNull(other);
        var maximum = Math.Min(MaximumVersion, other.MaximumVersion);
        var minimum = Math.Max(MinimumVersion, other.MinimumVersion);
        return minimum <= maximum ? maximum : null;
    }
}

/// <summary>References a bounded JSON schema used by an untyped contract.</summary>
public sealed record JsonSchemaReference(
    string ContractName,
    int Version,
    string? ContentHash = null);

/// <summary>Represents a safe error that can cross a contract boundary.</summary>
public sealed record ExecutionError(
    string Code,
    string Message,
    bool IsRetryable = false,
    IReadOnlyDictionary<string, string>? Details = null);

/// <summary>Identifies the caller that started an action or chat turn.</summary>
public sealed record RequestPrincipal(
    string SubjectId,
    string? DisplayName = null,
    IReadOnlySet<string>? Roles = null,
    bool IsAuthenticated = true)
{
    public static RequestPrincipal Anonymous { get; } =
        new("anonymous", "Anonymous", new HashSet<string>(StringComparer.Ordinal), false);
}

/// <summary>One versioned feature value declared by a registration.</summary>
public sealed record ExtensionFeature(
    string ContractName,
    int SchemaVersion,
    string OwnerId,
    int MaxBytes,
    JsonElement Value);

/// <summary>Immutable feature values carried through a turn or action context.</summary>
public sealed record ExtensionFeatureSet(
    IReadOnlyList<ExtensionFeature> Items)
{
    public static ExtensionFeatureSet Empty { get; } = new([]);

    public bool Contains(string contractName) =>
        Items.Any(item => string.Equals(item.ContractName, contractName, StringComparison.Ordinal));

    public ExtensionFeature? Find(string contractName) =>
        Items.FirstOrDefault(item =>
            string.Equals(item.ContractName, contractName, StringComparison.Ordinal));
}

/// <summary>Host-issued token for one durable continuation.</summary>
public sealed record ContinuationToken(Guid TokenId, string Secret);

/// <summary>Durable destination for a continuation result.</summary>
public sealed record ContinuationDestination(string Kind, string? Address = null);

/// <summary>Lifecycle state of a host-owned continuation.</summary>
public enum ContinuationState
{
    Pending,
    Claimed,
    CancelRequested,
    Cancelled,
    Completed,
    Delivered,
    Expired,
    Deleted,
    OutcomeUncertain,
}

/// <summary>Execution stage stored for continuation recovery.</summary>
public enum ContinuationExecutionStage
{
    BeforeTerminal,
    TerminalStarted,
    TerminalReceipted,
    OutcomePersisted,
    DeliveryStarted,
}

/// <summary>Certainty classification for a durable action result.</summary>
public enum ActionOutcomeCertainty
{
    Certain,
    Uncertain,
}

/// <summary>One lease and fencing generation for a continuation claim.</summary>
public sealed record ContinuationClaim(
    string Owner,
    DateTimeOffset LeaseExpiresAt,
    int Generation,
    long ExpectedRevision);

/// <summary>Safe points where a host can apply interruption or cancellation.</summary>
public enum ActionSafePoint
{
    BeforeContinuation,
    BeforeTerminal,
    AfterTerminal,
    BeforeCommit,
    AfterCommit,
}

/// <summary>Effective action capabilities granted to one registration hook.</summary>
public sealed record ActionCapabilityGrant(
    SharpClawActionKey ActionKey,
    int ActionVersion,
    ActionInterceptionCapabilities Capabilities,
    bool SensitiveApproved = false,
    bool AcceptUnknownSchemas = false);

/// <summary>Effective event capabilities granted to one registration listener or interceptor.</summary>
public sealed record EventCapabilityGrant(
    SharpClawEventKey EventKey,
    int EventVersion,
    EventInterceptionCapabilities Capabilities,
    bool SensitiveApproved = false,
    bool AcceptUnknownSchemas = false);

/// <summary>Immutable compiled action and event grants for one active turn.</summary>
public sealed record ActionPipelineSnapshot(
    string ContractHash,
    IReadOnlyList<ActionCapabilityGrant> ActionGrants,
    IReadOnlyList<EventCapabilityGrant>? EventGrants = null,
    int MaximumActionDepth = 32);

/// <summary>Exact approval for sensitive wildcard action and event selection.</summary>
public sealed record SensitiveWildcardApproval(
    string SourceId,
    IReadOnlyDictionary<string, int> ActionVersions,
    IReadOnlyDictionary<string, int> EventVersions)
{
    public bool CoversAction(SharpClawActionKey key, int version) =>
        ActionVersions.TryGetValue(key.Value, out var approved) && approved == version;

    public bool CoversEvent(SharpClawEventKey key, int version) =>
        EventVersions.TryGetValue(key.Value, out var approved) && approved == version;
}

/// <summary>Deterministic priority for one action or event hook.</summary>
public enum HookPriority
{
    Highest,
    High,
    Normal,
    Low,
    Lowest,
}

/// <summary>Failure handling allowed for one hook registration.</summary>
public enum HookFailurePolicy
{
    FailAction,
    BestEffort,
}

/// <summary>Delivery class for an event listener.</summary>
public enum EventDelivery
{
    Inline,
    Queued,
    Durable,
}

/// <summary>Ordering data used by the graph compiler.</summary>
public sealed record HookOrdering(
    string Id,
    HookPriority Priority = HookPriority.Normal,
    IReadOnlyList<string>? Before = null,
    IReadOnlyList<string>? After = null,
    TimeSpan? Timeout = null,
    HookFailurePolicy FailurePolicy = HookFailurePolicy.FailAction);

/// <summary>Claims one exclusive resolver or coordinator slot.</summary>
public sealed record ExclusiveClaim(string Id);

/// <summary>One registration-owned feature contract and its transport limit.</summary>
public sealed record FeatureDescriptor(
    string ContractName,
    int SchemaVersion,
    string OwnerId,
    int MaxBytes,
    bool Required = false);
