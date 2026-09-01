using System.Text.Json;
using System.Text.Json.Serialization;
using SharpClaw.Contracts.Providers;

namespace SharpClaw.Contracts.Modules;

public sealed record ToolHoldRequirement(
    string Code,
    string Description,
    string? ApprovalContract = null);

/// <summary>Input for one direct chat turn.</summary>
public sealed record ChatTurnInput(
    string Message,
    Guid? ConversationId = null,
    RequestPrincipal? Caller = null,
    ExtensionFeatureSet? Features = null,
    string? ClientType = null);

/// <summary>Immutable host authority for one chat operation.</summary>
public sealed record ChatOperationContext(
    Guid InvocationId,
    Guid? ParentInvocationId,
    Guid TraceId,
    Guid IdempotencyKey,
    int Depth,
    int Attempt,
    DateTimeOffset Deadline,
    RequestPrincipal Caller,
    ExtensionFeatureSet Features,
    [property: JsonIgnore] IHostActionEntry? HostActionEntry = null)
{
    public bool IsWellFormed(DateTimeOffset now) =>
        InvocationId != Guid.Empty &&
        TraceId != Guid.Empty &&
        IdempotencyKey != Guid.Empty &&
        Depth >= 0 &&
        Attempt >= 1 &&
        Deadline > now &&
        Caller is not null &&
        !string.IsNullOrWhiteSpace(Caller.SubjectId) &&
        Features is not null;
}

/// <summary>Result of conversation resolution for one turn.</summary>
public sealed record ConversationSelection(
    Guid ConversationId,
    bool Created = false);

/// <summary>Immutable context for one direct chat turn.</summary>
public sealed record ChatTurnContext(
    Guid TurnId,
    ChatTurnInput Input,
    ConversationSelection Conversation);

/// <summary>Provider and model settings selected for one chat turn.</summary>
public sealed record ChatProfile(
    string ProviderKey,
    Guid ModelId,
    string? ModelName = null,
    string? SystemPrompt = null,
    CompletionParameters? ProviderParameters = null);

/// <summary>Request supplied to context contributors.</summary>
public sealed record ChatContextRequest(
    Guid ConversationId,
    ChatProfile Profile,
    IReadOnlyList<ChatCompletionMessage> History,
    ChatTurnContext? Turn = null);

/// <summary>One bounded system prompt addition.</summary>
public sealed record SystemPromptSegment(
    string Key,
    string Content);

/// <summary>One immutable contribution to a chat context.</summary>
public sealed record ChatContextContribution(
    IReadOnlyList<SystemPromptSegment> SystemPromptSegments,
    IReadOnlyList<ChatCompletionMessage> Messages,
    IReadOnlyList<ExtensionFeature> Features)
{
    public static ChatContextContribution Empty { get; } = new([], [], []);
}

public interface IConversationResolver
{
    ValueTask<ConversationSelection> ResolveAsync(
        ChatTurnInput input,
        ChatOperationContext context,
        CancellationToken ct);
}

public interface IChatProfileResolver
{
    ValueTask<ChatProfile> ResolveAsync(
        ChatTurnContext turn,
        ChatOperationContext context,
        CancellationToken ct);
}

public interface IChatContextContributor
{
    ValueTask<ChatContextContribution> ContributeAsync(
        ChatContextRequest request,
        ChatOperationContext context,
        CancellationToken ct);
}

public interface IChatContextAssembler
{
    ValueTask<ChatContextContribution> BuildAsync(
        ChatContextRequest request,
        CancellationToken ct);
}

public interface IConversationStore
{
    ValueTask<IReadOnlyList<ChatCompletionMessage>> LoadHistoryAsync(
        Guid conversationId,
        ChatOperationContext context,
        CancellationToken ct);

    ValueTask CommitExchangeAsync(
        ChatExchange exchange,
        ChatOperationContext context,
        CancellationToken ct);
}

public sealed record ChatExchange(
    ChatTurnContext Turn,
    string UserMessage,
    ChatCompletionResult Completion);

public interface IProviderRoundLoop
{
    ValueTask<ChatCompletionResult> RunAsync(
        ProviderTurnRequest request,
        IUnifiedToolPipeline tools,
        CancellationToken ct);
}

public sealed record ProviderTurnRequest(
    ChatTurnContext Turn,
    ChatProfile Profile,
    ChatContextContribution Context,
    IReadOnlyList<ToolDescriptor> Tools);

public interface ICommittedEventWriter
{
    ValueTask PublishAsync<TEvent>(
        EventDescriptor<TEvent> descriptor,
        TEvent payload,
        CancellationToken ct);
}

public sealed record ChatTurnResult(
    Guid TurnId,
    Guid ConversationId,
    ChatCompletionResult Completion,
    IReadOnlyList<ExtensionFeature>? Features = null);

public sealed record ChatPipelineSnapshot(
    ActionPipelineSnapshot Actions,
    IReadOnlyList<ToolDescriptor> Tools,
    ExtensionFeatureSet Features);

/// <summary>One model tool request passed to the unified tool pipeline.</summary>
public sealed record ToolInvocation(
    Guid InvocationId,
    Guid? ConversationId,
    string ToolCallId,
    string ToolName,
    JsonElement Arguments,
    HostActionEntryRequestContext HostActionContext)
{
    public RequestPrincipal Caller => HostActionContext.Caller;
    public ExtensionFeatureSet Features => HostActionContext.Features;

    public bool IsWellFormed(DateTimeOffset now) =>
        InvocationId != Guid.Empty &&
        !string.IsNullOrWhiteSpace(ToolCallId) &&
        !string.IsNullOrWhiteSpace(ToolName) &&
        HostActionContext is not null &&
        HostActionContext.Ingress == HostActionEntryIngress.Tool &&
        HostActionContext.InvocationId == InvocationId &&
        HostActionContext.Contribution?.IngressBinding.Ingress == HostActionEntryIngress.Tool &&
        string.Equals(HostActionContext.Contribution.IngressBinding.PrimaryIdentity, ToolName, StringComparison.Ordinal) &&
        (ConversationId is null
            ? HostActionContext.Contribution.IngressBinding.SecondaryIdentity is null
            : ConversationId != Guid.Empty &&
              string.Equals(
                  HostActionContext.Contribution.IngressBinding.SecondaryIdentity,
                  ConversationId.Value.ToString("D"),
                  StringComparison.Ordinal)) &&
        HostActionContext.IsWellFormed(now);
}

/// <summary>One tool result returned by a module handler.</summary>
public sealed record ToolResult(
    string? Content,
    JsonElement? Data = null,
    bool IsError = false)
{
    public static ToolResult Text(string text) => new(text);

    public static ToolResult Error(string text) => new(text, IsError: true);
}

/// <summary>One tool schema and its stable name.</summary>
public sealed record ToolDescriptor(
    string Name,
    string Description,
    JsonElement ParametersSchema,
    int Version = 1,
    bool ContainsSensitiveData = false);

public static class ToolSchemas
{
    public static JsonElement EmptyObject =>
        JsonDocument.Parse("{\"type\":\"object\"}").RootElement.Clone();
}

public interface IToolHandler
{
    ValueTask<ToolResult> InvokeAsync(
        ToolInvocation invocation,
        CancellationToken ct);
}

public abstract record ToolGateDecision
{
    public sealed record Continue : ToolGateDecision;
    public sealed record Reject(string Code, string Message) : ToolGateDecision;
    public sealed record Hold(ToolHoldRequirement Requirement) : ToolGateDecision;
}

public interface IToolInvocationGate
{
    ValueTask<ToolGateDecision> EvaluateAsync(
        ToolInvocation invocation,
        CancellationToken ct);
}

public sealed record ToolExecutionPlan(
    ToolInvocation Invocation,
    IReadOnlyList<ToolHoldRequirement> Holds);

public delegate ValueTask<ToolResult> ToolExecutionDelegate(
    ToolInvocation invocation,
    CancellationToken ct);

public interface IToolExecutionCoordinator
{
    ValueTask<ToolInvocationOutcome> CoordinateAsync(
        ToolExecutionPlan plan,
        ToolExecutionDelegate execute,
        CancellationToken ct);
}

public sealed record ToolInvocationOutcome(
    ActionOutcomeKind Kind,
    ToolResult? Result = null,
    ExecutionError? Error = null,
    ContinuationToken? Continuation = null,
    ActionUncertainty? Uncertainty = null)
{
    public static ToolInvocationOutcome Completed(ToolResult result) =>
        new(ActionOutcomeKind.Completed, result);

    public static ToolInvocationOutcome Rejected(string code, string message) =>
        new(ActionOutcomeKind.Failed, Error: new ExecutionError(code, message));
}

public interface IUnifiedToolPipeline
{
    ValueTask<ToolInvocationOutcome> InvokeAsync(
        ToolInvocation invocation,
        CancellationToken ct);
}
