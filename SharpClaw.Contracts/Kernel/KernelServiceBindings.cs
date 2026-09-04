namespace SharpClaw.Contracts.Kernel;

/// <summary>Contains immutable host data for one service lifecycle.</summary>
public sealed record ServiceStartContext(
    string HostVersion,
    string ContractHash,
    ExtensionFeatureSet Features);

/// <summary>Starts and stops one service through the host lifecycle.</summary>
public interface IServiceLifecycle
{
    ValueTask StartAsync(ServiceStartContext context, CancellationToken cancellationToken);

    ValueTask StopAsync(CancellationToken cancellationToken);
}

/// <summary>Describes one action definition supplied through dependency injection.</summary>
public interface IActionDefinitionBinding
{
    string SourceId { get; }

    Type ActionType { get; }

    Type ResultType { get; }

    object Descriptor { get; }

    void AddTo(IActionDefinitionSink sink);
}

/// <summary>Accepts typed action definitions without runtime type recovery.</summary>
public interface IActionDefinitionSink
{
    void Add<TAction, TResult>(
        string sourceId,
        ActionDescriptor<TAction, TResult> descriptor);
}

/// <summary>Binds one typed action definition to its authority source.</summary>
public sealed record ActionDefinitionBinding<TAction, TResult>(
    string SourceId,
    ActionDescriptor<TAction, TResult> TypedDescriptor) : IActionDefinitionBinding
{
    public Type ActionType => typeof(TAction);

    public Type ResultType => typeof(TResult);

    public object Descriptor => TypedDescriptor;

    public void AddTo(IActionDefinitionSink sink)
    {
        ArgumentNullException.ThrowIfNull(sink);
        sink.Add(SourceId, TypedDescriptor);
    }
}

/// <summary>Describes one event definition supplied through dependency injection.</summary>
public interface IEventDefinitionBinding
{
    string SourceId { get; }

    Type EventType { get; }

    object Descriptor { get; }

    void AddTo(IEventDefinitionSink sink);
}

/// <summary>Accepts typed event definitions without runtime type recovery.</summary>
public interface IEventDefinitionSink
{
    void Add<TEvent>(string sourceId, EventDescriptor<TEvent> descriptor);
}

/// <summary>Binds one typed event definition to its authority source.</summary>
public sealed record EventDefinitionBinding<TEvent>(
    string SourceId,
    EventDescriptor<TEvent> TypedDescriptor) : IEventDefinitionBinding
{
    public Type EventType => typeof(TEvent);

    public object Descriptor => TypedDescriptor;

    public void AddTo(IEventDefinitionSink sink)
    {
        ArgumentNullException.ThrowIfNull(sink);
        sink.Add(SourceId, TypedDescriptor);
    }
}

/// <summary>Selects an action or event by key, category, or wildcard.</summary>
public enum BehaviorTargetKind
{
    Exact,
    Category,
    Any,
}

/// <summary>Binds one action interceptor to its target and authority source.</summary>
public sealed record ActionHookBinding(
    string SourceId,
    BehaviorTargetKind TargetKind,
    SharpClawActionKey? ActionKey,
    string? Category,
    Type HandlerType,
    bool IsUntyped,
    HookOrdering Ordering,
    string HandlerIdentity,
    IAnyActionInterceptor? BoundHandler = null);

/// <summary>Selects whether an event handler can change or only observe delivery.</summary>
public enum EventHookKind
{
    Interceptor,
    Listener,
}

/// <summary>Binds one event handler to its target and authority source.</summary>
public sealed record EventHookBinding(
    string SourceId,
    BehaviorTargetKind TargetKind,
    SharpClawEventKey? EventKey,
    string? Category,
    Type HandlerType,
    bool IsUntyped,
    EventHookKind Kind,
    EventDelivery Delivery,
    HookOrdering Ordering,
    string HandlerIdentity,
    object? BoundHandler = null);

/// <summary>Binds one tool handler to one public tool descriptor.</summary>
public sealed record ToolHandlerBinding(
    string SourceId,
    ToolDescriptor Descriptor,
    Type HandlerType,
    string HandlerIdentity,
    IToolHandler? BoundHandler = null);

/// <summary>Exposes host-issued authority for one external behavior source.</summary>
public interface IExternalBehaviorAuthority
{
    string SourceId { get; }

    SidecarHostAuthorization Authorization { get; }

    SidecarDiscoveryEnvelope Discovery { get; }
}

/// <summary>Describes one typed service contract supplied through dependency injection.</summary>
public sealed record ServiceContractBinding(
    string SourceId,
    Type ServiceType,
    string ContractName,
    int SchemaVersion,
    int MaxBytes,
    bool IsExport,
    bool Optional);
