using Microsoft.Extensions.DependencyInjection;

namespace SharpClaw.Contracts.Modules;

public interface ISharpClawModuleBuilder
{
    IServiceCollection Services { get; }
    IModuleContractBuilder Contracts { get; }
    IModuleStorageBuilder Storage { get; }
    IActionDefinitionBuilder Actions { get; }
    IActionHookBuilder Hooks { get; }
    IEventDefinitionBuilder Events { get; }
    IToolContributionBuilder Tools { get; }
    IChatLifecycleBuilder Chat { get; }
}

public interface ISharpClawApplicationBuilder
{
    IEndpointContributionBuilder Endpoints { get; }
    ICliContributionBuilder Cli { get; }
    IUiContributionBuilder Ui { get; }
}

public interface ISharpClawApplicationModule
{
    void ConfigureApplication(ISharpClawApplicationBuilder application);
}

public interface IModuleContractBuilder
{
    void Export<T>(string contractName, int schemaVersion = 1, int maxBytes = 65_536);

    void Require<T>(
        string contractName,
        int minimumSchemaVersion = 1,
        bool optional = false);
}

public interface IModuleStorageBuilder
{
    void Add(ModuleStorageContractDescriptor contract);
}

public interface IActionDefinitionBuilder
{
    void Add<TAction, TResult>(ActionDescriptor<TAction, TResult> descriptor);
}

public interface IEventDefinitionBuilder : IEventHookBuilder
{
    void Add<TEvent>(EventDescriptor<TEvent> descriptor);
}

public interface IActionHookBuilder
{
    IActionHookRegistrationBuilder For(SharpClawActionKey key);
    IActionHookRegistrationBuilder Category(string category);
    IActionHookRegistrationBuilder AnyAction();
}

public interface IActionHookRegistrationBuilder
{
    void Use<TInterceptor>(HookOrdering ordering);
    void UseAny<TInterceptor>(HookOrdering ordering);
}

public interface IEventHookBuilder
{
    IEventHookRegistrationBuilder For(SharpClawEventKey key);
    IEventHookRegistrationBuilder Category(string category);
    IEventHookRegistrationBuilder AnyEvent();
}

public interface IEventHookRegistrationBuilder
{
    void Intercept<TInterceptor>(HookOrdering ordering);
    void InterceptAny<TInterceptor>(HookOrdering ordering);
    void Listen<TListener>(EventDelivery delivery, HookOrdering ordering);
    void ListenAny<TListener>(EventDelivery delivery, HookOrdering ordering);
}

public interface IToolContributionBuilder
{
    void Add<THandler>(ToolDescriptor descriptor) where THandler : IToolHandler;
}

public interface IChatLifecycleBuilder
{
    void UseConversationResolver<TResolver>(ExclusiveRegistration registration)
        where TResolver : IConversationResolver;

    void UseChatProfileResolver<TResolver>(ExclusiveRegistration registration)
        where TResolver : IChatProfileResolver;

    void AddContextContributor<TContributor>() where TContributor : IChatContextContributor;
}

public interface IEndpointContributionBuilder
{
    void Add<TContribution>();
}

public interface ICliContributionBuilder
{
    void Add<THandler>(ModuleCliCommandDescriptor descriptor)
        where THandler : IModuleCliHandler;
}

public interface IUiContributionBuilder
{
    void Add<TContribution>();
}

public sealed record ModuleActionRegistration(
    SharpClawActionKey Key,
    int Version,
    string Category,
    ActionInterceptionCapabilities Capabilities,
    HookOrdering Ordering,
    bool Sensitive = false);

public sealed record ModuleEventRegistration(
    SharpClawEventKey Key,
    int Version,
    string Category,
    EventInterceptionCapabilities Capabilities,
    EventDelivery Delivery,
    HookOrdering Ordering,
    bool Sensitive = false);

public sealed record ModuleContractRegistration(
    string ContractName,
    int SchemaVersion,
    string OwnerModuleId,
    int MaxBytes,
    bool Required,
    bool Optional);

public sealed record ModuleManifestFeatureRef(
    string ContractName,
    int SchemaVersion,
    int MaxBytes,
    bool Required = false);

public sealed record ModuleManifestHookRequest(
    string Target,
    IReadOnlyList<string> Effects,
    bool Sensitive = false,
    ContractVersionRange? VersionRange = null);

public sealed record ModuleManifestEventRequest(
    string Target,
    string Delivery,
    IReadOnlyList<string> Effects,
    bool Sensitive = false,
    ContractVersionRange? VersionRange = null);
