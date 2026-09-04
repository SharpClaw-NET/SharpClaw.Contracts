using System.Text.Json;

namespace SharpClaw.Contracts.Kernel;

/// <summary>
/// Describes a typed frontend extension point that a registration contributes to
/// SharpClaw clients. Contributions are declarative: the registration declares
/// where the UI belongs and which internal API endpoint backs it, while each
/// client chooses the native controls that fit that surface.
/// </summary>
public sealed record FrontendContribution(
    string Id,
    string SourceId,
    FrontendContributionPoint Point,
    string BuilderKey,
    string Label,
    string? Icon = null,
    string? Tooltip = null,
    string? RequiredOwnerId = null,
    int Order = 0,
    FrontendAction? Action = null,
    FrontendForm? Form = null,
    FrontendList? List = null,
    IReadOnlyDictionary<string, JsonElement>? Metadata = null);

public enum FrontendContributionPoint
{
    SettingsPage,
    ChatInputAction,
    ResourcePanel,
    DashboardCard,
    NavigationItem,
}

public sealed record FrontendAction(
    string Method,
    string InternalApiPath,
    string? RequestSchemaKey = null,
    string? ResponseMode = null);

public sealed record FrontendForm(
    string? ReadInternalApiPath = null,
    string? SaveInternalApiPath = null,
    IReadOnlyList<FrontendField>? Fields = null);

public sealed record FrontendField(
    string Key,
    string Label,
    string FieldType,
    bool Required = false,
    string? HelpText = null,
    string? Placeholder = null,
    string? DefaultValue = null);

public sealed record FrontendList(
    string ListInternalApiPath,
    string? SyncInternalApiPath = null,
    string? DeleteInternalApiPathTemplate = null,
    string? EmptyText = null,
    IReadOnlyList<FrontendListColumn>? Columns = null);

public sealed record FrontendListColumn(string Key, string Label);

public sealed record FrontendContributionResponse(
    IReadOnlyList<FrontendContribution> Items);
