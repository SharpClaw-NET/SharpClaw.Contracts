namespace SharpClaw.Contracts.Providers;

/// <summary>
/// Creates provider clients with credentials that the host resolves from its
/// protected configuration.
/// </summary>
public interface IProviderCredentialBoundPlugin
{
    /// <summary>Creates a provider client with the supplied credential.</summary>
    IProviderApiClient CreateClient(
        ProviderClientOptions options,
        string credential);

    /// <summary>Creates an optional cost feed with the supplied credential.</summary>
    IProviderCostFeed? CreateCostFeed(
        ProviderClientOptions options,
        string credential);
}
