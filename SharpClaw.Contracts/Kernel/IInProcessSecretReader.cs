namespace SharpClaw.Contracts.Kernel;

/// <summary>
/// Reads host-owned secrets for trusted in-process registrations.
/// </summary>
/// <remarks>
/// The host registers this service only for in-process registrations that execute
/// inside the trusted host process and are allowed to receive protected secret
/// material directly. Out-of-process and foreign registrations are intentionally not
/// covered by this interface. If those registration types ever need secret-backed
/// behavior, they require a separate host-mediated operation that does not
/// expose this direct in-process reader contract.
/// </remarks>
public interface IInProcessSecretReader
{
    /// <summary>
    /// Returns the configured API key for a model provider key.
    /// </summary>
    /// <param name="providerKey">
    /// The stable provider key registered with the host.
    /// </param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>
    /// The provider API key, or <see langword="null"/> when the provider does
    /// not exist or no API key is configured.
    /// </returns>
    Task<string?> GetProviderApiKeyAsync(
        string providerKey,
        CancellationToken ct = default);

    /// <summary>
    /// Returns the configured API key for the provider that owns a model.
    /// </summary>
    /// <param name="modelId">
    /// The model whose provider API key should be resolved by the host.
    /// </param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>
    /// The owning provider API key, or <see langword="null"/> when the model
    /// does not exist, the provider does not exist, or no API key is
    /// configured.
    /// </returns>
    Task<string?> GetModelProviderApiKeyAsync(
        Guid modelId,
        CancellationToken ct = default);
}
