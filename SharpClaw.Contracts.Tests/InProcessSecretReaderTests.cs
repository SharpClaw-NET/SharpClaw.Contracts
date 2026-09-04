using System.Reflection;
using SharpClaw.Contracts.Kernel;

namespace SharpClaw.Contracts.Tests;

public sealed class InProcessRegistrationSecretReaderTests
{
    [Fact]
    public async Task ContractSupportsProviderAndModelApiKeyReads()
    {
        var modelId = Guid.NewGuid();
        IInProcessSecretReader reader = new DemoSecretReader(
            providerKey: "elevenlabs",
            modelId,
            apiKey: "stored-provider-key");

        var providerKey = await reader.GetProviderApiKeyAsync("elevenlabs");
        var modelProviderKey = await reader.GetModelProviderApiKeyAsync(modelId);
        var missingProvider = await reader.GetProviderApiKeyAsync("missing");
        var missingModel = await reader.GetModelProviderApiKeyAsync(Guid.NewGuid());

        Assert.Equal("stored-provider-key", providerKey);
        Assert.Equal("stored-provider-key", modelProviderKey);
        Assert.Null(missingProvider);
        Assert.Null(missingModel);
    }

    [Fact]
    public void ContractExposesOnlyTheExpectedSecretReadMethods()
    {
        var methods = typeof(IInProcessSecretReader)
            .GetMethods(BindingFlags.Public | BindingFlags.Instance)
            .OrderBy(method => method.Name)
            .ToArray();

        Assert.Equal(
            [
                "GetModelProviderApiKeyAsync",
                "GetProviderApiKeyAsync",
            ],
            methods.Select(method => method.Name));

        AssertMethod(
            methods[0],
            typeof(Task<string?>),
            typeof(Guid),
            typeof(CancellationToken));

        AssertMethod(
            methods[1],
            typeof(Task<string?>),
            typeof(string),
            typeof(CancellationToken));
    }

    private static void AssertMethod(
        MethodInfo method,
        Type returnType,
        params Type[] parameterTypes)
    {
        Assert.Equal(returnType, method.ReturnType);
        Assert.Equal(
            parameterTypes,
            method.GetParameters().Select(parameter => parameter.ParameterType));
    }

    private sealed class DemoSecretReader(
        string providerKey,
        Guid modelId,
        string apiKey) : IInProcessSecretReader
    {
        public Task<string?> GetProviderApiKeyAsync(
            string requestedProviderKey,
            CancellationToken ct = default) =>
            Task.FromResult<string?>(
                string.Equals(requestedProviderKey, providerKey, StringComparison.Ordinal)
                    ? apiKey
                    : null);

        public Task<string?> GetModelProviderApiKeyAsync(
            Guid requestedModelId,
            CancellationToken ct = default) =>
            Task.FromResult<string?>(requestedModelId == modelId ? apiKey : null);
    }
}
