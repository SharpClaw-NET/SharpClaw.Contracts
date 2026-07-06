using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using SharpClaw.Gateway.Contracts;

namespace SharpClaw.Gateway.Contracts.Tests;

public sealed class GatewayContractsTests
{
    [Fact]
    public async Task QueuedResponseSuccessPreservesJsonBodyAndStatus()
    {
        var response = new QueuedResponse
        {
            StatusCode = HttpStatusCode.Accepted,
            JsonBody = """{"accepted":true}""",
            Meta = new QueueResponseMeta(Guid.NewGuid(), 2, 10.5, 8.25),
        };

        var context = CreateHttpContext();
        await using var body = new MemoryStream();
        context.Response.Body = body;

        await response.ToResult().ExecuteAsync(context);

        body.Position = 0;
        var payload = await new StreamReader(body).ReadToEndAsync();
        Assert.Equal(StatusCodes.Status202Accepted, context.Response.StatusCode);
        Assert.Equal("application/json", context.Response.ContentType);
        Assert.Equal("""{"accepted":true}""", payload);
        Assert.True(response.IsSuccess);
        Assert.Equal(2, response.Meta.Position);
    }

    [Fact]
    public async Task QueuedResponseFailureCreatesGatewayErrorEnvelopeWhenBodyIsMissing()
    {
        var response = new QueuedResponse
        {
            StatusCode = HttpStatusCode.BadGateway,
            Error = "Upstream failed.",
        };

        var context = CreateHttpContext();
        await using var body = new MemoryStream();
        context.Response.Body = body;

        await response.ToResult().ExecuteAsync(context);

        body.Position = 0;
        using var document = await JsonDocument.ParseAsync(body);
        Assert.Equal(StatusCodes.Status502BadGateway, context.Response.StatusCode);
        Assert.Equal("Upstream failed.", document.RootElement.GetProperty("error").GetString());
        Assert.Equal(502, document.RootElement.GetProperty("status").GetInt32());
        Assert.False(response.IsSuccess);
    }

    [Fact]
    public void GatewayModuleExtensionContractSupportsEndpointGroupsAndServices()
    {
        var extension = new DemoGatewayModuleExtension();
        var services = new ServiceCollection();

        extension.ConfigureGatewayServices(services);

        var descriptor = Assert.Single(services);
        var group = Assert.Single(extension.GetEndpointGroups());
        Assert.Equal("demo.gateway", extension.ModuleId);
        Assert.Equal("demo.gateway.search", group.GroupId);
        Assert.Equal(ServiceLifetime.Singleton, descriptor.Lifetime);
    }

    [Fact]
    public async Task GatewayDispatcherContractReturnsQueuedResponse()
    {
        IGatewayDispatcher dispatcher = new DemoGatewayDispatcher();

        var response = await dispatcher.PostAsync("/api/demo", new { value = 42 });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("""{"ok":true}""", response.JsonBody);
    }

    private sealed class DemoGatewayModuleExtension : IGatewayModuleExtension
    {
        public string ModuleId => "demo.gateway";
        public string DisplayName => "Demo Gateway";

        public IReadOnlyList<GatewayEndpointGroup> GetEndpointGroups() =>
        [
            new(
                "demo.gateway.search",
                "Gateway Search",
                "Search endpoint group.",
                "gateway-search",
                DefaultEnabled: true),
        ];

        public void ConfigureGatewayServices(IServiceCollection services) =>
            services.AddSingleton<DemoGatewayState>();

        public void MapEndpoints(IGatewayEndpointGroupBuilder builder) =>
            builder.MapGet("/health", () => Results.Ok(new { ok = true }));
    }

    private sealed class DemoGatewayDispatcher : IGatewayDispatcher
    {
        public Task<QueuedResponse> PostAsync<TRequest>(
            string path,
            TRequest body,
            CancellationToken ct = default) =>
            Task.FromResult(Ok());

        public Task<QueuedResponse> PostAsync(string path, CancellationToken ct = default) =>
            Task.FromResult(Ok());

        public Task<QueuedResponse> PutAsync<TRequest>(
            string path,
            TRequest body,
            CancellationToken ct = default) =>
            Task.FromResult(Ok());

        public Task<QueuedResponse> DeleteAsync(string path, CancellationToken ct = default) =>
            Task.FromResult(Ok());

        private static QueuedResponse Ok() =>
            new()
            {
                StatusCode = HttpStatusCode.OK,
                JsonBody = """{"ok":true}""",
            };
    }

    private static DefaultHttpContext CreateHttpContext()
    {
        var services = new ServiceCollection()
            .AddLogging()
            .BuildServiceProvider();

        return new DefaultHttpContext
        {
            RequestServices = services,
        };
    }

    private sealed class DemoGatewayState;
}
