using System.Text.Json;
using SharpClaw.Contracts.Modules;

namespace SharpClaw.Contracts.Tests;

public sealed class ModuleEndpointContractsTests
{
    [Fact]
    public void HttpDescriptorCreatesCanonicalRouteIdentity()
    {
        var descriptor = new ModuleEndpointRouteDescriptor(
            "context.thread.list",
            "/sharpclaw/context/threads",
            "GET",
            HostEndpointTransport.Http);

        Assert.True(descriptor.IsWellFormed);
        Assert.Equal(
            new HostEndpointRouteIdentity(
                "context.thread.list",
                "/sharpclaw/context/threads",
                "GET",
                HostEndpointTransport.Http),
            descriptor.ToRouteIdentity());
    }

    [Theory]
    [InlineData("post")]
    [InlineData("POST")]
    public void WebSocketDescriptorRequiresGet(string method)
    {
        var descriptor = new ModuleEndpointRouteDescriptor(
            "editor.bridge.websocket",
            "/editor/ws",
            method,
            HostEndpointTransport.WebSocket);

        Assert.False(descriptor.IsWellFormed);
    }

    [Fact]
    public void JsonResponseContainsBoundedHttpMetadata()
    {
        var response = ModuleHttpEndpointResponse.Json(
            200,
            JsonSerializer.SerializeToElement(new { result = "ok" }));

        Assert.True(response.IsWellFormed);
        Assert.Equal("application/json; charset=utf-8", response.Headers["Content-Type"].Single());
        Assert.Contains("\"result\":\"ok\"", System.Text.Encoding.UTF8.GetString(response.Body));
    }

    [Fact]
    public void CloseMessageRequiresAWebSocketCloseStatus()
    {
        var invalid = new ModuleWebSocketMessage(
            ModuleWebSocketMessageType.Close,
            [],
            CloseDescription: "done");
        var valid = invalid with { CloseStatus = 1000 };

        Assert.False(invalid.IsWellFormed);
        Assert.True(valid.IsWellFormed);
    }
}
