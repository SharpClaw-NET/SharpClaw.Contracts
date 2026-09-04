using System.Text.Json;
using SharpClaw.Contracts.Kernel;

namespace SharpClaw.Contracts.Tests;

public sealed class EndpointContractsTests
{
    [Fact]
    public void HttpDescriptorCreatesCanonicalRouteIdentity()
    {
        var descriptor = new EndpointRouteDescriptor(
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
        var descriptor = new EndpointRouteDescriptor(
            "editor.bridge.websocket",
            "/editor/ws",
            method,
            HostEndpointTransport.WebSocket);

        Assert.False(descriptor.IsWellFormed);
    }

    [Fact]
    public void JsonResponseContainsBoundedHttpMetadata()
    {
        var response = HttpEndpointResponse.Json(
            200,
            JsonSerializer.SerializeToElement(new { result = "ok" }));

        Assert.True(response.IsWellFormed);
        Assert.Equal("application/json; charset=utf-8", response.Headers["Content-Type"].Single());
        Assert.Contains("\"result\":\"ok\"", System.Text.Encoding.UTF8.GetString(response.Body));
    }

    [Fact]
    public void CloseMessageRequiresAWebSocketCloseStatus()
    {
        var invalid = new WebSocketMessage(
            WebSocketMessageType.Close,
            [],
            CloseDescription: "done");
        var valid = invalid with { CloseStatus = 1000 };

        Assert.False(invalid.IsWellFormed);
        Assert.True(valid.IsWellFormed);
    }
}
