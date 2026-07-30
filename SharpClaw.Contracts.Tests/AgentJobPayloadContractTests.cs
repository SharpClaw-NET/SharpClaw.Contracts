using System.Text.Json;
using SharpClaw.Contracts.DTOs.AgentActions;
using SharpClaw.Contracts.Entities.Core.Jobs;
using SharpClaw.Contracts.Enums;

namespace SharpClaw.Contracts.Tests;

public sealed class AgentJobPayloadContractTests
{
    private static readonly JsonSerializerOptions JsonOptions =
        new(JsonSerializerDefaults.Web);

    [Fact]
    public void DotNetModuleJsonPayloadRemainsInAllJobContractForms()
    {
        const string payload = "{\"tool\":\"echo\",\"value\":42}";
        var now = DateTimeOffset.UtcNow;
        var request = new SubmitAgentJobRequest(
            ActionKey: "demo.echo",
            ScriptJson: payload);
        var response = new AgentJobResponse(
            Guid.NewGuid(),
            Guid.NewGuid(),
            Guid.NewGuid(),
            "demo.echo",
            null,
            AgentJobStatus.Queued,
            PermissionClearance.Unset,
            null,
            null,
            null,
            now,
            null,
            null,
            ScriptJson: payload);
        var detail = new AgentJobDetailResponse(
            Guid.NewGuid(),
            Guid.NewGuid(),
            Guid.NewGuid(),
            "demo.echo",
            null,
            AgentJobStatus.Queued,
            PermissionClearance.Unset,
            null,
            null,
            null,
            default,
            null,
            0,
            now,
            null,
            null,
            ScriptJson: payload);
        var entity = new AgentJobDB { ScriptJson = payload };

        AssertPayload(request, payload);
        AssertPayload(response, payload);
        AssertPayload(detail, payload);
        Assert.Equal(payload, entity.ScriptJson);
    }

    private static void AssertPayload<T>(T value, string expected)
    {
        using var document = JsonDocument.Parse(JsonSerializer.Serialize(value, JsonOptions));
        Assert.Equal(expected, document.RootElement.GetProperty("scriptJson").GetString());
    }
}
