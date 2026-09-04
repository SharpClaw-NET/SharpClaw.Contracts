using System.Text.Json;
using SharpClaw.Contracts.Kernel;

namespace SharpClaw.Contracts.Tests;

public sealed class JobsBoundaryContractTests
{
    [Fact]
    public void Job_document_has_no_host_feature_owner_fields()
    {
        var names = typeof(JobDocument)
            .GetProperties()
            .Select(property => property.Name)
            .ToHashSet(StringComparer.Ordinal);

        Assert.DoesNotContain("ChannelId", names);
        Assert.DoesNotContain("ContextId", names);
        Assert.DoesNotContain("AgentId", names);
        Assert.DoesNotContain("PermissionSetId", names);
    }

    [Fact]
    public void Typed_payload_codec_round_trips_contract_identity()
    {
        var codec = new JsonJobPayloadCodec<SubmissionValue>("jobs.sample.submit", 2);
        var payload = codec.Encode(new SubmissionValue("value"));

        Assert.Equal("jobs.sample.submit", payload.ContractName);
        Assert.Equal(2, payload.SchemaVersion);
        Assert.Equal(new SubmissionValue("value"), codec.Decode(payload));
    }

    [Fact]
    public void Typed_payload_codec_rejects_a_different_contract()
    {
        var codec = new JsonJobPayloadCodec<SubmissionValue>("jobs.sample.submit");
        var payload = new JobPayloadEnvelope("jobs.other", 1, "{\"value\":\"x\"}");

        var exception = Assert.Throws<InvalidOperationException>(() => codec.Decode(payload));

        Assert.Contains("does not match", exception.Message, StringComparison.Ordinal);
    }

    private sealed record SubmissionValue(string Value);
}
