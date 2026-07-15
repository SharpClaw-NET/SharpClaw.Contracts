using SharpClaw.Contracts.DTOs.AgentActions;

namespace SharpClaw.Contracts.Modules;

/// <summary>
/// Host-side read-only view of agent jobs.
/// Implemented by <c>AgentJobService</c>; injected into modules that
/// need to query job state without referencing Core or Infrastructure.
/// </summary>
public interface IAgentJobReader
{
    /// <summary>
    /// Returns the compact persisted job detail for <paramref name="jobId"/>,
    /// or <see langword="null"/> if it does not exist.
    /// </summary>
    Task<AgentJobDetailResponse?> GetJobAsync(
        Guid jobId,
        CancellationToken ct = default);

    /// <summary>
    /// Returns a bounded page of job summaries whose <c>ActionKey</c> starts
    /// with <paramref name="actionKeyPrefix"/>.
    /// </summary>
    Task<AgentJobSummaryPageResponse> ListJobSummariesByActionPrefixAsync(
        string actionKeyPrefix,
        Guid? resourceId = null,
        string? cursor = null,
        int take = 50,
        CancellationToken ct = default);

    /// <summary>
    /// Returns whether a job with <paramref name="jobId"/> exists and
    /// its <c>ActionKey</c> starts with <paramref name="actionKeyPrefix"/>.
    /// </summary>
    Task<bool> JobExistsWithActionPrefixAsync(
        Guid jobId, string actionKeyPrefix, CancellationToken ct = default);
}
