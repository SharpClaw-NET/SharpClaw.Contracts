using SharpClaw.Contracts.DTOs.Chat;
using SharpClaw.Contracts.DTOs.Diagnostics;
using SharpClaw.Contracts.Enums;

namespace SharpClaw.Contracts.DTOs.AgentActions;

// ── Requests ──────────────────────────────────────────────────────

public sealed record SubmitAgentJobRequest(
string? ActionKey = null,
Guid? ResourceId = null,
Guid? AgentId = null,
Guid? CallerAgentId = null,
string? ScriptJson = null,
string? WorkingDirectory = null);

public sealed record ApproveAgentJobRequest(
    Guid? ApproverAgentId = null);

// ── Responses ─────────────────────────────────────────────────────

/// <summary>
/// Transient result of a job operation. <see cref="ResultData"/> is returned
/// to the caller that executed the operation but is not the persisted job
/// query model.
/// </summary>
public sealed record AgentJobResponse(
    Guid Id,
    Guid ChannelId,
    Guid AgentId,
    string? ActionKey,
    Guid? ResourceId,
    AgentJobStatus Status,
    PermissionClearance EffectiveClearance,
    string? ResultData,
    string? ErrorCode,
    string? ErrorMessage,
    DateTimeOffset CreatedAt,
    DateTimeOffset? StartedAt,
    DateTimeOffset? CompletedAt,
    string? ScriptJson = null,
    string? WorkingDirectory = null,
    TokenUsageResponse? JobCost = null,
    ChannelCostResponse? ChannelCost = null);

/// <summary>
/// Compact persisted view of a job. Arbitrary result and diagnostic payloads
/// are represented by bounded metadata and separate retrieval endpoints.
/// </summary>
public sealed record AgentJobDetailResponse(
    Guid Id,
    Guid ChannelId,
    Guid AgentId,
    string? ActionKey,
    Guid? ResourceId,
    AgentJobStatus Status,
    PermissionClearance EffectiveClearance,
    ExecutionArtifactResponse? ResultArtifact,
    string? ErrorCode,
    string? ErrorMessage,
    DiagnosticCompleteness DiagnosticCompleteness,
    long? FinalLogSequence,
    long LogRecordCount,
    DateTimeOffset CreatedAt,
    DateTimeOffset? StartedAt,
    DateTimeOffset? CompletedAt,
    string? ScriptJson = null,
    string? WorkingDirectory = null,
    TokenUsageResponse? JobCost = null,
    ChannelCostResponse? ChannelCost = null);

/// <summary>
/// Lightweight summary returned by the list-summaries endpoint.
/// Contains only the fields needed to populate a dropdown or list view —
/// no <c>ResultData</c>, <c>ErrorLog</c>, or <c>Logs</c>.
/// </summary>
public sealed record AgentJobSummaryResponse(
    Guid Id,
    Guid ChannelId,
    Guid AgentId,
    string? ActionKey,
    Guid? ResourceId,
    AgentJobStatus Status,
    DateTimeOffset CreatedAt,
    DateTimeOffset? StartedAt,
    DateTimeOffset? CompletedAt);

public sealed record AgentJobSummaryPageResponse(
    IReadOnlyList<AgentJobSummaryResponse> Records,
    string? NextCursor,
    bool HasMore);
