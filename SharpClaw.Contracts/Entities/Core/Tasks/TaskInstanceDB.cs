using SharpClaw.Contracts.Entities.Core.Context;
using SharpClaw.Contracts.Entities;
using SharpClaw.Contracts.Enums;

namespace SharpClaw.Contracts.Entities.Core.Tasks;

/// <summary>
/// A single execution of a <see cref="TaskDefinitionDB"/>.  Tracks
/// lifecycle status, parameter values, and timing information. Execution
/// diagnostics and emitted output are owned by the host's diagnostic store.
/// </summary>
public class TaskInstanceDB : BaseEntity
{
    // ── Definition ────────────────────────────────────────────────

    public Guid TaskDefinitionId { get; set; }
    public TaskDefinitionDB TaskDefinition { get; set; } = null!;

    // ── Execution state ──────────────────────────────────────────

    public TaskInstanceStatus Status { get; set; } = TaskInstanceStatus.Queued;

    /// <summary>
    /// JSON-serialised dictionary of parameter name → value supplied
    /// when the instance was created.
    /// </summary>
    public string? ParameterValuesJson { get; set; }

    /// <summary>Error message when <see cref="Status"/> is <see cref="TaskInstanceStatus.Failed"/>.</summary>
    public string? ErrorMessage { get; set; }

    // ── Shared data snapshots ────────────────────────────────────

    // ── Timing ───────────────────────────────────────────────────

    public DateTimeOffset? StartedAt { get; set; }
    public DateTimeOffset? CompletedAt { get; set; }

    // ── Caller ───────────────────────────────────────────────────

    /// <summary>The user who started this instance (null if started by an agent).</summary>
    public Guid? CallerUserId { get; set; }

    /// <summary>The agent that started this instance (null if started by a user).</summary>
    public Guid? CallerAgentId { get; set; }

    // ── Channel ──────────────────────────────────────────────────

    /// <summary>
    /// Optional channel used for <c>Chat</c> / <c>ChatStream</c> operations
    /// within the task entry point.
    /// </summary>
    public Guid? ChannelId { get; set; }
    public ChannelDB? Channel { get; set; }

    /// <summary>
    /// Optional context the task was started against.  When <see cref="ChannelId"/>
    /// is absent the task must call <c>CreateChannel</c> to establish its own
    /// channel; that channel is automatically linked to this context.
    /// </summary>
    public Guid? ContextId { get; set; }

    // ── Navigation ────────────────────────────────────────────────

}
