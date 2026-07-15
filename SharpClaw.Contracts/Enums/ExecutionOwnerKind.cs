namespace SharpClaw.Contracts.Enums;

/// <summary>The transactional owner of a structured execution audit event.</summary>
public enum ExecutionOwnerKind
{
    /// <summary>An agent action job.</summary>
    AgentJob = 0,

    /// <summary>A task instance.</summary>
    TaskInstance = 1,
}
