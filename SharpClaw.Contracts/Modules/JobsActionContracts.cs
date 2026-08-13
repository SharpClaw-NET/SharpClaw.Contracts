using System.Text.Json;

namespace SharpClaw.Contracts.Modules;

/// <summary>Neutral lifecycle states used by typed Jobs checkpoints.</summary>
public enum JobStatus
{
    Pending,
    Held,
    Queued,
    Running,
    Paused,
    Completed,
    Failed,
    Cancelled,
    Expired,
    OutcomeUncertain
}

/// <summary>Safe points at which a Jobs operation can change its authority.</summary>
public enum JobSafePoint
{
    BeforeContinuation,
    BeforeTerminal,
    AfterTerminal,
    BeforeCommit,
    AfterCommit
}

/// <summary>Neutral typed input envelope for a Jobs operation.</summary>
public sealed record JobActionInput<TValue>(
    SharpClawActionKey ActionKey,
    TValue Value);

/// <summary>Neutral typed result envelope for a Jobs operation.</summary>
public sealed record JobActionResult<TValue>(
    SharpClawActionKey ActionKey,
    TValue Value);

/// <summary>Typed before and after state carried through a Jobs action boundary.</summary>
public sealed record JobCheckpoint<TValue>(
    Guid? JobId,
    Guid? AttemptId,
    Guid InvocationId,
    Guid IdempotencyKey,
    JobStatus CurrentStatus,
    JobStatus? ProposedStatus,
    JobSafePoint SafePoint,
    TValue Value,
    long ExpectedRevision);

/// <summary>Descriptor bundle for one typed Jobs operation and its checkpoints.</summary>
public sealed record JobActionContract<TInput, TResult>(
    ActionDescriptor<JobCheckpoint<TInput>, JobCheckpoint<TInput>> Before,
    ActionDescriptor<TInput, TResult> Action,
    ActionDescriptor<JobCheckpoint<TResult>, JobCheckpoint<TResult>> After);

/// <summary>Neutral JSON value used by Core standard Jobs descriptors.</summary>
public static class JobActionPayload
{
    public static JobActionInput<JsonElement> Input(
        SharpClawActionKey actionKey,
        JsonElement value) => new(actionKey, value);

    public static JobActionResult<JsonElement> Result(
        SharpClawActionKey actionKey,
        JsonElement value) => new(actionKey, value);
}
