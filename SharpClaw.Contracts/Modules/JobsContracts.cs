namespace SharpClaw.Contracts.Modules;

public enum JobStatus
{
    Queued,
    AwaitingApproval,
    Executing,
    Completed,
    Failed,
    Cancelled,
    OutcomeUncertain,
    Paused,
}

public enum JobOutcomeCertainty
{
    Certain,
    Uncertain,
}

public enum JobExecutionSafety
{
    Pure,
    Idempotent,
    Receipted,
    NonIdempotent,
}

public enum JobSafePoint
{
    BeforeQueueClaim,
    AfterLeaseClaim,
    BeforeHoldEvaluation,
    BeforeHandlerInvocation,
    AfterReceiptCapture,
    BeforeArtifactSealing,
    BeforeTerminalCommit,
}

public sealed record ToolHoldRequirement(
    string Code,
    string Description,
    string? ApprovalContract = null);

public sealed record ToolResultReference(
    string Kind,
    string Reference,
    string? ContentHash = null);

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

public sealed record JobDocument(
    Guid Id,
    Guid InvocationId,
    Guid? ConversationId,
    string ActionKey,
    RequestPrincipal Caller,
    ExtensionFeatureSet Features,
    JobStatus Status,
    IReadOnlyList<ToolHoldRequirement> Holds,
    DateTimeOffset CreatedAt,
    DateTimeOffset? StartedAt,
    DateTimeOffset? CompletedAt,
    Guid? ActiveAttemptId,
    JobOutcomeCertainty OutcomeCertainty,
    ToolResultReference? Result,
    ExecutionError? Error);

public sealed record JobAttemptDocument(
    Guid AttemptId,
    Guid JobId,
    Guid InvocationId,
    Guid IdempotencyKey,
    int AttemptNumber,
    JobExecutionSafety Safety,
    string? ReceiptId,
    DateTimeOffset StartedAt,
    DateTimeOffset? LeaseExpiresAt,
    DateTimeOffset? FinishedAt,
    long Revision);

public sealed record JobSubmission(
    ToolInvocation Invocation,
    IReadOnlyList<ToolHoldRequirement>? Holds = null,
    JobExecutionSafety Safety = JobExecutionSafety.NonIdempotent);

public sealed record JobSubmissionResult(
    Guid JobId,
    JobStatus Status,
    Guid InvocationId,
    string? Message = null);

public sealed record JobHandlerPlan(
    Guid JobId,
    Guid AttemptId,
    JobExecutionSafety Safety,
    Guid IdempotencyKey,
    IReadOnlyList<JobSafePoint> SafePoints,
    JsonSchemaReference? ResultSchema = null);

public sealed record JobHandlerResult(
    ToolResultReference? Result,
    string? ReceiptId,
    JobOutcomeCertainty Certainty,
    ExecutionError? Error = null);

public sealed record JobActionContract<TInput, TResult>(
    ActionDescriptor<JobCheckpoint<TInput>, JobCheckpoint<TInput>> Before,
    ActionDescriptor<TInput, TResult> Action,
    ActionDescriptor<JobCheckpoint<TResult>, JobCheckpoint<TResult>> After);

public static class JobsActionCoverageManifest
{
    public static IReadOnlyList<string> Families => SharpClawActionCatalog.JobsFamilies;

    public static IReadOnlyList<SharpClawActionKey> Keys => SharpClawActionCatalog.Jobs;

    public static int FamilyCount => Families.Count;

    public static int KeyCount => Keys.Count;
}
