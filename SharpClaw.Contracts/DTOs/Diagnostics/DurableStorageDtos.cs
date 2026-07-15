using SharpClaw.Contracts.Enums;

namespace SharpClaw.Contracts.DTOs.Diagnostics;

public sealed record ExecutionArtifactResponse(
    Guid Id,
    string MediaType,
    long Length,
    string Sha256,
    string? Preview = null);

public sealed record DurableLogRecordResponse(
    long Sequence,
    Guid RecordId,
    DateTimeOffset Timestamp,
    string Level,
    string EventName,
    string Message,
    string? ExceptionType = null,
    string? CorrelationId = null,
    ExecutionArtifactResponse? Artifact = null);

public sealed record DurableLogPageResponse(
    IReadOnlyList<DurableLogRecordResponse> Records,
    string? NextCursor,
    bool HasMore,
    int ReturnedRecords,
    int ReturnedBytes,
    long SnapshotLastSequence,
    long FirstAvailableSequence,
    long ExpiredRecordCount);

public sealed record ExecutionAuditEventResponse(
    Guid Id,
    ExecutionOwnerKind OwnerKind,
    Guid OwnerId,
    string EventKind,
    string? PreviousState,
    string? NewState,
    string? ActorKind,
    Guid? ActorId,
    string? ReasonCode,
    DateTimeOffset Timestamp);

public sealed record ExecutionAuditPageResponse(
    IReadOnlyList<ExecutionAuditEventResponse> Records,
    string? NextCursor,
    bool HasMore);

public sealed record DurableStorageHealthResponse(
    bool IsHealthy,
    string? DegradedReason,
    long LogBytes,
    long ArtifactBytes,
    int ActiveStreams,
    long SealedSegments,
    int QueueDepth,
    DateTimeOffset? LastSuccessfulFlush,
    DateTimeOffset? LastRetentionRun);
