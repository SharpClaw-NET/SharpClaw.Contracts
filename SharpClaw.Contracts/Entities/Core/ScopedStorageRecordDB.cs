using SharpClaw.Contracts.Entities;

namespace SharpClaw.Contracts.Entities.Core;

/// <summary>
/// Host-owned registration document record. Registrations access these records only
/// through the registration storage capability contract, including when running as
/// sidecars.
/// </summary>
public class ScopedStorageRecordDB : BaseEntity
{
    public required string SourceId { get; set; }
    public required string StorageName { get; set; }
    public required string RecordKey { get; set; }
    public required string ValueJson { get; set; }
}
