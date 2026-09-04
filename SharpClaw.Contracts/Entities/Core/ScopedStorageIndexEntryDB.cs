using SharpClaw.Contracts.Entities;

namespace SharpClaw.Contracts.Entities.Core;

/// <summary>
/// Host-owned secondary index entry for a registration storage record.
/// </summary>
public class ScopedStorageIndexEntryDB : BaseEntity
{
    public required string SourceId { get; set; }
    public required string StorageName { get; set; }
    public required string IndexName { get; set; }
    public required string RecordKey { get; set; }
    public string? StringValue { get; set; }
    public double? NumberValue { get; set; }
    public DateTimeOffset? DateTimeValue { get; set; }
    public bool? BoolValue { get; set; }
}
