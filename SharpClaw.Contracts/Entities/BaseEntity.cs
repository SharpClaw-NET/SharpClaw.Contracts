namespace SharpClaw.Contracts.Entities;

public abstract class BaseEntity
{
    public Guid Id { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }

    /// <summary>
    /// Optional human-readable identifier used by integrations and host
    /// services to reference entities without hard-coding GUIDs. Must be unique per
    /// entity type when set.
    /// </summary>
    public string? CustomId { get; set; }
}
