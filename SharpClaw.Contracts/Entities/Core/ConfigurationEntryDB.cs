using SharpClaw.Contracts.Entities;

namespace SharpClaw.Contracts.Entities.Core;

/// <summary>
/// Persistent key-value configuration entry for a registration.
/// Stored in the host <c>AppDbContext</c>, not accessible directly by registrations.
/// Registrations read/write through <see cref="Contracts.Registrations.IConfigurationStore"/>.
/// </summary>
public class ConfigurationEntryDB : BaseEntity
{
    /// <summary>Registration identifier that owns this entry.</summary>
    public required string SourceId { get; set; }

    /// <summary>Configuration key (max 128 characters).</summary>
    public required string Key { get; set; }

    /// <summary>Configuration value (max 4096 characters).</summary>
    public string? Value { get; set; }
}
