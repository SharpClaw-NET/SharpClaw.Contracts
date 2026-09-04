using SharpClaw.Contracts.Entities;

namespace SharpClaw.Contracts.Entities.Core;

/// <summary>
/// Tracks the enabled/disabled state of a bundled registration.
/// </summary>
public class RegistrationStateDB : BaseEntity
{
    /// <summary>Unique registration identifier (e.g. "sharpclaw_computer_use").</summary>
    public required string SourceId { get; set; }

    /// <summary>Whether the registration is enabled (tools registered, init executed).</summary>
    public bool Enabled { get; set; }

    /// <summary>Last known version string from the registration manifest.</summary>
    public string? Version { get; set; }
}
