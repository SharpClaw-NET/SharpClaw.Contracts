namespace SharpClaw.Contracts.Persistence;

/// <summary>
/// Implemented by a registration to declare which of its entity types need sharded
/// cold-entity indexes and which foreign-key properties should be indexed.
/// <para>
/// The host <c>ColdIndexRegistry</c> collects all registered contributors
/// at startup and merges them with the host's own static index definitions so
/// that <c>ColdEntityIndex</c> never needs to know about individual registration
/// entities.
/// </para>
/// <para>
/// Return a dictionary whose keys are CLR type names (e.g.
/// <c>nameof(MyEntityDB)</c>) and whose values are the property names that
/// should be indexed (e.g. <c>["ChannelId", "AgentId"]</c>).
/// </para>
/// </summary>
public interface IColdIndexContributor
{
    /// <summary>
    /// Returns the indexed-property declarations for this registration's cold entities.
    /// Keys are entity type names; values are arrays of foreign-key property names.
    /// </summary>
    IReadOnlyDictionary<string, string[]> GetIndexedProperties();
}
