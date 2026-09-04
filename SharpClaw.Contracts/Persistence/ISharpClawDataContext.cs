using SharpClaw.Contracts.Entities.Core;

namespace SharpClaw.Contracts.Persistence;

/// <summary>
/// Read-only data-access contract for retained kernel and generic registration data.
/// </summary>
/// <remarks>
/// The accessors return <see cref="IQueryable{T}"/> rather than
/// <c>DbSet&lt;T&gt;</c> so registration code cannot mutate core state
/// through this surface. The contract grows only when a registration
/// presents a real read need.
/// </remarks>
public interface ISharpClawDataContext
{
    IQueryable<ProviderDB> Providers { get; }
    IQueryable<ModelDB> Models { get; }
    IQueryable<RegistrationStateDB> RegistrationStates { get; }
    IQueryable<ConfigurationEntryDB> ConfigurationEntries { get; }
    IQueryable<ScopedStorageRecordDB> ScopedStorageRecords { get; }
    IQueryable<ScopedStorageIndexEntryDB> ScopedStorageIndexEntries { get; }
}
