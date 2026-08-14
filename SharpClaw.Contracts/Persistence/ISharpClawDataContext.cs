using SharpClaw.Contracts.Entities.Core;

namespace SharpClaw.Contracts.Persistence;

/// <summary>
/// Read-only data-access contract for retained kernel and generic module data.
/// </summary>
/// <remarks>
/// The accessors return <see cref="IQueryable{T}"/> rather than
/// <c>DbSet&lt;T&gt;</c> so module code cannot mutate core state
/// through this surface. The contract grows only when a module
/// presents a real read need.
/// </remarks>
public interface ISharpClawDataContext
{
    IQueryable<ProviderDB> Providers { get; }
    IQueryable<ModelDB> Models { get; }
    IQueryable<ModuleStateDB> ModuleStates { get; }
    IQueryable<ModuleConfigEntryDB> ModuleConfigEntries { get; }
    IQueryable<ModuleStorageRecordDB> ModuleStorageRecords { get; }
    IQueryable<ModuleStorageIndexEntryDB> ModuleStorageIndexEntries { get; }
}
