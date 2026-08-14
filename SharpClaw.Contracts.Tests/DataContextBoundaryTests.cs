using SharpClaw.Contracts.Entities.Core;
using SharpClaw.Contracts.Persistence;

namespace SharpClaw.Contracts.Tests;

public sealed class DataContextBoundaryTests
{
    [Fact]
    public void Minimal_data_context_exposes_only_authorized_base_sets()
    {
        ISharpClawDataContext context = new MinimalDataContext();

        Assert.Equal(
            [
                nameof(ISharpClawDataContext.Models),
                nameof(ISharpClawDataContext.ModuleConfigEntries),
                nameof(ISharpClawDataContext.ModuleStates),
                nameof(ISharpClawDataContext.ModuleStorageIndexEntries),
                nameof(ISharpClawDataContext.ModuleStorageRecords),
                nameof(ISharpClawDataContext.Providers)
            ],
            typeof(ISharpClawDataContext)
                .GetProperties()
                .Select(static property => property.Name)
                .OrderBy(static name => name)
                .ToArray());

        Assert.NotNull(context.Providers);
        Assert.NotNull(context.Models);
        Assert.NotNull(context.ModuleStates);
        Assert.NotNull(context.ModuleConfigEntries);
        Assert.NotNull(context.ModuleStorageRecords);
        Assert.NotNull(context.ModuleStorageIndexEntries);
    }

    private sealed class MinimalDataContext : ISharpClawDataContext
    {
        public IQueryable<ProviderDB> Providers { get; } = Empty<ProviderDB>();
        public IQueryable<ModelDB> Models { get; } = Empty<ModelDB>();
        public IQueryable<ModuleStateDB> ModuleStates { get; } = Empty<ModuleStateDB>();
        public IQueryable<ModuleConfigEntryDB> ModuleConfigEntries { get; } = Empty<ModuleConfigEntryDB>();
        public IQueryable<ModuleStorageRecordDB> ModuleStorageRecords { get; } = Empty<ModuleStorageRecordDB>();
        public IQueryable<ModuleStorageIndexEntryDB> ModuleStorageIndexEntries { get; } = Empty<ModuleStorageIndexEntryDB>();

        private static IQueryable<T> Empty<T>() => Array.Empty<T>().AsQueryable();
    }
}
