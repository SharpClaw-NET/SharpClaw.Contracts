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
                nameof(ISharpClawDataContext.ConfigurationEntries),
                nameof(ISharpClawDataContext.Models),
                nameof(ISharpClawDataContext.Providers),
                nameof(ISharpClawDataContext.RegistrationStates),
                nameof(ISharpClawDataContext.ScopedStorageIndexEntries),
                nameof(ISharpClawDataContext.ScopedStorageRecords)
            ],
            typeof(ISharpClawDataContext)
                .GetProperties()
                .Select(static property => property.Name)
                .OrderBy(static name => name)
                .ToArray());

        Assert.NotNull(context.Providers);
        Assert.NotNull(context.Models);
        Assert.NotNull(context.RegistrationStates);
        Assert.NotNull(context.ConfigurationEntries);
        Assert.NotNull(context.ScopedStorageRecords);
        Assert.NotNull(context.ScopedStorageIndexEntries);
    }

    private sealed class MinimalDataContext : ISharpClawDataContext
    {
        public IQueryable<ProviderDB> Providers { get; } = Empty<ProviderDB>();
        public IQueryable<ModelDB> Models { get; } = Empty<ModelDB>();
        public IQueryable<RegistrationStateDB> RegistrationStates { get; } = Empty<RegistrationStateDB>();
        public IQueryable<ConfigurationEntryDB> ConfigurationEntries { get; } = Empty<ConfigurationEntryDB>();
        public IQueryable<ScopedStorageRecordDB> ScopedStorageRecords { get; } = Empty<ScopedStorageRecordDB>();
        public IQueryable<ScopedStorageIndexEntryDB> ScopedStorageIndexEntries { get; } = Empty<ScopedStorageIndexEntryDB>();

        private static IQueryable<T> Empty<T>() => Array.Empty<T>().AsQueryable();
    }
}
