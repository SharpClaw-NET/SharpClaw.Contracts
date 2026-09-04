namespace SharpClaw.Contracts.Persistence;

/// <summary>
/// Factory boundary used by registrations to request host-configured instances of
/// their own persistence context types.
/// </summary>
public interface IOwnedDbContextFactory
{
    /// <summary>
    /// Creates a registration-owned context instance for the specified context type.
    /// The returned instance is owned by the caller and must be disposed.
    /// </summary>
    object CreateDbContext(Type dbContextType);

    /// <summary>
    /// Creates a registration-owned context instance for the specified context type.
    /// The returned instance is owned by the caller and must be disposed.
    /// </summary>
    TContext CreateDbContext<TContext>()
        where TContext : class, IDisposable
        => (TContext)CreateDbContext(typeof(TContext));
}
