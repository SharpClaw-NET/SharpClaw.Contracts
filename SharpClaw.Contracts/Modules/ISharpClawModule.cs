namespace SharpClaw.Contracts.Modules;

/// <summary>Neutral public contract for one trusted SharpClaw module.</summary>
public interface ISharpClawModule
{
    ModuleIdentity Identity { get; }

    void Configure(ISharpClawModuleBuilder module);

    ValueTask StartAsync(ModuleStartContext context, CancellationToken ct) =>
        ValueTask.CompletedTask;

    ValueTask StopAsync(CancellationToken ct) =>
        ValueTask.CompletedTask;
}
