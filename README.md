# SharpClaw.Contracts

SharpClaw.Contracts is the public MIT-licensed contract package for SharpClaw.
It contains the DTOs, records, interfaces, module descriptors, provider
contracts, and persistence-facing abstractions that
SharpClaw implementations and modules are allowed to reference.

Install the package when a module or integration needs to compile against the
SharpClaw contract surface without depending on SharpClaw.Core or an
application host.

```bash
dotnet add package SharpClaw.Contracts
```

Core pipeline modules should reference this package when they only need to
contribute provider, tool, storage-contract, permission, or other
pure pipeline behavior through `ISharpClawCoreModule`. Runtime modules should
reference it through `ISharpClawRuntimeModule` when they also expose application
surfaces such as CLI commands, API endpoints, gateway routes, or frontend
contributions.

Code that loads modules, runs host services, stores data, or implements runtime
mechanics should depend on these contracts without moving that implementation
behavior into the contract package.
