# SharpClaw.Gateway.Contracts

SharpClaw.Gateway.Contracts is the MIT-licensed transport contract package for
the SharpClaw Gateway. It provides request dispatch, internal API, queue, and
response types without a dependency on the Runtime application.

```bash
dotnet add package SharpClaw.Gateway.Contracts
```

Gateway code can use `IGatewayInternalApi` for direct reads. It can use
`IGatewayDispatcher` for queued mutation requests. `QueuedResponse` preserves
the upstream status and response body through the Gateway boundary.

The package keeps `IResult` in its public surface. This type lets Gateway
handlers return a `QueuedResponse` through ASP.NET without a local response model.
