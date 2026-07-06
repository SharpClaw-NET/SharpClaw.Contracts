# SharpClaw.Gateway.Contracts

SharpClaw.Gateway.Contracts is the MIT-licensed gateway contract package for
SharpClaw modules that publish endpoint groups through the gateway process.
Use it when module or gateway host code needs the shared gateway interfaces and
response models without taking a dependency on the SharpClaw runtime app.

```bash
dotnet add package SharpClaw.Gateway.Contracts
```

Modules implement `IGatewayModuleExtension` when they need to expose gateway
routes. The gateway passes an `IGatewayEndpointGroupBuilder` into the module so
routes are enrolled through the gateway-owned path prefix, rate limiting, and
gating pipeline. Module code can use `IGatewayInternalApi` for read-only
forwarding and `IGatewayDispatcher` for queued mutation forwarding.

The package intentionally keeps ASP.NET endpoint types in the gateway contract
surface because module endpoint mapping is expressed with ASP.NET minimal API
types such as `RouteHandlerBuilder` and `IResult`.
