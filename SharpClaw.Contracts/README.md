# SharpClaw.Contracts

SharpClaw.Contracts provides the MIT-licensed public types that registrations and
integrations use to connect to SharpClaw without a SharpClaw.Core reference.

Use this package for direct chat values, unified tool handlers, registration features,
action and event hooks, durable continuation records, and sidecar messages.

```bash
dotnet add package SharpClaw.Contracts
```

Implementations own dispatch, persistence, transport, and host services.
Registration code should use the interfaces and records in this package for those
boundaries and should keep host behavior in the host application.
