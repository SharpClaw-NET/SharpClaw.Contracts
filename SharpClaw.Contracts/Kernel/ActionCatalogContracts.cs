namespace SharpClaw.Contracts.Kernel;

/// <summary>Canonical kernel and Jobs action keys.</summary>
public static class SharpClawActionCatalog
{
    private static readonly string[] KernelNames =
    [
        "runtime.start.prepare",
        "runtime.start.configure",
        "runtime.start.bind",
        "runtime.stop.prepare",
        "runtime.stop.complete",
        "runtime.request.receive",
        "runtime.request.authenticate",
        "runtime.request.authorize",
        "runtime.request.route",
        "runtime.request.handler.invoke",
        "runtime.request.response.prepare",
        "runtime.request.response.write",
        "runtime.request.complete",
        "runtime.request.fail",
        "runtime.request.cancel",
        "runtime.cli.parse",
        "runtime.cli.command.select",
        "runtime.cli.execute",
        "runtime.cli.output.write",
        "runtime.cli.complete",
        "runtime.cli.fail",
        "runtime.cli.cancel",
        "security.api_key.resolve",
        "security.session.validate",
        "security.administrator.authorize",
        "security.secret.read",
        "security.secret.write",
        "security.secret.delete",
        "security.remote_pairing.validate",
        "security.decision.fail",
        "security.decision.cancel",
        "client.command.receive",
        "client.command.validate",
        "client.command.dispatch",
        "client.command.complete",
        "client.command.fail",
        "client.command.cancel",
        "client.navigation.prepare",
        "client.navigation.commit",
        "client.state.prepare",
        "client.state.commit",
        "gateway.request.receive",
        "gateway.request.authenticate",
        "gateway.request.authorize",
        "gateway.request.route",
        "gateway.request.forward",
        "gateway.request.response",
        "gateway.request.fail",
        "gateway.request.cancel",
        "gateway.stream.open",
        "gateway.stream.chunk.receive",
        "gateway.stream.chunk.forward",
        "gateway.stream.close",
        "gateway.stream.fail",
        "gateway.stream.cancel",
        "gateway.endpoint.dispatch",
        "gateway.bridge.session.validate",
        "gateway.bridge.forward",
        "chat.turn.start",
        "chat.conversation.resolve",
        "chat.profile.resolve",
        "chat.history.load",
        "chat.user_message.prepare",
        "chat.user_message.commit",
        "chat.context.assemble.start",
        "chat.context.contributor.invoke",
        "chat.context.assemble.complete",
        "chat.tools.collect",
        "chat.tools.select",
        "chat.provider_round.start",
        "chat.provider_round.complete",
        "chat.assistant_message.prepare",
        "chat.assistant_message.commit",
        "chat.turn.complete",
        "chat.turn.fail",
        "chat.turn.cancel",
        "provider.resolve",
        "provider.client.create",
        "provider.request.prepare",
        "provider.request.serialize",
        "provider.request.serialize.after",
        "provider.request.send",
        "provider.stream.open",
        "provider.stream.chunk.receive",
        "provider.stream.chunk.transform",
        "provider.stream.chunk.send",
        "provider.stream.close",
        "provider.response.deserialize",
        "provider.response.complete",
        "provider.request.fail",
        "provider.request.cancel",
        "tool.definition.register",
        "tool.definition.select",
        "tool.call.parse",
        "tool.call.propose",
        "tool.call.input.transform",
        "tool.call.check",
        "tool.call.defer",
        "tool.call.coordinate",
        "tool.handler.invoke",
        "tool.result.transform",
        "tool.result.return",
        "tool.call.fail",
        "tool.call.cancel",
        "conversation.create",
        "conversation.history.query",
        "conversation.message.prepare",
        "conversation.message.commit",
        "conversation.message.delete",
        "conversation.clear.prepare",
        "conversation.clear.commit",
        "storage.get",
        "storage.list",
        "storage.query",
        "storage.claim",
        "storage.upsert.prepare",
        "storage.upsert.commit",
        "storage.delete.prepare",
        "storage.delete.commit",
        "storage.transaction.prepare",
        "storage.transaction.begin",
        "storage.transaction.commit",
        "storage.transaction.rollback",
        "storage.operation.fail",
        "storage.operation.cancel",
        "event.define",
        "event.publish.preview",
        "event.publish.commit",
        "event.enqueue",
        "event.deliver",
        "event.acknowledge",
        "event.delivery.fail",
        "continuation.create",
        "continuation.claim",
        "continuation.lease.renew",
        "continuation.resume",
        "continuation.cancel",
        "continuation.recover",
        "continuation.complete",
        "continuation.deliver",
        "continuation.acknowledge",
        "continuation.expire",
        "continuation.delete",
        "action_recovery.create",
        "action_recovery.query",
        "action_recovery.evaluate",
        "action_recovery.resolve",
        "action_recovery.deliver",
        "action_recovery.acknowledge",
        "action_recovery.delete",
        "background.service.start",
        "background.tick.prepare",
        "background.tick.execute",
        "background.tick.complete",
        "background.tick.fail",
        "background.tick.cancel",
        "background.service.stop",
    ];

    private static readonly string[] JobsFamilyNames =
    [
        "jobs.submit",
        "jobs.validate",
        "jobs.identity.create",
        "jobs.queue.persist",
        "jobs.hold.evaluate",
        "jobs.hold.resolve",
        "jobs.dispatch",
        "jobs.start",
        "jobs.handler.invoke",
        "jobs.progress.report",
        "jobs.artifact.seal",
        "jobs.complete",
        "jobs.fail",
        "jobs.cancel",
        "jobs.cancel.request",
        "jobs.cancel.apply",
        "jobs.pause",
        "jobs.stop",
        "jobs.recovery",
        "jobs.recovery.scan",
        "jobs.recovery.classify",
        "jobs.retry",
        "jobs.retry.evaluate",
        "jobs.retry.schedule",
        "jobs.resume",
        "jobs.delete",
        "jobs.read",
        "jobs.list",
        "jobs.logs.read",
        "jobs.audit.read",
        "jobs.artifact.read",
        "jobs.event.deliver",
        "jobs.state.transition",
        "jobs.state.transition.prepare",
        "jobs.state.transition.commit",
        "jobs.state.transition.rollback",
        "jobs.persistence",
        "jobs.persistence.prepare",
        "jobs.persistence.commit",
        "jobs.persistence.rollback",
        "jobs.interruption.check",
        "jobs.external_call",
        "jobs.irreversible_effect",
        "jobs.external_effect.prepare",
        "jobs.external_effect.receipt",
        "jobs.external_effect.uncertain",
    ];

    public static IReadOnlyList<SharpClawActionKey> Kernel { get; } =
        KernelNames.Select(name => new SharpClawActionKey(name)).ToArray();

    public static IReadOnlyList<string> JobsFamilies { get; } = JobsFamilyNames;

    public static IReadOnlyList<SharpClawActionKey> Jobs { get; } =
        JobsFamilyNames
            .SelectMany(name => new[]
            {
                new SharpClawActionKey(name),
                new SharpClawActionKey($"{name}.before"),
                new SharpClawActionKey($"{name}.after"),
            })
            .ToArray();

    public static IReadOnlyList<SharpClawActionKey> All { get; } =
        Kernel.Concat(Jobs).ToArray();

    public static int JobsFamilyCount => JobsFamilies.Count;

    public static int JobsKeyCount => Jobs.Count;
}

/// <summary>Typed names for the proposal's frequently used action keys.</summary>
public static class SharpClawActions
{
    public static class Chat
    {
        public static readonly SharpClawActionKey Turn = new("chat.turn.start");
        public static readonly SharpClawActionKey ResolveConversation = new("chat.conversation.resolve");
        public static readonly SharpClawActionKey ResolveProfile = new("chat.profile.resolve");
        public static readonly SharpClawActionKey LoadHistory = new("chat.history.load");
        public static readonly SharpClawActionKey AssembleContext = new("chat.context.assemble.start");
        public static readonly SharpClawActionKey SelectTools = new("chat.tools.select");
        public static readonly SharpClawActionKey ProviderRound = new("chat.provider_round.start");
        public static readonly SharpClawActionKey CommitExchange = new("chat.assistant_message.commit");
    }

    public static class Provider
    {
        public static readonly SharpClawActionKey Resolve = new("provider.resolve");
        public static readonly SharpClawActionKey BeforeSerialize = new("provider.request.serialize");
        public static readonly SharpClawActionKey Send = new("provider.request.send");
        public static readonly SharpClawActionKey AfterTransport = new("provider.response.complete");
    }

    public static class Tools
    {
        public static readonly SharpClawActionKey Invoke = new("tool.call.propose");
        public static readonly SharpClawActionKey Resolve = new("tool.definition.select");
        public static readonly SharpClawActionKey Check = new("tool.call.check");
        public static readonly SharpClawActionKey InvokeHandler = new("tool.handler.invoke");
        public static readonly SharpClawActionKey Coordinate = new("tool.call.coordinate");
    }

    public static class Jobs
    {
        public static SharpClawActionKey Family(string name) =>
            new(name.StartsWith("jobs.", StringComparison.Ordinal) ? name : $"jobs.{name}");

        public static readonly SharpClawActionKey Submit = Family("submit");
        public static readonly SharpClawActionKey Validate = Family("validate");
        public static readonly SharpClawActionKey Dispatch = Family("dispatch");
        public static readonly SharpClawActionKey HandlerInvoke = Family("handler.invoke");
        public static readonly SharpClawActionKey Resume = Family("resume");
        public static readonly SharpClawActionKey Recovery = Family("recovery");
    }
}

/// <summary>Typed names for automatic and first-party event keys.</summary>
public static class SharpClawEvents
{
    public static readonly SharpClawEventKey ActionStarting = new("action.starting");
    public static readonly SharpClawEventKey ActionCompleted = new("action.completed");
    public static readonly SharpClawEventKey ActionDeferred = new("action.deferred");
    public static readonly SharpClawEventKey ActionFailed = new("action.failed");
    public static readonly SharpClawEventKey ActionCancelled = new("action.cancelled");
    public static readonly SharpClawEventKey JobsState = new("jobs.state");
    public static readonly SharpClawEventKey JobsProgress = new("jobs.progress");
    public static readonly SharpClawEventKey JobsReceipt = new("jobs.receipt");
    public static readonly SharpClawEventKey JobsRecovery = new("jobs.recovery");
    public static readonly SharpClawEventKey JobsTerminal = new("jobs.terminal");

    public static IReadOnlyList<SharpClawEventKey> Standard { get; } =
    [
        ActionStarting,
        ActionCompleted,
        ActionDeferred,
        ActionFailed,
        ActionCancelled,
        JobsState,
        JobsProgress,
        JobsReceipt,
        JobsRecovery,
        JobsTerminal,
    ];
}

public static class SharpClawCheckpoints
{
    public static class Provider
    {
        public static readonly SharpClawActionKey BeforeSerialize =
            new("provider.request.serialize");

        public static readonly SharpClawActionKey AfterSerialize =
            new("provider.request.serialize.after");

        public static readonly SharpClawActionKey AfterTransport =
            new("provider.response.complete");
    }
}
