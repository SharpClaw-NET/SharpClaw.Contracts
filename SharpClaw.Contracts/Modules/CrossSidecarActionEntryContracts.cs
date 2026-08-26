using System.Text.Json;

namespace SharpClaw.Contracts.Modules;

public sealed record SidecarModuleActionEntryDefinition(
    string ModuleId,
    string GraphId,
    SidecarActionDescriptorIdentity Descriptor,
    string TerminalOwnerModuleId,
    string TerminalOwnerGraphId)
{
    public bool IsWellFormed =>
        !string.IsNullOrWhiteSpace(ModuleId) &&
        !string.IsNullOrWhiteSpace(GraphId) &&
        Descriptor is not null &&
        Descriptor.IsWellFormed &&
        !string.IsNullOrWhiteSpace(TerminalOwnerModuleId) &&
        !string.IsNullOrWhiteSpace(TerminalOwnerGraphId) &&
        string.Equals(TerminalOwnerModuleId, ModuleId, StringComparison.Ordinal) &&
        string.Equals(TerminalOwnerGraphId, GraphId, StringComparison.Ordinal);
}

public sealed record SidecarActionPayloadLineage(
    string TypeIdentity,
    int SchemaVersion,
    string ContentHash,
    int ByteLength)
{
    public bool IsWellFormed =>
        !string.IsNullOrWhiteSpace(TypeIdentity) &&
        SchemaVersion >= 1 &&
        !string.IsNullOrWhiteSpace(ContentHash) &&
        ByteLength > 0;

    public static SidecarActionPayloadLineage From(SidecarSerializedPayload payload) =>
        new(payload.TypeIdentity, payload.SchemaVersion, payload.ContentHash, payload.ByteLength);
}

/// <summary>Neutral child request. It carries no target module or host descriptor authority.</summary>
public sealed record SidecarCrossSidecarActionEntryRequest(
    SharpClawActionKey ActionKey,
    int ActionVersion,
    SidecarSerializedPayload Action,
    DateTimeOffset Deadline,
    DateTimeOffset ExpiresAt)
{
    public bool IsWellFormed =>
        !string.IsNullOrWhiteSpace(ActionKey.Value) &&
        ActionVersion >= 1 &&
        Action is not null &&
        Action.IsValid &&
        Deadline > DateTimeOffset.MinValue &&
        ExpiresAt >= Deadline;
}

public sealed record SidecarCrossSidecarActionEntryAuthority(
    SidecarCapabilityCallIdentity SourceParentCall,
    SidecarCapabilityCallIdentity TargetChildCall,
    Guid SourceParentInvocationId,
    Guid TargetChildInvocationId,
    Guid CapabilityId,
    string CapabilityHandle,
    Guid RootBudgetId,
    long SourceBindingGeneration,
    long TargetBindingGeneration,
    SidecarModuleActionEntryDefinition TargetEntry,
    SidecarActionPayloadLineage Action,
    RequestPrincipal Caller,
    ExtensionFeatureSet Features,
    Guid TraceId,
    Guid IdempotencyKey,
    SidecarCancellationIdentity Cancellation,
    DateTimeOffset Deadline,
    DateTimeOffset IssuedAt,
    DateTimeOffset ExpiresAt,
    int Depth,
    int Attempt,
    string SnapshotContentHash,
    string TerminalOwnerModuleId,
    string TerminalOwnerGraphId,
    SidecarTerminalReceipt? ResultReceipt,
    string Proof)
{
    public SidecarActionDescriptorIdentity Descriptor => TargetEntry.Descriptor;

    public string CanonicalBindingHash { get; init; } = string.Empty;
    public SidecarCapabilityCallIdentity? PeerCall { get; init; }
    public long PeerBindingGeneration { get; init; }
    public Guid TerminalId { get; init; }
    public SidecarActionOutcomeEnvelope? OutcomeEnvelope { get; init; }
    public SidecarActionResultIdentity? ResultIdentity { get; init; }
    public SidecarTerminalExecutionResult? Execution { get; init; }
    public SidecarSafeFailureIdentity? ResponseSafeFailure { get; init; }

    public bool IsValid =>
        SourceParentCall is not null &&
        SourceParentCall.IsValid &&
        SourceParentCall.Capability == SidecarCapabilityKind.Action &&
        TargetChildCall is not null &&
        TargetChildCall.IsValid &&
        TargetChildCall.Capability == SidecarCapabilityKind.Action &&
        SourceParentCall.SessionId != TargetChildCall.SessionId &&
        SourceParentCall.CallId != TargetChildCall.CallId &&
        SourceParentInvocationId != Guid.Empty &&
        TargetChildInvocationId != Guid.Empty &&
        CapabilityId != Guid.Empty &&
        !string.IsNullOrWhiteSpace(CapabilityHandle) &&
        RootBudgetId != Guid.Empty &&
        SourceBindingGeneration > 0 &&
        TargetBindingGeneration > 0 &&
        TargetEntry is not null &&
        TargetEntry.IsWellFormed &&
        Action is not null &&
        Action.IsWellFormed &&
        Caller is not null &&
        !string.IsNullOrWhiteSpace(Caller.SubjectId) &&
        Features is not null &&
        Features.Items is not null &&
        TraceId != Guid.Empty &&
        IdempotencyKey != Guid.Empty &&
        Cancellation is not null &&
        Cancellation.CancellationId == TargetChildCall.CancellationId &&
        !string.IsNullOrWhiteSpace(Cancellation.AuthorityHash) &&
        Depth >= 0 &&
        Attempt >= 1 &&
        !string.IsNullOrWhiteSpace(SnapshotContentHash) &&
        !string.IsNullOrWhiteSpace(TerminalOwnerModuleId) &&
        !string.IsNullOrWhiteSpace(TerminalOwnerGraphId) &&
        string.Equals(TerminalOwnerModuleId, TargetEntry.ModuleId, StringComparison.Ordinal) &&
        string.Equals(TerminalOwnerGraphId, TargetEntry.GraphId, StringComparison.Ordinal) &&
        (PeerCall is null
            ? PeerBindingGeneration == 0
            : PeerCall.IsValid &&
              PeerCall.Capability == SidecarCapabilityKind.Action &&
              PeerCall.CallId == TargetChildCall.CallId &&
              PeerCall.ReplayNonce == TargetChildCall.ReplayNonce &&
              PeerCall.Sequence == TargetChildCall.Sequence &&
              PeerCall.Deadline == TargetChildCall.Deadline &&
              PeerBindingGeneration > 0) &&
        IssuedAt <= ExpiresAt &&
        Deadline > IssuedAt &&
        Deadline <= ExpiresAt &&
        !string.IsNullOrWhiteSpace(CanonicalBindingHash) &&
        !string.IsNullOrWhiteSpace(Proof) &&
        (ResultReceipt is null
            ? TerminalId == Guid.Empty &&
              OutcomeEnvelope is null &&
              ResultIdentity is null &&
              Execution is null &&
              ResponseSafeFailure is null
            : TerminalId != Guid.Empty &&
              OutcomeEnvelope is not null &&
              Execution is not null &&
              ResponseSafeFailure is not null &&
              ResponseSafeFailure.IsValid &&
              OutcomeEnvelope.TerminalCallCount == 1 &&
              OutcomeEnvelope.Receipt == ResultReceipt);

    public bool HasResultReceipt => ResultReceipt is not null;
}

public sealed record SidecarCrossSidecarActionEntryCarrier(
    Guid CarrierId,
    string Handle,
    SidecarCrossSidecarActionEntryAuthority Authority,
    SidecarSerializedPayload Action,
    long BindingGeneration,
    DateTimeOffset ExpiresAt)
{
    public SidecarActionDescriptorIdentity Descriptor => Authority.Descriptor;

    public bool IsWellFormed =>
        CarrierId != Guid.Empty &&
        !string.IsNullOrWhiteSpace(Handle) &&
        Authority is not null &&
        Authority.IsValid &&
        string.Equals(Handle, Authority.CapabilityHandle, StringComparison.Ordinal) &&
        Action is not null &&
        Action.IsValid &&
        string.Equals(Action.ContentHash, Authority.Action.ContentHash, StringComparison.OrdinalIgnoreCase) &&
        Action.ByteLength == Authority.Action.ByteLength &&
        Action.TypeIdentity == Authority.Action.TypeIdentity &&
        Action.SchemaVersion == Authority.Action.SchemaVersion &&
        BindingGeneration == Authority.TargetBindingGeneration &&
        ExpiresAt == Authority.ExpiresAt;
}

public sealed record SidecarCrossSidecarActionEntryRelay(
    SidecarCrossSidecarActionEntryCarrier Carrier,
    SidecarModuleActionEntryDefinition TargetEntry)
{
    public SidecarCapabilityCallIdentity? PeerCall { get; init; }
    public long PeerBindingGeneration { get; init; }
    public SidecarActionDescriptorIdentity Descriptor => TargetEntry.Descriptor;

    public bool IsWellFormed =>
        Carrier is not null &&
        Carrier.IsWellFormed &&
        TargetEntry is not null &&
        TargetEntry.IsWellFormed &&
        TargetEntry == Carrier.Authority.TargetEntry &&
        PeerCall == Carrier.Authority.PeerCall &&
        PeerBindingGeneration == Carrier.Authority.PeerBindingGeneration;
}

public enum SidecarCrossSidecarActionEntryOutcomeKind
{
    Completed,
    Failed,
    Cancelled,
}

public sealed record SidecarCrossSidecarActionEntryOutcome(
    SidecarCrossSidecarActionEntryOutcomeKind Kind,
    SidecarActionOutcomeEnvelope? Outcome,
    SidecarTerminalReceipt? ResultReceipt,
    SidecarSafeFailureIdentity Failure,
    SidecarCrossSidecarActionEntryAuthority Authority)
{
    public bool IsWellFormed =>
        Enum.IsDefined(Kind) &&
        Failure is not null &&
        Failure.IsValid &&
        Authority is not null &&
        Authority.IsValid &&
        Authority.ResultReceipt == ResultReceipt &&
        (Kind == SidecarCrossSidecarActionEntryOutcomeKind.Completed
            ? Outcome is not null &&
              Outcome.Kind == ActionOutcomeKind.Completed &&
              Outcome.Result is not null &&
              ResultReceipt is not null
            : Outcome is not null &&
              Outcome.Result is null &&
              ResultReceipt is not null);
}

public static class SidecarCrossSidecarActionEntryValidation
{
    public static string ComputeAuthorityHash(SidecarCrossSidecarActionEntryAuthority authority)
    {
        ArgumentNullException.ThrowIfNull(authority);

        var canonical = new
        {
            SourceParentCall = authority.SourceParentCall,
            TargetChildCall = authority.TargetChildCall,
            authority.SourceParentInvocationId,
            authority.TargetChildInvocationId,
            authority.CapabilityId,
            authority.CapabilityHandle,
            authority.RootBudgetId,
            authority.SourceBindingGeneration,
            authority.TargetBindingGeneration,
            TargetEntry = authority.TargetEntry,
            Action = authority.Action,
            Caller = authority.Caller,
            Features = authority.Features,
            authority.TraceId,
            authority.IdempotencyKey,
            Cancellation = authority.Cancellation,
            authority.Deadline,
            authority.IssuedAt,
            authority.ExpiresAt,
            authority.Depth,
            authority.Attempt,
            authority.SnapshotContentHash,
            authority.TerminalOwnerModuleId,
            authority.TerminalOwnerGraphId,
            PeerCall = authority.PeerCall,
            authority.PeerBindingGeneration,
            ResultReceipt = authority.ResultReceipt,
            authority.TerminalId,
            OutcomeEnvelope = authority.OutcomeEnvelope,
            ResultIdentity = authority.ResultIdentity,
            Execution = authority.Execution,
            ResponseSafeFailure = authority.ResponseSafeFailure,
        };

        return SidecarCapabilityTransportCodec.ComputeSha256(
            SidecarCapabilityTransportCodec.Serialize(canonical));
    }

    public static SidecarCapabilityValidationResult ValidateRequest(
        SidecarCrossSidecarActionEntryRequest request,
        SidecarCapabilityCallIdentity parentCall,
        SidecarCapabilitySessionBinding sourceBinding,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(parentCall);
        ArgumentNullException.ThrowIfNull(sourceBinding);

        if (!request.IsWellFormed ||
            !parentCall.IsValid ||
            parentCall.Capability != SidecarCapabilityKind.Action ||
            parentCall.SessionId != sourceBinding.SessionId ||
            parentCall.RequestId != sourceBinding.RequestId ||
            parentCall.CancellationId != sourceBinding.CancellationId ||
            !string.Equals(parentCall.ModuleId, sourceBinding.ModuleId, StringComparison.Ordinal) ||
            !string.Equals(parentCall.GraphId, sourceBinding.GraphId, StringComparison.Ordinal) ||
            request.Deadline != parentCall.Deadline ||
            request.Deadline <= now ||
            request.ExpiresAt < request.Deadline ||
            request.ExpiresAt > sourceBinding.ExpiresAt)
        {
            return SidecarCapabilityValidationResult.Reject(
                SidecarCapabilityErrors.SpoofedIdentity,
                "The cross-sidecar child request is outside the parent authority.");
        }

        return SidecarCapabilityTransportValidation.ValidateSerializedPayload(
            request.Action,
            required: true,
            sourceBinding.PayloadLimits.ActionInputBytes);
    }

    public static SidecarCapabilityValidationResult ValidateCarrier(
        SidecarCrossSidecarActionEntryCarrier carrier,
        SidecarCapabilitySessionBinding targetBinding,
        DateTimeOffset now,
        Func<SidecarCrossSidecarActionEntryAuthority, string, bool> authenticate)
    {
        ArgumentNullException.ThrowIfNull(carrier);
        ArgumentNullException.ThrowIfNull(targetBinding);
        ArgumentNullException.ThrowIfNull(authenticate);

        var authority = carrier.Authority;
        if (!carrier.IsWellFormed ||
            authority.TargetChildCall.SessionId != targetBinding.SessionId ||
            authority.TargetChildCall.RequestId != targetBinding.RequestId ||
            authority.TargetChildCall.CancellationId != targetBinding.CancellationId ||
            !string.Equals(authority.TargetChildCall.ModuleId, targetBinding.ModuleId, StringComparison.Ordinal) ||
            !string.Equals(authority.TargetChildCall.GraphId, targetBinding.GraphId, StringComparison.Ordinal) ||
            authority.TargetChildCall.Deadline != authority.Deadline ||
            authority.SourceParentCall.Deadline != authority.Deadline ||
            authority.TargetEntry.ModuleId != targetBinding.ModuleId ||
            authority.TargetEntry.GraphId != targetBinding.GraphId ||
            authority.TargetBindingGeneration <= 0 ||
            authority.ExpiresAt <= now ||
            authority.Deadline <= now ||
            authority.ExpiresAt > targetBinding.ExpiresAt ||
            !string.Equals(authority.CanonicalBindingHash, ComputeAuthorityHash(authority), StringComparison.OrdinalIgnoreCase) ||
            !authenticate(authority, authority.CanonicalBindingHash))
        {
            return SidecarCapabilityValidationResult.Reject(
                SidecarCapabilityErrors.SpoofedIdentity,
                "The cross-sidecar child carrier is not authenticated for the target session.");
        }

        return SidecarCapabilityTransportValidation.ValidateSerializedPayload(
            carrier.Action,
            required: true,
            targetBinding.PayloadLimits.ActionInputBytes);
    }

    public static SidecarCapabilityValidationResult ValidatePeerCarrier(
        SidecarCrossSidecarActionEntryCarrier carrier,
        SidecarCapabilitySessionBinding peerBinding,
        DateTimeOffset now,
        Func<SidecarCrossSidecarActionEntryAuthority, string, bool> authenticate)
    {
        ArgumentNullException.ThrowIfNull(carrier);
        ArgumentNullException.ThrowIfNull(peerBinding);
        ArgumentNullException.ThrowIfNull(authenticate);

        var authority = carrier.Authority;
        var peerCall = authority?.PeerCall;
        if (!carrier.IsWellFormed ||
            peerCall is null ||
            authority.PeerBindingGeneration <= 0 ||
            peerCall.SessionId != peerBinding.SessionId ||
            peerCall.RequestId != peerBinding.RequestId ||
            peerCall.CancellationId != peerBinding.CancellationId ||
            !string.Equals(peerCall.ModuleId, peerBinding.ModuleId, StringComparison.Ordinal) ||
            !string.Equals(peerCall.GraphId, peerBinding.GraphId, StringComparison.Ordinal) ||
            authority.PeerBindingGeneration <= 0 ||
            peerCall.Deadline != authority.Deadline ||
            authority.ExpiresAt <= now ||
            authority.Deadline <= now ||
            authority.ExpiresAt > peerBinding.ExpiresAt ||
            !string.Equals(authority.CanonicalBindingHash, ComputeAuthorityHash(authority), StringComparison.OrdinalIgnoreCase) ||
            !authenticate(authority, authority.CanonicalBindingHash))
        {
            return SidecarCapabilityValidationResult.Reject(
                SidecarCapabilityErrors.SpoofedIdentity,
                "The cross-sidecar peer carrier is not authenticated for the receiving session.");
        }

        return SidecarCapabilityTransportValidation.ValidateSerializedPayload(
            carrier.Action,
            required: true,
            peerBinding.PayloadLimits.ActionInputBytes);
    }

    public static SidecarCapabilityValidationResult ValidateOutcome(
        SidecarCrossSidecarActionEntryOutcome result,
        SidecarCapabilitySessionBinding targetBinding,
        DateTimeOffset now,
        Func<SidecarCrossSidecarActionEntryAuthority, string, bool> authenticate)
    {
        ArgumentNullException.ThrowIfNull(result);

        var carrierResult = result.IsWellFormed &&
            result.Authority.ResultReceipt is not null &&
            result.ResultReceipt is not null &&
            result.ResultReceipt.CallId == result.Authority.TargetChildCall.CallId &&
            result.ResultReceipt.ActionKey == result.Authority.Descriptor.Key &&
            result.ResultReceipt.ActionVersion == result.Authority.Descriptor.Version &&
            result.ResultReceipt.Attempt == result.Authority.Attempt &&
            result.Authority.ExpiresAt > now &&
            string.Equals(result.Authority.CanonicalBindingHash, ComputeAuthorityHash(result.Authority), StringComparison.OrdinalIgnoreCase) &&
            authenticate(result.Authority, result.Authority.CanonicalBindingHash);
        if (!carrierResult)
        {
            return SidecarCapabilityValidationResult.Reject(
                SidecarCapabilityErrors.InvalidResponse,
                "The cross-sidecar child outcome is not authenticated.");
        }

        var outcome = result.Outcome;
        var validOutcome = result.Kind switch
        {
            SidecarCrossSidecarActionEntryOutcomeKind.Completed =>
                outcome is not null &&
                outcome.Kind == ActionOutcomeKind.Completed &&
                outcome.Result is not null &&
                outcome.Error is null &&
                outcome.Uncertainty is null &&
                outcome.TerminalCallCount == 1,
            SidecarCrossSidecarActionEntryOutcomeKind.Failed =>
                outcome is not null &&
                outcome.Kind == ActionOutcomeKind.Failed &&
                outcome.Result is null &&
                outcome.Error is not null &&
                outcome.Uncertainty is null &&
                outcome.TerminalCallCount == 1,
            SidecarCrossSidecarActionEntryOutcomeKind.Cancelled =>
                outcome is not null &&
                outcome.Kind == ActionOutcomeKind.Cancelled &&
                outcome.Result is null &&
                outcome.Error is null &&
                outcome.Uncertainty is null &&
                outcome.TerminalCallCount == 1,
            _ => false,
        };
        var authorityOutcome = result.Authority.OutcomeEnvelope;
        var authorityExecution = result.Authority.Execution;
        var authorityFailure = result.Authority.ResponseSafeFailure;
        var terminalAuthorityMatches =
            authorityOutcome == outcome &&
            authorityOutcome?.Receipt == result.ResultReceipt &&
            authorityFailure == result.Failure &&
            authorityExecution is not null &&
            authorityExecution.Completed &&
            authorityExecution.Result == outcome?.Result &&
            authorityExecution.Failure == (result.Kind == SidecarCrossSidecarActionEntryOutcomeKind.Completed ? null : result.Failure);
        if (!validOutcome ||
            outcome!.Receipt != result.ResultReceipt ||
            !terminalAuthorityMatches)
        {
            return SidecarCapabilityValidationResult.Reject(
                SidecarCapabilityErrors.InvalidResponse,
                "The cross-sidecar child outcome shape is invalid.");
        }

        var payloadResult = SidecarCapabilityTransportValidation.ValidateSerializedPayload(
            outcome.Result,
            required: result.Kind == SidecarCrossSidecarActionEntryOutcomeKind.Completed,
            targetBinding.PayloadLimits.ActionResultBytes);
        if (!payloadResult.Accepted)
            return payloadResult;

        if (outcome.Result is not null &&
            (outcome.Result.TypeIdentity != result.Authority.Descriptor.ResultTypeIdentity ||
             outcome.Result.SchemaVersion != result.Authority.Descriptor.ResultSchemaVersion ||
             result.Authority.ResultIdentity is null ||
             result.Authority.ResultIdentity.CallId != result.Authority.TargetChildCall.CallId ||
             result.Authority.ResultIdentity.ActionKey != result.Authority.Descriptor.Key ||
             result.Authority.ResultIdentity.ActionVersion != result.Authority.Descriptor.Version ||
             result.Authority.ResultIdentity.ResultTypeIdentity != outcome.Result.TypeIdentity ||
             result.Authority.ResultIdentity.ContentHash != outcome.Result.ContentHash))
        {
            return SidecarCapabilityValidationResult.Reject(
                SidecarCapabilityErrors.InvalidResponse,
                "The cross-sidecar child result does not match its authority.");
        }

        if (outcome.Result is null && result.Authority.ResultIdentity is not null)
        {
            return SidecarCapabilityValidationResult.Reject(
                SidecarCapabilityErrors.InvalidResponse,
                "A non-completed cross-sidecar outcome cannot carry a result identity.");
        }

        return SidecarCapabilityValidationResult.Accept();
    }
}
