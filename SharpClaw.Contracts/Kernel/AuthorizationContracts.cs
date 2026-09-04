using System.Text.Json;

namespace SharpClaw.Contracts.Kernel;

/// <summary>Identifies one resource in an authorization request.</summary>
public sealed record AuthorizationResource(
    string Type,
    string Id);

/// <summary>Provides one bounded, typed fact for an authorization request.</summary>
public sealed record AuthorizationFact(
    string Name,
    JsonElement Value);

/// <summary>Describes one operation without carrying caller authority.</summary>
public sealed record AuthorizationRequest(
    string Operation,
    AuthorizationResource Resource,
    IReadOnlyList<AuthorizationResource>? RelatedResources = null,
    IReadOnlyList<AuthorizationFact>? Facts = null)
{
    public IReadOnlyList<AuthorizationResource> EffectiveRelatedResources =>
        RelatedResources ?? [];

    public IReadOnlyList<AuthorizationFact> EffectiveFacts =>
        Facts ?? [];

    public void Validate()
    {
        ValidateName(Operation, nameof(Operation));
        ValidateResource(Resource, nameof(Resource));

        foreach (var resource in EffectiveRelatedResources)
            ValidateResource(resource, nameof(RelatedResources));

        var factNames = new HashSet<string>(StringComparer.Ordinal);
        foreach (var fact in EffectiveFacts)
        {
            ArgumentNullException.ThrowIfNull(fact);
            ValidateName(fact.Name, nameof(Facts));
            if (!factNames.Add(fact.Name))
                throw new ArgumentException($"Authorization fact '{fact.Name}' occurs more than once.", nameof(Facts));
            if (fact.Value.ValueKind == JsonValueKind.Undefined)
                throw new ArgumentException($"Authorization fact '{fact.Name}' has no value.", nameof(Facts));
        }
    }

    private static void ValidateResource(AuthorizationResource resource, string parameterName)
    {
        ArgumentNullException.ThrowIfNull(resource, parameterName);
        ValidateName(resource.Type, parameterName);
        ArgumentException.ThrowIfNullOrWhiteSpace(resource.Id, parameterName);
        if (resource.Id.Length > 512 || resource.Id.Any(char.IsControl))
            throw new ArgumentException("An authorization resource identifier is invalid.", parameterName);
    }

    private static void ValidateName(string value, string parameterName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value, parameterName);
        if (value.Length > 128 ||
            !value.All(character =>
                character is >= 'a' and <= 'z' or >= '0' and <= '9' or '.' or '-' or '_'))
        {
            throw new ArgumentException(
                "An authorization name must use lowercase ASCII letters, digits, periods, hyphens, or underscores.",
                parameterName);
        }
    }
}

/// <summary>Returns the authoritative result of one authorization request.</summary>
public sealed record AuthorizationDecision(
    bool Allowed,
    string Code,
    string Message)
{
    public static AuthorizationDecision Allow(string code = "allowed") =>
        new(true, code, "Access allowed.");

    public static AuthorizationDecision Deny(string code, string message) =>
        new(false, code, message);
}

/// <summary>Evaluates all authorization requests for one active policy.</summary>
public interface IAuthorizationPolicy
{
    ValueTask<AuthorizationDecision> EvaluateAsync(
        ActionContext<AuthorizationRequest> context,
        CancellationToken cancellationToken = default);
}

/// <summary>Preserves or denies an authorization request without granting access.</summary>
public readonly record struct AuthorizationRestriction
{
    private AuthorizationRestriction(bool denied, string? code, string? message)
    {
        Denied = denied;
        Code = code;
        Message = message;
    }

    public bool Denied { get; }

    public string? Code { get; }

    public string? Message { get; }

    public static AuthorizationRestriction Preserve() => default;

    public static AuthorizationRestriction Deny(string code, string message)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(code);
        ArgumentException.ThrowIfNullOrWhiteSpace(message);
        return new AuthorizationRestriction(true, code, message);
    }
}

/// <summary>Applies one independent restriction before the authoritative policy runs.</summary>
public interface IAuthorizationRestriction
{
    ValueTask<AuthorizationRestriction> EvaluateAsync(
        ActionContext<AuthorizationRequest> context,
        CancellationToken cancellationToken = default);
}

/// <summary>Identifies the neutral authorization contract.</summary>
public sealed record AuthorizationContract;
