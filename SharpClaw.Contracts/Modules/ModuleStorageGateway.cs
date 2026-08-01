using System.Text.Json;

namespace SharpClaw.Contracts.Modules;

public interface IModuleStorageGateway
{
    IReadOnlyList<ModuleStorageContractDescriptor> ListContracts();

    Task<JsonElement> InvokeAsync(
        string moduleId,
        string storageName,
        string operation,
        JsonElement parameters,
        CancellationToken ct = default);

    Task<ModuleStorageMutationAndOutboxResult> CommitMutationAndOutboxAsync(
        string moduleId,
        string storageName,
        ModuleStorageMutationAndOutboxRequest request,
        CancellationToken ct = default);

    Task<ModuleStorageClaimResult<T>> ClaimAsync<T>(
        string moduleId,
        string storageName,
        ModuleDocumentClaimPayload request,
        CancellationToken ct = default);

    Task<ModuleStorageClaimRenewalResult> RenewClaimAsync(
        string moduleId,
        string storageName,
        ModuleStorageClaimRenewalRequest request,
        CancellationToken ct = default);

    Task<ModuleStorageClaimRecoveryResult> RecoverClaimAsync(
        string moduleId,
        string storageName,
        ModuleStorageClaimRecoveryRequest request,
        CancellationToken ct = default);
}

public interface IModuleStorageContractProvider
{
    IReadOnlyList<ModuleStorageContractDescriptor> GetStorageContracts();

    ModuleStorageContractDescriptor? FindStorageContract(
        string moduleId,
        string storageName);
}

public static class ModuleStorageOperations
{
    public const string Get = "get";
    public const string Upsert = "upsert";
    public const string BatchUpsert = "batchUpsert";
    public const string Delete = "delete";
    public const string BatchDelete = "batchDelete";
    public const string List = "list";
    public const string Query = "query";
    public const string Claim = "claim";
    public const string RenewClaim = "renewClaim";
    public const string RecoverClaim = "recoverClaim";
    public const string MutateAndOutbox = "mutateAndOutbox";
}

public static class ModuleStorageErrors
{
    public const string RevisionConflict = "revision_conflict";
    public const string StaleClaim = "stale_claim";
    public const string FencingRejected = "fencing_rejected";
    public const string AtomicCommitRejected = "atomic_commit_rejected";
    public const string MalformedResponse = "malformed_response";
    public const string MissingRecordKey = "missing_record_key";
    public const string RecordKeyMismatch = "record_key_mismatch";
    public const string MissingRevision = "missing_revision";
    public const string InvalidRevision = "invalid_revision";
    public const string CommitIdentityConflict = "commit_identity_conflict";
}

public static class ModuleStorageComparisonOperators
{
    public const string EqualTo = "equals";
    public const string LessThanOrEqual = "lessThanOrEqual";
    public const string GreaterThanOrEqual = "greaterThanOrEqual";
}

public static class ModuleStorageSortDirections
{
    public const string Ascending = "asc";
    public const string Descending = "desc";
}

public sealed record ModuleStorageContractDescriptor(
    string ModuleId,
    string StorageName,
    IReadOnlyList<ModuleStorageOperationDescriptor> Operations,
    string? Description = null,
    IReadOnlyList<ModuleStorageIndexDescriptor>? Indexes = null,
    int MaxDocumentBytes = 65_536,
    int MaxBatchSize = 100);

public sealed record ModuleStorageOperationDescriptor(
    string Name,
    string? Description = null);

public sealed record ModuleStorageIndexDescriptor(
    string Name,
    ModuleStorageIndexValueKind ValueKind,
    bool AllowsEquality = true,
    bool AllowsRange = false);

public enum ModuleStorageIndexValueKind
{
    String,
    Number,
    DateTime,
    Bool,
}

public sealed record ModuleDocumentIndexFilter(
    string IndexName,
    string Operator,
    object? Value);

public sealed record ModuleDocumentIndexOrder(
    string IndexName,
    string Direction = ModuleStorageSortDirections.Ascending);

public sealed record ModuleDocumentQueryPayload(
    IReadOnlyList<ModuleDocumentIndexFilter> Filters,
    ModuleDocumentIndexOrder? OrderBy = null,
    int? Limit = null);

public sealed record ModuleDocumentClaimPayload(
    IReadOnlyList<ModuleDocumentIndexFilter> Filters,
    ModuleDocumentIndexOrder? OrderBy,
    int? Limit,
    object Patch,
    object? Indexes = null,
    long? ExpectedRevision = null,
    ModuleStorageClaimAuthority? Authority = null,
    string? OwnerId = null);

public sealed record ModuleDocumentWrite<T>(
    string Key,
    T Value,
    object? Indexes = null,
    long? ExpectedRevision = null,
    ModuleStorageClaimAuthority? Authority = null);

public sealed record ModuleDocumentDelete(
    string Key,
    long? ExpectedRevision = null,
    ModuleStorageClaimAuthority? Authority = null);

public sealed record ModuleStorageRevision(string Key, long Revision);

/// <summary>Host-issued authority for one claimed mutation or continuation.</summary>
public sealed record ModuleStorageClaimAuthority(
    string OwnerId,
    Guid HostToken,
    DateTimeOffset LeaseExpiresAt,
    long Generation,
    long Revision)
{
    public bool HasFiniteLease =>
        LeaseExpiresAt > DateTimeOffset.MinValue && LeaseExpiresAt < DateTimeOffset.MaxValue;

    public bool IsActiveAt(DateTimeOffset now) =>
        HasFiniteLease && LeaseExpiresAt > now && Generation >= 0 && Revision >= 0;
}

public sealed record ModuleStorageClaimRequest(
    string OwnerId,
    IReadOnlyList<ModuleDocumentIndexFilter> Filters,
    ModuleDocumentIndexOrder? OrderBy = null,
    int? Limit = null,
    object? Patch = null,
    object? Indexes = null,
    long? ExpectedRevision = null);

public sealed record ModuleStorageClaimRenewalRequest(
    string OwnerId,
    Guid HostToken,
    long Generation,
    DateTimeOffset RequestedLeaseExpiresAt);

public sealed record ModuleStorageClaimRecoveryRequest(
    string OwnerId,
    Guid HostToken,
    long Generation,
    DateTimeOffset ObservedAt);

public sealed record ModuleStorageClaimRecord<T>(
    string Key,
    T? Value,
    long Revision,
    ModuleStorageClaimAuthority Authority,
    object? Indexes = null);

public sealed record ModuleStorageClaimResult<T>(
    IReadOnlyList<ModuleStorageClaimRecord<T>> Records,
    ModuleStorageClaimAuthority Authority);

public sealed record ModuleStorageClaimRenewalResult(
    bool Renewed,
    ModuleStorageClaimAuthority? Authority,
    string? ErrorCode = null);

public sealed record ModuleStorageClaimRecoveryResult(
    bool Recovered,
    ModuleStorageClaimAuthority? Authority,
    string? ErrorCode = null);

public sealed record ModuleDocumentRecord<T>(
    string Key,
    T? Value,
    long Revision,
    object? Indexes = null);

public sealed record ModuleStorageMutation(
    string Operation,
    string Key,
    JsonElement? Value = null,
    JsonElement? Patch = null,
    object? Indexes = null,
    long? ExpectedRevision = null,
    ModuleStorageClaimAuthority? Authority = null);

public sealed record ModuleStorageCommitIdentity(
    Guid OperationId,
    string IdempotencyKey);

public sealed record ModuleStorageEventEnvelope(
    Guid EventId,
    SharpClawEventKey EventKey,
    int Version,
    JsonSchemaReference Schema,
    EventDelivery Delivery,
    string OwnerModuleId,
    string Origin,
    JsonElement Payload);

public sealed record ModuleStorageOutboxMessage(
    ModuleStorageCommitIdentity Commit,
    ModuleStorageEventEnvelope Event,
    DateTimeOffset? NotBefore = null);

/// <summary>
/// One atomic state and outbox commit. The host must reject the whole request
/// when any expected revision or fence is stale.
/// </summary>
public sealed record ModuleStorageMutationAndOutboxRequest(
    ModuleStorageCommitIdentity Commit,
    IReadOnlyList<ModuleStorageMutation> Mutations,
    IReadOnlyList<ModuleStorageOutboxMessage> Outbox,
    ModuleStorageClaimAuthority? Authority = null);

public sealed record ModuleStorageMutationAndOutboxResult(
    ModuleStorageCommitIdentity Commit,
    IReadOnlyList<ModuleStorageRevision> Revisions,
    IReadOnlyList<string> OutboxMessageIds,
    long CommitRevision,
    bool AlreadyCommitted = false);

public sealed record ModuleStorageRevisionConflict(
    string Key,
    long? ExpectedRevision,
    long ActualRevision);

public sealed record ModuleStorageContractFailure(
    string Code,
    string Message,
    string? Key = null,
    long? ExpectedRevision = null,
    long? ActualRevision = null);

public sealed class ModuleStorageContractException(
    ModuleStorageContractFailure Failure) : Exception(Failure.Message)
{
    public ModuleStorageContractFailure Failure { get; } = Failure;
}

public sealed class ModuleDocumentStore<T>(
    IModuleStorageGateway gateway,
    string moduleId,
    string storageName,
    JsonSerializerOptions? jsonOptions = null)
{
    private readonly JsonSerializerOptions _jsonOptions = jsonOptions ?? new JsonSerializerOptions(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = true,
    };

    public async Task<T?> GetAsync(string key, CancellationToken ct = default)
    {
        var record = await GetRecordAsync(key, ct);
        if (record is null)
            return default;

        return record.Value;
    }

    public async Task<ModuleDocumentRecord<T>?> GetRecordAsync(
        string key,
        CancellationToken ct = default)
    {
        using var parameters = JsonDocument.Parse(
            JsonSerializer.Serialize(new { key }, _jsonOptions));
        var response = await gateway.InvokeAsync(
            moduleId,
            storageName,
            ModuleStorageOperations.Get,
            parameters.RootElement,
            ct);

        if (!response.TryGetProperty("found", out var found) ||
            (found.ValueKind != JsonValueKind.True && found.ValueKind != JsonValueKind.False))
        {
            throw ContractFailure(
                ModuleStorageErrors.MalformedResponse,
                "The get response must contain a Boolean found value.",
                key);
        }

        if (found.ValueKind == JsonValueKind.False)
            return default;

        if (!response.TryGetProperty("value", out var value) ||
            value.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined)
        {
            throw ContractFailure(ModuleStorageErrors.MalformedResponse, "The found record has no value.", key);
        }

        if (!response.TryGetProperty("key", out var keyElement) ||
            keyElement.ValueKind != JsonValueKind.String ||
            string.IsNullOrWhiteSpace(keyElement.GetString()))
        {
            throw ContractFailure(ModuleStorageErrors.MissingRecordKey, "The found record has no key.", key);
        }

        var responseKey = keyElement.GetString()!;
        if (!string.Equals(responseKey, key, StringComparison.Ordinal))
        {
            throw ContractFailure(
                ModuleStorageErrors.RecordKeyMismatch,
                "The get response key does not match the requested key.",
                key);
        }

        if (!response.TryGetProperty("revision", out var revisionElement))
        {
            throw ContractFailure(ModuleStorageErrors.MissingRevision, "The found record has no valid revision.", key);
        }

        if (!revisionElement.TryGetInt64(out var revision) || revision < 0)
            throw ContractFailure(ModuleStorageErrors.InvalidRevision, "The found record has an invalid revision.", key);

        var item = value.Deserialize<T>(_jsonOptions);
        if (item is null)
            throw ContractFailure(ModuleStorageErrors.MalformedResponse, "The found record value is not valid.", key);

        JsonElement? indexes = response.TryGetProperty("indexes", out var indexesElement)
            ? indexesElement.Clone()
            : null;

        return new ModuleDocumentRecord<T>(responseKey, item, revision, indexes);
    }

    public async Task<IReadOnlyList<T>> ListAsync(CancellationToken ct = default)
    {
        using var parameters = JsonDocument.Parse("{}");
        var response = await gateway.InvokeAsync(
            moduleId,
            storageName,
            ModuleStorageOperations.List,
            parameters.RootElement,
            ct);

        return DeserializeDocumentRecords(response)
            .Where(record => record.Value is not null)
            .Select(record => record.Value!)
            .ToArray();
    }

    public ModuleDocumentQuery<T> Query() => new(this);

    public ModuleDocumentClaim<T> Claim() => new(this);

    public async Task UpsertAsync(
        string key,
        T value,
        object? indexes = null,
        CancellationToken ct = default,
        long? expectedRevision = null,
        ModuleStorageClaimAuthority? authority = null)
    {
        var payload = new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["key"] = key,
            ["value"] = value,
        };
        if (indexes is not null) payload["indexes"] = indexes;
        if (expectedRevision is not null) payload["expectedRevision"] = expectedRevision;
        if (authority is not null) payload["authority"] = authority;

        using var parameters = JsonDocument.Parse(JsonSerializer.Serialize(payload, _jsonOptions));
        await gateway.InvokeAsync(
            moduleId,
            storageName,
            ModuleStorageOperations.Upsert,
            parameters.RootElement,
            ct);
    }

    public async Task<int> UpsertManyAsync(
        IEnumerable<ModuleDocumentWrite<T>> records,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(records);

        var payload = new
        {
            records = records.Select(record => new
                {
                    key = record.Key,
                    value = record.Value,
                    indexes = record.Indexes,
                    expectedRevision = record.ExpectedRevision,
                    authority = record.Authority,
                }).ToArray(),
            };

        using var parameters = JsonDocument.Parse(JsonSerializer.Serialize(payload, _jsonOptions));
        var response = await gateway.InvokeAsync(
            moduleId,
            storageName,
            ModuleStorageOperations.BatchUpsert,
            parameters.RootElement,
            ct);

        return response.TryGetProperty("saved", out var saved) && saved.TryGetInt32(out var count)
            ? count
            : 0;
    }

    public Task<bool> DeleteAsync(string key, CancellationToken ct = default) =>
        DeleteAsync(key, ct, null);

    public async Task<bool> DeleteAsync(
        string key,
        CancellationToken ct,
        long? expectedRevision,
        ModuleStorageClaimAuthority? authority = null)
    {
        var payload = new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["key"] = key,
        };
        if (expectedRevision is not null) payload["expectedRevision"] = expectedRevision;
        if (authority is not null) payload["authority"] = authority;

        using var parameters = JsonDocument.Parse(JsonSerializer.Serialize(payload, _jsonOptions));
        var response = await gateway.InvokeAsync(
            moduleId,
            storageName,
            ModuleStorageOperations.Delete,
            parameters.RootElement,
            ct);

        return response.TryGetProperty("deleted", out var deleted)
               && deleted.ValueKind == JsonValueKind.True;
    }

    public async Task<int> DeleteManyAsync(
        IEnumerable<string> keys,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(keys);

        using var parameters = JsonDocument.Parse(
            JsonSerializer.Serialize(new { keys = keys.ToArray() }, _jsonOptions));
        var response = await gateway.InvokeAsync(
            moduleId,
            storageName,
            ModuleStorageOperations.BatchDelete,
            parameters.RootElement,
            ct);

        return response.TryGetProperty("deleted", out var deleted) && deleted.TryGetInt32(out var count)
            ? count
            : 0;
    }

    public async Task<int> DeleteManyAsync(
        IEnumerable<ModuleDocumentDelete> records,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(records);

        using var parameters = JsonDocument.Parse(
            JsonSerializer.Serialize(new { records = records.ToArray() }, _jsonOptions));
        var response = await gateway.InvokeAsync(
            moduleId,
            storageName,
            ModuleStorageOperations.BatchDelete,
            parameters.RootElement,
            ct);

        return response.TryGetProperty("deleted", out var deleted) && deleted.TryGetInt32(out var count)
            ? count
            : 0;
    }

    internal Task<IReadOnlyList<T>> QueryAsync(
        ModuleDocumentQueryPayload payload,
        CancellationToken ct) =>
        InvokeRecordsAsync(ModuleStorageOperations.Query, payload, ct);

    internal Task<IReadOnlyList<ModuleDocumentRecord<T>>> QueryRecordsAsync(
        ModuleDocumentQueryPayload payload,
        CancellationToken ct) =>
        InvokeDocumentRecordsAsync(ModuleStorageOperations.Query, payload, ct);

    internal async Task<IReadOnlyList<T>> ClaimAsync(
        ModuleDocumentClaimPayload payload,
        CancellationToken ct)
    {
        var result = await ClaimWithAuthorityAsync(payload, ct);
        return result.Records
            .Where(record => record.Value is not null)
            .Select(record => record.Value!)
            .ToArray();
    }

    internal async Task<IReadOnlyList<ModuleDocumentRecord<T>>> ClaimRecordsAsync(
        ModuleDocumentClaimPayload payload,
        CancellationToken ct)
    {
        var result = await ClaimWithAuthorityAsync(payload, ct);
        return result.Records
            .Select(record => new ModuleDocumentRecord<T>(
                record.Key,
                record.Value,
                record.Revision,
                record.Indexes))
            .ToArray();
    }

    internal async Task<ModuleStorageClaimResult<T>> ClaimWithAuthorityAsync(
        ModuleDocumentClaimPayload payload,
        CancellationToken ct)
    {
        using var parameters = JsonDocument.Parse(JsonSerializer.Serialize(payload, _jsonOptions));
        var response = await gateway.InvokeAsync(
            moduleId,
            storageName,
            ModuleStorageOperations.Claim,
            parameters.RootElement,
            ct);

        if (!response.TryGetProperty("authority", out var authorityElement))
            throw ContractFailure(ModuleStorageErrors.MalformedResponse, "The claim response has no host authority.");

        var authority = authorityElement.Deserialize<ModuleStorageClaimAuthority>(_jsonOptions);
        if (authority is null || !authority.HasFiniteLease || authority.Generation < 0 || authority.Revision < 0)
            throw ContractFailure(ModuleStorageErrors.MalformedResponse, "The claim response has invalid host authority.");

        if (!response.TryGetProperty("records", out var records) || records.ValueKind != JsonValueKind.Array)
            throw ContractFailure(ModuleStorageErrors.MalformedResponse, "The claim response must contain a records array.");

        var result = new List<ModuleStorageClaimRecord<T>>();
        foreach (var record in records.EnumerateArray())
        {
            if (record.ValueKind != JsonValueKind.Object ||
                !record.TryGetProperty("key", out var keyElement) ||
                keyElement.ValueKind != JsonValueKind.String ||
                string.IsNullOrWhiteSpace(keyElement.GetString()) ||
                !record.TryGetProperty("revision", out var revisionElement) ||
                !revisionElement.TryGetInt64(out var revision) ||
                revision < 0 ||
                !record.TryGetProperty("value", out var valueElement) ||
                valueElement.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined)
            {
                throw ContractFailure(ModuleStorageErrors.MalformedResponse, "A claim record is missing key, revision, or value.");
            }

            var item = valueElement.Deserialize<T>(_jsonOptions);
            if (item is null)
                throw ContractFailure(ModuleStorageErrors.MalformedResponse, "A claim record value is not valid.");

            var recordAuthority = record.TryGetProperty("authority", out var recordAuthorityElement)
                ? recordAuthorityElement.Deserialize<ModuleStorageClaimAuthority>(_jsonOptions)
                : authority;
            if (recordAuthority is null || !recordAuthority.HasFiniteLease || recordAuthority.Generation < 0)
                throw ContractFailure(ModuleStorageErrors.MalformedResponse, "A claim record has invalid authority.");

            JsonElement? indexes = record.TryGetProperty("indexes", out var indexesElement)
                ? indexesElement.Clone()
                : null;
            result.Add(new ModuleStorageClaimRecord<T>(
                keyElement.GetString()!,
                item,
                revision,
                recordAuthority,
                indexes));
        }

        return new ModuleStorageClaimResult<T>(result, authority);
    }

    private async Task<IReadOnlyList<T>> InvokeRecordsAsync(
        string operation,
        object payload,
        CancellationToken ct)
    {
        var records = await InvokeDocumentRecordsAsync(operation, payload, ct);
        return records
            .Where(record => record.Value is not null)
            .Select(record => record.Value!)
            .ToArray();
    }

    private async Task<IReadOnlyList<ModuleDocumentRecord<T>>> InvokeDocumentRecordsAsync(
        string operation,
        object payload,
        CancellationToken ct)
    {
        using var parameters = JsonDocument.Parse(JsonSerializer.Serialize(payload, _jsonOptions));
        var response = await gateway.InvokeAsync(
            moduleId,
            storageName,
            operation,
            parameters.RootElement,
            ct);

        return DeserializeDocumentRecords(response);
    }

    private IReadOnlyList<ModuleDocumentRecord<T>> DeserializeDocumentRecords(JsonElement response)
    {
        if (!response.TryGetProperty("records", out var records)
            || records.ValueKind != JsonValueKind.Array)
        {
            throw ContractFailure(
                ModuleStorageErrors.MalformedResponse,
                "The storage response must contain a records array.");
        }

        var result = new List<ModuleDocumentRecord<T>>();
        foreach (var record in records.EnumerateArray())
        {
            if (record.ValueKind != JsonValueKind.Object)
                throw ContractFailure(ModuleStorageErrors.MalformedResponse, "A storage record is not an object.");

            if (!record.TryGetProperty("key", out var keyElement) ||
                keyElement.ValueKind != JsonValueKind.String ||
                string.IsNullOrWhiteSpace(keyElement.GetString()))
            {
                throw ContractFailure(ModuleStorageErrors.MissingRecordKey, "A storage record has no key.");
            }

            if (!record.TryGetProperty("revision", out var revisionElement))
            {
                throw ContractFailure(ModuleStorageErrors.MissingRevision, "A storage record has no valid revision.");
            }

            if (!revisionElement.TryGetInt64(out var revision) || revision < 0)
                throw ContractFailure(ModuleStorageErrors.InvalidRevision, "A storage record has an invalid revision.");

            if (!record.TryGetProperty("value", out var value)
                || value.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined)
            {
                throw ContractFailure(ModuleStorageErrors.MalformedResponse, "A storage record has no value.");
            }

            if (value.Deserialize<T>(_jsonOptions) is not { } item)
                throw ContractFailure(ModuleStorageErrors.MalformedResponse, "A storage record value is not valid.");

            JsonElement? indexes = record.TryGetProperty("indexes", out var indexesElement)
                ? indexesElement.Clone()
                : null;

            result.Add(new ModuleDocumentRecord<T>(keyElement.GetString()!, item, revision, indexes));
        }

        return result;
    }

    private static ModuleStorageContractException ContractFailure(
        string code,
        string message,
        string? key = null) =>
        new(new ModuleStorageContractFailure(code, message, key));
}

public sealed class ModuleDocumentQuery<T>
{
    private readonly ModuleDocumentStore<T> _store;
    private readonly List<ModuleDocumentIndexFilter> _filters = [];
    private ModuleDocumentIndexOrder? _orderBy;
    private int? _limit;

    internal ModuleDocumentQuery(ModuleDocumentStore<T> store)
    {
        _store = store;
    }

    public ModuleDocumentIndexFilterBuilder<ModuleDocumentQuery<T>, T> WhereIndex(string indexName) =>
        new(this, indexName);

    public ModuleDocumentQuery<T> OrderByIndex(string indexName) =>
        SetOrder(indexName, ModuleStorageSortDirections.Ascending);

    public ModuleDocumentQuery<T> OrderByIndexDescending(string indexName) =>
        SetOrder(indexName, ModuleStorageSortDirections.Descending);

    public ModuleDocumentQuery<T> Take(int limit)
    {
        _limit = limit;
        return this;
    }

    public Task<IReadOnlyList<T>> ToListAsync(CancellationToken ct = default) =>
        _store.QueryAsync(new ModuleDocumentQueryPayload(_filters.ToArray(), _orderBy, _limit), ct);

    public Task<IReadOnlyList<ModuleDocumentRecord<T>>> ToRecordsAsync(
        CancellationToken ct = default) =>
        _store.QueryRecordsAsync(
            new ModuleDocumentQueryPayload(_filters.ToArray(), _orderBy, _limit),
            ct);

    internal ModuleDocumentQuery<T> AddFilter(
        string indexName,
        string comparisonOperator,
        object? value)
    {
        _filters.Add(new ModuleDocumentIndexFilter(indexName, comparisonOperator, value));
        return this;
    }

    private ModuleDocumentQuery<T> SetOrder(string indexName, string direction)
    {
        _orderBy = new ModuleDocumentIndexOrder(indexName, direction);
        return this;
    }
}

public sealed class ModuleDocumentClaim<T>
{
    private readonly ModuleDocumentStore<T> _store;
    private readonly List<ModuleDocumentIndexFilter> _filters = [];
    private ModuleDocumentIndexOrder? _orderBy;
    private int? _limit;
    private object? _patch;
    private object? _indexes;
    private long? _expectedRevision;
    private ModuleStorageClaimAuthority? _authority;

    internal ModuleDocumentClaim(ModuleDocumentStore<T> store)
    {
        _store = store;
    }

    public ModuleDocumentIndexFilterBuilder<ModuleDocumentClaim<T>, T> WhereIndex(string indexName) =>
        new(this, indexName);

    public ModuleDocumentClaim<T> OrderByIndex(string indexName) =>
        SetOrder(indexName, ModuleStorageSortDirections.Ascending);

    public ModuleDocumentClaim<T> OrderByIndexDescending(string indexName) =>
        SetOrder(indexName, ModuleStorageSortDirections.Descending);

    public ModuleDocumentClaim<T> Take(int limit)
    {
        _limit = limit;
        return this;
    }

    public ModuleDocumentClaim<T> Patch(object patch, object? indexes = null)
    {
        _patch = patch;
        _indexes = indexes;
        return this;
    }

    public ModuleDocumentClaim<T> AtRevision(long expectedRevision)
    {
        if (expectedRevision < 0)
            throw new ArgumentOutOfRangeException(nameof(expectedRevision));

        _expectedRevision = expectedRevision;
        return this;
    }

    public ModuleDocumentClaim<T> WithAuthority(ModuleStorageClaimAuthority authority)
    {
        ArgumentNullException.ThrowIfNull(authority);
        _authority = authority;
        return this;
    }

    public Task<IReadOnlyList<T>> ToListAsync(CancellationToken ct = default)
    {
        if (_patch is null)
            throw new InvalidOperationException("Module storage claim requires a patch before execution.");

        return _store.ClaimAsync(
            new ModuleDocumentClaimPayload(
                _filters.ToArray(),
                _orderBy,
                _limit,
                _patch,
                _indexes,
                _expectedRevision,
                _authority),
            ct);
    }

    public Task<IReadOnlyList<ModuleDocumentRecord<T>>> ToRecordsAsync(
        CancellationToken ct = default)
    {
        if (_patch is null)
            throw new InvalidOperationException("Module storage claim requires a patch before execution.");

        return _store.ClaimRecordsAsync(
            new ModuleDocumentClaimPayload(
                _filters.ToArray(),
                _orderBy,
                _limit,
                _patch,
                _indexes,
                _expectedRevision,
                _authority),
            ct);
    }

    public Task<ModuleStorageClaimResult<T>> ToClaimRecordsAsync(
        CancellationToken ct = default)
    {
        if (_patch is null)
            throw new InvalidOperationException("Module storage claim requires a patch before execution.");

        return _store.ClaimWithAuthorityAsync(
            new ModuleDocumentClaimPayload(
                _filters.ToArray(),
                _orderBy,
                _limit,
                _patch,
                _indexes,
                _expectedRevision,
                _authority),
            ct);
    }

    internal ModuleDocumentClaim<T> AddFilter(
        string indexName,
        string comparisonOperator,
        object? value)
    {
        _filters.Add(new ModuleDocumentIndexFilter(indexName, comparisonOperator, value));
        return this;
    }

    private ModuleDocumentClaim<T> SetOrder(string indexName, string direction)
    {
        _orderBy = new ModuleDocumentIndexOrder(indexName, direction);
        return this;
    }
}

public sealed class ModuleDocumentIndexFilterBuilder<TQuery, TDocument>
{
    private readonly TQuery _query;
    private readonly string _indexName;

    internal ModuleDocumentIndexFilterBuilder(TQuery query, string indexName)
    {
        _query = query;
        _indexName = indexName;
    }

    public TQuery EqualTo(object? value) =>
        Add(ModuleStorageComparisonOperators.EqualTo, value);

    public TQuery LessThanOrEqual(object? value) =>
        Add(ModuleStorageComparisonOperators.LessThanOrEqual, value);

    public TQuery GreaterThanOrEqual(object? value) =>
        Add(ModuleStorageComparisonOperators.GreaterThanOrEqual, value);

    private TQuery Add(string comparisonOperator, object? value)
    {
        return _query switch
        {
            ModuleDocumentQuery<TDocument> query =>
                (TQuery)(object)query.AddFilter(_indexName, comparisonOperator, value),
            ModuleDocumentClaim<TDocument> claim =>
                (TQuery)(object)claim.AddFilter(_indexName, comparisonOperator, value),
            _ => throw new InvalidOperationException(
                $"Unsupported module document query builder '{typeof(TQuery).Name}'."),
        };
    }
}
