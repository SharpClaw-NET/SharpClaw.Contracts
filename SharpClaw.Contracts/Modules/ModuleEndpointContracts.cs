using System.Text.Json;

namespace SharpClaw.Contracts.Modules;

/// <summary>Describes one public route that a module owns.</summary>
public sealed record ModuleEndpointRouteDescriptor(
    string Id,
    string Path,
    string Method,
    HostEndpointTransport Transport)
{
    /// <summary>Gets whether the descriptor has one canonical route identity.</summary>
    public bool IsWellFormed =>
        new HostEndpointRouteIdentity(Id, Path, Method, Transport).IsWellFormed &&
        (Transport != HostEndpointTransport.WebSocket ||
         string.Equals(Method, "GET", StringComparison.Ordinal));

    /// <summary>Creates the route identity used by host authority.</summary>
    public HostEndpointRouteIdentity ToRouteIdentity() =>
        new(Id, Path, Method, Transport);
}

/// <summary>Contains one complete module HTTP response.</summary>
public sealed record ModuleHttpEndpointResponse(
    int StatusCode,
    IReadOnlyDictionary<string, string[]> Headers,
    byte[] Body)
{
    /// <summary>Gets whether the response contains valid HTTP metadata.</summary>
    public bool IsWellFormed =>
        StatusCode is >= 100 and <= 599 &&
        HostEndpointRouteAuthorityValidator.IsHeaderMetadataWellFormed(Headers) &&
        Body is not null;

    /// <summary>Creates a JSON response.</summary>
    public static ModuleHttpEndpointResponse Json(
        int statusCode,
        JsonElement payload) =>
        new(
            statusCode,
            new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
            {
                ["Content-Type"] = ["application/json; charset=utf-8"],
            },
            JsonSerializer.SerializeToUtf8Bytes(payload));

    /// <summary>Creates an empty response.</summary>
    public static ModuleHttpEndpointResponse Empty(int statusCode) =>
        new(
            statusCode,
            new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase),
            []);
}

/// <summary>Executes one registered module HTTP route.</summary>
public interface IModuleHttpEndpointHandler
{
    /// <summary>Executes the route with host-authenticated action authority.</summary>
    ValueTask<ModuleHttpEndpointResponse> InvokeAsync(
        HostEndpointRouteRequest request,
        IHostActionEntry hostActionEntry,
        CancellationToken cancellationToken);
}

/// <summary>Identifies one neutral WebSocket message type.</summary>
public enum ModuleWebSocketMessageType
{
    Text,
    Binary,
    Close,
}

/// <summary>Contains one complete WebSocket message.</summary>
public sealed record ModuleWebSocketMessage(
    ModuleWebSocketMessageType Type,
    byte[] Payload,
    int? CloseStatus = null,
    string? CloseDescription = null)
{
    /// <summary>Gets whether the message contains valid frame data.</summary>
    public bool IsWellFormed =>
        Enum.IsDefined(Type) &&
        Payload is not null &&
        (Type == ModuleWebSocketMessageType.Close
            ? CloseStatus is >= 1000 and <= 4999 &&
              (CloseDescription is null || CloseDescription.Length <= 123)
            : CloseStatus is null && CloseDescription is null);
}

/// <summary>Transfers messages for one accepted module WebSocket route.</summary>
public interface IModuleWebSocketChannel
{
    /// <summary>Receives one complete message or null after peer closure.</summary>
    ValueTask<ModuleWebSocketMessage?> ReceiveAsync(CancellationToken cancellationToken);

    /// <summary>Sends one complete message.</summary>
    ValueTask SendAsync(
        ModuleWebSocketMessage message,
        CancellationToken cancellationToken);

    /// <summary>Closes the route once.</summary>
    ValueTask CloseAsync(
        int closeStatus,
        string? description,
        CancellationToken cancellationToken);
}

/// <summary>Executes one registered module WebSocket route.</summary>
public interface IModuleWebSocketEndpointHandler
{
    /// <summary>Executes the route with host-authenticated action authority.</summary>
    ValueTask InvokeAsync(
        HostEndpointRouteRequest request,
        IModuleWebSocketChannel channel,
        IHostActionEntry hostActionEntry,
        CancellationToken cancellationToken);
}
