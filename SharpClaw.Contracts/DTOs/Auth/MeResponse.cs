namespace SharpClaw.Contracts.DTOs.Auth;

public sealed record MeResponse(
    Guid Id,
    string Username,
    string? Bio,
    bool IsUserAdmin = false);
