namespace SharpClaw.Contracts.DTOs.Users;

public sealed record UserEntry(
    Guid Id,
    string Username,
    string? Bio,
    bool IsUserAdmin);
