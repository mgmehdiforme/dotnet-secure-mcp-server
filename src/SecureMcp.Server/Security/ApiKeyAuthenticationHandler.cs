using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace SecureMcp.Server.Security;

/// <summary>Bearer API-key authentication. Missing key = 401, unknown key = 401, valid key = a principal with its scopes.</summary>
public sealed class ApiKeyAuthenticationHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder,
    ApiKeyStore store) : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    public const string SchemeName = "ApiKey";

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        string? header = Request.Headers.Authorization;
        if (string.IsNullOrEmpty(header))
        {
            return Task.FromResult(AuthenticateResult.NoResult());
        }

        if (!header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            return Task.FromResult(AuthenticateResult.Fail("Unsupported authorization scheme."));
        }

        var key = header["Bearer ".Length..].Trim();
        if (key.Length is < 16 or > 256)
        {
            return Task.FromResult(AuthenticateResult.Fail("Malformed key."));
        }

        var entry = store.Find(key);
        if (entry is null)
        {
            Logger.LogWarning("Rejected an unknown API key from {RemoteIp}", Context.Connection.RemoteIpAddress);
            return Task.FromResult(AuthenticateResult.Fail("Unknown key."));
        }

        var claims = new List<Claim> { new(ClaimTypes.NameIdentifier, entry.Id), new(ClaimTypes.Name, entry.Id) };
        claims.AddRange(entry.Scopes.Select(s => new Claim(Scopes.ClaimType, s)));
        var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, SchemeName));
        return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(principal, SchemeName)));
    }

    protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        Response.StatusCode = StatusCodes.Status401Unauthorized;
        Response.Headers.WWWAuthenticate = "Bearer realm=\"mcp\"";
        await Response.WriteAsJsonAsync(new { error = "unauthorized", message = "Send a valid API key: Authorization: Bearer <key>" });
    }

    protected override async Task HandleForbiddenAsync(AuthenticationProperties properties)
    {
        Response.StatusCode = StatusCodes.Status403Forbidden;
        await Response.WriteAsJsonAsync(new { error = "forbidden", message = "This key does not have the scope for this action." });
    }
}
