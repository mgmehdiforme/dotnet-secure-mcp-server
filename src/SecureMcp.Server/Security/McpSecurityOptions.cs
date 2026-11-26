using System.ComponentModel.DataAnnotations;
using System.Text.RegularExpressions;

namespace SecureMcp.Server.Security;

/// <summary>Security settings for the MCP endpoint. Bound from the "McpSecurity" section and validated at startup.</summary>
public sealed partial class McpSecurityOptions
{
    public const string Section = "McpSecurity";

    [GeneratedRegex("^[0-9a-fA-F]{64}$")]
    private static partial Regex HashPattern();

    [GeneratedRegex("^[a-zA-Z0-9._-]{1,64}$")]
    private static partial Regex IdPattern();

    public static bool IsValidHash(string? value) => value is not null && HashPattern().IsMatch(value);

    public static bool IsValidId(string? value) => value is not null && IdPattern().IsMatch(value);

    /// <summary>
    /// Checks every key entry (DataAnnotations does not look inside lists). Returns the problems, empty when valid.
    /// </summary>
    public IEnumerable<string> KeyProblems()
    {
        foreach (var (k, i) in ApiKeys.Select((k, i) => (k, i)))
        {
            if (!IsValidId(k.Id)) yield return $"ApiKeys:{i}:Id must be 1-64 characters: letters, digits, '.', '_' or '-'.";
            if (!IsValidHash(k.Sha256)) yield return $"ApiKeys:{i}:Sha256 must be 64 hex characters (the hash printed by new-key).";
            if (k.Scopes.Count == 0) yield return $"ApiKeys:{i}:Scopes must list at least one scope.";
            foreach (var s in k.Scopes.Where(s => !Security.Scopes.All.Contains(s)))
                yield return $"ApiKeys:{i}:Scopes has an unknown scope '{s}'. Every key needs a known scope ({string.Join(", ", Security.Scopes.All)}).";
        }
        if (ApiKeys.Select(k => k.Id).Distinct(StringComparer.Ordinal).Count() != ApiKeys.Count) yield return "API key ids must be unique.";
        if (ApiKeys.Select(k => k.Sha256.ToUpperInvariant()).Distinct(StringComparer.Ordinal).Count() != ApiKeys.Count) yield return "API key hashes must be unique.";
    }

    /// <summary>Host names this server answers to. Anything else is a DNS-rebinding attempt and gets 403.</summary>
    [MinLength(1, ErrorMessage = "McpSecurity:AllowedHosts must list at least one host (for example localhost).")]
    public List<string> AllowedHosts { get; set; } = [];

    /// <summary>Browser origins allowed to call the server. Requests without an Origin header (CLI and desktop clients) are allowed.</summary>
    public List<string> AllowedOrigins { get; set; } = [];

    /// <summary>API keys, stored as SHA-256 hashes only. Generate one with: dotnet run -- new-key &lt;id&gt; &lt;scope&gt;...</summary>
    [MinLength(1, ErrorMessage = "No API keys configured. Run: dotnet run --project src/SecureMcp.Server -- new-key my-client orders.read")]
    public List<ApiKeyEntry> ApiKeys { get; set; } = [];

    /// <summary>Requests per minute, per API key (or per IP before authentication).</summary>
    [Range(1, 100_000)]
    public int RequestsPerMinute { get; set; } = 60;

    /// <summary>Largest JSON-RPC request body accepted, in bytes.</summary>
    [Range(1024, 10 * 1024 * 1024)]
    public long MaxRequestBodyBytes { get; set; } = 64 * 1024;
}

public sealed class ApiKeyEntry
{
    /// <summary>Who holds the key. Shows up in audit logs and traces, never the key itself.</summary>
    public string Id { get; set; } = "";

    /// <summary>Lower-case hex SHA-256 of the key.</summary>
    public string Sha256 { get; set; } = "";

    /// <summary>What the key may do, for example orders.read or orders.write.</summary>
    public List<string> Scopes { get; set; } = [];
}
