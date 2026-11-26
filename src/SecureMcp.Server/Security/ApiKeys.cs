using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;

namespace SecureMcp.Server.Security;

/// <summary>Creates and hashes API keys. Keys are random 32-byte values; only their SHA-256 hash is ever stored.</summary>
public static class ApiKeys
{
    public const string Prefix = "smcp_";

    public static string NewKey() =>
        Prefix + Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static byte[] Hash(string key) => SHA256.HashData(Encoding.UTF8.GetBytes(key));

    public static string HashHex(string key) => Convert.ToHexStringLower(Hash(key));
}

/// <summary>The configured keys. Rebuilt when configuration changes, so a revoked key stops working without a restart.</summary>
public sealed class ApiKeyStore
{
    private volatile (ApiKeyEntry Entry, byte[] Hash)[] _keys;

    public ApiKeyStore(IOptionsMonitor<McpSecurityOptions> options)
    {
        _keys = Build(options.CurrentValue);
        options.OnChange(o => _keys = Build(o));
    }

    private static (ApiKeyEntry, byte[])[] Build(McpSecurityOptions o) =>
        o.ApiKeys.Where(k => McpSecurityOptions.IsValidHash(k.Sha256)).Select(k => (k, Convert.FromHexString(k.Sha256))).ToArray();

    public ApiKeyEntry? Find(string presentedKey)
    {
        var hash = ApiKeys.Hash(presentedKey);
        ApiKeyEntry? match = null;
        foreach (var (entry, expected) in _keys)
        {
            // No early exit: every key is compared, each in constant time.
            if (CryptographicOperations.FixedTimeEquals(hash, expected))
            {
                match ??= entry;
            }
        }
        return match;
    }
}
