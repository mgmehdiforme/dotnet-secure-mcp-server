using SecureMcp.Server.Security;

/// <summary>Generates a key for a client. The key is shown once; only its hash goes into configuration.</summary>
internal static class KeyCommand
{
    public static int Run(string[] args)
    {
        var quiet = args.Contains("--quiet");
        args = args.Where(a => a != "--quiet").ToArray();
        var id = args.Length > 0 ? args[0] : "my-client";
        var scopes = args.Length > 1 ? args[1..] : [Scopes.OrdersRead];

        if (!McpSecurityOptions.IsValidId(id))
        {
            Console.Error.WriteLine("Client id must be 1-64 characters: letters, digits, '.', '_' or '-'.");
            return 2;
        }

        var unknown = scopes.Where(s => !Scopes.All.Contains(s)).ToArray();
        if (unknown.Length > 0)
        {
            Console.Error.WriteLine($"Unknown scope(s): {string.Join(", ", unknown)}. Known: {string.Join(", ", Scopes.All)}");
            return 2;
        }

        var key = ApiKeys.NewKey();
        var hash = ApiKeys.HashHex(key);
        if (quiet)
        {
            Console.WriteLine($"{key} {hash}");
            return 0;
        }

        Console.WriteLine($"""
            API key for '{id}' (shown once, store it in the client's secret store):

              {key}

            Add this to the server configuration (appsettings or environment), never the key itself:

              "McpSecurity": {"{"} "ApiKeys": [ {"{"} "Id": "{id}", "Sha256": "{hash}", "Scopes": [{string.Join(", ", scopes.Select(s => $"\"{s}\""))}] {"}"} ] {"}"}

            or as environment variables:

              McpSecurity__ApiKeys__0__Id={id}
              McpSecurity__ApiKeys__0__Sha256={hash}
            {string.Join(Environment.NewLine, scopes.Select((s, i) => $"  McpSecurity__ApiKeys__0__Scopes__{i}={s}"))}
            """);
        return 0;
    }
}
