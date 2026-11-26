namespace SecureMcp.Server.Security;

/// <summary>Scopes double as ASP.NET Core authorization policy names.</summary>
public static class Scopes
{
    public const string ClaimType = "scope";
    public const string OrdersRead = "orders.read";
    public const string OrdersWrite = "orders.write";

    public static readonly IReadOnlySet<string> All = new HashSet<string>(StringComparer.Ordinal) { OrdersRead, OrdersWrite };
}
