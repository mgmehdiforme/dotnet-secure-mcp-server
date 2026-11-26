using System.ComponentModel;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using ModelContextProtocol;
using ModelContextProtocol.Server;
using SecureMcp.Server.Data;
using SecureMcp.Server.Security;

namespace SecureMcp.Server.Tools;

public sealed record OrderView(long Id, string Customer, string Status, decimal Total, string CreatedAt)
{
    public static OrderView From(Order o) => new(o.Id, Pii.MaskEmail(o.CustomerEmail), o.Status, o.Total, o.CreatedAt);
}

public sealed record SearchResult(int Count, IReadOnlyList<OrderView> Orders);

/// <summary>
/// The tools the model can call. Each tool validates its input like a public API, returns only what the
/// model needs (emails masked), and declares the scope it requires. Validation errors are thrown as
/// McpException so the model sees a clear message; any other exception is hidden from the client.
/// </summary>
[McpServerToolType]
public sealed class OrderTools(OrderRepository orders, IHttpContextAccessor http)
{
    public const int MaxLimit = 50;

    [McpServerTool(Name = "search_orders", ReadOnly = true, Idempotent = true, OpenWorld = false)]
    [Description("Search orders by customer email (exact match, case-insensitive) and/or status. Returns at most 50 orders, newest first. Customer emails are masked.")]
    [Authorize(Policy = Scopes.OrdersRead)]
    public async Task<SearchResult> SearchOrders(
        [Description("Exact customer email, for example ana@example.com. Optional.")] string? customerEmail = null,
        [Description("One of: pending, paid, shipped, delivered, cancelled. Optional.")] string? status = null,
        [Description("How many orders to return, 1-50. Default 20.")] int limit = 20,
        CancellationToken cancellationToken = default)
    {
        if (customerEmail is { Length: > 254 })
        {
            throw new McpException("customerEmail is too long.");
        }

        if (status is not null && !OrderStatus.IsValid(status))
        {
            throw new McpException($"Unknown status '{Pii.Truncate(status)}'. Use one of: {string.Join(", ", OrderStatus.All)}.");
        }

        if (limit < 1)
        {
            throw new McpException("limit must be 1 or more.");
        }

        var found = await orders.SearchAsync(customerEmail?.Trim(), status, Math.Min(limit, MaxLimit), cancellationToken);
        return new SearchResult(found.Count, found.Select(OrderView.From).ToList());
    }

    [McpServerTool(Name = "get_order", ReadOnly = true, Idempotent = true, OpenWorld = false)]
    [Description("Get one order by its numeric id. The customer email is masked.")]
    [Authorize(Policy = Scopes.OrdersRead)]
    public async Task<OrderView> GetOrder(
        [Description("The order id, a positive number.")] long orderId,
        CancellationToken cancellationToken = default)
    {
        if (orderId <= 0)
        {
            throw new McpException("orderId must be a positive number.");
        }

        var order = await orders.GetAsync(orderId, cancellationToken) ?? throw new McpException($"Order {orderId} does not exist.");
        return OrderView.From(order);
    }

    [McpServerTool(Name = "update_order_status", ReadOnly = false, Destructive = false, Idempotent = false, OpenWorld = false)]
    [Description("Move an order to its next status. Allowed: pending->paid|cancelled, paid->shipped|cancelled, shipped->delivered. A reason is required and is written to the audit log.")]
    [Authorize(Policy = Scopes.OrdersWrite)]
    public async Task<OrderView> UpdateOrderStatus(
        [Description("The order id.")] long orderId,
        [Description("The new status.")] string newStatus,
        [Description("Why the status changes, 5-200 characters. Stored in the audit log.")] string reason,
        CancellationToken cancellationToken = default)
    {
        if (orderId <= 0)
        {
            throw new McpException("orderId must be a positive number.");
        }

        if (!OrderStatus.IsValid(newStatus))
        {
            throw new McpException($"Unknown status '{Pii.Truncate(newStatus)}'. Use one of: {string.Join(", ", OrderStatus.All)}.");
        }

        reason = reason?.Trim() ?? "";
        if (reason.Length is < 5 or > 200 || reason.Any(char.IsControl))
        {
            throw new McpException("reason must be 5-200 characters on one line.");
        }

        var actor = http.HttpContext?.User.FindFirstValue(ClaimTypes.NameIdentifier) ?? "unknown";
        try
        {
            var updated = await orders.UpdateStatusAsync(orderId, newStatus, actor, reason, cancellationToken);
            return OrderView.From(updated);
        }
        catch (OrderNotFoundException e)
        {
            throw new McpException(e.Message);
        }
        catch (InvalidTransitionException e)
        {
            throw new McpException(e.Message);
        }
    }
}

public static class Pii
{
    /// <summary>ana@example.com -> a***@example.com. The model rarely needs the full address.</summary>
    public static string MaskEmail(string email)
    {
        var at = email.IndexOf('@', StringComparison.Ordinal);
        return at <= 0 ? "***" : $"{email[0]}***{email[at..]}";
    }

    public static string Truncate(string value, int max = 40) => value.Length <= max ? value : value[..max] + "…";
}
