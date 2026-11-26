using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using ModelContextProtocol;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;
using SecureMcp.Server.Data;

namespace SecureMcp.Tests;

/// <summary>Real MCP calls through the official C# client.</summary>
public sealed class ToolTests(ServerFactory server) : IClassFixture<ServerFactory>
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static JsonElement Json(CallToolResult r)
    {
        Assert.False(r.IsError == true, string.Join(" ", r.Content.OfType<TextContentBlock>().Select(t => t.Text)));
        var text = Assert.IsType<TextContentBlock>(r.Content[0]).Text;
        return JsonDocument.Parse(text).RootElement;
    }

    private static string ErrorText(CallToolResult r)
    {
        Assert.True(r.IsError);
        return string.Join(" ", r.Content.OfType<TextContentBlock>().Select(t => t.Text));
    }

    private static Dictionary<string, object?> Args(params (string Key, object? Value)[] items) => items.ToDictionary(i => i.Key, i => i.Value);

    [Fact]
    public async Task Reader_sees_only_read_tools()
    {
        await using var mcp = await server.McpAsync(server.ReaderKey);
        var names = (await mcp.ListToolsAsync(cancellationToken: Ct)).Select(t => t.Name).ToList();
        Assert.DoesNotContain(server.AuditLines, l => l.Contains("client=test-reader tool=update_order_status", StringComparison.Ordinal) && !l.Contains("forbidden", StringComparison.Ordinal));
        Assert.Contains("search_orders", names);
        Assert.Contains("get_order", names);
        Assert.DoesNotContain("update_order_status", names);
    }

    [Fact]
    public async Task Writer_sees_all_tools_with_read_only_hints()
    {
        await using var mcp = await server.McpAsync(server.WriterKey);
        var tools = await mcp.ListToolsAsync(cancellationToken: Ct);
        Assert.Equal(3, tools.Count);
        Assert.True(tools.Single(t => t.Name == "search_orders").ProtocolTool.Annotations?.ReadOnlyHint);
        Assert.False(tools.Single(t => t.Name == "update_order_status").ProtocolTool.Annotations?.ReadOnlyHint);
    }

    [Fact]
    public async Task Search_masks_customer_emails()
    {
        await using var mcp = await server.McpAsync(server.ReaderKey);
        var json = Json(await mcp.CallToolAsync("search_orders", Args(("customerEmail", "ana@example.com")), cancellationToken: Ct));
        Assert.True(json.GetProperty("count").GetInt32() > 0);
        foreach (var o in json.GetProperty("orders").EnumerateArray())
        {
            Assert.Equal("a***@example.com", o.GetProperty("customer").GetString());
        }
    }

    [Fact]
    public async Task Search_limit_is_capped_at_50()
    {
        await using var mcp = await server.McpAsync(server.ReaderKey);
        var json = Json(await mcp.CallToolAsync("search_orders", Args(("limit", 100000)), cancellationToken: Ct));
        Assert.InRange(json.GetProperty("count").GetInt32(), 1, 50);
    }

    [Theory]
    [InlineData("' OR '1'='1")]
    [InlineData("x'; DROP TABLE orders; --")]
    public async Task Sql_injection_is_treated_as_plain_data(string payload)
    {
        await using var mcp = await server.McpAsync(server.ReaderKey);
        var json = Json(await mcp.CallToolAsync("search_orders", Args(("customerEmail", payload)), cancellationToken: Ct));
        Assert.Equal(0, json.GetProperty("count").GetInt32());

        var repo = server.Services.GetRequiredService<OrderRepository>();
        Assert.Equal(12, await repo.CountAsync(Ct));
    }

    [Fact]
    public async Task Unknown_status_is_a_clear_tool_error()
    {
        await using var mcp = await server.McpAsync(server.ReaderKey);
        var error = ErrorText(await mcp.CallToolAsync("search_orders", Args(("status", "refunded")), cancellationToken: Ct));
        Assert.Contains("Unknown status", error, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Missing_order_is_a_clear_tool_error()
    {
        await using var mcp = await server.McpAsync(server.ReaderKey);
        var error = ErrorText(await mcp.CallToolAsync("get_order", Args(("orderId", 999)), cancellationToken: Ct));
        Assert.Contains("does not exist", error, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Reader_cannot_call_the_write_tool()
    {
        await using var mcp = await server.McpAsync(server.ReaderKey);
        var denied = false;
        try
        {
            var r = await mcp.CallToolAsync("update_order_status", Args(("orderId", 4), ("newStatus", "paid"), ("reason", "customer paid")), cancellationToken: Ct);
            denied = r.IsError == true;
        }
        catch (McpException)
        {
            denied = true;
        }

        Assert.True(denied);
        Assert.Contains(server.AuditLines, l => l.Contains("client=test-reader tool=update_order_status required_scope=orders.write outcome=forbidden", StringComparison.Ordinal));
        var repo = server.Services.GetRequiredService<OrderRepository>();
        Assert.Empty(await repo.GetAuditAsync(4, Ct));
    }

    [Fact]
    public async Task Writer_moves_status_and_the_change_is_audited_with_the_key_id()
    {
        await using var mcp = await server.McpAsync(server.WriterKey);
        // Seed: order 8 is pending (8 % 4 == 0).
        var json = Json(await mcp.CallToolAsync("update_order_status", Args(("orderId", 8), ("newStatus", "paid"), ("reason", "payment confirmed")), cancellationToken: Ct));
        Assert.Equal("paid", json.GetProperty("status").GetString());

        var audit = await server.Services.GetRequiredService<OrderRepository>().GetAuditAsync(8, Ct);
        var entry = Assert.Single(audit);
        Assert.Equal(("pending", "paid", "test-writer"), (entry.FromStatus, entry.ToStatus, entry.Actor));
    }

    [Fact]
    public async Task Illegal_transition_is_refused()
    {
        await using var mcp = await server.McpAsync(server.WriterKey);
        // Seed: order 3 is delivered (3 % 4 == 3) and cannot go back.
        var error = ErrorText(await mcp.CallToolAsync("update_order_status", Args(("orderId", 3), ("newStatus", "pending"), ("reason", "agent tried to reopen")), cancellationToken: Ct));
        Assert.Contains("cannot move", error, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Write_without_a_reason_is_refused()
    {
        await using var mcp = await server.McpAsync(server.WriterKey);
        var error = ErrorText(await mcp.CallToolAsync("update_order_status", Args(("orderId", 12), ("newStatus", "paid"), ("reason", "")), cancellationToken: Ct));
        Assert.Contains("reason", error, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Every_successful_call_is_audited_with_client_and_outcome()
    {
        await using var mcp = await server.McpAsync(server.ReaderKey);
        await mcp.CallToolAsync("get_order", Args(("orderId", 1)), cancellationToken: Ct);
        Assert.Contains(server.AuditLines, l => l.Contains("client=test-reader tool=get_order outcome=ok", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Client_sent_tool_names_never_reach_logs()
    {
        await using var mcp = await server.McpAsync(server.ReaderKey);
        try
        {
            await mcp.CallToolAsync("not_a_tool injected=1", cancellationToken: Ct);
        }
        catch (McpException)
        {
        }

        Assert.DoesNotContain(server.AuditLines, l => l.Contains("injected", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Email_search_is_case_insensitive()
    {
        await using var mcp = await server.McpAsync(server.ReaderKey);
        var json = Json(await mcp.CallToolAsync("search_orders", Args(("customerEmail", "ANA@Example.com")), cancellationToken: Ct));
        Assert.True(json.GetProperty("count").GetInt32() > 0);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-5)]
    public async Task Limit_below_one_is_refused(int limit)
    {
        await using var mcp = await server.McpAsync(server.ReaderKey);
        Assert.Contains("limit", ErrorText(await mcp.CallToolAsync("search_orders", Args(("limit", limit)), cancellationToken: Ct)), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Reason_with_line_breaks_is_refused()
    {
        await using var mcp = await server.McpAsync(server.WriterKey);
        var error = ErrorText(await mcp.CallToolAsync("update_order_status", Args(("orderId", 12), ("newStatus", "paid"), ("reason", "ok\nactor=admin")), cancellationToken: Ct));
        Assert.Contains("one line", error, StringComparison.Ordinal);
    }
}
