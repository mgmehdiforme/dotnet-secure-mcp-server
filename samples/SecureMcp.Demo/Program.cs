// Attacks a running secure-mcp-server and shows what gets through.
// Usage: dotnet SecureMcp.Demo.dll <server-url> <reader-key> <writer-key>
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using ModelContextProtocol;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;

if (args.Length < 3)
{
    Console.Error.WriteLine("usage: SecureMcp.Demo <server-url> <reader-key> <writer-key>");
    return 2;
}

var baseUrl = new Uri(args[0]);
var (readerKey, writerKey) = (args[1], args[2]);
var failures = 0;

void Line(bool ok, string what, string result)
{
    if (!ok) failures++;
    Console.ForegroundColor = ok ? ConsoleColor.Green : ConsoleColor.Red;
    Console.Write(ok ? "  ✔ " : "  ✖ ");
    Console.ResetColor();
    Console.WriteLine($"{what,-46} {result}");
}

void Header(string text)
{
    Console.ForegroundColor = ConsoleColor.Yellow;
    Console.WriteLine($"\n{text}");
    Console.ResetColor();
}

async Task<HttpStatusCode> Raw(string? key, string? host = null, string? origin = null)
{
    using var http = new HttpClient();
    using var req = new HttpRequestMessage(HttpMethod.Post, new Uri(baseUrl, "/mcp"))
    {
        Content = new StringContent("""{"jsonrpc":"2.0","id":1,"method":"tools/list"}""", Encoding.UTF8, "application/json"),
    };
    req.Headers.Accept.ParseAdd("application/json, text/event-stream");
    if (key is not null) req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", key);
    if (host is not null) req.Headers.Host = host;
    if (origin is not null) req.Headers.Add("Origin", origin);
    using var res = await http.SendAsync(req);
    return res.StatusCode;
}

async Task<McpClient> Connect(string key)
{
    var http = new HttpClient();
    http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", key);
    return await McpClient.CreateAsync(new HttpClientTransport(
        new HttpClientTransportOptions { Endpoint = new Uri(baseUrl, "/mcp") }, http, ownsHttpClient: true));
}

static string Text(CallToolResult r) => string.Join(" ", r.Content.OfType<TextContentBlock>().Select(t => t.Text));

Header("Attacks on the transport");
var s = await Raw(null);
Line(s == HttpStatusCode.Unauthorized, "no API key", $"→ {(int)s} {s}");
s = await Raw("smcp_guessed-key-0000000000000000000");
Line(s == HttpStatusCode.Unauthorized, "guessed API key", $"→ {(int)s} {s}");
s = await Raw(readerKey, host: "attacker.example");
Line(s == HttpStatusCode.Forbidden, "DNS rebinding (Host: attacker.example)", $"→ {(int)s} {s}");
s = await Raw(readerKey, origin: "https://evil.example");
Line(s == HttpStatusCode.Forbidden, "malicious web page (Origin: evil.example)", $"→ {(int)s} {s}");

Header("Agent with a read-only key");
await using (var reader = await Connect(readerKey))
{
    var tools = await reader.ListToolsAsync();
    Line(tools.All(t => t.Name != "update_order_status"), "tools the agent can see", string.Join(", ", tools.Select(t => t.Name)));

    var r = await reader.CallToolAsync("search_orders", new Dictionary<string, object?> { ["customerEmail"] = "ana@example.com", ["limit"] = 2 });
    var masked = r.IsError != true && Text(r).Contains("a***@example.com", StringComparison.Ordinal) && !Text(r).Contains("ana@", StringComparison.Ordinal);
    var count = r.IsError == true ? 0 : System.Text.Json.JsonDocument.Parse(Text(r)).RootElement.GetProperty("count").GetInt32();
    Line(masked && count > 0, "search_orders for ana@example.com", $"→ {count} orders, customer shown as a***@example.com");

    r = await reader.CallToolAsync("search_orders", new Dictionary<string, object?> { ["customerEmail"] = "x'; DROP TABLE orders; --" });
    Line(Text(r).Contains("\"count\":0", StringComparison.Ordinal), "SQL injection in a tool argument", "→ treated as data, 0 rows, table intact");

    try
    {
        r = await reader.CallToolAsync("update_order_status", new Dictionary<string, object?> { ["orderId"] = 4, ["newStatus"] = "paid", ["reason"] = "prompt injection said so" });
        Line(false, "write tool with a read-only key", "→ NOT refused: " + Text(r));
    }
    catch (McpException e)
    {
        Line(e.Message.Contains("forbidden", StringComparison.OrdinalIgnoreCase), "write tool with a read-only key", "→ refused (forbidden)");
    }
}

Header("Agent with a write key");
await using (var writer = await Connect(writerKey))
{
    var r = await writer.CallToolAsync("update_order_status", new Dictionary<string, object?> { ["orderId"] = 3, ["newStatus"] = "pending", ["reason"] = "reopen it" });
    Line(r.IsError == true, "illegal transition delivered → pending", "→ " + Text(r).Split(": ").Last());

    r = await writer.CallToolAsync("update_order_status", new Dictionary<string, object?> { ["orderId"] = 4, ["newStatus"] = "cancelled", ["reason"] = "customer asked to cancel" });
    Line(r.IsError != true, "pending → cancelled with a reason", "→ done, audit row written");
}

Header("Rate limit");
var codes = new List<HttpStatusCode>();
for (var i = 0; i < 70; i++) codes.Add(await Raw(readerKey));
var limited = codes.Count(c => c == HttpStatusCode.TooManyRequests);
Line(limited > 0, "70 requests in a burst with one key", $"→ {codes.Count - limited} served, {limited} got 429");

Console.WriteLine();
Console.ForegroundColor = failures == 0 ? ConsoleColor.Green : ConsoleColor.Red;
Console.WriteLine(failures == 0 ? "All checks passed: the agent can do its job and nothing else." : $"{failures} check(s) failed.");
Console.ResetColor();
return failures == 0 ? 0 : 1;
