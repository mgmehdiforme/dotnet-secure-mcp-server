using System.Net;
using System.Text;

namespace SecureMcp.Tests;

/// <summary>Attacks that must be stopped before the MCP layer runs.</summary>
public sealed class TransportSecurityTests(ServerFactory server) : IClassFixture<ServerFactory>
{
    private static HttpRequestMessage ListTools(string url = "/mcp") => new(HttpMethod.Post, url)
    {
        Content = new StringContent("""{"jsonrpc":"2.0","id":1,"method":"tools/list"}""", Encoding.UTF8, "application/json"),
        Headers = { { "Accept", "application/json, text/event-stream" } },
    };

    [Fact]
    public async Task Health_endpoint_needs_no_key()
    {
        var res = await server.Http().GetAsync("/healthz", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
    }

    [Fact]
    public async Task No_key_is_401_with_bearer_challenge()
    {
        var res = await server.Http().SendAsync(ListTools(), TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Unauthorized, res.StatusCode);
        Assert.Contains("Bearer", res.Headers.WwwAuthenticate.ToString(), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("smcp_this-key-was-never-issued-000000000")]
    [InlineData("short")]
    public async Task Unknown_or_malformed_key_is_401(string key)
    {
        var res = await server.Http(key).SendAsync(ListTools(), TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Unauthorized, res.StatusCode);
    }

    [Fact]
    public async Task Basic_auth_scheme_is_rejected()
    {
        var http = server.Http();
        http.DefaultRequestHeaders.Authorization = new("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes("a:" + server.ReaderKey)));
        var res = await http.SendAsync(ListTools(), TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Unauthorized, res.StatusCode);
    }

    [Theory]
    [InlineData("http://attacker.example/mcp")]     // DNS rebinding: attacker's domain now points at 127.0.0.1
    [InlineData("http://192.168.1.20/mcp")]         // unexpected interface / host
    public async Task Rebound_host_is_403_even_with_a_valid_key(string url)
    {
        var res = await server.Http(server.ReaderKey).SendAsync(ListTools(url), TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Forbidden, res.StatusCode);
        Assert.Contains("host_not_allowed", await res.Content.ReadAsStringAsync(TestContext.Current.CancellationToken), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("https://evil.example")]
    [InlineData("null")]
    public async Task Cross_site_origin_is_403_even_with_a_valid_key(string origin)
    {
        var req = ListTools();
        req.Headers.Add("Origin", origin);
        var res = await server.Http(server.ReaderKey).SendAsync(req, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Forbidden, res.StatusCode);
    }

    [Fact]
    public async Task Allowed_origin_passes_the_guard()
    {
        var req = ListTools();
        req.Headers.Add("Origin", "https://app.example.com");
        var res = await server.Http(server.ReaderKey).SendAsync(req, TestContext.Current.CancellationToken);
        Assert.NotEqual(HttpStatusCode.Forbidden, res.StatusCode);
        Assert.NotEqual(HttpStatusCode.Unauthorized, res.StatusCode);
    }

    [Fact]
    public async Task Oversized_body_is_413()
    {
        var req = ListTools();
        req.Content = new StringContent(new string('x', 70_000), Encoding.UTF8, "application/json");
        var res = await server.Http(server.ReaderKey).SendAsync(req, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, res.StatusCode);
    }
}

public sealed class RateLimitTests
{
    [Fact]
    public async Task Requests_over_the_per_key_limit_get_429_with_retry_after()
    {
        await using var server = new ServerFactory { RequestsPerMinute = 3 };
        var http = server.Http(server.ReaderKey);
        var codes = new List<HttpStatusCode>();
        for (var i = 0; i < 5; i++)
        {
            var req = new HttpRequestMessage(HttpMethod.Post, "/mcp")
            {
                Content = new StringContent("""{"jsonrpc":"2.0","id":1,"method":"tools/list"}""", Encoding.UTF8, "application/json"),
                Headers = { { "Accept", "application/json, text/event-stream" } },
            };
            var res = await http.SendAsync(req, TestContext.Current.CancellationToken);
            codes.Add(res.StatusCode);
            if (res.StatusCode == HttpStatusCode.TooManyRequests)
            {
                Assert.True(res.Headers.Contains("Retry-After"));
            }
        }

        Assert.DoesNotContain(HttpStatusCode.TooManyRequests, codes.Take(3));
        Assert.Equal(HttpStatusCode.TooManyRequests, codes[3]);
        Assert.Equal(HttpStatusCode.TooManyRequests, codes[4]);
    }

    [Fact]
    public async Task One_noisy_client_does_not_rate_limit_another()
    {
        await using var server = new ServerFactory { RequestsPerMinute = 2 };
        var reader = server.Http(server.ReaderKey);
        for (var i = 0; i < 3; i++)
        {
            await reader.GetAsync("/mcp", TestContext.Current.CancellationToken);
        }

        var req = new HttpRequestMessage(HttpMethod.Post, "/mcp")
        {
            Content = new StringContent("""{"jsonrpc":"2.0","id":1,"method":"tools/list"}""", Encoding.UTF8, "application/json"),
            Headers = { { "Accept", "application/json, text/event-stream" } },
        };
        var res = await server.Http(server.WriterKey).SendAsync(req, TestContext.Current.CancellationToken);
        Assert.NotEqual(HttpStatusCode.TooManyRequests, res.StatusCode);
    }
}
