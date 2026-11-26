using Microsoft.Extensions.Options;
using SecureMcp.Server.Data;
using SecureMcp.Server.Security;
using SecureMcp.Server.Tools;

namespace SecureMcp.Tests;

public sealed class UnitTests
{
    [Fact]
    public void Generated_keys_are_unique_prefixed_and_only_match_their_own_hash()
    {
        var a = ApiKeys.NewKey();
        var b = ApiKeys.NewKey();
        Assert.NotEqual(a, b);
        Assert.StartsWith(ApiKeys.Prefix, a, StringComparison.Ordinal);
        Assert.True(a.Length >= 40);

        var options = new McpSecurityOptions
        {
            ApiKeys = [new ApiKeyEntry { Id = "a", Sha256 = ApiKeys.HashHex(a), Scopes = [Scopes.OrdersRead] }],
        };
        var store = new ApiKeyStore(new StaticMonitor(options));
        Assert.Equal("a", store.Find(a)?.Id);
        Assert.Null(store.Find(b));
    }

    [Theory]
    [InlineData("ana@example.com", "a***@example.com")]
    [InlineData("@example.com", "***")]
    [InlineData("not-an-email", "***")]
    public void Emails_are_masked(string input, string expected) => Assert.Equal(expected, Pii.MaskEmail(input));

    [Theory]
    [InlineData("pending", "paid", true)]
    [InlineData("paid", "shipped", true)]
    [InlineData("shipped", "delivered", true)]
    [InlineData("delivered", "pending", false)]
    [InlineData("cancelled", "paid", false)]
    [InlineData("pending", "delivered", false)]
    public void Only_forward_transitions_are_allowed(string from, string to, bool allowed) =>
        Assert.Equal(allowed, OrderStatus.CanMove(from, to));

    [Fact]
    public void Server_refuses_to_start_without_api_keys()
    {
        using var factory = new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactory<Program>()
            .WithWebHostBuilder(b => b.UseSetting("ConnectionStrings:Orders", "Data Source=:memory:"));
        var ex = Assert.ThrowsAny<Exception>(() => factory.CreateClient());
        Assert.Contains("No API keys configured", ex.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void Server_refuses_to_start_with_an_unknown_scope()
    {
        using var factory = new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactory<Program>()
            .WithWebHostBuilder(b => b
                .UseSetting("ConnectionStrings:Orders", "Data Source=:memory:")
                .UseSetting("McpSecurity:ApiKeys:0:Id", "x")
                .UseSetting("McpSecurity:ApiKeys:0:Sha256", new string('a', 64))
                .UseSetting("McpSecurity:ApiKeys:0:Scopes:0", "admin.everything"));
        var ex = Assert.ThrowsAny<Exception>(() => factory.CreateClient());
        Assert.Contains("known scope", ex.ToString(), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("x", "replace-with-the-64-char-sha256-from-new-key", "64 hex characters")]
    [InlineData("x", "abc123", "64 hex characters")]
    [InlineData("bad id", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "Id must be")]
    public void Server_refuses_to_start_with_a_malformed_key_entry(string id, string hash, string expected)
    {
        using var factory = new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactory<Program>()
            .WithWebHostBuilder(b => b
                .UseSetting("ConnectionStrings:Orders", "Data Source=:memory:")
                .UseSetting("McpSecurity:ApiKeys:0:Id", id)
                .UseSetting("McpSecurity:ApiKeys:0:Sha256", hash)
                .UseSetting("McpSecurity:ApiKeys:0:Scopes:0", "orders.read"));
        var ex = Assert.ThrowsAny<Exception>(() => factory.CreateClient());
        Assert.Contains(expected, ex.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void Server_refuses_to_start_with_the_same_hash_twice()
    {
        var hash = new string('b', 64);
        using var factory = new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactory<Program>()
            .WithWebHostBuilder(b => b
                .UseSetting("ConnectionStrings:Orders", "Data Source=:memory:")
                .UseSetting("McpSecurity:ApiKeys:0:Id", "a").UseSetting("McpSecurity:ApiKeys:0:Sha256", hash).UseSetting("McpSecurity:ApiKeys:0:Scopes:0", "orders.read")
                .UseSetting("McpSecurity:ApiKeys:1:Id", "b").UseSetting("McpSecurity:ApiKeys:1:Sha256", hash).UseSetting("McpSecurity:ApiKeys:1:Scopes:0", "orders.write"));
        var ex = Assert.ThrowsAny<Exception>(() => factory.CreateClient());
        Assert.Contains("hashes must be unique", ex.ToString(), StringComparison.Ordinal);
    }
}

internal sealed class StaticMonitor(McpSecurityOptions value) : IOptionsMonitor<McpSecurityOptions>
{
    public McpSecurityOptions CurrentValue => value;

    public McpSecurityOptions Get(string? name) => value;

    public IDisposable? OnChange(Action<McpSecurityOptions, string?> listener) => null;
}
