using System.Net.Http.Headers;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using System.Collections.Concurrent;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using ModelContextProtocol.Client;
using SecureMcp.Server.Security;

namespace SecureMcp.Tests;

/// <summary>Runs the real server in memory with two freshly generated keys and a throwaway database.</summary>
public sealed class ServerFactory : WebApplicationFactory<Program>
{
    public string ReaderKey { get; } = ApiKeys.NewKey();
    public string WriterKey { get; } = ApiKeys.NewKey();
    public int RequestsPerMinute { get; init; } = 1000;

    /// <summary>Every "SecureMcp.Audit" log line the server wrote.</summary>
    public ConcurrentQueue<string> AuditLines { get; } = new();
    private readonly string _dbPath = Path.Combine(Path.GetTempPath(), $"secure-mcp-test-{Guid.NewGuid():N}.db");

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");
        builder.ConfigureServices(s => s.AddSingleton<ILoggerProvider>(new CaptureProvider(AuditLines)));
        builder.ConfigureAppConfiguration(c => c.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["ConnectionStrings:Orders"] = $"Data Source={_dbPath};Pooling=False",
            ["McpSecurity:AllowedOrigins:0"] = "https://app.example.com",
            ["McpSecurity:RequestsPerMinute"] = RequestsPerMinute.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["McpSecurity:ApiKeys:0:Id"] = "test-reader",
            ["McpSecurity:ApiKeys:0:Sha256"] = ApiKeys.HashHex(ReaderKey),
            ["McpSecurity:ApiKeys:0:Scopes:0"] = Scopes.OrdersRead,
            ["McpSecurity:ApiKeys:1:Id"] = "test-writer",
            ["McpSecurity:ApiKeys:1:Sha256"] = ApiKeys.HashHex(WriterKey),
            ["McpSecurity:ApiKeys:1:Scopes:0"] = Scopes.OrdersRead,
            ["McpSecurity:ApiKeys:1:Scopes:1"] = Scopes.OrdersWrite,
        }));
    }

    public HttpClient Http(string? key = null)
    {
        var client = CreateClient();
        if (key is not null)
        {
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", key);
        }
        return client;
    }

    public async Task<McpClient> McpAsync(string key)
    {
        var http = Http(key);
        var transport = new HttpClientTransport(
            new HttpClientTransportOptions { Endpoint = new Uri(http.BaseAddress!, "/mcp") },
            http, NullLoggerFactory.Instance, ownsHttpClient: true);
        return await McpClient.CreateAsync(transport, cancellationToken: TestContext.Current.CancellationToken);
    }

    public override async ValueTask DisposeAsync()
    {
        await base.DisposeAsync();
        foreach (var f in new[] { _dbPath, _dbPath + "-wal", _dbPath + "-shm" })
        {
            try { File.Delete(f); } catch (IOException) { }
        }
    }
}

internal sealed class CaptureProvider(ConcurrentQueue<string> lines) : ILoggerProvider
{
    public ILogger CreateLogger(string categoryName) => categoryName == "SecureMcp.Audit" ? new Capture(lines) : Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance;

    public void Dispose() { }

    private sealed class Capture(ConcurrentQueue<string> lines) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
            lines.Enqueue(formatter(state, exception));
    }
}
