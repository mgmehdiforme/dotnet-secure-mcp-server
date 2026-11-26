using System.Security.Claims;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using OpenTelemetry;
using OpenTelemetry.Metrics;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;
using SecureMcp.Server.Data;
using SecureMcp.Server.Observability;
using SecureMcp.Server.Security;
using SecureMcp.Server.Tools;

// `dotnet run -- new-key <client-id> [scopes...]` prints a fresh key and the hash to configure.
if (args is ["new-key", ..])
{
    return KeyCommand.Run(args[1..]);
}

var builder = WebApplication.CreateBuilder(args);

// ---- Security options: fail fast at startup if they are missing or malformed ----
builder.Services.AddOptions<McpSecurityOptions>()
    .Bind(builder.Configuration.GetSection(McpSecurityOptions.Section))
    .ValidateDataAnnotations()
    .ValidateOnStart();
builder.Services.AddSingleton<IValidateOptions<McpSecurityOptions>, KeyEntriesValidator>();
builder.Services.AddSingleton<ApiKeyStore>();

// ---- AuthN / AuthZ: bearer API keys with scopes; every tool declares the scope it needs ----
builder.Services.AddAuthentication(ApiKeyAuthenticationHandler.SchemeName)
    .AddScheme<AuthenticationSchemeOptions, ApiKeyAuthenticationHandler>(ApiKeyAuthenticationHandler.SchemeName, null);
// Records every refused authorization (for example a read-only key calling a write tool after a prompt injection).
builder.Services.AddSingleton<Microsoft.AspNetCore.Authorization.IAuthorizationService, AuditingAuthorizationService>();
builder.Services.AddAuthorizationBuilder()
    .AddPolicy(Scopes.OrdersRead, p => p.RequireAuthenticatedUser().RequireClaim(Scopes.ClaimType, Scopes.OrdersRead))
    .AddPolicy(Scopes.OrdersWrite, p => p.RequireAuthenticatedUser().RequireClaim(Scopes.ClaimType, Scopes.OrdersWrite));

// ---- Rate limiting: per API key, falling back to per IP before authentication ----
builder.Services.AddRateLimiter(o =>
{
    o.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    o.OnRejected = async (ctx, ct) =>
    {
        var retry = ctx.Lease.TryGetMetadata(MetadataName.RetryAfter, out var after) ? Math.Max(1, (int)Math.Ceiling(after.TotalSeconds)) : 60;
        ctx.HttpContext.Response.Headers.RetryAfter = retry.ToString(System.Globalization.CultureInfo.InvariantCulture);
        ctx.HttpContext.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("SecureMcp.Audit").LogWarning(
            "audit rate_limited client={Client}", ctx.HttpContext.User.FindFirstValue(ClaimTypes.NameIdentifier) ?? $"ip:{ctx.HttpContext.Connection.RemoteIpAddress}");
        await ctx.HttpContext.Response.WriteAsJsonAsync(new { error = "rate_limited", message = "Too many requests. Retry later." }, ct);
    };
    o.AddPolicy("per-client", http => RateLimitPartition.GetFixedWindowLimiter(
        http.User.FindFirstValue(ClaimTypes.NameIdentifier) ?? $"ip:{http.Connection.RemoteIpAddress}",
        _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = http.RequestServices.GetRequiredService<IOptionsMonitor<McpSecurityOptions>>().CurrentValue.RequestsPerMinute, Window = TimeSpan.FromMinutes(1),
            QueueLimit = 0,
        }));
});

// ---- Data ----
builder.Services.AddSingleton(sp => new OrderRepository(
    sp.GetRequiredService<IConfiguration>().GetConnectionString("Orders") ?? "Data Source=orders.db"));
builder.Services.AddHttpContextAccessor();

// ---- MCP server: Streamable HTTP, stateless (scales behind a load balancer), tool-level authorization ----
builder.Services.AddMcpServer(o => o.ServerInfo = new() { Name = "secure-orders-mcp", Version = "1.0.0" })
    .WithHttpTransport(o => o.Stateless = true)
    .AddAuthorizationFilters()
    .WithRequestFilters(f => f.AddCallToolFilter(Telemetry.AuditToolCalls(Telemetry.ToolNamesOf<OrderTools>())))
    .WithTools<OrderTools>();


// ---- Observability: traces + metrics over OTLP when OTEL_EXPORTER_OTLP_ENDPOINT is set ----
var otel = builder.Services.AddOpenTelemetry()
    .ConfigureResource(r => r.AddService("secure-mcp-server"))
    .WithTracing(t => t.AddSource(Telemetry.Name).AddAspNetCoreInstrumentation(a => a.Filter = ctx => ctx.Request.Path != "/healthz"))
    .WithMetrics(m => m.AddMeter(Telemetry.Name).AddAspNetCoreInstrumentation());
if (!string.IsNullOrEmpty(builder.Configuration["OTEL_EXPORTER_OTLP_ENDPOINT"]))
{
    otel.UseOtlpExporter();
}

builder.Services.AddHealthChecks();

var app = builder.Build();

await app.Services.GetRequiredService<OrderRepository>().InitializeAsync();

// Order matters: reject rebinding / cross-site / oversized requests before any auth or MCP code runs.
app.UseMiddleware<HostOriginGuardMiddleware>();
app.UseAuthentication();
app.UseRateLimiter();
app.UseAuthorization();

app.MapHealthChecks("/healthz");
app.MapMcp("/mcp").RequireAuthorization().RequireRateLimiting("per-client");

app.Run();
return 0;

public partial class Program;

/// <summary>Validates each API key entry and reports every problem at startup.</summary>
internal sealed class KeyEntriesValidator : IValidateOptions<McpSecurityOptions>
{
    public ValidateOptionsResult Validate(string? name, McpSecurityOptions options)
    {
        var problems = options.KeyProblems().ToList();
        return problems.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(problems);
    }
}
