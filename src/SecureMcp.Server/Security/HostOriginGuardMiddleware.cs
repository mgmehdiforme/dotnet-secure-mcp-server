using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.Options;

namespace SecureMcp.Server.Security;

/// <summary>
/// Blocks DNS rebinding and cross-site requests before anything else runs.
/// A web page that rebinds its domain to 127.0.0.1 still sends its own name in the Host header,
/// and a browser always sends the page's Origin. Both are checked against allow-lists.
/// Also caps the request body size.
/// </summary>
public sealed class HostOriginGuardMiddleware(
    RequestDelegate next,
    IOptionsMonitor<McpSecurityOptions> options,
    ILogger<HostOriginGuardMiddleware> logger)
{
    public async Task InvokeAsync(HttpContext context)
    {
        var o = options.CurrentValue;

        var host = context.Request.Host.Host;
        if (string.IsNullOrEmpty(host) || !o.AllowedHosts.Contains(host, StringComparer.OrdinalIgnoreCase))
        {
            logger.LogWarning("Blocked request with Host {Host}: not in AllowedHosts (possible DNS rebinding)", Sanitize(host));
            await Reject(context, StatusCodes.Status403Forbidden, "host_not_allowed", "This server does not answer to that host name.");
            return;
        }

        var origin = context.Request.Headers.Origin.ToString();
        if (origin.Length > 0 && !o.AllowedOrigins.Contains(origin, StringComparer.OrdinalIgnoreCase))
        {
            logger.LogWarning("Blocked request with Origin {Origin}: not in AllowedOrigins", Sanitize(origin));
            await Reject(context, StatusCodes.Status403Forbidden, "origin_not_allowed", "Cross-site requests are not allowed.");
            return;
        }

        if (context.Request.ContentLength > o.MaxRequestBodyBytes)
        {
            await Reject(context, StatusCodes.Status413PayloadTooLarge, "payload_too_large", "Request body is too large.");
            return;
        }

        var sizeFeature = context.Features.Get<IHttpMaxRequestBodySizeFeature>();
        if (sizeFeature is { IsReadOnly: false })
        {
            sizeFeature.MaxRequestBodySize = o.MaxRequestBodyBytes;
        }

        await next(context);
    }

    private static Task Reject(HttpContext context, int status, string error, string message)
    {
        context.Response.StatusCode = status;
        return context.Response.WriteAsJsonAsync(new { error, message });
    }

    // Header values are attacker-controlled: keep log lines short and single-line.
    private static string Sanitize(string value) =>
        new string(value.Take(100).Select(c => char.IsControl(c) ? '?' : c).ToArray());
}
