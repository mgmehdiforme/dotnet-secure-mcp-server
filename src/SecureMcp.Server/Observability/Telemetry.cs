using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Security.Claims;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

namespace SecureMcp.Server.Observability;

/// <summary>One trace span, two metrics and one audit log line per tool call. Arguments are never logged: they can hold personal data.</summary>
public static class Telemetry
{
    public const string Name = "SecureMcp";
    public static readonly ActivitySource Source = new(Name);
    private static readonly Meter Meter = new(Name);
    private static readonly Counter<long> Calls = Meter.CreateCounter<long>("mcp.tool.calls", description: "Tool calls by tool and outcome");
    private static readonly Histogram<double> Duration = Meter.CreateHistogram<double>("mcp.tool.duration", "ms", "Tool call duration");

    /// <summary>The tool names declared on a tool type, so client-sent names never become log fields or metric tags.</summary>
    public static IReadOnlySet<string> ToolNamesOf<T>() =>
        typeof(T).GetMethods()
            .Select(m => m.GetCustomAttributes(typeof(McpServerToolAttribute), false).OfType<McpServerToolAttribute>().FirstOrDefault()?.Name)
            .OfType<string>()
            .ToHashSet(StringComparer.Ordinal);

    public static McpRequestFilter<CallToolRequestParams, CallToolResult> AuditToolCalls(IReadOnlySet<string> knownTools) => next => async (context, cancellationToken) =>
    {
        var requested = context.Params?.Name;
        var tool = requested is not null && knownTools.Contains(requested) ? requested : "unknown_tool";
        var caller = context.User?.FindFirstValue(ClaimTypes.NameIdentifier) ?? "anonymous";
        var log = context.Services?.GetService<ILoggerFactory>()?.CreateLogger("SecureMcp.Audit");

        using var activity = Source.StartActivity($"mcp.tool {tool}");
        activity?.SetTag("mcp.tool.name", tool);
        activity?.SetTag("mcp.client.id", caller);

        var started = Stopwatch.GetTimestamp();
        var outcome = "error";
        try
        {
            var result = await next(context, cancellationToken);
            outcome = result.IsError == true ? "tool_error" : "ok";
            return result;
        }
        catch (ModelContextProtocol.McpException)
        {
            outcome = "rejected"; // input validation or business rule: the model gets the message
            throw;
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            outcome = "failed"; // unexpected: the client only sees a generic error
            throw;
        }
        finally
        {
            var ms = Stopwatch.GetElapsedTime(started).TotalMilliseconds;
            var tags = new TagList { { "tool", tool }, { "outcome", outcome } };
            Calls.Add(1, tags);
            Duration.Record(ms, tags);
            activity?.SetTag("mcp.tool.outcome", outcome);
            log?.LogInformation("audit tool_call client={Client} tool={Tool} outcome={Outcome} duration_ms={DurationMs:F1}", caller, tool, outcome, ms);
        }
    };

    /// <summary>Refused calls count in the same metric as all other calls, with outcome "forbidden".</summary>
    public static void RecordForbidden(string tool, string requiredScope) =>
        Calls.Add(1, new TagList { { "tool", tool }, { "outcome", "forbidden" }, { "required_scope", requiredScope } });
}
