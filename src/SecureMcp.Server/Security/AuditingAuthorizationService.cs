using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Infrastructure;
using Microsoft.Extensions.Options;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using SecureMcp.Server.Observability;

namespace SecureMcp.Server.Security;

/// <summary>
/// The standard ASP.NET Core authorization service, plus one audit line and one metric for every refusal.
/// The MCP SDK checks tool scopes before any tool filter runs, so this is where refused tool calls become visible.
/// </summary>
public sealed class AuditingAuthorizationService(
    IAuthorizationPolicyProvider policyProvider,
    IAuthorizationHandlerProvider handlers,
    ILogger<DefaultAuthorizationService> logger,
    IAuthorizationHandlerContextFactory contextFactory,
    IAuthorizationEvaluator evaluator,
    IOptions<AuthorizationOptions> options,
    ILoggerFactory loggerFactory)
    : DefaultAuthorizationService(policyProvider, handlers, logger, contextFactory, evaluator, options)
{
    private static readonly IReadOnlySet<string> KnownTools = Telemetry.ToolNamesOf<Tools.OrderTools>();
    private readonly ILogger _audit = loggerFactory.CreateLogger("SecureMcp.Audit");

    public override async Task<AuthorizationResult> AuthorizeAsync(ClaimsPrincipal user, object? resource, IEnumerable<IAuthorizationRequirement> requirements)
    {
        var list = requirements as IReadOnlyCollection<IAuthorizationRequirement> ?? requirements.ToList();
        var result = await base.AuthorizeAsync(user, resource, list);
        // tools/list also runs this check to hide tools a key can't use; that is not an attempt, so only tool calls are audited.
        if (!result.Succeeded && resource is RequestContext<CallToolRequestParams> call)
        {
            var requested = call.Params?.Name;
            var tool = requested is not null && KnownTools.Contains(requested) ? requested : "unknown_tool";
            var scopes = list.OfType<ClaimsAuthorizationRequirement>()
                .Where(r => r.ClaimType == Scopes.ClaimType)
                .SelectMany(r => r.AllowedValues ?? [])
                .ToArray();
            var required = scopes.Length > 0 ? string.Join("|", scopes) : "authenticated";
            Telemetry.RecordForbidden(tool, required);
            _audit.LogWarning("audit tool_call client={Client} tool={Tool} required_scope={Scope} outcome={Outcome}",
                user.FindFirstValue(ClaimTypes.NameIdentifier) ?? "anonymous", tool, required, "forbidden");
        }
        return result;
    }
}
