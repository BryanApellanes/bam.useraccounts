using System.Threading.RateLimiting;
using Bam.DependencyInjection;
using Bam.Protocol.Data;
using Bam.UserAccounts.Passkeys;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.DependencyInjection;

namespace Bam.UserAccounts.Web;

/// <summary>
/// Host wiring for the passkey account template: one call to register it, one to add its
/// middleware, and <see cref="AccountEndpoints.MapPasskeyAccounts"/> to map its endpoints.  The
/// bam <see cref="ServiceRegistry"/> stays the owner of every account service; ASP.NET Core's
/// container resolves them from it, so nothing is registered twice.
/// </summary>
public static class AccountWebRegistration
{
    /// <summary>The authorization policy the signed-in endpoints and the manage page require.</summary>
    public const string Policy = "Bam.Account";

    /// <summary>
    /// Registers the account template.  The registry must already bind what the host owns: an
    /// <see cref="IPublicKeySetRegistrar"/>, an <see cref="IUserAccountService"/> and an
    /// <see cref="IProfileRepository"/> (and whatever the persisted passkey and challenge
    /// repositories need, unless the host binds its own).
    /// </summary>
    /// <param name="services">The host's service collection.</param>
    /// <param name="registry">The host's bam registry.</param>
    /// <param name="site">Branding, cookie, rate-limit and sign-up settings.</param>
    /// <param name="passkeys">The relying party: id, name and allowed origins.</param>
    /// <returns>The service collection.</returns>
    public static IServiceCollection AddPasskeyAccounts(this IServiceCollection services, ServiceRegistry registry, AccountSiteOptions site, PasskeyOptions passkeys)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(registry);
        ArgumentNullException.ThrowIfNull(site);
        ArgumentNullException.ThrowIfNull(passkeys);
        site.Validate();
        registry.AddPasskeys(passkeys).AddPasskeySignUp(site.SignUp);

        services.AddSingleton(site);
        services.AddSingleton(passkeys);
        services.AddSingleton(new AccountRegistry(registry));
        services.AddTransient<IPasskeySignUp>(_ => registry.Get<IPasskeySignUp>());
        services.AddTransient<IPasskeyCeremony>(_ => registry.Get<IPasskeyCeremony>());
        services.AddTransient<IPasskeyInventory>(_ => registry.Get<IPasskeyInventory>());
        services.AddTransient<IPasskeyCredentialRepository>(_ => registry.Get<IPasskeyCredentialRepository>());
        services.AddScoped<AccountSession>();

        services.AddAuthentication(options => options.DefaultScheme ??= AccountCookieOptions.Scheme)
            .AddCookie(AccountCookieOptions.Scheme, options => ConfigureCookie(options, site));
        services.AddAuthorization(options => options.AddPolicy(Policy, policy => policy
            .AddAuthenticationSchemes(AccountCookieOptions.Scheme)
            .RequireAuthenticatedUser()
            .RequireClaim(AccountClaims.Handle)
            .RequireClaim(AccountClaims.CredentialId)));
        services.AddCascadingAuthenticationState();
        services.AddRateLimiter(options => ConfigureRateLimiter(options, site.RateLimits));
        return services;
    }

    /// <summary>
    /// Adds the rate limiter, authentication and authorization middleware, in that order, after
    /// checking the registry (see <see cref="VerifyPrerequisites"/>).  Call it after
    /// <c>UseForwardedHeaders</c> on a host behind a proxy, so limits are per visitor.
    /// </summary>
    /// <param name="app">The host's pipeline.</param>
    /// <returns>The pipeline.</returns>
    public static IApplicationBuilder UsePasskeyAccounts(this IApplicationBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);
        VerifyPrerequisites(app.ApplicationServices);
        app.UseRateLimiter();
        app.UseAuthentication();
        app.UseAuthorization();
        return app;
    }

    /// <summary>
    /// Throws <see cref="InvalidOperationException"/> listing every bam binding the account
    /// template needs and cannot resolve, so a host learns of all of them at startup instead of
    /// one per request.
    /// </summary>
    /// <param name="services">The host's built service provider.</param>
    public static void VerifyPrerequisites(IServiceProvider services)
    {
        ArgumentNullException.ThrowIfNull(services);
        AccountRegistry holder = services.GetService<AccountRegistry>()
            ?? throw new InvalidOperationException("Call AddPasskeyAccounts before UsePasskeyAccounts or MapPasskeyAccounts.");
        ServiceRegistry registry = holder.Registry;
        List<string> problems = new List<string>();
        RequireBinding<IPublicKeySetRegistrar>(registry, problems);
        RequireBinding<IUserAccountService>(registry, problems);
        RequireBinding<IProfileRepository>(registry, problems);
        if (problems.Count == 0)
        {
            RequireResolvable<IPasskeyCredentialRepository>(registry, problems);
            RequireResolvable<IPasskeyCeremony>(registry, problems);
            RequireResolvable<IPasskeySignUp>(registry, problems);
            RequireResolvable<IPasskeyInventory>(registry, problems);
        }
        if (problems.Count > 0)
        {
            throw new InvalidOperationException("The passkey account template cannot start. " + string.Join(" ", problems));
        }
    }

    private static void RequireBinding<TService>(ServiceRegistry registry, List<string> problems)
    {
        if (!registry.Contains<TService>())
        {
            problems.Add($"The ServiceRegistry has no binding for {typeof(TService).Name}.");
        }
    }

    private static void RequireResolvable<TService>(ServiceRegistry registry, List<string> problems)
    {
        try
        {
            if (registry.Get<TService>() is null)
            {
                problems.Add($"The ServiceRegistry resolved {typeof(TService).Name} to null.");
            }
        }
        catch (Exception e)
        {
            problems.Add($"The ServiceRegistry cannot construct {typeof(TService).Name}: {e.GetBaseException().Message}");
        }
    }

    private static void ConfigureCookie(CookieAuthenticationOptions options, AccountSiteOptions site)
    {
        options.Cookie.Name = site.Cookie.CookieName;
        options.Cookie.HttpOnly = true;
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        options.Cookie.SameSite = site.Cookie.SameSite;
        options.Cookie.IsEssential = true;
        options.ExpireTimeSpan = site.Cookie.SessionLifetime;
        options.SlidingExpiration = site.Cookie.SlidingExpiration;
        options.LoginPath = AccountRoutes.SignIn;
        options.AccessDeniedPath = AccountRoutes.SignIn;
        options.ReturnUrlParameter = "returnUrl";
        options.Events.OnValidatePrincipal = context => context.HttpContext.RequestServices.GetRequiredService<AccountSession>().ValidateAsync(context);
        options.Events.OnRedirectToLogin = context => RedirectOrRefuse(context, StatusCodes.Status401Unauthorized);
        options.Events.OnRedirectToAccessDenied = context => RedirectOrRefuse(context, StatusCodes.Status403Forbidden);
    }

    // A page request is sent to the sign-in page; an endpoint request (the browser module or a
    // native client) gets a status it can read instead of a redirect to HTML.
    private static Task RedirectOrRefuse(RedirectContext<CookieAuthenticationOptions> context, int statusCode)
    {
        if (AccountEndpoints.IsEndpointRequest(context.Request))
        {
            context.Response.StatusCode = statusCode;
            return Task.CompletedTask;
        }
        context.Response.Redirect(context.RedirectUri);
        return Task.CompletedTask;
    }

    private static void ConfigureRateLimiter(RateLimiterOptions options, AccountRateLimitOptions limits)
    {
        options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
        options.AddPolicy(AccountRateLimitOptions.AnonymousPolicy, context => Partition(context, limits, limits.PermitLimit));
        options.AddPolicy(AccountRateLimitOptions.AvailabilityPolicy, context => Partition(context, limits, limits.AvailabilityPermitLimit));
    }

    private static RateLimitPartition<string> Partition(HttpContext context, AccountRateLimitOptions limits, int permitLimit)
    {
        if (!limits.Enabled)
        {
            return RateLimitPartition.GetNoLimiter("unlimited");
        }
        string client = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        return RateLimitPartition.GetFixedWindowLimiter(client, _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = permitLimit,
            Window = limits.Window,
            QueueLimit = 0,
            AutoReplenishment = true
        });
    }
}

/// <summary>Carries the host's bam registry through ASP.NET Core's container to <see cref="AccountWebRegistration.VerifyPrerequisites"/>.</summary>
internal sealed class AccountRegistry
{
    public AccountRegistry(ServiceRegistry registry)
    {
        Registry = registry;
    }

    public ServiceRegistry Registry { get; }
}
