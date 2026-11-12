using System.Security.Claims;
using Bam.Logging;
using Bam.Protocol;
using Bam.UserAccounts.Passkeys;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace Bam.UserAccounts.Web;

/// <summary>
/// The JSON endpoints the browser module (and any non-browser client) calls, under
/// <see cref="AccountRoutes.Prefix"/>.  Bodies are the types in <c>AccountWire.cs</c>, camelCase.
/// <para>
/// Every state-changing request must carry the <see cref="AccountRoutes.RequestHeader"/> header,
/// and an <c>Origin</c> header, when the client sends one, must be this site's own or one of
/// <see cref="PasskeyOptions.AllowedOrigins"/>.  The signed-in endpoints take the person from
/// the session cookie and never from the body.
/// </para>
/// </summary>
public static class AccountEndpoints
{
    private const int MaxBodyBytes = 64 * 1024;

    /// <summary>Maps the endpoint group and checks the host's registry (<see cref="AccountWebRegistration.VerifyPrerequisites"/>).</summary>
    /// <param name="routes">The host's endpoint route builder.</param>
    /// <returns>The group, for further conventions.</returns>
    public static RouteGroupBuilder MapPasskeyAccounts(this IEndpointRouteBuilder routes)
    {
        ArgumentNullException.ThrowIfNull(routes);
        AccountWebRegistration.VerifyPrerequisites(routes.ServiceProvider);
        AccountSiteOptions site = routes.ServiceProvider.GetRequiredService<AccountSiteOptions>();

        // The anonymous-access marker lets a host that also runs bam.protocol.aspnetcore's actor
        // middleware pass these routes through; the session cookie, not a bearer token, guards them.
        RouteGroupBuilder group = routes.MapGroup(AccountRoutes.Prefix).WithMetadata(new AnonymousAccessAttribute());
        group.AddEndpointFilter(GuardAsync);

        group.MapPost("/passkey/registration/begin", BeginRegistrationAsync).RequireRateLimiting(AccountRateLimitOptions.AnonymousPolicy);
        group.MapPost("/passkey/registration/complete", CompleteRegistrationAsync).RequireRateLimiting(AccountRateLimitOptions.AnonymousPolicy);
        group.MapPost("/passkey/assertion/begin", BeginAssertionAsync).RequireRateLimiting(AccountRateLimitOptions.AnonymousPolicy);
        group.MapPost("/passkey/assertion/complete", CompleteAssertionAsync).RequireRateLimiting(AccountRateLimitOptions.AnonymousPolicy);
        group.MapPost("/passkey/additional/begin", BeginAdditional).RequireAuthorization(AccountWebRegistration.Policy);
        group.MapPost("/passkey/additional/complete", CompleteAdditionalAsync).RequireAuthorization(AccountWebRegistration.Policy);
        group.MapPost("/signout", SignOutAsync);
        if (site.SignUp.AllowHandleAvailabilityCheck)
        {
            group.MapGet("/handle/{handle}/availability", CheckHandle).RequireRateLimiting(AccountRateLimitOptions.AvailabilityPolicy);
        }
        group.MapGet("/passkeys", ListPasskeys).RequireAuthorization(AccountWebRegistration.Policy);
        group.MapPost("/passkeys/{credentialId}/name", RenameAsync).RequireAuthorization(AccountWebRegistration.Policy);
        group.MapDelete("/passkeys/{credentialId}", RemoveAsync).RequireAuthorization(AccountWebRegistration.Policy);
        group.MapPost("/profile", CompleteProfileAsync).RequireAuthorization(AccountWebRegistration.Policy);
        return group;
    }

    /// <summary>
    /// Whether a request is addressed to these endpoints rather than to a page: it carries the
    /// <see cref="AccountRoutes.RequestHeader"/> header or its path is under one of the endpoint
    /// segments.  An unauthenticated endpoint request is answered with a status, not a redirect.
    /// </summary>
    /// <param name="request">The request.</param>
    public static bool IsEndpointRequest(HttpRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!string.IsNullOrEmpty(request.Headers[AccountRoutes.RequestHeader]))
        {
            return true;
        }
        return request.Path.StartsWithSegments(AccountRoutes.Prefix + "/passkey")
            || request.Path.StartsWithSegments(AccountRoutes.Prefix + "/passkeys")
            || request.Path.StartsWithSegments(AccountRoutes.Prefix + "/signout")
            || request.Path.StartsWithSegments(AccountRoutes.Prefix + "/profile")
            || request.Path.StartsWithSegments(AccountRoutes.Prefix + "/handle");
    }

    private static async ValueTask<object?> GuardAsync(EndpointFilterInvocationContext invocation, EndpointFilterDelegate next)
    {
        HttpRequest request = invocation.HttpContext.Request;
        if (!Microsoft.AspNetCore.Http.HttpMethods.IsGet(request.Method) && !Microsoft.AspNetCore.Http.HttpMethods.IsHead(request.Method))
        {
            AccountSiteOptions site = invocation.HttpContext.RequestServices.GetRequiredService<AccountSiteOptions>();
            PasskeyOptions passkeys = invocation.HttpContext.RequestServices.GetRequiredService<PasskeyOptions>();
            if (string.IsNullOrWhiteSpace(request.Headers[AccountRoutes.RequestHeader]) || !IsOwnOrigin(request, passkeys))
            {
                Log.Warn("Account request to {0} refused: missing {1} header or foreign origin", invocation.HttpContext.GetEndpoint()?.DisplayName ?? "an account endpoint", AccountRoutes.RequestHeader);
                return Refusal(StatusCodes.Status403Forbidden, AccountErrorCodes.RequestRefused, site.Strings.ActionFailedMessage);
            }
        }
        return await next(invocation);
    }

    private static bool IsOwnOrigin(HttpRequest request, PasskeyOptions passkeys)
    {
        string? origin = request.Headers.Origin;
        if (string.IsNullOrEmpty(origin))
        {
            // Browsers send Origin on every cross-site POST and DELETE; a client that sends none is not a browser.
            return true;
        }
        string own = request.Scheme + "://" + request.Host.Value;
        return string.Equals(origin, own, StringComparison.OrdinalIgnoreCase) || passkeys.IsOriginAllowed(origin);
    }

    private static async Task<IResult> BeginRegistrationAsync(HttpContext context, IPasskeySignUp signUp, AccountSiteOptions site)
    {
        PasskeySignUpRequest? request = await ReadAsync<PasskeySignUpRequest>(context.Request);
        if (request is null)
        {
            return BadRequest(site);
        }
        PasskeySignUpBeginResult begun = signUp.Begin(request);
        if (!begun.Success || begun.Options is null)
        {
            return SignUpRefused(begun.Refusal, site);
        }
        return Json(new CreationOptionsResponse { Options = begun.Options });
    }

    private static async Task<IResult> CompleteRegistrationAsync(HttpContext context, IPasskeySignUp signUp, AccountSession session, AccountSiteOptions site)
    {
        RegistrationCompleteRequest? body = await ReadAsync<RegistrationCompleteRequest>(context.Request);
        if (body is null || body.Credential is null)
        {
            return BadRequest(site);
        }
        PasskeySignUpRequest request = new PasskeySignUpRequest { Handle = body.Handle, DisplayName = body.DisplayName, Email = body.Email, InviteCode = body.InviteCode };
        PasskeySignUpResult result = signUp.Complete(request, body.Credential);
        ClaimsPrincipal? principal = AccountPrincipal.From(result);
        if (principal is null)
        {
            return SignUpRefused(result.Refusal, site);
        }
        await session.SignInAsync(context, principal);
        return Json(new SignedInResponse
        {
            Handle = AccountPrincipal.Handle(principal)!,
            DisplayName = AccountPrincipal.DisplayName(principal)!,
            NextUrl = AccountRoutes.LocalOr(result.NextUrl, site.DefaultReturnUrl),
            ProfileCreated = result.ProfileCreated
        });
    }

    private static async Task<IResult> BeginAssertionAsync(HttpContext context, IPasskeyCeremony ceremony, AccountSiteOptions site)
    {
        AssertionBeginRequest? body = await ReadAsync<AssertionBeginRequest>(context.Request);
        if (body is null)
        {
            return BadRequest(site);
        }
        // A handle-scoped ceremony lists the handle's passkeys, which says the handle exists. A
        // host that keeps handles private gets a discoverable ceremony whatever was sent.
        string handle = site.SignUp.AllowHandleAvailabilityCheck ? SignUpPolicy.NormalizeHandle(body.Handle) : string.Empty;
        PasskeyRequestOptions options = ceremony.BeginAssertion(handle.Length == 0 ? null : handle);
        return Json(new RequestOptionsResponse { Options = options, CeremonyId = options.CeremonyId ?? string.Empty });
    }

    private static async Task<IResult> CompleteAssertionAsync(HttpContext context, IPasskeyCeremony ceremony, AccountSession session, AccountSiteOptions site)
    {
        AssertionCompleteRequest? body = await ReadAsync<AssertionCompleteRequest>(context.Request);
        if (body is null || body.Credential is null)
        {
            return BadRequest(site);
        }
        PasskeyAssertionResponse response = body.Credential with { CeremonyId = string.IsNullOrEmpty(body.CeremonyId) ? body.Credential.CeremonyId : body.CeremonyId };
        PasskeySignInResult result = ceremony.CompleteAssertion(response);
        ClaimsPrincipal? principal = AccountPrincipal.From(result);
        if (principal is null)
        {
            // One code and one message for every cause: the response never says which check failed.
            return Refusal(StatusCodes.Status400BadRequest, AccountErrorCodes.SignInFailed, site.Strings.SignInFailedMessage);
        }
        await session.SignInAsync(context, principal);
        return Json(new SignedInResponse
        {
            Handle = AccountPrincipal.Handle(principal)!,
            DisplayName = AccountPrincipal.DisplayName(principal)!,
            NextUrl = AccountRoutes.LocalOr(body.ReturnUrl, site.DefaultReturnUrl)
        });
    }

    private static IResult BeginAdditional(HttpContext context, IPasskeyCeremony ceremony)
    {
        string handle = AccountPrincipal.Handle(context.User)!;
        PasskeyCreationOptions options = ceremony.BeginAdditionalRegistration(handle, AccountPrincipal.DisplayName(context.User) ?? handle);
        return Json(new CreationOptionsResponse { Options = options });
    }

    private static async Task<IResult> CompleteAdditionalAsync(HttpContext context, IPasskeyCeremony ceremony, IPasskeyInventory inventory, AccountSiteOptions site)
    {
        AdditionalCompleteRequest? body = await ReadAsync<AdditionalCompleteRequest>(context.Request);
        if (body is null || body.Credential is null)
        {
            return BadRequest(site);
        }
        string handle = AccountPrincipal.Handle(context.User)!;
        PasskeyRegistrationResult result = ceremony.CompleteAdditionalRegistration(handle, body.Credential);
        if (!result.Success || string.IsNullOrEmpty(result.CredentialId))
        {
            return Refusal(StatusCodes.Status400BadRequest, AccountErrorCodes.PasskeyNotAdded, site.Strings.ActionFailedMessage);
        }
        if (!string.IsNullOrWhiteSpace(body.Name))
        {
            inventory.Rename(handle, result.CredentialId, body.Name);
        }
        Log.Info("Passkey {0} added for {1}", result.CredentialId, handle);
        return Json(new PasskeyAddedResponse { CredentialId = result.CredentialId });
    }

    private static async Task<IResult> SignOutAsync(HttpContext context, AccountSession session, AccountSiteOptions site)
    {
        await session.SignOutAsync(context);
        return Json(new SignedOutResponse { SignedOut = true, NextUrl = site.SignedOutUrl });
    }

    private static IResult CheckHandle(string handle, IPasskeySignUp signUp)
    {
        HandleAvailability availability = signUp.CheckHandle(handle);
        return Json(new AvailabilityResponse { Handle = availability.Handle, Available = availability.Available, Reason = availability.Reason.ToString() });
    }

    private static IResult ListPasskeys(HttpContext context, IPasskeyInventory inventory)
    {
        string handle = AccountPrincipal.Handle(context.User)!;
        string? current = AccountPrincipal.CredentialId(context.User);
        PasskeyListResponse response = new PasskeyListResponse();
        foreach (PasskeyCredentialData credential in inventory.List(handle).OrderBy(credential => credential.CreatedUtc))
        {
            response.Passkeys.Add(PasskeySummary.Of(credential, current));
        }
        return Json(response);
    }

    private static async Task<IResult> RenameAsync(string credentialId, HttpContext context, IPasskeyInventory inventory, AccountSiteOptions site)
    {
        RenameRequest? body = await ReadAsync<RenameRequest>(context.Request);
        if (body is null)
        {
            return BadRequest(site);
        }
        string handle = AccountPrincipal.Handle(context.User)!;
        if (!inventory.Rename(handle, credentialId, body.Name))
        {
            return Refusal(StatusCodes.Status404NotFound, AccountErrorCodes.NotFound, site.Strings.ActionFailedMessage);
        }
        return Results.NoContent();
    }

    private static async Task<IResult> CompleteProfileAsync(HttpContext context, IPasskeySignUp signUp, AccountSiteOptions site)
    {
        ProfileRequest? body = await ReadAsync<ProfileRequest>(context.Request);
        if (body is null)
        {
            return BadRequest(site);
        }
        string handle = AccountPrincipal.Handle(context.User)!;
        ProfileCompletion completion = signUp.CompleteProfile(handle, body.DisplayName, body.Email);
        switch (completion)
        {
            case ProfileCompletion.Created:
            case ProfileCompletion.AlreadyExists:
                return Results.NoContent();
            case ProfileCompletion.InvalidEmail:
                return Refusal(StatusCodes.Status400BadRequest, AccountErrorCodes.EmailRequired, site.Strings.EmailRequiredMessage);
            default:
                return Refusal(StatusCodes.Status409Conflict, AccountErrorCodes.ProfileNotSaved, site.Strings.ProfileNotSavedMessage);
        }
    }

    private static async Task<IResult> RemoveAsync(string credentialId, HttpContext context, IPasskeyInventory inventory, AccountSession session, AccountSiteOptions site)
    {
        string handle = AccountPrincipal.Handle(context.User)!;
        PasskeyRemoval removal = inventory.Remove(handle, credentialId);
        if (removal == PasskeyRemoval.LastCredential)
        {
            return Refusal(StatusCodes.Status409Conflict, AccountErrorCodes.LastPasskey, site.Strings.LastPasskeyMessage);
        }
        if (removal != PasskeyRemoval.Removed)
        {
            return Refusal(StatusCodes.Status404NotFound, AccountErrorCodes.NotFound, site.Strings.ActionFailedMessage);
        }
        bool wasCurrent = string.Equals(AccountPrincipal.CredentialId(context.User), credentialId, StringComparison.Ordinal);
        if (wasCurrent)
        {
            await session.SignOutAsync(context);
        }
        return Json(new SignedOutResponse { SignedOut = wasCurrent, NextUrl = wasCurrent ? site.SignedOutUrl : null });
    }

    private static IResult SignUpRefused(SignUpRefusal refusal, AccountSiteOptions site)
    {
        AccountStrings strings = site.Strings;
        if (refusal == SignUpRefusal.HandleTaken && !site.SignUp.AllowHandleAvailabilityCheck)
        {
            // A host that treats handles as private never says a handle exists, at any step.
            refusal = SignUpRefusal.CeremonyFailed;
        }
        return refusal switch
        {
            SignUpRefusal.SignUpClosed => Refusal(StatusCodes.Status403Forbidden, AccountErrorCodes.SignUpClosed, strings.SignUpClosed),
            SignUpRefusal.InviteRequired => Refusal(StatusCodes.Status403Forbidden, AccountErrorCodes.InviteRequired, strings.InviteRequiredMessage),
            SignUpRefusal.InvalidHandle => Refusal(StatusCodes.Status400BadRequest, AccountErrorCodes.InvalidHandle, strings.HandleInvalidMessage),
            SignUpRefusal.HandleTaken => Refusal(StatusCodes.Status409Conflict, AccountErrorCodes.HandleTaken, strings.HandleTakenMessage),
            SignUpRefusal.EmailRequired => Refusal(StatusCodes.Status400BadRequest, AccountErrorCodes.EmailRequired, strings.EmailRequiredMessage),
            _ => Refusal(StatusCodes.Status400BadRequest, AccountErrorCodes.SignUpFailed, strings.SignUpFailedMessage)
        };
    }

    private static IResult BadRequest(AccountSiteOptions site)
    {
        return Refusal(StatusCodes.Status400BadRequest, AccountErrorCodes.BadRequest, site.Strings.ActionFailedMessage);
    }

    private static IResult Refusal(int statusCode, string code, string message)
    {
        return Results.Content(PasskeyJson.Serialize(new AccountError { Error = code, Message = message }), "application/json", System.Text.Encoding.UTF8, statusCode);
    }

    private static IResult Json<TBody>(TBody body) where TBody : class
    {
        return Results.Content(PasskeyJson.Serialize(body), "application/json", System.Text.Encoding.UTF8, StatusCodes.Status200OK);
    }

    // Reads a JSON body of at most MaxBodyBytes; null for a missing, oversized, non-JSON or malformed body.
    private static async Task<TBody?> ReadAsync<TBody>(HttpRequest request) where TBody : class
    {
        if (request.ContentType is null || !request.ContentType.StartsWith("application/json", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }
        if (request.ContentLength is long declared && declared > MaxBodyBytes)
        {
            return null;
        }
        using MemoryStream buffer = new MemoryStream();
        byte[] chunk = new byte[8192];
        int read;
        while ((read = await request.Body.ReadAsync(chunk.AsMemory(0, chunk.Length), request.HttpContext.RequestAborted)) > 0)
        {
            if (buffer.Length + read > MaxBodyBytes)
            {
                return null;
            }
            buffer.Write(chunk, 0, read);
        }
        if (buffer.Length == 0)
        {
            return null;
        }
        try
        {
            return PasskeyJson.Deserialize<TBody>(buffer.ToArray());
        }
        catch (PasskeyFormatException)
        {
            return null;
        }
    }
}
