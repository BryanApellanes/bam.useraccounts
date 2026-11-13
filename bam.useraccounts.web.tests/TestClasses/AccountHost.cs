using System.Net;
using System.Net.Http.Headers;
using System.Text;
using Bam.DependencyInjection;
using Bam.Encryption;
using Bam.Protocol.Data;
using Bam.UserAccounts.Passkeys;
using Bam.UserAccounts.Tests.TestClasses;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Bam.UserAccounts.Web.Tests.TestClasses;

/// <summary>
/// A real host of the account template on a loopback port: the class library's pages, endpoints
/// and static assets over Kestrel, wired the way the README tells a host to wire them, over the
/// in-memory ceremony fixtures.  Requests go through <see cref="HttpClient"/> with cookies handled
/// by hand, because the session cookie is Secure and the test host speaks plain http.
/// </summary>
public sealed class AccountHost : IDisposable
{
    private readonly WebApplication _app;
    private readonly HttpClient _client;
    private volatile CountingReadStream? _lastBody;

    public AccountHost(Action<AccountSiteOptions>? configure = null, Action<ServiceRegistry>? bind = null)
    {
        Fixture = new SignUpFixture();
        Site = new AccountSiteOptions { ProductName = "Lumberjack" };
        Site.RateLimits.PermitLimit = 1000;
        Site.RateLimits.AvailabilityPermitLimit = 1000;
        Site.Cookie.RevalidateEvery = TimeSpan.Zero;
        configure?.Invoke(Site);
        Registry = BindHostServices(new ServiceRegistry(), Fixture);
        // A test's own bindings (a real registrar, the rotation proofs) replace the fixture's.
        bind?.Invoke(Registry);

        WebApplicationBuilder builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = Environments.Development });
        builder.Logging.ClearProviders();
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        builder.Services.AddRazorComponents();
        builder.Services.AddPasskeyAccounts(Registry, Site, PasskeyFixture.DefaultOptions());
        _app = builder.Build();
        // Count what the endpoints read of each body. The count is taken before the endpoint runs,
        // so it is complete by the time the client has the response.
        _app.Use(async (HttpContext context, RequestDelegate next) =>
        {
            CountingReadStream counting = new CountingReadStream(context.Request.Body);
            context.Request.Body = counting;
            _lastBody = counting;
            await next(context);
        });
        _app.UseStaticFiles();
        _app.UsePasskeyAccounts();
        _app.UseAntiforgery();
        _app.MapPasskeyAccounts();
        _app.MapRazorComponents<AccountTestRoot>().AddAdditionalAssemblies(typeof(AccountEndpoints).Assembly);
        _app.StartAsync().GetAwaiter().GetResult();
        BaseUrl = _app.Urls.First();
        _client = new HttpClient(new HttpClientHandler { UseCookies = false, AllowAutoRedirect = false }) { BaseAddress = new Uri(BaseUrl) };
    }

    public SignUpFixture Fixture { get; }
    public AccountSiteOptions Site { get; }
    public ServiceRegistry Registry { get; }
    public string BaseUrl { get; }

    /// <summary>Binds what a host owns: the registrar, the account service, the profile repository and in-memory custody.</summary>
    public static ServiceRegistry BindHostServices(ServiceRegistry registry, SignUpFixture fixture)
    {
        registry.For<IConfirmationChallengeRepository>().UseSingleton(fixture.Passkeys.Challenges);
        registry.For<IPasskeyCredentialRepository>().UseSingleton(fixture.Passkeys.Credentials);
        registry.For<IDetachedSignatureVerifier>().UseSingleton(fixture.Passkeys.SignatureVerifier);
        registry.For<IPublicKeySetRegistrar>().UseSingleton(fixture.Passkeys.Registrar);
        registry.For<IUserAccountService>().UseSingleton(fixture.Accounts);
        registry.For<IProfileRepository>().UseSingleton(fixture.Profiles);
        return registry;
    }

    public AccountReply Get(string path, string? cookie = null)
    {
        return Send(HttpMethod.Get, path, null, cookie, false, null);
    }

    public AccountReply Post<TBody>(string path, TBody body, string? cookie = null, bool withHeader = true, string? origin = null) where TBody : class
    {
        return Send(HttpMethod.Post, path, PasskeyJson.Serialize(body), cookie, withHeader, origin);
    }

    /// <summary>Posts a body as given, with the request header: for the endpoints' body rules.</summary>
    public AccountReply PostRaw(string path, string content, string mediaType, bool chunked = false)
    {
        using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, path);
        request.Content = new StringContent(content, Encoding.UTF8, mediaType);
        request.Headers.Add(AccountRoutes.RequestHeader, "1");
        if (chunked)
        {
            // Chunked transfer sends no Content-Length, so only the streamed cap can stop it.
            request.Headers.TransferEncodingChunked = true;
        }
        return Read(request);
    }

    /// <summary>The bytes the endpoints read from the most recent request's body.</summary>
    public long LastBodyBytesRead => _lastBody?.BytesRead ?? 0;

    public AccountReply Delete(string path, string? cookie = null)
    {
        return Send(HttpMethod.Delete, path, null, cookie, true, null);
    }

    /// <summary>Signs a new person up through the endpoints and returns the complete call's reply.</summary>
    public AccountReply SignUp(string handle, string displayName, SyntheticAuthenticator authenticator, string? origin = null, string? email = null)
    {
        AccountReply begun = Post("/account/passkey/registration/begin", new PasskeySignUpRequest { Handle = handle, DisplayName = displayName, Email = email });
        if (begun.Status != HttpStatusCode.OK)
        {
            return begun;
        }
        byte[] challenge = Base64UrlEncoder.Default.Decode(begun.As<CreationOptionsResponse>().Options.Challenge);
        return Post("/account/passkey/registration/complete", new RegistrationCompleteRequest
        {
            Handle = handle,
            DisplayName = displayName,
            Email = email,
            Credential = authenticator.Register(challenge, origin)
        });
    }

    /// <summary>Signs in through the endpoints and returns the complete call's reply.</summary>
    public AccountReply SignIn(SyntheticAuthenticator authenticator, string? handle, string? returnUrl = null, string? origin = null)
    {
        AccountReply begun = Post("/account/passkey/assertion/begin", new AssertionBeginRequest { Handle = handle });
        if (begun.Status != HttpStatusCode.OK)
        {
            return begun;
        }
        RequestOptionsResponse options = begun.As<RequestOptionsResponse>();
        byte[] challenge = Base64UrlEncoder.Default.Decode(options.Options.Challenge);
        authenticator.SignCount++;
        return Post("/account/passkey/assertion/complete", new AssertionCompleteRequest
        {
            CeremonyId = options.CeremonyId,
            Credential = authenticator.Assert(challenge, null, null, origin),
            ReturnUrl = returnUrl
        });
    }

    public void Dispose()
    {
        _client.Dispose();
        _app.StopAsync().GetAwaiter().GetResult();
        _app.DisposeAsync().AsTask().GetAwaiter().GetResult();
    }

    private AccountReply Send(HttpMethod method, string path, string? json, string? cookie, bool withHeader, string? origin)
    {
        using HttpRequestMessage request = new HttpRequestMessage(method, path);
        if (json is not null)
        {
            request.Content = new StringContent(json, Encoding.UTF8, "application/json");
        }
        if (withHeader)
        {
            request.Headers.Add(AccountRoutes.RequestHeader, "1");
        }
        if (origin is not null)
        {
            request.Headers.Add("Origin", origin);
        }
        if (cookie is not null)
        {
            request.Headers.Add("Cookie", cookie);
        }
        return Read(request);
    }

    private AccountReply Read(HttpRequestMessage request)
    {
        using HttpResponseMessage response = _client.SendAsync(request).GetAwaiter().GetResult();
        string body = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
        string? setCookie = response.Headers.TryGetValues("Set-Cookie", out IEnumerable<string>? values) ? string.Join("\n", values) : null;
        MediaTypeHeaderValue? contentType = response.Content.Headers.ContentType;
        return new AccountReply(response.StatusCode, body, setCookie, response.Headers.Location?.ToString(), contentType?.MediaType);
    }
}

/// <summary>What one request to the test host came back with.</summary>
public sealed record AccountReply(HttpStatusCode Status, string Body, string? SetCookie, string? Location, string? MediaType)
{
    /// <summary>The session cookie as a <c>Cookie</c> header value, or null when none was issued (or it was cleared).</summary>
    public string? SessionCookie
    {
        get
        {
            if (SetCookie is null)
            {
                return null;
            }
            foreach (string line in SetCookie.Split('\n'))
            {
                string pair = line.Split(';')[0].Trim();
                if (pair.StartsWith(".Bam.Account=", StringComparison.Ordinal) && pair.Length > ".Bam.Account=".Length)
                {
                    return pair;
                }
            }
            return null;
        }
    }

    /// <summary>Whether the response cleared the session cookie.</summary>
    public bool ClearsSession => SetCookie is not null && SetCookie.Split('\n').Any(line => line.StartsWith(".Bam.Account=;", StringComparison.Ordinal));

    public TBody As<TBody>() where TBody : class
    {
        return PasskeyJson.Deserialize<TBody>(System.Text.Encoding.UTF8.GetBytes(Body));
    }

    public string? ErrorCode => MediaType == "application/json" && Body.Contains("\"error\"", StringComparison.Ordinal) ? As<AccountError>().Error : null;
}
