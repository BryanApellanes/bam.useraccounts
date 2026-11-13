# bam.useraccounts.web

A white-label passkey account template for Blazor hosts: sign-up, sign-in and manage-passkeys pages, the JSON endpoints behind them, a session cookie and a browser module. A visitor picks a handle, creates a passkey and is signed in. The passkey is both their credential and their registered key set.

The decisions live in `bam.useraccounts` (`IPasskeySignUp`, `IPasskeyInventory`, `IPasskeyCeremony`). This library is the web shell over them.

## Wiring a host

```csharp
using Bam.UserAccounts.Passkeys;
using Bam.UserAccounts.Web;

builder.Services.AddRazorComponents();
builder.Services.AddPasskeyAccounts(
    registry,                                        // the host's bam ServiceRegistry
    new AccountSiteOptions { ProductName = "Example" },
    new PasskeyOptions
    {
        RpId = "example.com",
        RpName = "Example",
        AllowedOrigins = new List<string> { "https://example.com" }
    });

WebApplication app = builder.Build();
app.UseForwardedHeaders();                           // behind a proxy, before UsePasskeyAccounts
app.UseStaticFiles();                                // or MapStaticAssets
app.UsePasskeyAccounts();                            // rate limiter, authentication, authorization
app.UseAntiforgery();
app.MapPasskeyAccounts();                            // the JSON endpoints
app.MapRazorComponents<App>().AddAdditionalAssemblies(typeof(AccountEndpoints).Assembly);
```

Add the same assembly to the router in `Routes.razor` (`AdditionalAssemblies="new[] { typeof(AccountEndpoints).Assembly }"`).

The host project must be a web-SDK project (`Microsoft.NET.Sdk.Web`). That is what serves the library's `wwwroot` under `/_content/bam.useraccounts.web/`.

### What the registry must already bind

`AddPasskeyAccounts` calls `AddPasskeys` and `AddPasskeySignUp` on the registry. The host binds the rest before calling it:

- `IPublicKeySetRegistrar`: where the passkey is registered as the person's key set.
- `IUserAccountService`: writes the person profile after the passkey claims the handle.
- `IProfileRepository`: the availability check reads it, so a person without a passkey still counts as taken.
- Whatever `PersistedPasskeyCredentialRepository` and `PersistedConfirmationChallengeRepository` need, unless the host binds its own `IPasskeyCredentialRepository` and `IConfirmationChallengeRepository`.

`UsePasskeyAccounts` and `MapPasskeyAccounts` check this at startup and throw one `InvalidOperationException` naming every binding that is missing.

## Pages

| Path | Page |
|---|---|
| `/account/signup` | Handle, name, optional email, invite code when sign-up is invite-only |
| `/account/signin` | Sign in with a passkey; honours a local `returnUrl` |
| `/account` | Manage passkeys: add, rename, remove, sign out. Requires a session |
| `/account/signedout` | Shown after signing out |

The prefix is fixed. The pages are routable components, so their routes are compiled in.

The pages are static server-rendered and render inside the host's own layout. They don't open a circuit.

The browser module listens on the document rather than binding to page elements, so it keeps working when Blazor's enhanced navigation swaps an account page in. A host that uses `blazor.web.js` should load the module once from `App.razor` as well, so it's there whichever page a visitor arrives on:

```html
<script type="module" src="_content/bam.useraccounts.web/passkeys.js"></script>
```

Loaded that way, the module runs next to content the host didn't write: comments, bios, rendered markdown. So it takes nothing from the page that decides where a request goes or where the browser navigates. The prefix and the request header are constants in the module. It acts only on `data-account-action` elements inside the account shell the pages render, and reads forms only from that shell. It runs nothing off the `/account` pages, runs the account-changing actions (add, rename, remove, profile) only on the manage page, and runs nothing at all on a page that has more than one shell, so markup injected next to the real shell disables the module rather than borrowing it. Don't put account actions in the host's own markup. Before it navigates it checks the target is a local path, by the same rule the server uses, and falls back to `/account` or `/account/signedout` if it isn't. The shell's `data-account-config` carries only the availability flag and the host's wording.

The account layout loads the same URL, and a module only runs once per document, so loading it twice is harmless.

## Branding

Everything a host changes is on `AccountSiteOptions`:

- `ProductName`, `LogoUrl`, `Tagline`, `SupportEmail`, `TermsUrl`, `PrivacyUrl`.
- `Branding`: `None` (default), `ThreeHeadzCompany` or `ThreeHeadzPlatform` for the footer line.
- `Theme`: colours, radius and font, emitted as CSS custom properties (`--account-primary` and friends) on the page shell.
- `Strings`: every visible string, English by default.
- `Slots`: host components for the hero, the manage page and the footer.
- `DefaultReturnUrl` and `SignedOutUrl`: where people land. Both must be paths on the site.

Markup carries Bootstrap 5 classes. The library ships only `account.css`, which lays the pages out and gives a host without Bootstrap usable defaults.

## Sign-up policy

`AccountSiteOptions.SignUp` is the core `SignUpPolicy`: `OpenSignUp`, `InviteCodes`, `RequireEmail`, `HandlePattern`, `ReservedHandlePrefixes`, `AllowHandleAvailabilityCheck`. With sign-up closed and no invite codes the page shows a message and no form.

The availability check is on by default because a handle is a public identifier. Turn it off and handles stay private: the endpoint isn't mapped, a taken handle fails sign-up without saying why, and sign-in ignores the handle it's sent and runs the discoverable ceremony. A handle-scoped sign-in lists that handle's passkeys, which would say the handle exists. So every passkey there has to be discoverable. `AddPasskeyAccounts` sets `PasskeyOptions.ResidentKey` to `required` on such a host (for sign-up and for added passkeys alike), and the browser refuses an authenticator that can't store one rather than creating a passkey that could never sign in. The sign-in page doesn't show the handle field there, since it would be ignored.

A host runs its own step after sign-up by registering an `IPostSignUpStep` on the registry (`registry.AddPostSignUpStep<MyStep>()`). Its `NextUrl` is where the new person lands, when it is a path on the site.

## Session

A verified sign-up or sign-in issues a cookie under the `Bam.Account` scheme: `HttpOnly`, `Secure`, `SameSite=Lax`, 14 days, sliding. `[Authorize(Policy = AccountWebRegistration.Policy)]` requires it. `AccountPrincipal.Handle(user)` reads the person's handle; the claim types are on `AccountClaims`. `User.Identity.Name` is the handle too. The display name is the person's own choice, so it's only on `AccountClaims.DisplayName` and `AccountPrincipal.DisplayName(user)`; don't use it to identify anyone.

The session's passkey is checked against the credential store every `Cookie.RevalidateEvery` (5 minutes). With `SlidingExpiration` off the cookie is never reissued, so the check runs on every request instead. Removing a passkey ends the sessions opened with it at their next check.

`AddPasskeyAccounts` makes `Bam.Account` the default authentication scheme only when the host hasn't set one.

On sign-in the display name claim is the handle. Sign-up carries the name the person typed.

## Endpoints

All under `/account`, JSON in and out, camelCase. The types are in `AccountWire.cs`.

| Method and path | Body | Returns |
|---|---|---|
| `POST /passkey/registration/begin` | `{ handle, displayName, email?, inviteCode? }` | `{ options }` for `navigator.credentials.create` |
| `POST /passkey/registration/complete` | the same fields plus `credential` (the `RegistrationResponseJSON`) | `{ handle, displayName, nextUrl, profileCreated }` and the cookie |
| `POST /passkey/assertion/begin` | `{ handle? }` | `{ options, ceremonyId }` for `navigator.credentials.get` |
| `POST /passkey/assertion/complete` | `{ ceremonyId, credential, returnUrl? }` | `{ handle, displayName, nextUrl }` and the cookie |
| `POST /passkey/additional/begin` | `{}` | `{ options }`. Session required |
| `POST /passkey/additional/complete` | `{ credential, name? }` | `{ credentialId }`. Session required |
| `GET /passkeys` | | `{ passkeys: [{ id, name, createdUtc, lastUsedUtc, current, registeredKeySet }] }`. Session required |
| `POST /passkeys/{id}/name` | `{ name }` | 204. Session required |
| `DELETE /passkeys/{id}` | | `{ signedOut, nextUrl }`. 409 `KeySetHandoverRequired` when the passkey holds the key set and it can move; `?keySet=keep` removes it anyway and leaves the key registered. Session required |
| `POST /passkeys/{id}/handover/begin` | `{ heir? }` | `{ handoverId, options }` for `navigator.credentials.get` with the passkey being removed. 404 `NotFound`, 409 `LastCredential`, 400 `InvalidHeir`, 400 `NotKeySet`, 409 `RotationUnavailable`. Session required |
| `POST /passkeys/{id}/handover/complete` | `{ handoverId, credential }` | `{ signedOut, nextUrl }`: the key set has moved and the passkey is removed. 400 `HandoverExpired`, 400 `ProofRefused`, 409 `KeySetChanged`, 409 `HeirGone`. Session required |
| `POST /profile` | `{ displayName, email? }` | 204 when saved or already there. 400 `EmailRequired` when the host requires an email and none (or an implausible one) is sent. 409 `ProfileNotSaved` when the store refuses or the session's handle has no passkey. 401 without a session. Saves a profile that wasn't saved at sign-up. The session's display name updates at the next sign-in |
| `POST /signout` | `{}` | `{ signedOut, nextUrl }` |
| `GET /handle/{handle}/availability` | | `{ handle, available, reason }` |

The signed-in endpoints take the person from the cookie. No body carries a handle for them.

A refusal is `{ error, message }`. `error` is one of `AccountErrorCodes`; `message` is the host's wording. Sign-in fails with `SignInFailed` whatever the cause. A request without a session gets 401, not a redirect. A request past the rate limit gets 429.

### The rule every state-changing request must meet

A `POST` or `DELETE` must carry the header `X-Bam-Account` with any non-empty value. If it also carries an `Origin` header, that origin must be the host's own or one of `PasskeyOptions.AllowedOrigins`. Anything else is refused with 403 `RequestRefused`.

A browser can't add a custom header to a cross-site request without a preflight the host never grants, so another site can't drive these endpoints with a visitor's cookie. A native client sends the header and no `Origin`, and keeps the cookie in its own HTTP client.

### Native apps

The endpoints are the whole contract; the pages are optional. An Android app's origin goes in `PasskeyOptions.AllowedAppOrigins` (see the passkey section of the repository README). iOS and Mac Catalyst apps present `https://<rp id>`.

## Rate limits

The sign-up and sign-in endpoints allow 10 requests a minute per client address, the availability check 30 (`AccountSiteOptions.RateLimits`). Behind a proxy the host must call `UseForwardedHeaders` first, or every visitor shares one bucket. `AddPasskeyAccounts` sets the rate limiter's rejection status to 429 for the whole host.

A host behind Caddy can also limit at the edge (with the `caddy-ratelimit` module):

```
rate_limit {
    zone account {
        match {
            path /account/passkey/* /account/handle/*
        }
        key    {remote_host}
        events 30
        window 1m
    }
}
```

## Known states and limits

- **Profile not written.** The passkey claims the handle before the profile is written. If that write fails the person is signed in anyway and `profileCreated` is false. The manage page then asks for their name and email again and saves them through `POST /profile`, under the same email rule as sign-up. Nothing is written until the person enters their details, so a host that requires email never gets a profile without one.
- **Removing the first passkey.** The first passkey is the handle's key set. When the host trusts the passkey rotation proof (see "Moving the key set to another passkey" in the repository README), removing it asks the person to confirm once with it, moves the key set to another of their passkeys, and then removes it. The browser module does this from the remove button. If the heir can't be used it tries another listed passkey, and if the key set can't move it asks before removing the passkey with `?keySet=keep`. Without the proof, or with `?keySet=keep`, the passkey stops working at once and its key stays registered in `bam.protocol` until it is revoked there.
- **Lost key-set passkey.** Recovering the key set from a surviving passkey is bam.protocol#85, not built yet.
- **Sign out everywhere** isn't built. Removing a passkey ends that passkey's sessions; other sessions run until they expire.
- **Passkey prompts need a secure context**: https, or `http://localhost` in development.
