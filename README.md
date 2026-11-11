# bam.useraccounts

User account management library providing authentication, credential management, role-based access control, email composition, and a generated DAO data layer.

## Overview

The `bam.useraccounts` project is a .NET 10 class library that provides a comprehensive user account management system for the Bam framework. It spans several concerns: credential storage and retrieval (`Bam.Encryption` namespace), authentication (`Bam.UserAccounts`), role-based authorization (`Bam.ServiceProxy`), email template composition (`Bam.Messaging`), and a generated DAO data layer with tables for users, accounts, logins, passwords, sessions, groups, roles, and permissions.

The credential subsystem defines a layered provider model (`ICredentialProvider` -> `INamedCredentialProvider` -> `IServiceCredentialProvider` -> `ICredentialManager`) supporting simple, target-scoped, and machine-service-scoped credential retrieval. The default implementation reads credentials from application configuration settings.

Authentication is handled through the `IAuthenticator` interface and its implementations: `Authenticator` (abstract base with SHA1 password hashing) and `CompositeAuthenticator` (chains multiple authenticators, short-circuiting on first success). The generated DAO layer (in `UserAccounts/UserAccounts_Generated/`) provides database-backed entities for Account, User, Login, Password, Session, Group, Role, Permission, and their relationships, though several DAO-dependent classes (`DaoAuthenticator`, `DaoIdentity`, `DaoRoleResolver`, `DaoUserResolver`, `UserManager`) are excluded from compilation.

## Key Classes

| Class | Description |
|-------|-------------|
| **Credential Management** | |
| `ICredentialProvider` | Base interface: `GetUserName()`, `GetPassword()`. |
| `INamedCredentialProvider` | Target-scoped credentials: `GetUserNameFor(targetIdentifier)`, `GetPasswordFor(targetIdentifier)`. |
| `IServiceCredentialProvider` | Machine-service-scoped credentials: `GetUserNameFor(machineName, serviceName)`. |
| `ICredentialManager` | Read/write credential management combining all three provider interfaces with `Set*` methods. |
| `CredentialProvider` | Abstract base class implementing all three provider interfaces. Has a static `Default` singleton. |
| `DefaultConfigurationCredentialProvider` | Reads credentials from `DefaultConfiguration` app settings using a configurable key pattern. |
| `CredentialInfo` | Data class: `UserName`, `Password`, `TargetService`, `MachineName`. |
| **Authentication** | |
| `IAuthenticator` | Interface: `IsPasswordValid(userName, password)`. |
| `Authenticator` | Abstract base: validates passwords by SHA1 hashing and comparing against stored hashes. |
| `CompositeAuthenticator` | Chains multiple `IAuthenticator` instances, returning `true` on first match. Extends `Loggable`. |
| **Roles and Authorization** | |
| `IRoleResolver` | Interface: `IsInRole(userResolver, roleName)`, `GetRoles(userResolver)`. Requires HTTP context. |
| `IRoleProvider` | Interface: CRUD for roles (`AddUsersToRoles`, `CreateRole`, `DeleteRole`, `RemoveUsersFromRoles`). |
| `RoleRequiredAttribute` | Attribute for classes/methods specifying required roles and a redirect URL. |
| **User Management** | |
| `IUserProvider` | Interface: `SetUser(context, userName, isAuthenticated)`. |
| `IDaoUserResolver` | Combined `IUserResolver` + `IUserProvider` with database access. |
| `UserAccountsDatabase` | Wrapper around `IDatabase` with implicit conversion from `Database`. |
| `UserAccountResponse` | Abstract base response class (`Success`, `Message`, `Data`) with JSON serialization. |
| `LoginResponse` | Response for login operations. |
| `SignUpResponse` | Response for sign-up operations. |
| `SignUpOptions` | Input data: `EmailAddress`, `UserName`, `PasswordHash`, `SendConfirmation`. |
| **Passkeys (`Bam.UserAccounts.Passkeys`)** | |
| `PasskeyOptions` | Relying-party policy: `RpId`, `RpName`, `AllowedOrigins`, `AllowedAppOrigins`, `RequireUserVerification`, `ChallengeLifetime`, `Algorithms` (ES256, RS256 by default). `Validate()` runs at registration. |
| `IPasskeyCeremony` / `PasskeyCeremony` | The WebAuthn ceremonies: sign-up `BeginRegistration` / `CompleteRegistration`, authenticated-only `BeginAdditionalRegistration` / `CompleteAdditionalRegistration`, `BeginAssertion` / `CompleteAssertion`, plus `ToRequestOptions` for a confirmation challenge. Challenges live in `IConfirmationChallengeRepository` under `passkey-*:` prefixed handles. |
| `PasskeyRegistrationVerifier`, `PasskeyAssertionVerifier` | Pure verifiers for a registration response (WebAuthn section 7.1) and an assertion (section 7.2). Never throw on client input; return a `PasskeyVerification` with a `PasskeyVerificationFailure`. |
| `IPasskeyCredentialRepository` | Credential custody: `Save`, `FindByCredentialId`, `FindByHandle`, `FindByUserHandle`, `RecordUse`, `FlagSignCountRegression`, `Activate`, `Remove`. `InMemoryPasskeyCredentialRepository` and `PersistedPasskeyCredentialRepository` (over `IRepository`). |
| `PasskeyCredentialData` | The stored credential: credential id, user handle, public key PEM, COSE algorithm, sign counter, AAGUID, transports, backup flags, whether it is the person's registered key set. |
| `PasskeyChallengeSignatureVerifier` | `IChallengeSignatureVerifier` whose signed challenge is the JSON of a `PasskeyAssertionResponse`. |
| `PasskeyAccountConfirmation` | `IAccountConfirmation` for passkeys; issues the same signed actor certificate as `DeviceKeyAccountConfirmation`. |
| `PasskeysServiceRegistration` | `AddPasskeys(ServiceRegistry, PasskeyOptions)` wires everything above. |
| **Email** | |
| `EmailComposer` | Abstract base for composing emails from templates stored as JSON files. Supports template caching and HTML/text modes. |
| `NamedFormatEmailComposer` | Concrete composer using named format strings (e.g., `{PropertyName}`) to populate templates. |
| `EmailTemplate` | Data class: `EmailName`, `IsHtml`, `TemplateContent`. |
| **Generated DAO Layer** | |
| `Account`, `User`, `Login`, `Password`, `Session`, `Group`, `Role`, `Permission`, etc. | Auto-generated DAO classes with collections, column definitions, queries, and partial extensions. Located in `UserAccounts/UserAccounts_Generated/`. |

## Dependencies

### Project References
- `bam.base` -- core framework primitives, extension methods, `Email`, `BamProfile`, `Args`
- `bam.data.repositories` -- data repository interfaces
- `bam.data` -- `Database`, `IDatabase`, data access layer
- `bam.encryption` -- `IPublicKey`, `EccPublicKey`/`RsaPublicKey`, COSE key parsing and detached signature verification used by passkeys
- `bam.protocol.data`, `bam.protocol.profile` -- `IPublicKeySetRegistrar`, `IProfileRepository`, `PublicKeyFingerprint`

### Package References
- `Newtonsoft.Json` 13.0.4 -- JSON serialization for `CredentialInfo`, `UserAccountResponse`, and email templates

### Content Files
- `UserAccounts/UserAccounts.db.js` -- JavaScript literal schema definition for the UserAccounts database

## Usage Examples

### Credential retrieval from configuration
```csharp
using Bam.Encryption;

ICredentialProvider provider = DefaultConfigurationCredentialProvider.Instance;
string userName = provider.GetUserName();
string password = provider.GetPassword();
```

### Named/service credential retrieval
```csharp
using Bam.Encryption;

INamedCredentialProvider provider = CredentialProvider.Default;
string dbUser = provider.GetUserNameFor("DatabaseService");
string dbPass = provider.GetPasswordFor("DatabaseService");
```

### Authentication
```csharp
using Bam.UserAccounts;

// Single authenticator
IAuthenticator authenticator = GetMyAuthenticator();
bool valid = authenticator.IsPasswordValid("admin", "password123");

// Composite authenticator (chains multiple)
var composite = new CompositeAuthenticator();
composite.AddAuthenticators(localAuthenticator, ldapAuthenticator);
bool authenticated = composite.IsPasswordValid("admin", "password123");
```

### Role-based access control via attribute
```csharp
using Bam;

[RoleRequired("/unauthorized", "Admin", "SuperUser")]
public class AdminController
{
    // Only accessible to users in "Admin" or "SuperUser" roles
}
```

### Composing emails from templates
```csharp
using Bam.Messaging;

var composer = new NamedFormatEmailComposer("./email-templates");
composer.SetEmailTemplate("welcome", "Hello {UserName}, welcome!", isHtml: false);

Email email = composer.Compose("Welcome!", "welcome", new { UserName = "Alice" });
```

### Passkeys

A passkey (WebAuthn credential) is registered as the person's key set and then used to sign in or to confirm the account. The library does the server half of both ceremonies; the host serves the options to the browser, which runs `navigator.credentials.create()` / `get()`, and posts the browser's response back as JSON.

```csharp
using Bam.UserAccounts.Passkeys;

// Registration. IRepository, IPublicKeySetRegistrar, IProfileRepository and ICertificateManager
// come from the host registry.
registry.AddPasskeys(new PasskeyOptions
{
    RpId = "example.com",
    RpName = "Example",
    AllowedOrigins = new List<string> { "https://example.com" }
});
IPasskeyCeremony ceremony = registry.Get<IPasskeyCeremony>();

// 1. Sign-up: send the creation options to the browser, verify what it returns. Anonymous callers
//    may reach this; it claims the handle for its first passkey and refuses a handle that is taken.
PasskeyCreationOptions creation = ceremony.BeginRegistration("person-handle", "Jane Doe");
// ... browser runs navigator.credentials.create({ publicKey: creation }) and posts the result ...
PasskeyRegistrationResponse registration = PasskeyRegistrationResponse.FromJson(requestBodyBytes);
PasskeyRegistrationResult registered = ceremony.CompleteRegistration("person-handle", registration);
// registered.KeySetRegistered is true: this credential is the person's key set.

// 1b. Adding a passkey to an existing person. ONLY for a caller the host has already
//     authenticated as "person-handle" (a signed-in session): never on an anonymous surface.
PasskeyCreationOptions more = ceremony.BeginAdditionalRegistration("person-handle", "Jane Doe");
PasskeyRegistrationResult added = ceremony.CompleteAdditionalRegistration("person-handle", PasskeyRegistrationResponse.FromJson(requestBodyBytes));

// 2. Sign-in: a discoverable (handle-less) or handle-scoped assertion.
PasskeyRequestOptions request = ceremony.BeginAssertion(personHandle: null);
// ... browser runs navigator.credentials.get({ publicKey: request }); the response carries request.CeremonyId ...
PasskeySignInResult signedIn = ceremony.CompleteAssertion(PasskeyAssertionResponse.FromJson(requestBodyBytes));

// 3. Account confirmation with the passkey instead of a device key.
PasskeyAccountConfirmation confirmation = registry.Get<PasskeyAccountConfirmation>();
ConfirmationChallenge challenge = confirmation.CreateChallenge("person-handle");
PasskeyRequestOptions toSign = ceremony.ToRequestOptions(challenge);
// ... browser signs; the signed challenge is the UTF-8 JSON of the assertion response ...
ConfirmationResult confirmed = confirmation.VerifySignedChallenge("person-handle", signedChallengeBytes);
```

Behaviour worth knowing:

- Every failure returns one generic message (`PasskeyCeremony.VerificationFailedMessage` or `DeviceKeyAccountConfirmation.VerificationFailedMessage`); the specific `PasskeyVerificationFailure` and detail are logged at warning level and carried on the result for the host, never for the wire.
- Challenges are single-use and expire after `PasskeyOptions.ChallengeLifetime`. A failed attempt consumes the challenge.
- Sign-up (`BeginRegistration` / `CompleteRegistration`) claims a handle: the passkey is registered as the person's public key set through `IPublicKeySetRegistrar`, and a handle that already has a passkey or a key set is refused (`HandleAlreadyRegistered`) with nothing stored, so an anonymous caller can never attach a credential to an existing person. `BeginRegistration` reveals nothing about whether a handle exists. Key material already registered to another handle, or revoked, is refused. The credential row is saved before the registrar is consulted, marked `Pending`, and removed when the registrar refuses. A pending credential cannot sign in or confirm an account and is not offered in `allowCredentials`; it becomes usable only once the registrar has accepted its key. A pending row left by a process that stopped, or a store that faulted, mid-registration is inert. After `PasskeyCeremony.PendingCredentialGrace` (5 minutes) the next registration for its handle settles it by asking the registrar: a row whose key the registrar holds as the handle's key set is activated, any other is removed. Custody enforces credential-id uniqueness itself: `Save` throws `PasskeyCredentialConflictException` for an id that already has a row, and `Activate` / `Remove` address a row by person handle and credential id together.
- Adding a passkey (`BeginAdditionalRegistration` / `CompleteAdditionalRegistration`) is the authenticated path: call it only for a caller already signed in as the handle. It reuses the person's user id, excludes their existing credentials, and stores the passkey as an additional credential; when the person has only a device-key key set, that key set stands.
- `BeginAssertion(handle)` binds the ceremony to the handle: a credential belonging to anyone else fails. It also reveals whether the handle has credentials, so anonymous sign-in surfaces should prefer discoverable sign-in (`BeginAssertion(null)`) and read the person from `PasskeySignInResult.PersonHandle`.
- Every `Begin*` call stores a challenge row for any caller; hosts rate-limit anonymous surfaces as they do for confirmation challenges.
- The sign counter is enforced when the stored counter is non-zero; a counter that does not advance flags the credential (`SignCountRegressed`) and refuses the assertion.
- Base64url fields over 64 KiB are refused before decoding. Hosts should still bound the request body.
- `AddPasskeys` binds the two adapters under their concrete types and, when the host has not bound them, under `IAccountConfirmation` / `IChallengeSignatureVerifier`, so a passkey-only host gets `UserAccountService.ConfirmAccount` on passkeys purely by registration. A host that calls `AddDeviceKeyAccountConfirmation` first keeps the device-key bindings and reaches the passkey path by resolving `PasskeyAccountConfirmation`. Existing `IConfirmationChallengeRepository`, `IPasskeyCredentialRepository` and `IDetachedSignatureVerifier` bindings are respected; note that `AddDeviceKeyAccountConfirmation` itself rebinds challenge custody, so bind custom custody after it.
- Attestation statements are not verified; registration asks for `attestation: "none"`.

### Passkeys from native apps

A browser presents an https origin. A native Android app that uses Credential Manager presents `android:apk-key-hash:<hash>` instead, where the hash identifies the certificate the app was signed with. List each one in `AllowedAppOrigins`:

```csharp
registry.AddPasskeys(new PasskeyOptions
{
    RpId = "example.com",
    RpName = "Example",
    AllowedOrigins = new List<string> { "https://example.com" },
    AllowedAppOrigins = new List<string>
    {
        "android:apk-key-hash:<release key hash>",
        "android:apk-key-hash:<debug key hash>"
    }
});
```

App origins are matched as exact, case-sensitive strings and only against this list. The browser list keeps its own rule (scheme, host and port), and the two never cross. The list is empty by default, so no Android app is accepted until one is listed. A browser origin is still required: the relying-party domain has to exist to serve the association files.

Every key that signs the app needs its own entry: the debug key on each developer machine, the upload key, and the Play app signing key if Google re-signs the release. Leave debug hashes out of production configuration.

To get the value, take the SHA-256 fingerprint of the signing certificate (`keytool -list -v -keystore <keystore> -alias <alias>`, or the Play Console's app signing page), convert the 32 bytes from hex to base64url, and drop the `=` padding. The surest check is to run one ceremony from the app and read the origin the server refused: with the list empty the failure detail names it. Sources disagree on whether some Android versions send a SHA-1 hash here; the server compares the whole string, so whatever the device sends is what goes in the list.

iOS and Mac Catalyst apps present `https://<rp id>`, so `AllowedOrigins` already covers them.

The app's domain also has to vouch for the app (`/.well-known/assetlinks.json` for Android, `/.well-known/apple-app-site-association` for Apple) or the operating system refuses the ceremony before the server sees it. Serving those from options is tracked in #13.

## Known Gaps / Not Yet Implemented

- **`IAuthenticator` interface** -- Contains a `TODO: redesign this concept to align with modern authentication concepts` comment, suggesting a future move toward challenge-based authentication.
- **Excluded DAO classes** -- `DaoAuthenticator.cs`, `DaoIdentity.cs`, `DaoRoleResolver.cs`, `DaoUserResolver.cs`, and `UserManager.cs` are excluded from compilation in the `.csproj`. These were likely database-backed implementations that need updating.
- **`Password` partial** -- The `Set` method in `UserAccounts_Generated/Partials/Password.cs` throws `NotImplementedException("Revisit this to correct password storage handling")`.
- **`Session` partial** -- Contains a `TODO: Write unit test` comment on `Session.End()` and throws `NotImplementedException("Revisit this to determine appropriate implementation for binary data")` in session state handling.
- **`UserAccountsDatabase.Default`** -- The static default database property is commented out, with the previous SQLite-based implementation disabled.
- **Generated DAO layer excluded** -- The entire `UserAccounts/UserAccounts_Generated/` directory is removed from compilation via the `.csproj`, meaning the DAO data layer is not actively compiled or used.
