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

## Known Gaps / Not Yet Implemented

- **`IAuthenticator` interface** -- Contains a `TODO: redesign this concept to align with modern authentication concepts` comment, suggesting a future move toward challenge-based authentication.
- **Excluded DAO classes** -- `DaoAuthenticator.cs`, `DaoIdentity.cs`, `DaoRoleResolver.cs`, `DaoUserResolver.cs`, and `UserManager.cs` are excluded from compilation in the `.csproj`. These were likely database-backed implementations that need updating.
- **`Password` partial** -- The `Set` method in `UserAccounts_Generated/Partials/Password.cs` throws `NotImplementedException("Revisit this to correct password storage handling")`.
- **`Session` partial** -- Contains a `TODO: Write unit test` comment on `Session.End()` and throws `NotImplementedException("Revisit this to determine appropriate implementation for binary data")` in session state handling.
- **`UserAccountsDatabase.Default`** -- The static default database property is commented out, with the previous SQLite-based implementation disabled.
- **Generated DAO layer excluded** -- The entire `UserAccounts/UserAccounts_Generated/` directory is removed from compilation via the `.csproj`, meaning the DAO data layer is not actively compiled or used.
